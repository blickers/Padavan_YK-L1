------------------------------------------------
-- This file is part of the luci-app-ssr-plus subscribe.lua
-- @author William Chan <root@williamchan.me>
-- 2020/03/15 by chongshengB
-- add support for xhttp, reality and more modern options.
-- 2026/08/05 by blickers
------------------------------------------------
require 'nixio'
local cjson = require "cjson"

local luci = luci
local tinsert = table.insert
local ssub, slen, schar, sbyte, sformat, sgsub = string.sub, string.len, string.char, string.byte, string.format, string.gsub
local b64decode = nixio.bin.b64decode
local cache = {}
local nodeResult = setmetatable({}, { __index = cache })  -- update result
local name = 'shadowsocksr'
local uciType = 'servers'
local subscribe_url = {}
local i = 1

local tfilter_words = io.popen("echo -n `nvram get ss_keyword`")
local filter_words = tfilter_words:read("*all")

-- 1. 安全读取 /tmp/dlist.txt，防止空文件或找不到文件
local dlist_file = io.open("/tmp/dlist.txt", "r")
if dlist_file then
	for line in dlist_file:lines() do
		if line and line ~= "" then
			print(line)
			subscribe_url[i] = line
			i = i + 1
		end
	end
	dlist_file:close()
end

local function base64Decode(text)
	local raw = text
	if not text then return '' end
	text = text:gsub("%z", "")
	text = text:gsub("_", "/")
	text = text:gsub("-", "+")
	local mod4 = #text % 4
	text = text .. string.sub('====', mod4 + 1)
	local result = b64decode(text)
	
	if result then
		return result:gsub("%z", "")
	else
		return raw
	end
end

local log = function(...)
	print(os.date("%Y-%m-%d %H:%M:%S ") .. table.concat({ ... }, " "))
	os.execute("logger -t 'SS' '" .. table.concat({ ... }, " ") .. "'")
end

local function split(full, sep)
	if not full then return {} end
	full = full:gsub("%z", "")
	local off, result = 1, {}
	while true do
		local nStart, nEnd = full:find(sep, off)
		if not nEnd then
			local res = ssub(full, off, slen(full))
			if #res > 0 then
				tinsert(result, res)
			end
			break
		else
			tinsert(result, ssub(full, off, nStart - 1))
			off = nEnd + 1
		end
	end
	return result
end

local function get_urlencode(c)
	return sformat("%%%02X", sbyte(c))
end

local function urlEncode(szText)
	local str = szText:gsub("([^0-9a-zA-Z ])", get_urlencode)
	str = str:gsub(" ", "+")
	return str
end

local function get_urldecode(h)
	return schar(tonumber(h, 16))
end

local function UrlDecode(szText)
	return szText:gsub("+", " "):gsub("%%(%x%x)", get_urldecode)
end

local function trim(text)
	if not text or text == "" then
		return ""
	end
	return (sgsub(text, "^%s*(.-)%s*$", "%1"))
end

local function md5(content)
	local stdout = io.popen("echo -n '" .. urlEncode(content) .. "'|md5sum|cut -d ' ' -f1")
	local stdout2 = stdout:read("*all")
	return trim(stdout2)
end

-- 辅助函数：安全地解析 JSON 字符串，捕获语法错误
local function safe_json_decode(str)
	if not str or str == "" then return nil end
	str = trim(str)
	local ok, res = pcall(cjson.decode, str)
	if ok then
		return res
	end
	return nil
end

local function processData(szType, content)
	local result = {
		type = szType,
		local_port = 1234,
		kcp_param = '--nocomp'
	}
	if szType == 'ssr' then
		local dat = split(content, "/%?")
		local hostInfo = split(dat[1], ':')
		result.server = hostInfo[1]
		result.server_port = hostInfo[2]
		result.protocol = hostInfo[3]
		result.encrypt_method = hostInfo[4]
		result.obfs = hostInfo[5]
		result.password = base64Decode(hostInfo[6])
		local params = {}
		if dat[2] then
			for _, v in pairs(split(dat[2], '&')) do
				local t = split(v, '=')
				if t[1] then params[t[1]] = t[2] end
			end
		end
		result.obfs_param = base64Decode(params.obfsparam)
		result.protocol_param = base64Decode(params.protoparam)
		local group = base64Decode(params.group)
		if group then
			result.alias = "["  .. group .. "] "
		end
		result.alias = (result.alias or "") .. base64Decode(params.remarks)
	elseif szType == 'vmess' then
		local info = safe_json_decode(content)
		if not info then return nil end
		result.type = 'v2ray'
		result.server = info.add
		result.server_port = info.port
		result.transport = info.net
		result.alter_id = info.aid
		result.vmess_id = info.id
		result.alias = info.ps
		result.network = info.net
		if info.net == 'ws' then
			result.ws_host = info.host
			result.ws_path = info.path
		end
		if info.net == 'h2' then
			result.h2_host = info.host
			result.h2_path = info.path
		end
		if info.net == 'tcp' then
			if info.type and info.type ~= "http" then
				info.type = "none"
			end
			result.tcp_guise = info.type
			result.http_host = info.host
			result.http_path = info.path
		end
		if info.net == 'kcp' then
			result.kcp_guise = info.type
			result.mtu = 1350
			result.tti = 50
			result.uplink_capacity = 5
			result.downlink_capacity = 20
			result.read_buffer_size = 2
			result.write_buffer_size = 2
		end
		if info.net == 'quic' then
			result.quic_guise = info.type
			result.quic_key = info.key
			result.quic_security = info.securty
		end
		if info.security then
			result.security = info.security
		end
		if info.tls == "tls" or info.tls == "1" then
			result.tls = "1"
			result.tls_host = info.host
			result.insecure = 1
		else
			result.tls = "0"
		end
		if info.fp and info.fp ~= "" then result.tls_fp = info.fp end
		if info.alpn and info.alpn ~= "" then result.alpn = info.alpn end
	elseif szType == 'vless' then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = (idx_sp > 0) and content:sub(1, idx_sp - 1) or content
		local hostInfo = split(info, "@")
		if not hostInfo[2] then return nil end
		local host = split(hostInfo[2], ":")
		local userinfo = hostInfo[1]
		local password = userinfo		
		result.alias = UrlDecode(alias)
		result.type = "xray"
		result.server = host[1]
		result.insecure = "0"
		result.security = "none"
		result.tls = "1"
		
		if host[2] and host[2]:find("%?") then
			local query = split(host[2], "%?")
			result.server_port = query[1]
			local params = {}
			if query[2] then
				for _, v in pairs(split(UrlDecode(query[2]), '&')) do
					local t = split(v, '=')
					if t[1] and t[2] then
						params[t[1]] = t[2]
					end
				end
			end
			
			result.transport = params.type or "tcp"
			result.network = result.transport
			
			if result.transport == 'ws' then
				result.ws_host = params.host
				result.ws_path = params.path
			elseif result.transport == 'httpupgrade' then
				result.ws_host = params.host
				result.ws_path = params.path
			elseif result.transport == 'xhttp' then
				result.http_host = params.host
				result.http_path = params.path
				result.mode = params.mode or "auto"
				result.extra = params.extra
			elseif result.transport == 'grpc' then
				result.service_name = params.serviceName or params.path
				result.multi_mode = params.mode
			elseif result.transport == 'h2' then
				result.h2_host = params.host
				result.h2_path = params.path
			elseif result.transport == 'tcp' then
				if params.headerType and params.headerType ~= "none" then
					result.tcp_guise = params.headerType
				else
					result.tcp_guise = params.type or "none"
				end
				result.http_host = params.host
				result.http_path = params.path
			elseif result.transport == 'kcp' then
				result.kcp_guise = params.headerType or params.type
				result.mtu = 1350
				result.tti = 50
				result.uplink_capacity = 5
				result.downlink_capacity = 20
				result.read_buffer_size = 2
				result.write_buffer_size = 2
			elseif result.transport == 'quic' then
				result.quic_guise = params.headerType or params.type
				result.quic_key = params.key
				result.quic_security = params.quicSecurity
			end

			if params.encryption then
				result.security = params.encryption
			end
			result.flow = params.flow

			if params.fp and params.fp ~= "" and params.fp ~= "none" then
				result.tls_fp = params.fp
			end
			if params.alpn and params.alpn ~= "" then
				result.alpn = params.alpn
			end
			if params.ech and params.ech ~= "" then
				result.ech_config = params.ech
			end

			local sec = params.security
			if sec == "tls" or sec == "1" then
				result.tls = "1"
				result.tls_host = params.sni or params.host
				result.insecure = (params.allowInsecure == "1" or params.allowInsecure == "true") and 1 or 0
			elseif sec == "reality" or sec == "2" then
				result.tls = "2"
				result.tls_host = params.sni or params.host
				result.public_key = params.pbk
				result.short_id = params.sid
				result.spiderx = params.spx
				result.insecure = 0
			elseif sec == "xtls" then
				result.tls = "1"
				result.tls_host = params.sni or params.host
				result.insecure = 0
			else
				result.tls = "0"
			end
		else
			result.server_port = host[2]
		end
		
		result.alter_id = 0
		result.vmess_id = password
	elseif szType == "ss" then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = (idx_sp > 0) and content:sub(1, idx_sp - 1) or content
		local hostInfo = split(base64Decode(info), "@")
		if not hostInfo[2] then return nil end
		local host = split(hostInfo[2], ":")
		local userinfo = base64Decode(hostInfo[1])
		local method = userinfo:sub(1, (userinfo:find(":") or 1) - 1)
		local password = userinfo:sub((userinfo:find(":") or 0) + 1, #userinfo)
		result.alias = UrlDecode(alias)
		result.type = "ss"
		result.server = host[1]
		if host[2] and host[2]:find("/%?") then
			local query = split(host[2], "/%?")
			result.server_port = query[1]
			local params = {}
			if query[2] then
				for _, v in pairs(split(query[2], '&')) do
					local t = split(v, '=')
					if t[1] then params[t[1]] = t[2] end
				end
			end
			if params.plugin then
				local plugin_info = UrlDecode(params.plugin)
				local idx_pn = plugin_info:find(";")
				if idx_pn then
					result.plugin = plugin_info:sub(1, idx_pn - 1)
					result.plugin_opts = plugin_info:sub(idx_pn + 1, #plugin_info)
				else
					result.plugin = plugin_info
				end
				if result.plugin == "simple-obfs" then
					result.plugin = "obfs-local"
				end
			end
		else
			result.server_port = host[2] and host[2]:gsub("/","") or "8388"
		end
		result.encrypt_method_ss = method
		result.password = password
	elseif szType == "trojan" then
		local idx_sp = 0
		local alias = ""
		if content:find("#") then
			idx_sp = content:find("#")
			alias = content:sub(idx_sp + 1, -1)
		end
		local info = (idx_sp > 0) and content:sub(1, idx_sp - 1) or content
		local hostInfo = split(info, "@")
		if not hostInfo[2] then return nil end
		local host = split(hostInfo[2], ":")
		local userinfo = hostInfo[1]
		local password = userinfo
		result.alias = UrlDecode(alias)
		result.type = "trojan"
		result.server = host[1]
		result.insecure = "0"
		result.tls = "1"
		if host[2] and host[2]:find("%?") then
			local query = split(host[2], "%?")
			result.server_port = query[1]
			local params = {}
			if query[2] then
				for _, v in pairs(split(query[2], '&')) do
					local t = split(v, '=')
					if t[1] then params[t[1]] = t[2] end
				end
			end
			if params.sni then
				result.tls_host = params.sni
			end
			if params.allowInsecure == "1" then
				result.insecure = "1"
			else
				result.insecure = "0"
			end
			if params.fp and params.fp ~= "" then result.tls_fp = params.fp end
			if params.alpn and params.alpn ~= "" then result.alpn = params.alpn end
		else
			result.server_port = host[2]
		end
		result.password = password
	end
	if not result.alias then
		result.alias = (result.server or "") .. ':' .. (result.server_port or "")
	end
	local alias = result.alias
	result.alias = nil
	local switch_enable = result.switch_enable
	result.switch_enable = nil
	result.hashkey = md5(cjson.encode(result))
	print(result.hashkey)
	result.alias = alias
	result.switch_enable = switch_enable
	return result
end

local function wget(url)
	local stdout = io.popen('curl -k -s --connect-timeout 15 --retry 5 "' .. url .. '"')
	local sresult = stdout:read("*all")
    return trim(sresult)
end

local function check_filer(result)
	local filter_word = split(filter_words, "/")
	print(cjson.encode(filter_word))
	for i, v in pairs(filter_word) do
		if v and v ~= "" and result.alias and result.alias:find(v) then
			log('订阅节点关键字过滤:“' .. v ..'” ，该节点被丢弃')
			return true
		end
	end
end

local add, del = 0, 0
do
	for k, url in ipairs(subscribe_url) do
		local raw = wget(url)
		
		if #raw > 0 then
			local nodes, szType
			local groupHash = md5(url)
			cache[groupHash] = {}
			tinsert(nodeResult, {})
			local index = #nodeResult
			local info = safe_json_decode(raw)
			if info then
				nodes = info.servers or info
				if nodes[1] and nodes[1].server and nodes[1].method then
					szType = 'sip008'
				end
			else
				nodes = split(base64Decode(raw):gsub(" ", "_"), "\n")
			end
			for _, v in ipairs(nodes) do
				if v then
					local result
					if szType then
						result = processData(szType, v)
					else
						local node = trim(v)
						local dat = split(node, "://")
						if dat and dat[1] and dat[2] then
							local dat3 = ""
							if dat[3] then
								dat3 = "://" .. dat[3]
							end
							if dat[1] == 'ss' or dat[1] == 'trojan' or dat[1] == 'vless' then
								result = processData(dat[1], dat[2] .. dat3)
							else
								result = processData(dat[1], base64Decode(dat[2]))
							end
						end
					end
					if result then
						if not result.server or not result.server_port or check_filer(result) or result.server:match("[^0-9a-zA-Z%-%.%s]") then
							log('丢弃无效节点: ' .. (result.type or "") ..' 节点, ' .. (result.alias or ""))
						else
							log('成功解析: ' .. (result.type or "") ..' 节点, ' .. (result.alias or ""))
							result.grouphashkey = groupHash
							tinsert(nodeResult[index], result)
							cache[groupHash][result.hashkey] = nodeResult[index][#nodeResult[index]]
						end
					end
				end
			end
			log('成功解析节点数量: ' .. (nodes and #nodes or 0))
		else
			log(url .. ': 获取内容为空')
		end
	end
end

-- 2. 修改：增加安全控制，防止旧文件不存在或包含非 JSON 数据时崩溃
do
	if next(nodeResult) == nil then
		log("更新失败，没有可用的节点信息")
		return
	end
	
	local add, del = 0, 0
	local old_file = io.open("/tmp/dlinkold.txt", "r")
	if old_file then
		for line in old_file:lines() do
			line = trim(line)
			if line and line ~= "" then
				local olddb = io.popen("dbus get ssconf_basic_json_" .. line)
				local old_str = olddb:read("*all")
				olddb:close()
				
				-- 使用 safe_json_decode 替代直接 decode
				local old = safe_json_decode(old_str)
				if old then
					if old.grouphashkey or old.hashkey then
						if not nodeResult[old.grouphashkey] or not nodeResult[old.grouphashkey][old.hashkey] then
							io.popen("dbus remove ssconf_basic_json_" .. line)
							del = del + 1
						else
							setmetatable(nodeResult[old.grouphashkey][old.hashkey], { __index = { _ignore = true } })
						end
					else
						if not old.coustom then
							old.alias = (old.server or "") .. ':' .. (old.server_port or "")
						end
						log('忽略手动添加的节点: ' .. (old.alias or ""))
					end
				end
			end
		end
		old_file:close()
	end

	local ssrindext = io.popen('dbus list ssconf_basic_|grep _json_ | cut -d "=" -f1|cut -d "_" -f4|sort -rn|head -n1')
	local ssrindex_str = ssrindext:read("*all")
	ssrindext:close()
	
	local ssrindex = 1
	if ssrindex_str and #trim(ssrindex_str) > 0 then
		ssrindex = tonumber(trim(ssrindex_str)) + 1
	end

	for k, v in ipairs(nodeResult) do
		for kk, vv in ipairs(v) do
			if not vv._ignore then				
				io.popen("dbus set ssconf_basic_json_" .. ssrindex .. "='" .. cjson.encode(vv) .. "'")
				ssrindex = ssrindex + 1
				add = add + 1
			end
		end
	end
	log('新增节点数量: ' .. add, '删除节点数量: ' .. del)
	log('订阅更新成功')
end
