-- 生成 sing-box-lx 的配置文件，支持 xhttp 和 reality

local cjson = require "cjson"
local server_section = arg[1]
local proto = arg[2]
local local_port = arg[3] or "0"
local socks_port = arg[4] or "0"
local ssrindext = io.popen("dbus get ssconf_basic_json_" .. server_section)
local servertmp = ssrindext:read("*all")
local server = cjson.decode(servertmp)

-- 1. 辅助函数：将逗号分隔的 ALPN 字符串转为数组 (如 "h2,http/1.1" -> {"h2", "http/1.1"})
local function parse_alpn(alpn_str)
	if not alpn_str or alpn_str == "" then return nil end
	local alpn_table = {}
	for item in string.gmatch(alpn_str, "([^,]+)") do
		table.insert(alpn_table, item)
	end
	return #alpn_table > 0 and alpn_table or nil
end

-- 2. 组装 TLS / REALITY / uTLS / ALPN / ECH 配置
local tls_config = nil
if server.tls == '1' or server.tls == '2' then
	tls_config = {
		enabled = true,
		server_name = server.tls_host,
		insecure = (server.insecure == 1 or server.insecure == "1") and true or nil,
		alpn = parse_alpn(server.alpn)
	}

	-- REALITY 模式
	if server.tls == '2' then
		tls_config.reality = {
			enabled = true,
			public_key = server.public_key,
			short_id = server.short_id
		}
	end

	-- uTLS Fingerprint 伪装指纹
	if server.tls_fp and server.tls_fp ~= "" and server.tls_fp ~= "0" and server.tls_fp ~= "none" then
		tls_config.utls = {
			enabled = true,
			fingerprint = server.tls_fp
		}
	end

	-- ECH (Encrypted Client Hello)
	if server.ech_config and server.ech_config ~= "" then
		local ech_str = server.ech_config
		-- 过滤/过滤掉非法的 URL 或 DoH 组合语法（如带 http、https、+、/dns-query 等）
		local is_url_syntax = ech_str:find("http://") or ech_str:find("https://") or ech_str:find("%+")
		-- 判断是否为大致合法的 Base64 字符串（只包含字母、数字、+、/、= 且不含 URL 标记）
		if not is_url_syntax then
			tls_config.ech = {
				enabled = true,
				config = { ech_str }
			}
		end
	end
end

-- 3. 组装 Transport (传输层) 配置
local transport_config = nil
if server.transport == "ws" then
	transport_config = {
		type = "ws",
		path = server.ws_path,
		headers = (server.ws_host and server.ws_host ~= "") and {
			Host = server.ws_host
		} or nil
	}
elseif server.transport == "httpupgrade" then
	transport_config = {
		type = "httpupgrade",
		path = server.ws_path,
		host = server.ws_host
	}
elseif server.transport == "grpc" then
	transport_config = {
		type = "grpc",
		service_name = server.service_name,
		idle_timeout = "15s",
		ping_timeout = "15s"
	}
elseif server.transport == "h2" then
	transport_config = {
		type = "http",
		host = (server.h2_host and server.h2_host ~= "") and { server.h2_host } or nil,
		path = server.h2_path
	}
elseif server.transport == "xhttp" then
	local extra_json = nil
	if server.extra and server.extra ~= "" then
		pcall(function() extra_json = cjson.decode(server.extra) end)
	end
	transport_config = {
		type = "xhttp",
		path = server.http_path,
		host = server.http_host,
		mode = (server.mode and server.mode ~= "") and server.mode or "auto",
		extra = extra_json
	}
end

-- 4. 组装 Inbounds (在 inbound 中不包含过时的 sniff 字段)
local inbounds = {}

if local_port ~= "0" then
	table.insert(inbounds, {
		type = "redirect",
		tag = "redirect-in",
		listen = "0.0.0.0",
		listen_port = tonumber(local_port)
	})
end

if proto == "tcp" and socks_port ~= "0" then
	table.insert(inbounds, {
		type = "socks",
		tag = "socks-in",
		listen = "0.0.0.0",
		listen_port = tonumber(socks_port)
	})
end

-- 5. 组装 Route Rules (符合 sing-box 1.11+ 的规则嗅探机制)
local route_rules = {
	{
		action = "sniff",
		sniffer = { "http", "tls", "quic" },
		timeout = "300ms"
	}
}

-- 6. 构建最终的 JSON 数据
local singbox = {
	log = {
		level = "warn",
		timestamp = true
	},
	inbounds = inbounds,
	outbounds = {
		{
			type = "vless",
			tag = "proxy",
			server = server.server,
			server_port = tonumber(server.server_port),
			uuid = server.vmess_id,
			flow = (server.flow and server.flow ~= "" and server.flow ~= "0" and server.flow ~= "none") and server.flow or nil,
			tls = tls_config,
			transport = transport_config
		},
		{
			type = "direct",
			tag = "direct"
		},
		{
			type = "block",
			tag = "block"
		}
	},
	route = {
		rules = route_rules,
		auto_detect_interface = true
	}
}

print(cjson.encode(singbox))
