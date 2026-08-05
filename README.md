# Github Actions Padavan YK-L1

- Padavan源码是[fightroad/Padavan-KVR](https://github.com/fightroad/Padavan-KVR)。
- Github Actions参考自[Ljzkirito/Actions-Padavan_Redmi-AC2100](https://github.com/Ljzkirito/Actions-Padavan_Redmi-AC2100)。
- 编译目标为YK-L1
- 默认登陆地址[192.168.2.1](http://192.168.2.1),登录名admin/admin
- wifi密码1234567890
- 开启插件`shadowsocks`,`xray`(使用 `singbox-lx_mini` 代替)

## 其它路由器型号也可以刷

- 更换对应的配置文件(YK-L1.config)
- 修改`.github/workflows/build-Padavan.yml` 环境变量为对应型号
- 这里提供的是`mips32le`版本，根据自己路由器cpu架构选择更换singbox-lx_mini二进制文件
```
支持xhttp,xtls-rprx-vision,reality,utls
开启服务后剩余内存约为30MB
```

# 截图
- ![](https://raw.githubusercontent.com/blickers/Padavan_YK-L1/main/screenshot1.png)
- ![](https://raw.githubusercontent.com/blickers/Padavan_YK-L1/main/screenshot2.png)

