# 介绍

最好用的 sing-box 一键安装脚本 & 管理脚本

**系统支持：Ubuntu，Debian，CentOS。推荐使用 Ubuntu 22，谨慎使用 CentOS，脚本可能无法正常运行！**

## 一键安装命令

```bash
bash <(wget -qO- -o- https://github.com/fanassasj/sing-box/raw/main/install.sh)
```

- 如需查看安装命令帮助，在安装命令后面加 `-h` 即可。

# 特点

- 快速安装
- 无敌好用
- 零学习成本
- 自动化 TLS
- 简化所有流程
- 兼容 sing-box 命令
- 强大的快捷参数
- 支持所有常用协议
- 一键添加 VLESS-REALITY (默认)
- 一键添加 TUIC
- 一键添加 Trojan
- 一键添加 Hysteria2
- 一键添加 Shadowsocks 2022
- 一键添加 VMess-(TCP/HTTP/QUIC)
- 一键添加 VMess-(WS/H2/HTTPUpgrade)-TLS
- 一键添加 VLESS-(WS/H2/HTTPUpgrade)-TLS
- 一键添加 Trojan-(WS/H2/HTTPUpgrade)-TLS
- 一键启用 BBR
- 一键更改伪装网站
- 一键更改 (端口/UUID/密码/域名/路径/加密方式/SNI/等...)
- 还有更多...

# 设计理念

设计理念为：**高效率，超快速，极易用**

脚本基于作者的自身使用需求，以 **多配置同时运行** 为核心设计

并且专门优化了，添加、更改、查看、删除、这四项常用功能

你只需要一条命令即可完成 添加、更改、查看、删除、等操作

例如，添加一个配置仅需不到 1 秒！瞬间完成添加！其他操作亦是如此！

脚本的参数非常高效率并且超级易用，请掌握参数的使用

# 文档

安装及使用：https://233boy.com/sing-box/sing-box-script/

# 帮助

使用：`sing-box help`

```
sing-box script v1.0 by 233boy
Usage: sing-box [options]... [args]...

基本:
   v, version                                      显示当前版本
   ip                                              返回当前主机的 IP
   pbk                                             同等于 sing-box generate reality-keypair
   get-port                                        返回一个可用的端口
   ss2022                                          返回一个可用于 Shadowsocks 2022 的密码

一般:
   a, add [protocol] [args... | auto]              添加配置
   c, change [name] [option] [args... | auto]      更改配置
   d, del [name]                                   删除配置**
   i, info [name]                                  查看配置
   qr [name]                                       二维码信息
   url [name]                                      URL 信息
   log                                             查看日志
更改:
   full [name] [...]                               更改多个参数
   id [name] [uuid | auto]                         更改 UUID
   host [name] [domain]                            更改域名
   port [name] [port | auto]                       更改端口
   path [name] [path | auto]                       更改路径
   passwd [name] [password | auto]                 更改密码
   key [name] [Private key | atuo] [Public key]    更改密钥
   method [name] [method | auto]                   更改加密方式
   sni [name] [ ip | domain]                       更改 serverName
   new [name] [...]                                更改协议
   web [name] [domain]                             更改伪装网站

进阶:
   dns [...]                                       设置 DNS
   dd, ddel [name...]                              删除多个配置**
   fix [name]                                      修复一个配置
   fix-all                                         修复全部配置
   fix-caddyfile                                   修复 Caddyfile
   fix-config.json                                 修复 config.json
   import                                          导入 sing-box/v2ray 脚本配置

管理:
   un, uninstall                                   卸载
   u, update [core | sh | caddy] [ver]             更新
   U, update.sh                                    更新脚本
   s, status                                       运行状态
   start, stop, restart [caddy]                    启动, 停止, 重启
   t, test                                         测试运行
   reinstall                                       重装脚本

测试:
   debug [name]                                    显示一些 debug 信息, 仅供参考
   gen [...]                                       同等于 add, 但只显示 JSON 内容, 不创建文件, 测试使用
   no-auto-tls [...]                               同等于 add, 但禁止自动配置 TLS, 可用于 *TLS 相关协议
其他:
   bbr                                             启用 BBR, 如果支持
   bin [...]                                       运行 sing-box 命令, 例如: sing-box bin help
   [...] [...]                                     兼容绝大多数的 sing-box 命令, 例如: sing-box generate uuid
   h, help                                         显示此帮助界面




# http 代理使用教程

## 添加 http 代理

1.  **快速添加 HTTP 代理**：
    默认情况下，用户名和密码会自动随机生成。您可以只指定端口号：
    ```bash
    sing-box add http <端口号>
    # 例如：sing-box add http 3128
    ```
    在交互式创建过程中，脚本会询问您是否启用 IP 白名单，并提示输入 IP 列表（如果启用）。

2.  **添加 HTTP 代理并自定义认证和白名单（命令行参数方式）**：
    您也可以在添加时直接指定用户名、密码、是否启用白名单以及白名单 IP 列表：
    ```bash
    sing-box add http <端口号> [用户名] [密码] [是否启用白名单(1为是,0为否)] [IP列表(逗号分隔)]
    # 示例1: 指定用户名和密码，不启用白名单
    # sing-box add http 3129 myuser mypass 0
    # 示例2: 自动生成用户名密码，但启用白名单并指定IP
    # sing-box add http 3130 auto auto 1 "1.1.1.1,2.2.2.0/24"
    # 示例3: 指定所有参数
    # sing-box add http 3131 customuser custpass 1 "192.168.1.100,10.0.0.0/8"
    ```
    *   如果用户名或密码想使用自动生成的，请在该参数位置使用 `auto`。
    *   IP 列表请用英文逗号分隔，如果包含特殊字符或空格，建议用引号括起来。

## 查看与管理 HTTP 代理

1.  **查看 HTTP 代理配置信息**：
    此命令会显示代理的端口、用户名、密码、当前白名单状态及IP列表（如果已启用）等。
    ```bash
    sing-box info <配置名>
    # 例如，如果通过 'sing-box add http 3128' 创建，配置名通常是 Http-3128.json
    # sing-box info Http-3128.json
    # 您也可以不带配置名运行 sing-box info，然后在列表中选择。
    ```

2.  **修改 HTTP 代理白名单（创建后）**：
    如果您在创建时未设置白名单，或需要修改现有白名单：
    *   启用/禁用白名单：
        ```bash
        sing-box change <配置名> "启用/禁用 http 白名单"
        # 脚本会提示您选择启用 (1) 或禁用 (0)。
        ```
    *   设置/更新白名单 IP 列表：
        ```bash
        sing-box change <配置名> "设置 http 白名单"
        # 脚本会提示您输入新的 IP 列表 (逗号分隔，例如: 1.2.3.4,5.6.7.8)。
        # 如果之前已启用白名单，这会覆盖旧的IP列表。如果之前未启用，通常需要先执行上面的启用操作。
        ```

    **重要提示**：当通过脚本成功添加、修改或删除白名单规则后，`sing-box` 服务将会自动重启以确保规则立即生效。

3.  **代理 URL**：
    `sing-box info` 命令会直接显示可用于客户端配置的 HTTP 代理 URL。

4.  **其他管理命令**：
    如更改端口、用户名、密码等，请参考 `sing-box help` 中 `change` 命令的相关参数，操作逻辑与 SOCKS5 代理类似。
    删除代理请使用 `sing-box del <配置名>`。

谨慎使用 del, ddel, 此选项会直接删除配置; 无需确认

反馈问题) https://github.com/233boy/sing-box/issues
文档(doc) https://233boy.com/sing-box/sing-box-script/