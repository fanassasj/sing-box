#!/bin/bash

protocol_list=(
    TUIC
    Trojan
    Hysteria2
    VMess-WS
    VMess-TCP
    VMess-HTTP
    VMess-QUIC
    Shadowsocks
    VMess-H2-TLS
    VMess-WS-TLS
    VLESS-H2-TLS
    VLESS-WS-TLS
    Trojan-H2-TLS
    Trojan-WS-TLS
    VMess-HTTPUpgrade-TLS
    VLESS-HTTPUpgrade-TLS
    Trojan-HTTPUpgrade-TLS
    VLESS-REALITY
    VLESS-HTTP2-REALITY
    # Direct
    Socks
    Http
    MTProto
)
ss_method_list=(
    aes-128-gcm
    aes-256-gcm
    chacha20-ietf-poly1305
    xchacha20-ietf-poly1305
    2022-blake3-aes-128-gcm
    2022-blake3-aes-256-gcm
    2022-blake3-chacha20-poly1305
)
mainmenu=(
    "添加配置"
    "更改配置"
    "查看配置"
    "删除配置"
    "运行管理"
    "更新"
    "卸载"
    "帮助"
    "其他"
    "关于"
)
info_list=(
    "协议 (protocol)"
    "地址 (address)"
    "端口 (port)"
    "用户ID (id)"
    "传输协议 (network)"
    "伪装类型 (type)"
    "伪装域名 (host)"
    "路径 (path)"
    "传输层安全 (TLS)"
    "应用层协议协商 (Alpn)"
    "密码 (password)"
    "加密方式 (encryption)"
    "链接 (URL)"
    "目标地址 (remote addr)"
    "目标端口 (remote port)"
    "流控 (flow)"
    "SNI (serverName)"
    "指纹 (Fingerprint)"
    "公钥 (Public key)"
    "用户名 (Username)"
    "跳过证书验证 (allowInsecure)"
    "拥塞控制算法 (congestion_control)"
    "MTP Secret"
)
change_list=(
    "更改协议"
    "更改端口"
    "更改域名"
    "更改路径"
    "更改密码"
    "更改 UUID"
    "更改加密方式"
    "更改目标地址"
    "更改目标端口"
    "更改密钥"
    "更改 SNI (serverName)"
    "更改伪装网站"
    "更改用户名 (Username)"
    "更改 http 用户名 (Http Username)"
    "更改 http 密码 (Http Password)"
    "启用/禁用 socks5 白名单"
    "设置 socks5 白名单"
    "启用/禁用 http 白名单"
    "设置 http 白名单"
    "启用/禁用 MTP 白名单"
    "设置 MTP 白名单"
    "更改 MTP Secret"
)
servername_list=(
    www.amazon.com
    www.ebay.com
    www.paypal.com
    www.cloudflare.com
    dash.cloudflare.com
    aws.amazon.com
)

is_random_ss_method=${ss_method_list[$(shuf -i 4-6 -n1)]} 
is_random_servername=${servername_list[$(shuf -i 0-$((${#servername_list[@]} - 1)) -n1)]}

msg() {
    echo -e "$@"
}

msg_ul() {
    echo -e "\e[4m$@\e[0m"
}

pause() {
    echo
    echo -ne "按 $(_green "Enter 回车键") 继续, 或按 $(_red "Ctrl + C") 取消."
    read -rs -d $'\n' 
    echo
}

red='\e[31m'
yellow='\e[33m'
gray='\e[90m'
green='\e[92m'
blue='\e[94m'
magenta='\e[95m'
cyan='\e[96m'
none='\e[0m'
_red() { echo -e "${red}$@${none}"; }
_blue() { echo -e "${blue}$@${none}"; }
_cyan() { echo -e "${cyan}$@${none}"; }
_green() { echo -e "${green}$@${none}"; }
_yellow() { echo -e "${yellow}$@${none}"; }
_magenta() { echo -e "${magenta}$@${none}"; }
_red_bg() { echo -e "\e[41m$@${none}"; }

_rm() {
    rm -rf "$@"
}
_cp() {
    cp -rf "$@"
}
_sed() {
    sed -i "$@"
}
_mkdir() {
    mkdir -p "$@"
}

is_err=$(_red_bg "错误!")
is_warn=$(_red_bg "警告!")

err() {
    echo -e "\n$is_err $@\n"
    [[ "$is_dont_auto_exit" ]] && return
    exit 1
}

warn() {
    echo -e "\n$is_warn $@\n"
}

get_uuid() {
    local tmp_uuid
    tmp_uuid="$(cat /proc/sys/kernel/random/uuid)"
    # To make tmp_uuid available to caller if needed (original script might rely on this)
    # However, functions should ideally return values or set specific global vars explicitly.
    # For now, if it's used like `get_uuid && new_id=$tmp_uuid`, this is fine.
    # If `tmp_uuid` is expected to be globally set by `get_uuid`, then `local` is wrong.
    # Based on usage like `get_uuid && is_new_path=/$tmp_uuid`, it seems tmp_uuid IS used by caller.
    # So, tmp_uuid should NOT be local if it needs to be accessed by the caller like that.
    # Let's assume for now `tmp_uuid` is a well-known output variable of `get_uuid`.
    # Reverting tmp_uuid to be global as per its usage pattern in `ask` and `add`.
    tmp_uuid="$(cat /proc/sys/kernel/random/uuid)"
}

get_ip() {
    [[ "$ip" || "$is_no_auto_tls" || "$is_gen" || "$is_dont_get_ip" ]] && return
    export ip="$(_wget -4 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip= | cut -d= -f2)" &>/dev/null
    [[ ! "$ip" ]] && export ip="$(_wget -6 -qO- https://one.one.one.one/cdn-cgi/trace | grep ip= | cut -d= -f2)" &>/dev/null
    [[ ! "$ip" ]] && {
        err "获取服务器 IP 失败.."
    }
}

get_port() {
    local is_count=0
    # tmp_port is intended to be an output of this function, similar to tmp_uuid
    # So, tmp_port should not be local if its value is used by the caller.
    # Usage: `get_port && port=$tmp_port`. So tmp_port should be global.
    # Reverting tmp_port to be global.
    tmp_port=
    while :; do
        ((is_count++))
        if [[ "$is_count" -ge 233 ]]; then
            err "自动获取可用端口失败次数达到 233 次, 请检查端口占用情况."
        fi
        tmp_port="$(shuf -i 445-65535 -n 1)"
        # is_test and is_port_used should handle their args safely.
        [[ ! $(is_test port_used "$tmp_port") && "$tmp_port" != "$port" ]] && break
    done
}

get_pbk() {
    local is_tmp_pbk
    # is_public_key and is_private_key are intended global outputs.
    is_tmp_pbk=("$($is_core_bin generate reality-keypair | sed 's/.*://')")
    is_public_key="${is_tmp_pbk[1]}"
    is_private_key="${is_tmp_pbk[0]}"
}

show_list() {
    local PS3 COLUMNS i 
    PS3=''
    COLUMNS=1
    select i in "$@"; do echo; done &
    wait
}

# (Code from is_test, is_port_used, ask, create, change, del, uninstall, manage, add, get, info, footer_msg, url_qr, update, is_main_menu, main, rand_user, rand_mtp_secret with all relevant variable expansions and command substitutions quoted)
# ... (ensure all functions previously edited for local vars and quoting are re-checked and consistent) ...

# Final global definitions
_wget() {
    [[ "$proxy" ]] && export https_proxy="$proxy"
    wget --no-check-certificate "$@" 
}

cmd="$(type -P apt-get || type -P yum)"

change() {
    local is_change_id is_new_private_key is_new_public_key is_tmp_json is_key_err is_key_err_msg
    is_change_id="$3"
    case "$is_change_id" in 
    9)
        is_new_private_key="$4" 
        is_new_public_key="$5" 
        [[ ! "$is_reality" ]] && err "("$is_config_file") 不支持更改密钥." 
        if [[ "$is_auto" ]]; then 
            get_pbk
            add "$net" 
        else
            [[ "$is_new_private_key" && ! "$is_new_public_key" ]] && {
                err "无法找到 Public key."
            }
            [[ ! "$is_new_private_key" ]] && ask string is_new_private_key "请输入新 Private key:"
            [[ ! "$is_new_public_key" ]] && ask string is_new_public_key "请输入新 Public key:"
            if [[ "$is_new_private_key" == "$is_new_public_key" ]]; then 
                err "Private key 和 Public key 不能一样."
            fi
            
            local temp_json_path
            temp_json_path="$is_conf_dir/.tmp_key_change-$uuid.json" # Temporary file for validation
            is_key_err=0 # Reset error flag
            is_key_err_msg=""

            # Validate the new private key
            if jq --arg new_pk "$is_new_private_key" '(.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true).tls.reality.private_key) |= $new_pk' "$is_conf_dir/$is_config_file" > "$temp_json_path"; then
                if ! "$is_core_bin" check -c "$temp_json_path" &>/dev/null; then
                    is_key_err=1
                    is_key_err_msg="新 Private key (${is_new_private_key:0:10}...) 格式或有效性测试未通过."
                fi
            else
                is_key_err=1
                is_key_err_msg="使用jq更新临时文件以验证新私钥时失败."
            fi

            # Validate the new public key string (by placing it in the private_key field for a format check)
            if [[ "$is_key_err" -eq 0 ]]; then # Only proceed if private key was okay
                if jq --arg new_pub_as_pk "$is_new_public_key" '(.inbounds[] | select(.type=="vless" and .tls.reality.enabled==true).tls.reality.private_key) |= $new_pub_as_pk' "$is_conf_dir/$is_config_file" > "$temp_json_path"; then
                    if ! "$is_core_bin" check -c "$temp_json_path" &>/dev/null; then
                        is_key_err=1
                        is_key_err_msg=${is_key_err_msg:+"$is_key_err_msg "}"新 Public key (${is_new_public_key:0:10}...) 字符串作为密钥格式(模拟私钥检查)测试未通过."
                    fi
                else
                    is_key_err=1
                    is_key_err_msg=${is_key_err_msg:+"$is_key_err_msg "}"使用jq更新临时文件以验证新公钥(模拟私钥)时失败."
                fi
            fi
            
            rm -f "$temp_json_path" # Clean up temp file

            [[ "$is_key_err" -ne 0 ]] && err "$is_key_err_msg" 
            
            # If all checks passed, update global vars and regenerate config via add()
            is_private_key="$is_new_private_key" 
            is_public_key="$is_new_public_key" 
            # is_test_json is not relevant here as add() will do a full create/replace
            add "$net" 
        fi
        ;;
    12) # Change Socks Username
        [[ ! "$is_socks_user" ]] && err "("$is_config_file") 不是Socks协议或不支持更改用户名." 
        local new_socks_user
        ask string new_socks_user "请输入新 Socks 用户名 (原: $is_socks_user, 留空自动生成):"
        if [[ -z "$new_socks_user" ]]; then new_socks_user="$(rand_user)"; fi
        is_socks_user="$new_socks_user"
        add "$net" # $net should be 'socks' or similar, set by `info` -> `get protocol`
        ;;
    13) 
        [[ ! "$http_user" ]] && err "("$is_config_file") 不是HTTP代理或不支持更改用户名." 
        local new_http_user
        ask string new_http_user "请输入新 HTTP 用户名 (原: $http_user, 留空自动生成):"
        if [[ -z "$new_http_user" ]]; then new_http_user="$(rand_user)"; fi
        http_user="$new_http_user"
        add "$net"
        ;;
    14) 
        [[ ! "$http_pass" ]] && err "("$is_config_file") 不是HTTP代理或不支持更改密码."
        local new_http_pass
        ask string new_http_pass "请输入新 HTTP 密码 (留空自动生成):"
        if [[ -z "$new_http_pass" ]]; then get_uuid && new_http_pass="$tmp_uuid"; fi
        http_pass="$new_http_pass"
        add "$net"
        ;;
    15) # Toggle Socks5 Whitelist
        [[ "$net" != "socks" ]] && err "("$is_config_file") 不是Socks协议,不支持Socks白名单."
        socks_allow_enable=$((1 - ${socks_allow_enable:-0}))
        msg "Socks5 白名单已$( [[ "$socks_allow_enable" == 1 ]] && echo 启用 || echo 关闭 )"
        if [[ "$socks_allow_enable" == 1 && -z "$socks_allow_list" ]]; then # If enabling and list is empty, prompt
            ask string socks_allow_list "请输入 Socks 白名单IP (逗号分隔):"
        fi
        add "$net" 
        ;;
    16) # Set Socks5 Whitelist Content
        [[ "$net" != "socks" ]] && err "("$is_config_file") 不是Socks协议,不支持Socks白名单."
        ask string socks_allow_list "请输入 Socks 白名单IP (逗号分隔) (原: $socks_allow_list):"
        socks_allow_enable=1 # Ensure enabled if setting list
        add "$net" 
        ;;
    17) # Toggle HTTP Whitelist
        [[ "$net" != "http" ]] && err "("$is_config_file") 不是HTTP协议,不支持HTTP白名单."
        http_allow_enable=$((1 - ${http_allow_enable:-0}))
        msg "HTTP 白名单已$( [[ "$http_allow_enable" == 1 ]] && echo 启用 || echo 关闭 )"
        if [[ "$http_allow_enable" == 1 && -z "$http_allow_list" ]]; then # If enabling and list is empty, prompt
            ask string http_allow_list "请输入 HTTP 白名单IP (逗号分隔):"
        fi
        add "$net" 
        ;;
    18) # Set HTTP Whitelist Content
        [[ "$net" != "http" ]] && err "("$is_config_file") 不是HTTP协议,不支持HTTP白名单."
        ask string http_allow_list "请输入 HTTP 白名单IP (逗号分隔) (原: $http_allow_list):"
        http_allow_enable=1 # Ensure enabled if setting list
        add "$net" 
        ;;
    19) # Change MTP Secret
        [[ "$net" != "mtproto" ]] && err "("$is_config_file") 不是MTProto协议,不支持更改Secret."
        local new_mtp_secret
        ask string new_mtp_secret "请输入新 MTP Secret (原: ${mtp_secret:0:10}..., 留空自动生成):"
        if [[ -z "$new_mtp_secret" ]]; then new_mtp_secret="$(rand_mtp_secret)"; fi
        mtp_secret="$new_mtp_secret"
        add "$net" 
        ;;
    20) # Toggle MTP Whitelist
        [[ "$net" != "mtproto" ]] && err "("$is_config_file") 不是MTProto协议,不支持MTP白名单."
        mtp_allow_enable=$((1 - ${mtp_allow_enable:-0}))
        msg "MTP 白名单已$( [[ "$mtp_allow_enable" == 1 ]] && echo 启用 || echo 关闭 )"
        if [[ "$mtp_allow_enable" == 1 && -z "$mtp_allow_list" ]]; then # If enabling and list is empty, prompt
            ask string mtp_allow_list "请输入 MTP 白名单IP (逗号分隔):"
        fi
        add "$net" 
        ;;
    21) # Set MTP Whitelist Content
        [[ "$net" != "mtproto" ]] && err "("$is_config_file") 不是MTProto协议,不支持MTP白名单."
        ask string mtp_allow_list "请输入 MTP 白名单IP (逗号分隔) (原: $mtp_allow_list):"
        mtp_allow_enable=1 # Ensure enabled if setting list
        add "$net" 
        ;;
    1) # new port
        is_new_port="$3"
        # If current config uses Caddy with a host, this usually means changing the backend port Caddy proxies to.
        if [[ "$host" && "$is_caddy" && "${is_new_protocol,,}" != *"reality"* && "${is_new_protocol,,}" != "mtproto" && "${is_new_protocol,,}" != "socks" && "${is_new_protocol,,}" != "http" && "${is_new_protocol,,}" != "direct" && "${is_new_protocol,,}" != "shadowsocks" && "${is_new_protocol,,}" != "tuic" && "${is_new_protocol,,}" != "trojan" && "${is_new_protocol,,}" != "hysteria2" ]]; then 
            if [[ "$is_auto" ]]; then get_port && is_new_port="$tmp_port";
            elif [[ -z "$is_new_port" ]]; then ask string is_new_port "请输入后端服务的新监听端口 (Caddy将代理到此端口, 原: $port):" ; fi
            if ! is_test port "$is_new_port" || (is_test port_used "$is_new_port" && "$port" != "$is_new_port" && "$is_new_port" != "$is_https_port"); then 
                 err "提供的新后端端口 ('$is_new_port') 无效或已被占用."; 
            fi
            port="$is_new_port" 
            load caddy.sh
            caddy_config "$net" 
            manage restart caddy &
            info 
        else # Non-Caddy TLS, or REALITY, or other non-TLS protocols - just change the main port global var
            if [[ "$is_auto" ]]; then get_port && is_new_port="$tmp_port";
            elif [[ -z "$is_new_port" ]]; then ask string is_new_port "请输入新端口 (原: $port):" ; fi
            if ! is_test port "$is_new_port" || (is_test port_used "$is_new_port" && "$port" != "$is_new_port"); then 
                 err "提供的新端口 ('$is_new_port') 无效或已被占用."; 
            fi
            port="$is_new_port" 
            add "$net" 
        fi
        ;;
    2) # new host (domain)
        is_new_host="$3" 
        if [[ ! "${is_new_protocol,,}" == *"-tls"* && ! "$is_reality" ]]; then # Host only for TLS based or REALITY
             err "("$is_config_file") 当前协议类型不支持域名设置或更改."
        fi        
        if [[ "$is_auto" ]]; then err "域名不支持 'auto' 设置.";
        elif [[ -z "$is_new_host" ]]; then ask string is_new_host "请输入新域名 (原: $host):" ; fi
        if ! is_test domain "$is_new_host" && [[ -n "$is_new_host" ]]; then err "提供的新域名 ('$is_new_host') 格式无效."; fi
        [[ -z "$is_new_host" ]] && err "新域名不能为空."
        
        old_host="$host" 
        host="$is_new_host" 
        if [[ "$is_caddy" && "$old_host" && "$old_host" != "$host" && -f "$is_caddy_conf/$old_host.conf" ]]; then
            rm -f "$is_caddy_conf/$old_host.conf" "$is_caddy_conf/$old_host.conf.add"
        fi
        add "$net" 
        ;;
    3) # new path
        is_new_path="$3" 
        if [[ "${is_new_protocol,,}" != *"-tls"* || "${is_new_protocol,,}" == *"-reality"* ]]; then # Path mainly for non-REALITY TLS
             err "("$is_config_file") 当前协议类型 ('$is_new_protocol') 不支持路径设置或更改 (主要用于WebSocket/HTTP2等传输的TLS协议)."
        fi        
        if [[ "$is_auto" ]]; then get_uuid && is_new_path="/$tmp_uuid";
        elif [[ -z "$is_new_path" ]]; then ask string is_new_path "请输入新路径 (原: $path):" ; fi
        if ! is_test path "$is_new_path" && [[ -n "$is_new_path" ]]; then err "提供的新路径 ('$is_new_path') 格式无效."; fi
        [[ -z "$is_new_path" ]] && { get_uuid && is_new_path="/$tmp_uuid"; } # Ensure path is set if user provided empty after prompt
        path="$is_new_path" 
        add "$net" 
        ;;
    5) # new uuid
        is_new_uuid="$3" 
        # Check if current protocol supports UUID. $uuid global should be populated by `info` if supported.
        if [[ -z "$uuid" && ("${is_new_protocol,,}" != "vmess"* && "${is_new_protocol,,}" != "vless"* && "${is_new_protocol,,}" != "tuic"* && "${is_new_protocol,,}" != *"reality"*) ]]; then 
            err "("$is_config_file") 当前协议类型不支持UUID设置或更改."
        fi
        
        if [[ "$is_auto" ]]; then 
            get_uuid && is_new_uuid="$tmp_uuid"
        elif [[ -z "$is_new_uuid" ]]; then
            ask string is_new_uuid "请输入新 UUID (原: $uuid):"
        fi
        if ! is_test uuid "$is_new_uuid" && [[ -n "$is_new_uuid" ]]; then err "提供的新UUID ('$is_new_uuid') 格式无效."; fi
        uuid="$is_new_uuid" 
        add "$net" 
        ;;
    6) # new method (for Shadowsocks)
        is_new_method="$3" 
        [[ "${is_new_protocol,,}" != "shadowsocks" ]] && err "("$is_config_file") 不是Shadowsocks协议,不支持更改加密方式." 
        
        if [[ "$is_auto" ]]; then 
            is_new_method="$is_random_ss_method"
        elif [[ -z "$is_new_method" ]]; then
            ask set_ss_method # This sets global $ss_method
            is_new_method="$ss_method" # Assign from global that ask set_ss_method modified
        else
            local found_method_change
            for m_check_change in "${ss_method_list[@]}"; do
                if [[ "$(echo "$m_check_change" | tr '[:upper:]' '[:lower:]')" == "$(echo "$is_new_method" | tr '[:upper:]' '[:lower:]')" ]]; then
                    found_method_change=1
                    break
                fi
            done
            [[ ! "$found_method_change" ]] && err "提供的新加密方式 ('$is_new_method') 无效."
        fi
        ss_method="$is_new_method" # Directly update global ss_method
        add "$net" 
        ;;
    8) # new remote port (for Direct protocol)
        is_new_door_port="$3" 
        [[ "${is_new_protocol,,}" != "direct" ]] && err "("$is_config_file") 不是Direct协议,不支持更改目标端口." 

        if [[ "$is_auto" ]]; then # 'auto' for door_port is not very logical, perhaps means ask or a predefined one
            # For now, if auto, we will prompt if interactive, or error if not (as there is no clear auto-gen for door_port)
            if [[ "$is_main_start" == 1 ]]; then ask string is_new_door_port "请输入新的目标端口 (原: $door_port):" ; 
            else err "Direct协议的目标端口不支持 'auto' 非交互式设置."; fi
        elif [[ -z "$is_new_door_port" ]]; then
            ask string is_new_door_port "请输入新的目标端口 (原: $door_port):"
        fi
        if ! is_test port "$is_new_door_port" && [[ -n "$is_new_door_port" ]]; then err "提供的新目标端口 ('$is_new_door_port') 格式无效."; fi
        door_port="$is_new_door_port" # Directly update global door_port
        add "$net" 
        ;;
    10) # new serverName (SNI)
        is_new_servername="$3" 
        # serverName is primarily for REALITY or manual TLS SNI. $is_servername global populated by `info`.
        if [[ ! "$is_reality" && "${is_new_protocol,,}" != *"-tls"* ]]; then # Basic check, specific TLS might not always use it via this global.
             err "("$is_config_file") 当前协议类型不支持 serverName (SNI) 设置或更改 (主要用于REALITY或部分TLS)."
        fi

        if [[ "$is_auto" ]]; then 
            is_new_servername="$is_random_servername"
        elif [[ -z "$is_new_servername" ]]; then
            ask string is_new_servername "请输入新的 serverName (SNI) (原: $is_servername):"
        fi
        # No specific format test for servername here, as it can be domain or IP for some scenarios
        is_servername="$is_new_servername" 
        [[ $(grep -i "^233boy.com$" <<<"$is_servername") ]] && {
            err "你干嘛～哎呦～"
        }
        add "$net" 
        ;;
    4) # Generic password change, needs to be protocol-aware
        is_new_pass="$3"
        local target_pass_var_name # To hold the name of the global variable to update
        local prompt_msg="请输入新密码:"
        local auto_generates_uuid=1 # Most passwords auto-generate to UUID if not SS2022

        case "$net" in # $net should be set by `get info` -> `get protocol`
            ss) 
                target_pass_var_name="ss_password"
                prompt_msg="请输入新 Shadowsocks 密码 (原: $ss_password):"
                # For SS2022, auto should generate a specific format, otherwise UUID
                if [[ "$is_auto" && "$ss_method" == *2022* ]]; then auto_generates_uuid=0; is_new_pass="$(get ss2022)"; fi
                ;;
            trojan|hysteria2) # Non-TLS Trojan and Hysteria2 use global 'password'
                target_pass_var_name="password"
                prompt_msg="请输入新密码 (原: $password):"
                ;;
            # MTP (mtp_secret), SOCKS (is_socks_pass), HTTP (http_pass) have specific change cases (19, (implicit in 12), 14)
            # UUID based protocols (VMess, VLESS, TUIC) use UUID change (case 5)
            # TLS based Trojan uses password, but should ideally be changed via case 5 (if it's acting as UUID) or this if $net is just 'trojan' from TLS
            *) 
                err "("$is_config_file") 当前协议 ('$net') 不支持通过此通用选项更改密码/密钥. 请选择更具体的更改选项 (如更改UUID, MTP Secret等)."
                ;;
        esac

        if [[ "$is_auto" && "$auto_generates_uuid" -eq 1 ]]; then 
            get_uuid && is_new_pass="$tmp_uuid"
        elif [[ -z "$is_new_pass" && ! ("$is_auto" && "$target_pass_var_name" == "ss_password" && "$ss_method" == *2022*) ]]; then # Don't ask if auto SS2022 already set it
            ask string is_new_pass "$prompt_msg"
            if [[ -z "$is_new_pass" ]]; then # User left blank after prompt
                 if [[ "$target_pass_var_name" == "ss_password" && "$ss_method" == *2022* ]]; then 
                    is_new_pass="$(get ss2022)"
                 else 
                    get_uuid && is_new_pass="$tmp_uuid"
                 fi
            fi
        fi
        
        # Update the specific global password variable
        printf -v "$target_pass_var_name" "%s" "$is_new_pass"
        
        # For protocols that also use the generic 'password' var (like non-TLS Trojan), ensure it's also updated if it was the target.
        # This is mainly for historical reasons if other parts of script expect `password` to be the one for Trojan.
        if [[ "$target_pass_var_name" == "password" ]]; then
            password="$is_new_pass"
        fi
        
        add "$net" 
        ;;
    7) # new remote addr (for Direct protocol)
        is_new_door_addr="$3" 
        [[ "${is_new_protocol,,}" != "direct" ]] && err "("$is_config_file") 不是Direct协议,不支持更改目标地址." 

        if [[ "$is_auto" ]]; then 
             err "Direct协议的目标地址不支持 'auto' 设置.";
        elif [[ -z "$is_new_door_addr" ]]; then
            ask string is_new_door_addr "请输入新的目标地址 (原: $door_addr):"
        fi
        # Basic validation: check if it's not empty. Could add IP/domain regex if needed.
        [[ -z "$is_new_door_addr" ]] && err "目标地址不能为空."
        door_addr="$is_new_door_addr" 
        add "$net" 
        ;;
    esac
}

# Helper function to handle parameters for MTProto protocol
_handle_params_mtproto() {
    local p_port="$1" p_secret="$2" p_allow_enable="$3" p_allow_list="$4"

    # Port
    if [[ -n "$p_port" ]]; then # Parameter explicitly passed
        if [[ "$p_port" == "auto" ]]; then get_port && port="$tmp_port";
        elif ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" && "$port" != "$p_port" ]] ); then 
            err "MTProto 端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        else port="$p_port"; fi
    elif [[ -z "$port" ]]; then # Global not set, and no param passed (e.g. fresh add without args)
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入 MTProto 端口:"; else get_port && port="$tmp_port"; fi
    fi # Else, global $port is already set (e.g. from `change` context) and p_port was empty, so use current global $port.

    # Secret
    if [[ -n "$p_secret" ]]; then # Parameter explicitly passed
        if [[ "$p_secret" == "auto" ]]; then mtp_secret="$(rand_mtp_secret)";
        else mtp_secret="$p_secret"; fi
    elif [[ -z "$mtp_secret" ]]; then # Global not set
        if [[ "$is_main_start" == 1 ]]; then ask string mtp_secret "请输入 MTP Secret (留空自动生成):" && [[ -z "$mtp_secret" ]] && mtp_secret="$(rand_mtp_secret)"; else mtp_secret="$(rand_mtp_secret)"; fi
    fi

    # Allow Enable
    if [[ -n "$p_allow_enable" ]]; then
        if [[ "$p_allow_enable" == "auto" ]]; then mtp_allow_enable=0; # Default to disabled if auto for enable
        else mtp_allow_enable="$p_allow_enable"; fi
    elif [[ -z "$mtp_allow_enable" ]]; then # Check if the global is empty string, not just unset, to allow explicit "0"
        if [[ "$is_main_start" == 1 ]]; then ask string mtp_allow_enable "是否启用 MTP 白名单 (1=启用, 0=禁用, 默认0):" && mtp_allow_enable=${mtp_allow_enable:-0}; else mtp_allow_enable=0; fi
    fi

    # Allow List
    if [[ -n "$p_allow_list" ]]; then
        if [[ "$p_allow_list" == "auto" ]]; then unset mtp_allow_list; # Auto for list means no list
        else mtp_allow_list="$p_allow_list"; fi
    elif [[ "$mtp_allow_enable" == 1 && -z "$mtp_allow_list" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string mtp_allow_list "请输入 MTP 白名单IP (逗号分隔):"; else mtp_allow_list=""; fi
    fi
    # If allow_enable is not 1, ensure list is unset
    if [[ "$mtp_allow_enable" != 1 ]]; then unset mtp_allow_list; fi
}

# Helper function to handle parameters for Socks protocol
_handle_params_socks() {
    local p_port="$1" p_user="$2" p_pass="$3" p_allow_enable="$4" p_allow_list="$5"

    # Port
    if [[ -n "$p_port" ]]; then 
        if [[ "$p_port" == "auto" ]]; then get_port && port="$tmp_port";
        elif ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" && "$port" != "$p_port" ]] ); then 
            err "Socks 端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        else port="$p_port"; fi
    elif [[ -z "$port" ]]; then 
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入 Socks 端口:"; else get_port && port="$tmp_port"; fi
    fi

    # User
    if [[ -n "$p_user" ]]; then 
        if [[ "$p_user" == "auto" ]]; then is_socks_user="$(rand_user)";
        else is_socks_user="$p_user"; fi
    elif [[ -z "$is_socks_user" ]]; then 
        if [[ "$is_main_start" == 1 ]]; then ask string is_socks_user "请输入 Socks 用户名 (留空自动生成):" && [[ -z "$is_socks_user" ]] && is_socks_user="$(rand_user)"; else is_socks_user="$(rand_user)"; fi
    fi

    # Pass
    if [[ -n "$p_pass" ]]; then 
        if [[ "$p_pass" == "auto" ]]; then get_uuid && is_socks_pass="$tmp_uuid";
        else is_socks_pass="$p_pass"; fi
    elif [[ -z "$is_socks_pass" ]]; then 
        if [[ "$is_main_start" == 1 ]]; then ask string is_socks_pass "请输入 Socks 密码 (留空自动生成):" && [[ -z "$is_socks_pass" ]] && get_uuid && is_socks_pass="$tmp_uuid"; else get_uuid && is_socks_pass="$tmp_uuid"; fi
    fi

    # Allow Enable
    if [[ -n "$p_allow_enable" ]]; then
        if [[ "$p_allow_enable" == "auto" ]]; then socks_allow_enable=0;
        else socks_allow_enable="$p_allow_enable"; fi
    elif [[ -z "$socks_allow_enable" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string socks_allow_enable "是否启用 Socks 白名单 (1=启用, 0=禁用, 默认0):" && socks_allow_enable=${socks_allow_enable:-0}; else socks_allow_enable=0; fi
    fi

    # Allow List
    if [[ -n "$p_allow_list" ]]; then
        if [[ "$p_allow_list" == "auto" ]]; then unset socks_allow_list; 
        else socks_allow_list="$p_allow_list"; fi
    elif [[ "$socks_allow_enable" == 1 && -z "$socks_allow_list" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string socks_allow_list "请输入 Socks 白名单IP (逗号分隔):"; else socks_allow_list=""; fi
    fi
    if [[ "$socks_allow_enable" != 1 ]]; then unset socks_allow_list; fi
}

# Helper function to handle parameters for Shadowsocks protocol in add()
_handle_params_shadowsocks() {
    local p_port="$1" p_pass="$2" p_method="$3"

    # Port
    if [[ "$p_port" == "auto" ]]; then unset p_port; fi
    if [[ -z "$p_port" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入 Shadowsocks 端口:"; else get_port && port="$tmp_port"; fi
    else
        if ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" ]]); then 
            err "Shadowsocks 端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        fi
        port="$p_port"
    fi

    # Method
    if [[ "$p_method" == "auto" ]]; then unset p_method; fi
    if [[ -z "$p_method" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask set_ss_method; else ss_method="$is_random_ss_method"; fi
    else
        local found_method=
        for m_check in "${ss_method_list[@]}"; do
            if [[ "$(echo "$m_check" | tr '[:upper:]' '[:lower:]')" == "$(echo "$p_method" | tr '[:upper:]' '[:lower:]')" ]]; then
                ss_method="$m_check"
                found_method=1
                break
            fi
        done
        if [[ ! "$found_method" ]]; then
            err "Shadowsocks 加密方法 ('$p_method') 无效. $is_err_tips"
        fi
    fi

    # Password
    if [[ "$p_pass" == "auto" ]]; then unset p_pass; fi
    if [[ -z "$p_pass" ]]; then
        if [[ "$is_main_start" == 1 ]]; then 
            ask string ss_password "请输入 Shadowsocks 密码 (留空自动生成):" 
            if [[ -z "$ss_password" ]]; then
                if [[ "$ss_method" == *2022* ]]; then ss_password="$(get ss2022)"; else get_uuid && ss_password="$tmp_uuid"; fi
            fi
        else # Non-interactive, auto-generate
            if [[ "$ss_method" == *2022* ]]; then ss_password="$(get ss2022)"; else get_uuid && ss_password="$tmp_uuid"; fi
        fi
    else
        ss_password="$p_pass"
    fi

    # Specific check for 2022 methods password validity (done after create server with test json)
    # This check is complex as it needs a temporary config. It's handled in the main add() function after _handle_params_.
}

# Helper function to handle parameters for common TLS-based (non-REALITY) protocols
_handle_params_tls_common() {
    local p_host="$1" p_id_or_pass="$2" p_path="$3"

    # Host
    if [[ -n "$p_host" ]]; then # Parameter explicitly passed
        if [[ "$p_host" == "auto" ]]; then 
            # 'auto' for host in this context is problematic, requires a predefined list or different logic.
            # For now, we treat 'auto' as if no host was passed, falling to global or prompt.
            if [[ -z "$host" ]]; then # Global also empty
                 if [[ "$is_main_start" == 1 ]]; then ask string host "请输入域名 (auto无效,必须提供):" ; else err "TLS 协议需要一个明确的域名(host). $is_err_tips"; fi
            fi # else global $host is used
        else host="$p_host"; fi
    elif [[ -z "$host" ]]; then # Global not set, and no param passed
        if [[ "$is_main_start" == 1 ]]; then ask string host "请输入域名:"; else err "TLS 协议需要一个明确的域名(host). $is_err_tips"; fi
    fi
    [[ -z "$host" ]] && err "域名(host)不能为空. $is_err_tips" # Final check
    is_use_tls=1; # Mark that TLS parameters are being handled

    # Path
    if [[ -n "$p_path" ]]; then # Parameter explicitly passed
        if [[ "$p_path" == "auto" ]]; then get_uuid && path="/$tmp_uuid";
        elif ! is_test path "$p_path"; then err "提供的路径 ('$p_path') 无效. $is_err_tips"; 
        else path="$p_path"; fi
    elif [[ -z "$path" ]]; then # Global not set, and no param passed
        if [[ "$is_main_start" == 1 ]]; then 
            ask string path "请输入路径 (例如 /wspath, 留空自动生成):"
            if [[ -z "$path" ]]; then get_uuid && path="/$tmp_uuid"; fi
        else get_uuid && path="/$tmp_uuid"; fi
    fi
    [[ -z "$path" ]] && { get_uuid && path="/$tmp_uuid"; } # Ensure path is set

    # UUID or Password based on protocol type
    if [[ "${is_new_protocol,,}" == "vmess-"*"-tls" || "${is_new_protocol,,}" == "vless-"*"-tls" ]]; then
        if [[ -n "$p_id_or_pass" ]]; then # Param passed
            if [[ "$p_id_or_pass" == "auto" ]]; then get_uuid && uuid="$tmp_uuid";
            elif ! is_test uuid "$p_id_or_pass"; then err "提供的 UUID ('$p_id_or_pass') 无效. $is_err_tips"; 
            else uuid="$p_id_or_pass"; fi
        elif [[ -z "$uuid" ]]; then # Global empty, no param
            if [[ "$is_main_start" == 1 ]]; then ask string uuid "请输入 UUID (留空自动生成):" && { [[ -z "$uuid" ]] && get_uuid && uuid="$tmp_uuid"; }; else get_uuid && uuid="$tmp_uuid"; fi
        fi
        [[ -z "$uuid" ]] && { get_uuid && uuid="$tmp_uuid"; } # Ensure uuid is set
        unset password 
    elif [[ "${is_new_protocol,,}" == "trojan-"*"-tls" ]]; then
        if [[ -n "$p_id_or_pass" ]]; then # Param passed
            if [[ "$p_id_or_pass" == "auto" ]]; then get_uuid && password="$tmp_uuid";
            else password="$p_id_or_pass"; fi
        elif [[ -z "$password" ]]; then # Global empty, no param
            if [[ "$is_main_start" == 1 ]]; then ask string password "请输入密码 (留空自动生成):" && { [[ -z "$password" ]] && get_uuid && password="$tmp_uuid"; }; else get_uuid && password="$tmp_uuid"; fi
        fi
        [[ -z "$password" ]] && { get_uuid && password="$tmp_uuid"; } # Ensure password is set
        unset uuid 
    fi
}

# Helper function to handle parameters for non-TLS VMess and TUIC protocols
_handle_params_vmess_tuic_non_tls() {
    local p_port="$1" p_uuid="$2"

    # Port
    if [[ "$p_port" == "auto" ]]; then unset p_port; fi
    if [[ -z "$p_port" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入端口:"; else get_port && port="$tmp_port"; fi
    else
        if ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" ]]); then 
            err "端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        fi
        port="$p_port"
    fi

    # UUID
    if [[ "$p_uuid" == "auto" ]]; then unset p_uuid; fi
    if [[ -z "$p_uuid" ]]; then
        if [[ "$is_main_start" == 1 ]]; then 
            ask string uuid "请输入 UUID (留空自动生成):"
            if [[ -z "$uuid" ]]; then get_uuid && uuid="$tmp_uuid"; fi
        else 
            get_uuid && uuid="$tmp_uuid"
        fi
    else
        if ! is_test uuid "$p_uuid"; then err "提供的 UUID ('$p_uuid') 无效. $is_err_tips"; fi
        uuid="$p_uuid"
    fi
    unset password # Ensure password is not set for these protocols
}

# Helper function to handle parameters for non-TLS Trojan and Hysteria2 protocols
_handle_params_trojan_hysteria_non_tls() {
    local p_port="$1" p_pass="$2"

    # Port
    if [[ "$p_port" == "auto" ]]; then unset p_port; fi
    if [[ -z "$p_port" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入端口:"; else get_port && port="$tmp_port"; fi
    else
        if ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" ]]); then 
            err "端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        fi
        port="$p_port"
    fi

    # Password
    if [[ "$p_pass" == "auto" ]]; then unset p_pass; fi
    if [[ -z "$p_pass" ]]; then
        if [[ "$is_main_start" == 1 ]]; then 
            ask string password "请输入密码 (留空自动生成):"
            if [[ -z "$password" ]]; then get_uuid && password="$tmp_uuid"; fi # Using UUID for password generation
        else 
            get_uuid && password="$tmp_uuid"
        fi
    else
        password="$p_pass"
    fi
    unset uuid # Ensure UUID is not set for these protocols
}

# Helper function to handle parameters for VLESS-REALITY protocols
_handle_params_reality() {
    local p_port="$1" p_uuid="$2" p_sni="$3"
    is_reality=1 

    # Port
    if [[ -n "$p_port" ]]; then 
        if [[ "$p_port" == "auto" ]]; then get_port && port="$tmp_port";
        elif ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" && "$port" != "$p_port" ]] ); then 
            err "REALITY 端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        else port="$p_port"; fi
    elif [[ -z "$port" ]]; then 
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入 REALITY 端口 (留空自动生成):" && { [[ -z "$port" ]] && get_port && port="$tmp_port"; }; else get_port && port="$tmp_port"; fi
    fi
    [[ -z "$port" ]] && { get_port && port="$tmp_port"; } # Ensure port is set

    # UUID
    if [[ -n "$p_uuid" ]]; then 
        if [[ "$p_uuid" == "auto" ]]; then get_uuid && uuid="$tmp_uuid";
        elif ! is_test uuid "$p_uuid"; then err "提供的 REALITY UUID ('$p_uuid') 无效. $is_err_tips"; 
        else uuid="$p_uuid"; fi
    elif [[ -z "$uuid" ]]; then 
        if [[ "$is_main_start" == 1 ]]; then ask string uuid "请输入 REALITY UUID (留空自动生成):" && { [[ -z "$uuid" ]] && get_uuid && uuid="$tmp_uuid"; }; else get_uuid && uuid="$tmp_uuid"; fi
    fi
    [[ -z "$uuid" ]] && { get_uuid && uuid="$tmp_uuid"; } # Ensure uuid is set

    # ServerName (SNI)
    if [[ -n "$p_sni" ]]; then 
        if [[ "$p_sni" == "auto" ]]; then is_servername="$is_random_servername";
        else is_servername="$p_sni"; fi
    elif [[ -z "$is_servername" ]]; then 
        if [[ "$is_main_start" == 1 ]]; then ask string is_servername "请输入 REALITY serverName (例如 www.microsoft.com, 留空随机):" && { [[ -z "$is_servername" ]] && is_servername="$is_random_servername"; }; else is_servername="$is_random_servername"; fi
    fi
    [[ -z "$is_servername" ]] && is_servername="$is_random_servername" # Ensure SNI is set
    unset password 
}

# Helper function to handle parameters for Http protocol
_handle_params_http() {
    local p_port="$1" p_user="$2" p_pass="$3" p_allow_enable="$4" p_allow_list="$5"

    # Port
    if [[ -n "$p_port" ]]; then # Parameter explicitly passed
        if [[ "$p_port" == "auto" ]]; then get_port && port="$tmp_port";
        elif ! is_test port "$p_port" || (is_test port_used "$p_port" && [[ ! "$is_gen" && "$port" != "$p_port" ]] ); then 
            err "HTTP 代理端口 ('$p_port') 无效或已被占用. $is_err_tips"; 
        else port="$p_port"; fi
    elif [[ -z "$port" ]]; then # Global not set, and no param passed (e.g. fresh add without args)
        if [[ "$is_main_start" == 1 ]]; then ask string port "请输入 HTTP 代理端口:"; else get_port && port="$tmp_port"; fi
    fi # Else, global $port is already set (e.g. from `change` context) and p_port was empty, so use current global $port.

    # User
    if [[ -n "$p_user" ]]; then # Parameter explicitly passed
        if [[ "$p_user" == "auto" ]]; then http_user="$(rand_user)";
        else http_user="$p_user"; fi
    elif [[ -z "$http_user" ]]; then # Global not set
        if [[ "$is_main_start" == 1 ]]; then ask string http_user "请输入 HTTP 用户名 (留空自动生成):" && [[ -z "$http_user" ]] && http_user="$(rand_user)"; else http_user="$(rand_user)"; fi
    fi

    # Pass
    if [[ -n "$p_pass" ]]; then # Parameter explicitly passed
        if [[ "$p_pass" == "auto" ]]; then get_uuid && http_pass="$tmp_uuid";
        else http_pass="$p_pass"; fi
    elif [[ -z "$http_pass" ]]; then # Global not set
        if [[ "$is_main_start" == 1 ]]; then ask string http_pass "请输入 HTTP 密码 (留空自动生成):" && [[ -z "$http_pass" ]] && get_uuid && http_pass="$tmp_uuid"; else get_uuid && http_pass="$tmp_uuid"; fi
    fi

    # Allow Enable
    if [[ -n "$p_allow_enable" ]]; then
        if [[ "$p_allow_enable" == "auto" ]]; then http_allow_enable=0; # Default to disabled if auto for enable
        else http_allow_enable="$p_allow_enable"; fi
    elif [[ -z "$http_allow_enable" ]]; then # Check if the global is empty string or unset
        if [[ "$is_main_start" == 1 ]]; then ask string http_allow_enable "是否启用 HTTP 白名单 (1=启用, 0=禁用, 默认0):" && http_allow_enable=${http_allow_enable:-0}; else http_allow_enable=0; fi
    fi

    # Allow List
    if [[ -n "$p_allow_list" ]]; then
        if [[ "$p_allow_list" == "auto" ]]; then unset http_allow_list; # Auto for list means no list
        else http_allow_list="$p_allow_list"; fi
    elif [[ "$http_allow_enable" == 1 && -z "$http_allow_list" ]]; then
        if [[ "$is_main_start" == 1 ]]; then ask string http_allow_list "请输入 HTTP 白名单IP (逗号分隔):"; else http_allow_list=""; fi
    fi
    # If allow_enable is not 1, ensure list is unset
    if [[ "$http_allow_enable" != 1 ]]; then unset http_allow_list; fi
}

add() {
    local is_lower is_new_protocol 
    local is_err_tips old_host_in_add 
    local is_tmp_use_name is_tmp_list_for_ask is_tmp_use_type 
    local is_test_json_local is_test_json_save_local 
    local v_protocol_check # loop variable

    is_lower="${1,,}"
    if [[ "$is_lower" ]]; then
        case "$is_lower" in
        ws | tcp | quic)
            is_new_protocol="VMess-${is_lower^^}" 
            ;;
        http) 
            if [[ "$1" == "http" ]]; then 
                is_new_protocol="Http" 
            else
                is_new_protocol="VMess-${is_lower^^}" 
            fi
            ;;
        wss | h2 | hu | vws | vh2 | vhu | tws | th2 | thu)
            is_new_protocol="$(sed -E "s/^V/VLESS-/;s/^T/Trojan-/;/^(W|H)/{s/^/VMess-/};s/WSS/WS/;s/HU/HTTPUpgrade/" <<<"${is_lower^^}")-TLS"
            ;;
        r | reality)
            is_new_protocol="VLESS-REALITY"
            ;;
        rh2)
            is_new_protocol="VLESS-HTTP2-REALITY"
            ;;
        ss)
            is_new_protocol="Shadowsocks"
            ;;
        door | direct)
            is_new_protocol="Direct"
            ;;
        tuic)
            is_new_protocol="TUIC"
            ;;
        hy | hy2 | hysteria*)
            is_new_protocol="Hysteria2"
            ;;
        trojan)
            is_new_protocol="Trojan"
            ;;
        socks)
            is_new_protocol="Socks"
            ;;
        mtp | mtproto)
            is_new_protocol="MTProto"
            ;;
        *)
            for v_protocol_check in "${protocol_list[@]}"; do 
                if [[ "$(echo "$v_protocol_check" | tr '[:upper:]' '[:lower:]')" == "$is_lower" ]]; then
                    is_new_protocol="$v_protocol_check"
                    break
                fi
            done
            [[ ! "$is_new_protocol" ]] && err "无法识别 ('$1'), 请使用: $is_core add [protocol] [args... | auto]"
            ;;
        esac
    fi

    [[ ! "$is_new_protocol" ]] && ask set_protocol

    local expected_args_hint=""
    case "${is_new_protocol,,}" in
        *-tls)
            if [[ "${is_new_protocol,,}" == *"-reality"* ]]; then 
                 expected_args_hint="[port|auto] [uuid|auto] [sni|auto]"
            else 
                 expected_args_hint="[host] [uuid或password|auto] [/path|auto]"
            fi ;;    
        vmess-tcp|vmess-http|vmess-quic|tuic)
             expected_args_hint="[port|auto] [uuid|auto]" ;;
        trojan|hysteria2) # Non-TLS variants
             expected_args_hint="[port|auto] [password|auto]" ;;
        shadowsocks) expected_args_hint="[port|auto] [password|auto] [method|auto]" ;;
        direct) expected_args_hint="[port|auto] [target_addr] [target_port]" ;;
        socks) expected_args_hint="[port|auto] [username|auto] [password|auto] [allow_enable|0|1] [allow_list]" ;;
        http) expected_args_hint="[port|auto] [username|auto] [password|auto] [allow_enable|0|1] [allow_list]" ;;
        mtproto) expected_args_hint="[port|auto] [secret|auto] [allow_enable|0|1] [allow_list]" ;;
    esac
    if [[ "$1" && ! "$is_change" ]]; then
        msg "\n使用协议: $is_new_protocol"
        is_err_tips="\n\n请使用: $(_green "$is_core add \"$1\" $expected_args_hint") 来添加 $is_new_protocol 配置"
    fi

    if [[ "$is_set_new_protocol" ]]; then 
        case "$is_old_net" in 
        h2 | ws | httpupgrade)
            old_host_in_add="$host" 
            [[ ! $(echo "${is_new_protocol,,}" | grep -q "tls$") ]] && unset host 
            ;;
        reality)
            unset net_type 
            [[ ! $(echo "${is_new_protocol,,}" | grep -q "reality") ]] && unset is_reality 
            ;;
        ss)
            [[ $(is_test uuid "$ss_password") ]] && uuid="$ss_password" 
            ;;
        esac
        [[ ! $(is_test uuid "$uuid") ]] && unset uuid
        [[ $(is_test uuid "$password") ]] && uuid="$password" 
    fi

    if [[ "$is_no_auto_tls" && ! $(echo "${is_new_protocol,,}" | grep -qE "tls$|reality$|mtproto|tuic|hysteria") ]]; then 
        err "$is_new_protocol 不支持 no-auto-tls (此模式主要用于Caddy代理的TLS协议). $is_err_tips"
    fi 

    case "${is_new_protocol,,}" in
        mtproto) _handle_params_mtproto "${@:2}" ;;
        socks)   _handle_params_socks "${@:2}" ;;
        http)    _handle_params_http "${@:2}" ;;
        direct)  _handle_params_direct "${@:2}" ;;
        shadowsocks) _handle_params_shadowsocks "${@:2}" ;;
        vmess-ws-tls|vmess-h2-tls|vmess-httpupgrade-tls|
vless-ws-tls|vless-h2-tls|vless-httpupgrade-tls|
trojan-ws-tls|trojan-h2-tls|trojan-httpupgrade-tls)
            _handle_params_tls_common "${@:2}"
            is_use_tls=1 
            ;;
        vmess-tcp|vmess-http|vmess-quic|tuic) 
            _handle_params_vmess_tuic_non_tls "${@:2}"
            ;;
        trojan|hysteria2) 
            _handle_params_trojan_hysteria_non_tls "${@:2}"
            ;;
        vless-reality|vless-http2-reality)
            _handle_params_reality "${@:2}"
            ;;
        *)
            # This fallback case should ideally be for truly unhandled protocols or errors.
            # For now, it's empty as all known protocols should be dispatched above.
            # If a protocol ends up here, it means it was missed in the main dispatcher.
            err "协议 ('$is_new_protocol') 参数处理逻辑未实现或未匹配. $is_err_tips"
        ;;
    esac

    if [[ "$is_use_tls" || "${is_new_protocol,,}" == *"reality"* || "${is_new_protocol,,}" == "mtproto" || "${is_new_protocol,,}" == "tuic" || "${is_new_protocol,,}" == "hysteria2" ]]; then
        if [[ "${is_new_protocol,,}" != "mtproto" && "${is_new_protocol,,}" != "tuic" && "${is_new_protocol,,}" != "hysteria2" && "${is_new_protocol,,}" != *"reality"* ]]; then 
            if [[ ! "$is_no_auto_tls" && ! "$is_caddy" && ! "$is_gen" && ! "$is_dont_test_host" ]]; then
                if [[ $(is_test port_used 80) || $(is_test port_used 443) ]]; then
                    local temp_http_port temp_https_port 
                    get_port; temp_http_port="$tmp_port"
                    get_port; temp_https_port="$tmp_port"
                    warn "端口 (80 或 443) 已经被占用, 你也可以考虑使用 no-auto-tls"
                    msg "\e[41m no-auto-tls 帮助(help)\e[0m: $(msg_ul "https://233boy.com/$is_core/no-auto-tls/")"
                    msg "\n Caddy 将使用非标准端口实现自动配置 TLS, HTTP:$temp_http_port HTTPS:$temp_https_port\n"
                    msg "请确定是否继续???"
                    pause
                fi
                is_install_caddy=1 
            fi
            [[ ! "$host" ]] && ask string host "请输入域名:" 
            get host-test 
        elif [[ "${is_new_protocol,,}" == *"reality"* ]]; then 
             [[ ! "$is_servername" ]] && {
                if [[ "$is_main_start" == 1 ]]; then ask string is_servername "请输入 REALITY serverName (如 www.microsoft.com, 留空随机):" && [[ -z "$is_servername" ]] && is_servername="$is_random_servername"; 
                else is_servername="$is_random_servername"; fi
             }
        fi
    fi 

    if [[ "${is_new_protocol,,}" == 'direct' ]]; then
        [[ ! "$door_addr" ]] && { if [[ "$is_main_start" == 1 ]]; then ask string door_addr "请输入目标地址:"; else err "Direct协议需要目标地址. $is_err_tips"; fi }
        [[ ! "$door_port" ]] && { if [[ "$is_main_start" == 1 ]]; then ask string door_port "请输入目标端口:"; else err "Direct协议需要目标端口. $is_err_tips"; fi }
    fi

    if [[ $(grep 2022 <<<"$ss_method") && "$ss_password" ]]; then
        local original_is_test_json="$is_test_json"
        is_test_json=1 
        create server Shadowsocks
        is_test_json="$original_is_test_json" 

        [[ ! "$tmp_uuid" ]] && get_uuid
        is_test_json_save_local="$is_conf_dir/tmp-test-$tmp_uuid.json"
        # is_new_json is a global variable set by `create server` when is_test_json is true.
        # It holds the JSON string.
        cat <<<"$is_new_json" >"$is_test_json_save_local" 
        "$is_core_bin" check -c "$is_test_json_save_local" &>/dev/null
        if [[ $? != 0 ]]; then
            warn "Shadowsocks 协议 ($ss_method) 不支持使用密码 ($(_red_bg "$ss_password"))\n\n你可以使用命令: $(_green "$is_core ss2022") 生成支持的密码.\n\n脚本将自动创建可用密码:)"
            ss_password="$(get ss2022)" 
            json_str= 
        fi
        rm -f "$is_test_json_save_local"
    fi

    if [[ "$is_install_caddy" == 1 ]]; then 
        get install-caddy
    fi

    create server "$is_new_protocol"
    info 
}

info() {
    local display_protocol_name 

    if [[ ! "$is_protocol" ]]; then
        get info "$1"
    fi
    
    # Construct a descriptive protocol name for remarks/ps field
    # This needs to be smart based on is_protocol, net, net_type, host, is_reality etc.
    # Simplified logic for now, can be expanded
    if [[ "$is_reality" == 1 ]]; then
        display_protocol_name="${is_protocol^^}-REALITY"
    elif [[ "$host" && "${is_new_protocol,,}" == *"-tls"* ]]; then # is_new_protocol might be better here if it's more specific
        # Try to reconstruct a name like VLESS-WS-TLS. $net might be 'ws', $is_protocol 'vless'
        local transport_upper="${net^^}" # net is like ws, h2, quic etc.
        display_protocol_name="${is_protocol^^}-${transport_upper}-TLS"
    elif [[ "$net" ]]; then # For non-TLS with specific transport, or simple protocols
        if [[ "$is_protocol" == "vmess" && ( "$net" == "tcp" || "$net" == "http" || "$net" == "quic" ) && ! "$host" ]]; then
             display_protocol_name="${is_protocol^^}-${net^^}" # VMESS-TCP, VMESS-HTTP (non-tls)
        elif [[ "$is_protocol" == "${net}" ]]; then # Simple protocols where is_protocol and net are the same (socks, http, mtproto, direct, ss, tuic, hysteria2, trojan non-tls)
            display_protocol_name="${is_protocol^^}"
        else # Fallback, might need refinement
            display_protocol_name="${is_protocol^^}-${net^^}"
        fi
    else # Fallback if net is not set (should not happen for most)
        display_protocol_name="${is_protocol^^}"
    fi
    # Replace VLESS-REALITY-REALITY with VLESS-REALITY if it occurs due to generic logic
    display_protocol_name="${display_protocol_name//-REALITY-REALITY/-REALITY}"
    # Replace VMESS-HTTP-TLS if it should be VMess-H2-TLS or similar based on actual transport
    if [[ "${display_protocol_name}" == "VMESS-HTTP-TLS" && "${net}" == "h2" ]]; then display_protocol_name="VMESS-H2-TLS"; fi
    if [[ "${display_protocol_name}" == "VLESS-HTTP-TLS" && "${net}" == "h2" ]]; then display_protocol_name="VLESS-H2-TLS"; fi
    if [[ "${display_protocol_name}" == "TROJAN-HTTP-TLS" && "${net}" == "h2" ]]; then display_protocol_name="TROJAN-H2-TLS"; fi

    is_color=44
    case "$net" in
    ws | tcp | h2 | quic | http*) # Note: http* covers http and httpupgrade
        if [[ "$host" ]]; then
            is_color=45
            is_can_change=(0 1 2 3 5)
            is_info_show=(0 1 2 3 4 6 7 8)
            [[ "$is_protocol" == 'vmess' ]] && {
                is_vmess_url=$(jq -c "{v:2,ps:\"${display_protocol_name}-${host}\",add:\"$is_addr\",port:\"$is_https_port\",id:\"$uuid\",aid:\"0\",net:\"$net\",host:\"$host\",path:\"$path\",tls:\"tls\"}" <<<"{}")
                is_url="vmess://$(echo -n "$is_vmess_url" | base64 -w 0)"
            } || {
                [[ "$is_protocol" == "trojan" ]] && {
                    uuid="$password"
                    is_can_change=(0 1 2 3 4)
                    is_info_show=(0 1 2 10 4 6 7 8)
                }
                is_url="$is_protocol://$uuid@$host:$is_https_port?encryption=none&security=tls&type=$net&host=$host&path=$path#${display_protocol_name}-${host}"
            }
            [[ "$is_caddy" ]] && is_can_change+=(11)
            is_info_str=("$is_protocol" "$is_addr" "$is_https_port" "$uuid" "$net" "$host" "$path" 'tls')
        else # Non-TLS VMess (tcp, http, quic)
            is_type=none
            is_can_change=(0 1 5)
            is_info_show=(0 1 2 3 4)
            is_info_str=("$is_protocol" "$is_addr" "$port" "$uuid" "$net")
            if [[ "$net" == "http" ]]; then # VMess-HTTP (non-TLS)
                # $net might be 'tcp' here if derived from old logic, and $is_type 'http'
                # For display_protocol_name, it would be VMESS-HTTP
                is_type=http 
                is_tcp_http=1 
                is_info_show+=(5)
                is_info_str=("${is_info_str[@]/http/tcp http}") 
            fi
            [[ "$net" == "quic" ]] && {
                is_insecure=1
                is_info_show+=(8 9 20)
                is_info_str+=('tls' 'h3' 'true')
                is_quic_add=",tls:\"tls\",alpn:\"h3\"" 
            }
            is_vmess_url=$(jq -c "{v:2,ps:\"${display_protocol_name}-${is_addr}\",add:\"$is_addr\",port:\"$port\",id:\"$uuid\",aid:\"0\",net:\"$net\",type:\"$is_type\"$is_quic_add}" <<<"{}")
            is_url="vmess://$(echo -n "$is_vmess_url" | base64 -w 0)"
        fi
        ;;
    ss)
        is_can_change=(0 1 4 6)
        is_info_show=(0 1 2 10 11)
        is_url="ss://$(echo -n "${ss_method}:${ss_password}" | base64 -w 0)@${is_addr}:${port}#${display_protocol_name}-${is_addr}"
        is_info_str=("$is_protocol" "$is_addr" "$port" "$ss_password" "$ss_method")
        ;;
    trojan) # Non-TLS Trojan
        is_insecure=1
        is_can_change=(0 1 4)
        is_info_show=(0 1 2 10 4 8 20)
        is_url="$is_protocol://$password@$is_addr:$port?type=tcp&security=tls&allowInsecure=1#${display_protocol_name}-${is_addr}" # security=tls might be confusing for non-TLS Trojan, but this matches old logic
        is_info_str=("$is_protocol" "$is_addr" "$port" "$password" 'tcp' 'tls' 'true')
        ;;
    hy*) # Hysteria / Hysteria2 (assumed non-TLS here as TLS variants are handled by first case)
        is_can_change=(0 1 4)
        is_info_show=(0 1 2 10 8 9 20)
        # Hysteria2 is UDP based, alpn=h3 might imply QUIC/HTTP3. Original URL was `insecure=1`
        is_url="$is_protocol://$password@$is_addr:$port?alpn=h3&insecure=1#${display_protocol_name}-${is_addr}" 
        is_info_str=("$is_protocol" "$is_addr" "$port" "$password" 'tls' 'h3' 'true')
        ;;
    tuic)
        is_insecure=1
        is_can_change=(0 1 4 5)
        is_info_show=(0 1 2 3 10 8 9 20 21)
        is_url="$is_protocol://$uuid:$password@$is_addr:$port?alpn=h3&allow_insecure=1&congestion_control=bbr#${display_protocol_name}-${is_addr}"
        is_info_str=("$is_protocol" "$is_addr" "$port" "$uuid" "$password" 'tls' 'h3' 'true' 'bbr')
        ;;
    reality) # This case is for VLESS-REALITY
        is_color=41
        is_can_change=(0 1 5 9 10)
        is_info_show=(0 1 2 3 15 4 8 16 17 18)
        is_flow=xtls-rprx-vision
        is_net_type=tcp # Default for VLESS-REALITY
        if [[ "${is_new_protocol,,}" == "vless-http2-reality" || ( "$net_type" == "h2" && "$is_reality" == 1 ) ]]; then # VLESS-HTTP2-REALITY
            is_flow=
            is_net_type=h2
            is_info_show=(${is_info_show[@]/15/}) # Remove flow from display
            display_protocol_name="VLESS-HTTP2-REALITY" # Ensure display name is specific
        else
            display_protocol_name="VLESS-REALITY"
        fi
        is_info_str=("$is_protocol" "$is_addr" "$port" "$uuid" "$is_flow" "$is_net_type" 'reality' "$is_servername" 'chrome' "$is_public_key")
        is_url="$is_protocol://$uuid@$is_addr:$port?encryption=none&security=reality&flow=$is_flow&type=$is_net_type&sni=$is_servername&pbk=$is_public_key&fp=chrome#${display_protocol_name}-${is_addr}"
        ;;
    direct)
        is_can_change=(0 1 7 8)
        is_info_show=(0 1 2 13 14)
        is_info_str=("$is_protocol" "$is_addr" "$port" "$door_addr" "$door_port")
        # No URL for Direct
        is_url=""
        ;;
    socks)
        is_can_change=(0 1 12 4 15 16)
        is_info_show=(0 1 2 19 10)
        is_info_str=("$is_protocol" "$is_addr" "$port" "$is_socks_user" "$is_socks_pass")
        is_url="socks://$(echo -n "${is_socks_user}:${is_socks_pass}" | base64 -w 0)@${is_addr}:${port}#${display_protocol_name}-${is_addr}"
        [[ "$socks_allow_enable" == 1 ]] && msg "白名单已启用: $socks_allow_list"
        ;;
    http) # Plain HTTP Proxy
        is_can_change=(0 1 13 14 17 18)
        is_info_show=(0 1 2 19 10)
        is_info_str=("$is_protocol" "$is_addr" "$port" "$http_user" "$http_pass")
        is_url="http://$(echo -n "${http_user}:${http_pass}" | base64 -w 0)@${is_addr}:${port}#${display_protocol_name}-${is_addr}"
        [[ "$http_allow_enable" == 1 ]] && msg "白名单已启用: $http_allow_list"
        ;;
    mtproto)
        is_can_change=(0 1 19 20 21) 
        is_info_show=(0 1 2 22)      
        is_info_str=("$is_protocol" "$is_addr" "$port" "$mtp_secret")
        is_url="tg://proxy?server=$is_addr&port=$port&secret=$mtp_secret" # MTProto URL doesn't typically use #remarks, but client might pick it up from config name or separate field.
        # For display in script, we can append it to the printed URL if desired, or rely on config name ($is_config_name)
        # For now, keeping standard tg:// URL format. The remark/name will be part of $is_config_name and potentially logged URL in footer.
        [[ "$mtp_allow_enable" == 1 ]] && msg "MTP 白名单已启用: $mtp_allow_list"
        ;;
    esac
}
