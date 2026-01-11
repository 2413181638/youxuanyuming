#!/bin/bash

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

# 检查是否为 Root 用户
[[ $EUID -ne 0 ]] && echo -e "${RED}错误: 必须使用 root 用户运行此脚本！${PLAIN}" && exit 1

# 变量定义
NGINX_CONF_DIR="/etc/nginx/sites-enabled"
SSL_DIR="/etc/nginx/ssl"
SCRIPT_PATH="/usr/local/bin/ng"

# 检查系统
check_sys() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ $ID != "debian" && $ID != "ubuntu" ]]; then
            echo -e "${RED}本脚本仅支持 Debian 或 Ubuntu 系统！${PLAIN}"
            exit 1
        fi
    else
        echo -e "${RED}无法检测系统版本！${PLAIN}"
        exit 1
    fi
}

# 安装环境
install_env() {
    echo -e "${YELLOW}正在安装依赖...${PLAIN}"
    apt update -y && apt install -y nginx curl socat ufw cron
    systemctl enable nginx && systemctl start nginx
    
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        echo -e "${YELLOW}正在安装 acme.sh...${PLAIN}"
        curl https://get.acme.sh | sh -s email=my@example.com
    fi
    
    # 设置快捷命令
    cp "$0" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    echo -e "${GREEN}安装完成！以后输入 'ng' 即可运行。${PLAIN}"
}

# 配置反代
configure_proxy() {
    read -p "请输入你的域名 (如 my.emby.com): " MY_DOMAIN
    read -p "请输入反代的后端域名 (如 proxy.domain.com): " PROXY_DOMAIN
    read -p "后端端口 (默认 443): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}

    # 1. 临时配置用于申请证书
    cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server {
    listen 80;
    server_name ${MY_DOMAIN};
}
EOF
    systemctl reload nginx

    # 2. 申请证书
    ~/.acme.sh/acme.sh --issue -d ${MY_DOMAIN} --nginx
    
    # 3. 安装证书
    mkdir -p ${SSL_DIR}/${MY_DOMAIN}
    ~/.acme.sh/acme.sh --install-cert -d ${MY_DOMAIN} \
        --key-file ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key \
        --fullchain-file ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer \
        --reloadcmd "systemctl reload nginx"

    # 4. 正式反代配置
    cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server {
    listen 80;
    server_name ${MY_DOMAIN};
    return 301 https://\$host\$request_uri;
}
server {
    listen 443 ssl http2;
    server_name ${MY_DOMAIN};
    ssl_certificate ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer;
    ssl_certificate_key ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key;
    
    location / {
        proxy_pass https://${PROXY_DOMAIN}:${PROXY_PORT};
        proxy_set_header Host \$proxy_host;
        proxy_ssl_name ${PROXY_DOMAIN};
        proxy_ssl_server_name on;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
}
EOF
    systemctl reload nginx
    echo -e "${GREEN}反代配置完成！${PLAIN}"
}

# 主菜单
main_menu() {
    clear
    echo -e "${GREEN}--- Nginx 反代一键脚本 ---${PLAIN}"
    echo -e "1. 初始化环境"
    echo -e "2. 配置反向代理"
    echo -e "3. 启动 Nginx"
    echo -e "4. 停止 Nginx"
    echo -e "5. 卸载全套"
    echo -e "0. 退出"
    read -p "选择: " opt
    case \$opt in
        1) install_env ;;
        2) configure_proxy ;;
        3) systemctl start nginx ;;
        4) systemctl stop nginx ;;
        5) 
            systemctl stop nginx
            apt purge -y nginx
            rm -rf /etc/nginx ~/.acme.sh "$SCRIPT_PATH"
            echo "已卸载"
            ;;
        *) exit 0 ;;
    esac
}

main_menu
