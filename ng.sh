#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
PLAIN='\033[0m'

NGINX_CONF_DIR="/etc/nginx/sites-enabled"
SSL_DIR="/etc/nginx/ssl"
SCRIPT_PATH="/usr/local/bin/ng"

install_env() {
    apt update -y && apt install -y nginx curl socat ufw cron
    systemctl enable nginx && systemctl start nginx
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        curl https://get.acme.sh | sh -s email=my@example.com
        ~/.acme.sh/acme.sh --set-default-ca --server letsencrypt
    fi
    cp "$0" "$SCRIPT_PATH" && chmod +x "$SCRIPT_PATH"
    echo -e "${GREEN}环境初始化完成！${PLAIN}"
}

configure_proxy() {
    read -p "请输入你的域名: " MY_DOMAIN
    read -p "请输入后端域名: " PROXY_DOMAIN
    read -p "后端端口 (默认 443): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}

    echo -e "请选择证书申请方式:"
    echo -e "1. HTTP 模式 (需要 80 端口开放)"
    echo -e "2. DNS 模式 (Cloudflare API)"
    read -p "请输入 [1-2]: " auth_type

    if [ "$auth_type" == "1" ]; then
        # HTTP 模式逻辑
        mkdir -p $NGINX_CONF_DIR
        cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server { listen 80; server_name ${MY_DOMAIN}; }
EOF
        systemctl reload nginx
        ~/.acme.sh/acme.sh --issue -d ${MY_DOMAIN} --nginx --force
    else
        # DNS 模式逻辑
        read -p "请输入 Cloudflare 邮箱: " CF_Email
        read -p "请输入 Cloudflare Global API Key: " CF_Key
        export CF_Email=$CF_Email
        export CF_Key=$CF_Key
        ~/.acme.sh/acme.sh --issue --dns dns_cf -d ${MY_DOMAIN} --force
    fi

    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败，请检查配置！${PLAIN}"
        return
    fi

    # 安装证书并配置 Nginx
    mkdir -p ${SSL_DIR}/${MY_DOMAIN}
    ~/.acme.sh/acme.sh --install-cert -d ${MY_DOMAIN} \
        --key-file ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key \
        --fullchain-file ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer \
        --reloadcmd "systemctl reload nginx"

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
    echo -e "${GREEN}反代成功！访问: https://${MY_DOMAIN}${PLAIN}"
}

main_menu() {
    while true; do
        clear
        echo -e "${GREEN}Nginx 反代管理 (支持 DNS 验证)${PLAIN}"
        echo "1. 初始化环境"
        echo "2. 配置反向代理"
        echo "3. 启动 Nginx"
        echo "4. 停止 Nginx"
        echo "5. 卸载全套"
        echo "0. 退出"
        read -p "选择: " opt
        case $opt in
            1) install_env; read -p "回车继续..." ;;
            2) configure_proxy; read -p "回车继续..." ;;
            3) systemctl start nginx; read -p "回车继续..." ;;
            4) systemctl stop nginx; read -p "回车继续..." ;;
            5) apt purge -y nginx; rm -rf /etc/nginx ~/.acme.sh "$SCRIPT_PATH"; exit 0 ;;
            0) exit 0 ;;
            *) echo "无效选择" ; sleep 1 ;;
        esac
    done
}

main_menu
