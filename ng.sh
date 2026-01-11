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
        echo -e "${RED}无法检测系统版本，请使用 Debian 12 或 Ubuntu 20+${PLAIN}"
        exit 1
    fi
}

# 安装依赖环境
install_env() {
    echo -e "${YELLOW}正在更新软件源并安装依赖...${PLAIN}"
    apt update -y
    apt install -y nginx curl socat ufw cron vi

    echo -e "${YELLOW}配置防火墙...${PLAIN}"
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    
    systemctl enable nginx
    systemctl start nginx

    # 安装 acme.sh
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        echo -e "${YELLOW}正在安装 acme.sh...${PLAIN}"
        curl https://get.acme.sh | sh -s email=my@example.com
        source ~/.bashrc
    fi
    
    # 建立 ng 快捷指令
    cp "$0" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    echo -e "${GREEN}环境安装完成！以后可以直接输入 'ng' 调出菜单。${PLAIN}"
}

# 配置反向代理
configure_proxy() {
    echo -e "${YELLOW}=== 开始配置反向代理 ===${PLAIN}"
    
    read -p "请输入你的域名 (例如: my.domain.com): " MY_DOMAIN
    read -p "请输入要反代的后端域名 (例如: proxy.domain.com): " PROXY_DOMAIN
    read -p "请输入后端端口 (默认 443): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}

    if [ -z "$MY_DOMAIN" ] || [ -z "$PROXY_DOMAIN" ]; then
        echo -e "${RED}域名不能为空！${PLAIN}"
        return
    fi

    echo -e "${YELLOW}1. 生成 Nginx 预配置文件 (HTTP)...${PLAIN}"
    mkdir -p $NGINX_CONF_DIR
    cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${MY_DOMAIN};
}
EOF

    nginx -t && nginx -s reload
    
    echo -e "${YELLOW}2. 申请 SSL 证书...${PLAIN}"
    ~/.acme.sh/acme.sh --issue -d ${MY_DOMAIN} --nginx
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名解析。${PLAIN}"
        return
    fi

    echo -e "${YELLOW}3. 安装证书到标准目录...${PLAIN}"
    mkdir -p ${SSL_DIR}/${MY_DOMAIN}
    ~/.acme.sh/acme.sh --install-cert -d ${MY_DOMAIN} \
        --key-file       ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key \
        --fullchain-file ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer \
        --reloadcmd     "service nginx force-reload"

    echo -e "${YELLOW}4. 生成最终反代配置文件...${PLAIN}"
    cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${MY_DOMAIN};
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name ${MY_DOMAIN};

    ssl_certificate         ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer;
    ssl_certificate_key     ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key;

    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_ciphers             HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache       shared:SSL:10m;
    ssl_session_timeout     1d;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        proxy_pass            https://${PROXY_DOMAIN}:${PROXY_PORT};
        proxy_set_header      Host \$proxy_host;
        proxy_set_header      X-Real-IP \$remote_addr;
        proxy_set_header      X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header      X-Forwarded-Proto \$scheme;
        
        # 开启 SNI 以支持套了 CF 的后端
        proxy_ssl_name        ${PROXY_DOMAIN};
        proxy_ssl_server_name on;
        proxy_ssl_session_reuse off;
    }
}
EOF

    nginx -t && nginx -s reload
    echo -e "${GREEN}配置成功！访问地址: https://${MY_DOMAIN}${PLAIN}"
}

# 卸载功能
uninstall() {
    read -p "确认卸载 Nginx 和所有配置吗？(y/n): " confirm
    if [[ $confirm == "y" ]]; then
        systemctl stop nginx
        apt remove --purge -y nginx
        rm -rf /etc/nginx
        rm -rf ~/.acme.sh
        rm -f "$SCRIPT_PATH"
        echo -e "${GREEN}卸载完成。${PLAIN}"
        exit 0
    fi
}

# 主菜单
main_menu() {
    clear
    echo -e "${GREEN}=====================================${PLAIN}"
    echo -e "${GREEN}    Nginx 反代一键脚本 (支持CF)      ${PLAIN}"
    echo -e "${GREEN}=====================================${PLAIN}"
    echo -e "1. 安装环境"
    echo -e "2. 配置反向代理"
    echo -e "3. 启动 Nginx"
    echo -e "4. 停止 Nginx"
    echo -e "5. 卸载脚本"
    echo -e "0. 退出"
    echo -e "${GREEN}=====================================${PLAIN}"
    read -p "请选择: " num
    case "$num" in
        1) install_env ;;
        2) configure_proxy ;;
        3) systemctl start nginx && echo -e "${GREEN}启动成功${PLAIN}" ;;
        4) systemctl stop nginx && echo -e "${GREEN}停止成功${PLAIN}" ;;
        5) uninstall ;;
        0) exit 0 ;;
        *) echo "无效输入" ;;
    esac
}

# 运行菜单
main_menu
