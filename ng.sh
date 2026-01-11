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
    echo -e "${YELLOW}正在更新源并安装依赖...${PLAIN}"
    apt update -y
    apt install -y nginx curl socat ufw cron
    systemctl enable nginx
    systemctl start nginx
    
    # 安装 acme.sh
    if [ ! -f ~/.acme.sh/acme.sh ]; then
        echo -e "${YELLOW}正在安装 acme.sh...${PLAIN}"
        curl https://get.acme.sh | sh -s email=my@example.com
    fi
    
    # 设置 ng 快捷命令
    cp "$0" "$SCRIPT_PATH"
    chmod +x "$SCRIPT_PATH"
    
    echo -e "${GREEN}环境安装完成！${PLAIN}"
}

# 配置反代
configure_proxy() {
    echo -e "${YELLOW}--- 开始配置反向代理 ---${PLAIN}"
    read -p "请输入你的域名 (例如 my.emby.com): " MY_DOMAIN
    read -p "请输入后端域名 (例如 proxy.domain.com): " PROXY_DOMAIN
    read -p "后端端口 (默认 443): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}

    if [ -z "$MY_DOMAIN" ] || [ -z "$PROXY_DOMAIN" ]; then
        echo -e "${RED}域名不能为空！${PLAIN}"
        return
    fi

    # 1. 临时配置用于申请证书
    echo -e "${YELLOW}1/4 生成临时配置...${PLAIN}"
    mkdir -p $NGINX_CONF_DIR
    cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server {
    listen 80;
    server_name ${MY_DOMAIN};
}
EOF
    systemctl reload nginx

    # 2. 申请证书
    echo -e "${YELLOW}2/4 正在申请 SSL 证书...${PLAIN}"
    ~/.acme.sh/acme.sh --issue -d ${MY_DOMAIN} --nginx
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查域名是否解析到本机 IP。${PLAIN}"
        return
    fi

    # 3. 安装证书
    echo -e "${YELLOW}3/4 安装证书到标准目录...${PLAIN}"
    mkdir -p ${SSL_DIR}/${MY_DOMAIN}
    ~/.acme.sh/acme.sh --install-cert -d ${MY_DOMAIN} \
        --key-file ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key \
        --fullchain-file ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer \
        --reloadcmd "systemctl reload nginx"

    # 4. 正式反代配置 (CF 优化版)
    echo -e "${YELLOW}4/4 写入最终配置...${PLAIN}"
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
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;

    location / {
        proxy_pass https://${PROXY_DOMAIN}:${PROXY_PORT};
        
        # 关键：欺骗后端，让它以为是通过后端域名访问的
        proxy_set_header Host \$proxy_host;
        
        # 关键：开启 SNI，告诉 Cloudflare 我们要访问哪个域名
        proxy_ssl_name ${PROXY_DOMAIN};
        proxy_ssl_server_name on;
        
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF
    systemctl reload nginx
    echo -e "${GREEN}=============================================${PLAIN}"
    echo -e "${GREEN} 成功！访问地址: https://${MY_DOMAIN} ${PLAIN}"
    echo -e "${GREEN}=============================================${PLAIN}"
}

# 卸载功能
uninstall() {
    read -p "确认卸载 Nginx 和所有配置吗？(y/n): " confirm
    if [[ $confirm == "y" ]]; then
        systemctl stop nginx
        apt remove --purge -y nginx nginx-common
        rm -rf /etc/nginx
        rm -rf ~/.acme.sh
        rm -f "$SCRIPT_PATH"
        echo -e "${GREEN}卸载完成。${PLAIN}"
        exit 0
    fi
}

# 主菜单 (循环模式)
main_menu() {
    while true; do
        clear
        echo -e "${GREEN}=====================================${PLAIN}"
        echo -e "${GREEN}    Nginx 反代一键脚本 (修复版)      ${PLAIN}"
        echo -e "${GREEN}=====================================${PLAIN}"
        echo -e "1. 初始化环境 (首次运行点这个)"
        echo -e "2. 配置反向代理"
        echo -e "3. 启动 Nginx"
        echo -e "4. 停止 Nginx"
        echo -e "5. 卸载全套"
        echo -e "0. 退出"
        echo -e "${GREEN}=====================================${PLAIN}"
        
        read -p "请输入数字 [0-5]: " opt
        case $opt in
            1) 
                check_sys
                install_env 
                read -p "按回车键返回菜单..." 
                ;;
            2) 
                configure_proxy 
                read -p "按回车键返回菜单..." 
                ;;
            3) 
                systemctl start nginx && echo -e "${GREEN}已启动${PLAIN}"
                read -p "按回车键返回菜单..." 
                ;;
            4) 
                systemctl stop nginx && echo -e "${GREEN}已停止${PLAIN}"
                read -p "按回车键返回菜单..." 
                ;;
            5) 
                uninstall 
                ;;
            0) 
                exit 0 
                ;;
            *) 
                echo -e "${RED}输入无效，请输入 0-5 之间的数字${PLAIN}" 
                sleep 1
                ;;
        esac
    done
}

# 启动脚本
main_menu
