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
    apt install -y nginx curl socat ufw cron

    echo -e "${YELLOW}配置防火墙...${PLAIN}"
    ufw allow ssh
    ufw allow 80/tcp
    ufw allow 443/tcp
    # 避免由脚本直接启用ufw导致ssh断连，仅添加规则，用户自行决定是否 enable
    echo -e "${GREEN}防火墙规则已添加 (SSH, 80, 443)。请确保你的服务商安全组也放行了这些端口。${PLAIN}"
    
    systemctl enable nginx
    systemctl start nginx

    # 安装 acme.sh
    if ! command -v acme.sh &> /dev/null; then
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
    read -p "请输入要反代的后端地址 (例如: proxy.domain.com): " PROXY_DOMAIN
    read -p "请输入后端端口 (默认 443): " PROXY_PORT
    PROXY_PORT=${PROXY_PORT:-443}

    if [ -z "$MY_DOMAIN" ] || [ -z "$PROXY_DOMAIN" ]; then
        echo -e "${RED}域名不能为空！${PLAIN}"
        return
    fi

    echo -e "${YELLOW}1. 生成 Nginx 预配置文件 (HTTP)...${PLAIN}"
    
    # 确保目录存在
    mkdir -p $NGINX_CONF_DIR
    
    # 写入临时配置用于申请证书
    cat > ${NGINX_CONF_DIR}/${MY_DOMAIN} <<EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${MY_DOMAIN};
}
EOF

    # 重载 Nginx
    nginx -t && nginx -s reload
    if [ $? -ne 0 ]; then
        echo -e "${RED}Nginx 配置测试失败，请检查域名解析是否正确指向本机 IP。${PLAIN}"
        return
    fi

    echo -e "${YELLOW}2. 申请 SSL 证书 (使用 acme.sh Nginx 模式)...${PLAIN}"
    ~/.acme.sh/acme.sh --issue -d ${MY_DOMAIN} --nginx
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}证书申请失败！请检查：${PLAIN}"
        echo -e "1. 域名 ${MY_DOMAIN} 是否已解析到本机 IP？"
        echo -e "2. 80 端口是否被占用或未放行？"
        return
    fi

    echo -e "${YELLOW}3. 安装证书到标准目录...${PLAIN}"
    mkdir -p ${SSL_DIR}/${MY_DOMAIN}
    ~/.acme.sh/acme.sh --install-cert -d ${MY_DOMAIN} \
        --key-file       ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key \
        --fullchain-file ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer \
        --reloadcmd     "service nginx force-reload"

    echo -e "${YELLOW}4. 生成最终 Nginx 配置文件 (HTTPS + Cloudflare 优化)...${PLAIN}"
    
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

    # SSL 证书配置
    ssl_certificate         ${SSL_DIR}/${MY_DOMAIN}/fullchain.cer;
    ssl_certificate_key     ${SSL_DIR}/${MY_DOMAIN}/${MY_DOMAIN}.key;

    # SSL 优化
    ssl_protocols           TLSv1.2 TLSv1.3;
    ssl_ciphers             HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache       shared:SSL:10m;
    ssl_session_timeout     1d;

    # 安全头
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;

    location / {
        # 反代到后端
        proxy_pass            https://${PROXY_DOMAIN}:${PROXY_PORT};
        
        # 传递 Host 头 (重要: 如果后端是 CF，这里通常需要用后端域名，而不是客户端请求的域名)
        # 如果后端严格校验 Host，这里使用 \$proxy_host
        proxy_set_header      Host \$proxy_host;
        
        proxy_set_header      X-Real-IP \$remote_addr;
        proxy_set_header      X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header      X-Forwarded-Proto \$scheme;
        
        # 关键配置：针对 Cloudflare 后端的 SNI 设置
        proxy_ssl_name        ${PROXY_DOMAIN};
        proxy_ssl_server_name on;
        
        # 如果后端也是 HTTPS，可能需要开启 SSL 验证或者关闭（视情况而定，这里默认开启并利用 SNI）
        proxy_ssl_session_reuse off;
    }
}
EOF

    echo -e "${YELLOW}5. 重载 Nginx 服务...${PLAIN}"
    nginx -t
    if [ $? -eq 0 ]; then
        nginx -s reload
        echo -e "${GREEN}==============================================${PLAIN}"
        echo -e "${GREEN} 反代配置成功！ ${PLAIN}"
        echo -e "${GREEN} 您的域名: https://${MY_DOMAIN} ${PLAIN}"
        echo -e "${GREEN} 后端地址: https://${PROXY_DOMAIN}:${PROXY_PORT} ${PLAIN}"
        echo -e "${GREEN}==============================================${PLAIN}"
    else
        echo -e "${RED}Nginx 配置写入有误，请检查日志。${PLAIN}"
    fi
}

# 启动 Nginx
start_nginx() {
    systemctl start nginx
    echo -e "${GREEN}Nginx 已启动${PLAIN}"
}

# 停止 Nginx
stop_nginx() {
    systemctl stop nginx
    echo -e "${GREEN}Nginx 已停止${PLAIN}"
}

# 卸载功能
uninstall() {
    echo -e "${RED}警告：这将卸载 Nginx, acme.sh 并删除所有配置文件。${PLAIN}"
    read -p "确认卸载吗？(y/n): " confirm
    if [[ $confirm == "y" ]]; then
        systemctl stop nginx
        apt remove --purge -y nginx nginx-common nginx-core
        rm -rf /etc/nginx
        rm -rf ~/.acme.sh
        rm -f "$SCRIPT_PATH"
        echo -e "${GREEN}卸载完成。${PLAIN}"
        exit 0
    else
        echo -e "${YELLOW}取消卸载。${PLAIN}"
    fi
}

# 主菜单
main_menu() {
    clear
    echo -e "${GREEN}=====================================${PLAIN}"
    echo -e "${GREEN}    Nginx Emby 反代一键脚本 (支持CF)
