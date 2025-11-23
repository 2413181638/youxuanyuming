#!/bin/bash
#
# 一键部署：自动切换公网 IP（eth0 ↔ eth1，每 1 分钟）
# 自动识别机器的公网 IP 和私网 IP
# ------------------------------------------

echo "🚀 开始部署自动公网 IP 切换服务..."

# 1️⃣ 自动获取公网 IP 和私网 IP
declare -A ip_map
declare -a ip_list

# 获取所有的 eth0 和 eth1 网卡 IP 地址
for dev in eth0 eth1; do
    PRIV_IP=$(ip addr show $dev | grep -oP 'inet \K[0-9.]+')
    if [[ ! -z "$PRIV_IP" ]]; then
        ip_map["$PRIV_IP"]=$dev
    fi
done

# 获取所有的公网 IP 地址
PUB_IPS=$(curl -s -4 ifconfig.me)
if [[ ! -z "$PUB_IPS" ]]; then
    ip_list=($PUB_IPS)
else
    echo "❌ 未能获取公网 IP 地址，检查网络配置。" | tee -a "/var/log/ip_switch.log"
    exit 1
fi

# 获取默认路由（网关）
DEFAULT_ROUTE=$(ip route show default | grep -oP 'via \K[0-9.]+')
if [ -z "$DEFAULT_ROUTE" ]; then
    echo "❌ 未找到默认路由，请检查网络配置。" | tee -a "/var/log/ip_switch.log"
    exit 1
fi
echo "✅ 默认路由和网关: $DEFAULT_ROUTE" | tee -a "/var/log/ip_switch.log"

# 2️⃣ 写入主脚本
cat >/root/auto_switch_qzmd.sh <<EOF
#!/bin/bash
#
# 自动循环切换公网出口 IP（eth0 ↔ eth1，每 1 分钟）
# ------------------------------------------

declare -A ip_map
ip_map["$PUB_IPS"]="eth0"
ip_map["$PUB_IPS"]="eth1"

GATEWAY="$DEFAULT_ROUTE"
LOG_FILE="/var/log/ip_switch.log"

echo "🔁 启动自动切换公网 IP（eth0 ↔ eth1，每 1 分钟）..." | tee -a "$LOG_FILE"

while true; do
    CURRENT_IP=$(curl -s -4 ifconfig.me)
    current_index=-1
    for i in "${!ip_list[@]}"; do
        [[ "${ip_list[$i]}" == "$CURRENT_IP" ]] && current_index=$i && break
    done

    next_index=$(( (current_index + 1) % ${#ip_list[@]} ))
    PUB_IP=${ip_list[$next_index]}
    DEV=${ip_map[$PUB_IP]}

    echo "➡️ $(date '+%F %T') 切换到公网 IP: $PUB_IP (网卡 $DEV)" | tee -a "$LOG_FILE"

    sudo ip route del default 2>/dev/null || true
    sudo ip route add default via $GATEWAY dev $DEV metric 1

    # 保留低优先级的备用路由
    for d in eth0 eth1; do
        if ip addr show $d >/dev/null 2>&1; then
            sudo ip route add default via $GATEWAY dev $d metric 100 2>/dev/null || true
        fi
    done

    sleep 2
    NEW_IP=$(curl -s -4 ifconfig.me)
    echo "✅ 当前出网公网 IP: $NEW_IP" | tee -a "$LOG_FILE"
    echo "------------------------------------" | tee -a "$LOG_FILE"

    sleep 60
done
EOF

chmod +x /root/auto_switch_qzmd.sh

# 3️⃣ 创建 systemd 服务
cat >/etc/systemd/system/ip-auto-switch.service <<'EOF'
[Unit]
Description=Auto switch public IP between eth0 and eth1
After=network-online.target

[Service]
Type=simple
ExecStart=/root/auto_switch_qzmd.sh
Restart=always
RestartSec=10
User=root
StandardOutput=append:/var/log/ip_switch.log
StandardError=append:/var/log/ip_switch.log

[Install]
WantedBy=multi-user.target
EOF

# 4️⃣ 启用 & 启动服务
systemctl daemon-reload
systemctl enable ip-auto-switch
systemctl restart ip-auto-switch

# 5️⃣ 展示结果
echo "✅ 部署完成！"
echo "------------------------------------"
echo "服务名称: ip-auto-switch"
echo "日志文件: /var/log/ip_switch.log"
echo "查看运行状态: systemctl status ip-auto-switch"
echo "实时查看日志: tail -f /var/log/ip_switch.log"
echo "------------------------------------"
