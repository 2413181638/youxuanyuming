#!/bin/bash
#
# 自动切换公网 IP（每 1 分钟），自动识别网卡和 IP 地址
# 保证脚本只有一个实例在运行，重复运行会重启当前实例
# ------------------------------------------

LOCK_FILE="/tmp/ip_switch.lock"  # 锁文件路径
LOG_FILE="/var/log/ip_switch.log" # 日志文件

# 自动识别默认网关
GATEWAY=$(ip route | grep default | awk '{print $3}')

# 检查锁文件，确保只有一个脚本实例在运行
if [ -f "$LOCK_FILE" ] && kill -0 $(cat "$LOCK_FILE"); then
    echo "🔄 脚本已经在运行，重新启动当前实例..." | tee -a "$LOG_FILE"
    # 重启脚本
    kill -HUP $(cat "$LOCK_FILE")
    exit 0
fi

# 创建锁文件并记录脚本的进程 ID
echo $$ > "$LOCK_FILE"

# 获取所有网卡接口（自动识别所有网卡）
interfaces=($(ip -o link show | awk -F': ' '{print $2}' | grep -E 'eth[0-9]+'))

# 获取当前的公网 IP
CURRENT_IP=$(curl -s -4 ifconfig.me)

# 日志输出
echo "🔁 启动自动切换公网 IP，每 1 分钟一次..." | tee -a "$LOG_FILE"

# 获取当前默认的入站 IP（默认为 eth0 或第一个有效网卡）
DEFAULT_IN_IP=$(ip addr show "${interfaces[0]}" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

# 循环执行 IP 切换
while true; do
    # 获取当前网卡的内网 IP（只取第一个有效网卡）
    PRIV_IP=$(ip addr show "${interfaces[0]}" | grep 'inet ' | awk '{print $2}' | cut -d/ -f1)

    # 获取当前公网 IP 地址
    CURRENT_IP=$(curl -s -4 ifconfig.me)

    # 日志输出
    echo "➡️ $(date '+%F %T') 当前公网 IP: $CURRENT_IP (内网 $PRIV_IP, 网卡 ${interfaces[0]})" | tee -a "$LOG_FILE"

    # 切换到另一个网卡
    if [ "${interfaces[0]}" == "eth0" ]; then
        DEV="eth1"
    else
        DEV="eth0"
    fi

    # 设置新的默认路由，切换网卡的出站流量
    echo "➡️ 切换到网卡 $DEV" | tee -a "$LOG_FILE"
    sudo ip route del default 2>/dev/null || true
    sudo ip route add default via $GATEWAY dev $DEV metric 1

    # 保持备用路由到默认网卡（不改变入站流量的 IP）
    sudo ip route add default via $GATEWAY dev ${interfaces[0]} metric 100 2>/dev/null || true

    # 检查新的公网 IP
    sleep 2
    NEW_IP=$(curl -s -4 ifconfig.me)
    echo "✅ 当前出网公网 IP: $NEW_IP" | tee -a "$LOG_FILE"
    echo "------------------------------------" | tee -a "$LOG_FILE"

    sleep 60
done

# 删除锁文件（仅当脚本结束时）
rm -f "$LOCK_FILE"
