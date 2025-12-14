#!/bin/bash

#####################################
# 脚本名称: bageddns.sh
# 功能: 检查 IP 封锁 + 循环监控 + 倒计时显示
# 状态: 包含检测次数与换IP次数统计
#####################################

LOCKFILE="/tmp/bageddns.lock"

# 防止重复运行
if [ -e "$LOCKFILE" ]; then
    echo "$(date '+%F %T') - 脚本已在运行中，退出。"
    exit 1
fi
touch "$LOCKFILE"
trap "rm -f $LOCKFILE" EXIT

# === 初始化统计变量 ===
check_count=0
change_count=0

# === 开始循环 ===
while true
do
    # 计数增加
    ((check_count++))

    # 打印当前状态面板
    echo "------------------------------------------------------"
    echo "当前时间: $(date '+%F %T')"
    echo "运行统计: [已检测: $check_count 次] | [已换IP: $change_count 次]"
    echo "------------------------------------------------------"

    # 1. 获取当前 IP
    ip_address=$(curl -s ifconfig.me)
    # 如果获取不到IP（比如网络完全断了），给一个提示并跳过
    if [ -z "$ip_address" ]; then
        echo "无法获取本机 IP，可能网络中断，稍后重试..."
    else
        echo "当前本机 IP: $ip_address"

        # 2. 检查 IP 是否被封锁
        # 使用 223.5.5.5 (阿里DNS) 作为 Ping 目标，比域名更稳定
        if ping -c 5 -W 2 -i 0.2 223.5.5.5 | grep "100% packet loss" > /dev/null; then
            echo "!!! 检测到丢包率 100%，IP 可能被封锁，准备更换..."

            # 3. 调用 API (Key 保持在 URL 中)
            response=$(curl -s "https://www.bagevm.com/index.php?m=hinet&vmip=$ip_address&apikey=9a312e84dfe6571400e37193ac06a2da&action=restip")
            
            echo "接口返回: $response"

            # 4. 判断结果
            if echo "$response" | grep -q '"status":"1000"'; then
                new_ip=$(echo "$response" | grep -oP '"mainip":"\K[0-9.]+')
                echo ">>> 成功! 新 IP: $new_ip"
                ((change_count++))
            else
                echo ">>> 失败! 请检查接口返回内容。"
            fi
        else
            echo ">>> 正常! 当前 IP 未被封锁。"
        fi
    fi

    echo ""
    # === 倒计时部分 (3分钟 = 180秒) ===
    # 使用 \r 可以在同一行刷新数字
    for ((i=180; i>0; i--)); do
        printf "\r下次检测倒计时: %3d 秒..." "$i"
        sleep 1
    done
    # 倒计时结束后换行，防止文字重叠
    echo -e "\r开始新一轮检测...                   "
done
