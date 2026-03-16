#!/bin/bash

#####################################
# 脚本名称: bageddns.sh
# 功能: 检查 IP 封锁 + 循环监控 + 倒计时显示
# 状态: 包含检测次数与换IP次数统计
# 新增: 如果检测到脚本已在运行，则自动打开当前日志
#####################################

LOCKFILE="/tmp/bageddns.lock"
LOGFILE="/tmp/bageddns.log"

# ========== 如果脚本已经运行，则自动查看日志 ==========
if [ -e "$LOCKFILE" ]; then
    echo "$(date '+%F %T') - 检测到脚本已在运行，自动打开当前日志：$LOGFILE"
    if [ -f "$LOGFILE" ]; then
        tail -f "$LOGFILE"
    else
        echo "日志文件不存在：$LOGFILE"
    fi
    exit 0
fi

# 创建锁文件
touch "$LOCKFILE"
trap 'rm -f "$LOCKFILE"' EXIT

# ========== 日志输出 ==========
touch "$LOGFILE"
exec > >(tee -a "$LOGFILE") 2>&1

echo "======================================================"
echo "脚本启动时间: $(date '+%F %T')"
echo "日志文件路径: $LOGFILE"
echo "======================================================"

# === 初始化统计变量 ===
check_count=0
change_count=0

# === 开始循环 ===
while true
do
    ((check_count++))

    echo "------------------------------------------------------"
    echo "当前时间: $(date '+%F %T')"
    echo "运行统计: [已检测: $check_count 次] | [已换IP: $change_count 次]"
    echo "------------------------------------------------------"

    # 1. 获取当前 IP
    ip_address=$(curl -s --max-time 10 ifconfig.me)

    if [ -z "$ip_address" ]; then
        echo "无法获取本机 IP，可能网络中断，稍后重试..."
    else
        echo "当前本机 IP: $ip_address"

        # 2. 检查 IP 是否被封锁
        if ping -c 5 -W 2 -i 0.2 223.5.5.5 | grep -q "100% packet loss"; then
            echo "!!! 检测到丢包率 100%，IP 可能被封锁，准备更换..."

            # 3. 调用 API
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
    echo "等待 180 秒后开始下一轮检测..."

    for ((i=180; i>0; i--)); do
        printf "\r下次检测倒计时: %3d 秒..." "$i"
        sleep 1
    done

    echo -e "\r开始新一轮检测...                   "
done
