#!/bin/bash

#####################################
# 脚本名称: bageddns.sh
# 功能: 检查 IP 是否封锁, 如果封锁则使用 BageVM API 重置 IP
# 确保脚本只能运行一个实例
#####################################

LOCKFILE="/tmp/bageddns.lock"

# 如果锁文件存在，则退出
if [ -e "$LOCKFILE" ]; then
    echo "$(date '+%F %T') - 脚本已在运行中，退出。"
    exit 1
fi

# 创建锁文件
touch "$LOCKFILE"

# 捕获脚本退出时删除锁文件
trap "rm -f $LOCKFILE" EXIT

# 循环执行
while true
do
    echo "$(date '+%F %T') - 脚本开始执行..."

    # 获取当前公网 IP
    ip_address=$(curl -s ifconfig.me)
    echo "当前 IP: $ip_address"

    # 检查 IP 是否被封锁
    if ping -c 5 -W 2 -i 0.2 www.itdog.cn | grep "100% packet loss" > /dev/null; then
        echo "检测到 IP 可能被封锁，尝试更换 IP..."

        # 调用 BageVM API 重置 IP
        response=$(curl -s "https://www.bagevm.com/index.php?m=hinet&vmip=$ip_address&apikey=9a312e84dfe6571400e37193ac06a2da&action=restip")

        echo "接口返回: $response"

        # 判断是否成功重置
        if echo "$response" | grep -q '"status":"1000"'; then
            new_ip=$(echo "$response" | grep -oP '"mainip":"\K[0-9.]+')
            echo "IP 重置成功! 新 IP: $new_ip"
        else
            echo "IP 重置失败，请检查返回内容或 API KEY 是否有效."
        fi
    else
        echo "当前 IP 未被封锁，无需更换."
    fi

    echo "$(date '+%F %T') - 本次检测完成，等待下一次..."

    # 每 3 分钟执行一次
    sleep 180
done
