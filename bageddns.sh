#!/bin/bash

# 确保只有一个脚本实例在运行
LOCKFILE="/tmp/bageddns.lock"

# 检查是否已经有实例在运行
if [ -e "$LOCKFILE" ]; then
    echo "脚本已经在运行，退出执行。"
    exit 1
else
    # 创建锁文件，表示脚本正在运行
    touch "$LOCKFILE"
    echo "开始运行脚本..."

    # 获取当前 IP 地址
    ip_address=$(curl -s ifconfig.me)
    echo "当前IP地址: $ip_address"

    # 执行 ping 命令并检查结果
    if ping -c 5 -W 2 -i 0.2 www.itdog.cn | grep "100% packet loss" > /dev/null
    then
        echo "当前IP已经被封锁，正在尝试换IP..."

        # 使用 BageVM API 请求重置 IP
        response=$(curl -s "https://www.bagevm.com/index.php?m=hinet&vmip=$ip_address&apikey=9a312e84dfe6571400e37193ac06a2da&action=restip")
        
        # 检查返回结果
        if echo "$response" | grep -q '"status":"1000"'; then
            new_ip=$(echo "$response" | grep -oP '"mainip":"\K[0-9\.]+')
            echo "IP已经成功更换，新IP地址: $new_ip"
        else
            echo "换IP失败，返回信息: $response"
        fi
    else
        echo "当前IP未被封锁"
    fi

    # 删除锁文件，表示脚本已完成
    rm -f "$LOCKFILE"
    echo "脚本执行完毕。"
fi
