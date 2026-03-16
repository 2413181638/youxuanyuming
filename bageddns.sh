#!/bin/bash

SCRIPT="/root/bageddns.sh"
PIDFILE="/tmp/bageddns.pid"
LOCKFILE="/tmp/bageddns.lock"
LOGFILE="/tmp/bageddns.log"

get_pid() {
    [ -f "$PIDFILE" ] && cat "$PIDFILE"
}

is_running() {
    local pid
    pid=$(get_pid)
    [ -n "$pid" ] && ps -p "$pid" > /dev/null 2>&1
}

fix_stale() {
    if [ -f "$PIDFILE" ]; then
        local pid
        pid=$(cat "$PIDFILE" 2>/dev/null)
        if [ -n "$pid" ] && ! ps -p "$pid" > /dev/null 2>&1; then
            rm -f "$PIDFILE" "$LOCKFILE"
        fi
    elif [ -f "$LOCKFILE" ]; then
        rm -f "$LOCKFILE"
    fi
}

start_service() {
    fix_stale

    if is_running; then
        echo "脚本已在运行中，PID: $(get_pid)"
        return
    fi

    if [ ! -f "$SCRIPT" ]; then
        echo "找不到脚本: $SCRIPT"
        return
    fi

    chmod +x "$SCRIPT"
    touch "$LOGFILE"

    nohup bash "$SCRIPT" >> "$LOGFILE" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1

    if is_running; then
        echo "启动成功，PID: $(get_pid)"
        echo "日志文件: $LOGFILE"
    else
        echo "启动失败，请检查日志: $LOGFILE"
    fi
}

stop_service() {
    fix_stale

    if is_running; then
        local pid
        pid=$(get_pid)

        kill "$pid" 2>/dev/null
        sleep 2

        if ps -p "$pid" > /dev/null 2>&1; then
            kill -9 "$pid" 2>/dev/null
        fi

        rm -f "$PIDFILE" "$LOCKFILE"
        echo "脚本已停止。"
    else
        rm -f "$PIDFILE" "$LOCKFILE"
        echo "脚本未运行。"
    fi
}

restart_service() {
    stop_service
    sleep 1
    start_service
}

status_service() {
    fix_stale

    if is_running; then
        echo "运行状态: 正在运行"
        echo "PID: $(get_pid)"
    else
        echo "运行状态: 未运行"
    fi

    echo "主脚本: $SCRIPT"
    echo "日志文件: $LOGFILE"
    echo "锁文件: $LOCKFILE"
}

view_log() {
    touch "$LOGFILE"
    echo "按 Ctrl+C 退出日志查看"
    tail -f "$LOGFILE"
}

show_menu() {
    clear
    echo "======================================"
    echo "         bageddns 管理面板"
    echo "======================================"
    echo "1. 启动脚本"
    echo "2. 停止脚本"
    echo "3. 重启脚本"
    echo "4. 查看状态"
    echo "5. 查看实时日志"
    echo "0. 退出"
    echo "======================================"
}

case "$1" in
    start)
        start_service
        exit 0
        ;;
    stop)
        stop_service
        exit 0
        ;;
    restart)
        restart_service
        exit 0
        ;;
    status)
        status_service
        exit 0
        ;;
    log)
        view_log
        exit 0
        ;;
esac

while true
do
    show_menu
    read -rp "请输入选项: " choice
    case "$choice" in
        1) start_service ;;
        2) stop_service ;;
        3) restart_service ;;
        4) status_service ;;
        5) view_log ;;
        0) exit 0 ;;
        *) echo "无效选项，请重新输入。" ;;
    esac
    echo
    read -rp "按回车继续..." _
done
EOF
