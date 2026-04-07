#!/usr/bin/env bash

set -u
set -o pipefail

# ========== 用户配置区 ==========
CF_API_TOKEN="cfut_3ZR4ZFfakq5MJxApE6ZLokxFWGdvoGQY8XAMrkZAa5f2f2f8"
CF_DOMAIN="awshkniubi.77yun77.com"
CF_ZONE_NAME="77yun77.com"
AWS_SB_SGT="4d48e86004924a0b9ce4a6c99816cee7"
# ================================

# 脚本路径和文件定义
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "$0")"
LOG_FILE="${LOG_FILE:-$HOME/.ddns/ddns.log}"
PID_FILE="/tmp/ddns-vps-daemon-$(id -u).pid"
LOCK_FILE="/tmp/ddns-vps-daemon-$(id -u).lock"

# ========== 工具函数 ==========

log_msg() {
  local msg="[$(date '+%F %T')] $1"
  echo "$msg"
  echo "$msg" >> "$LOG_FILE"
}

random_suffix() {
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' | head -c 12
}

curl_json() {
  local url="$1"
  shift
  curl -sS --fail \
    --connect-timeout 10 \
    --max-time 20 \
    --retry 3 \
    --retry-delay 2 \
    --retry-all-errors \
    "$@" \
    "$url"
}

cf_api() {
  local url="$1"
  shift
  curl_json \
    "$url" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    "$@"
}

print_json_errors() {
  local response="$1"
  echo "$response" | jq -c '.errors // .' 2>/dev/null || echo "$response"
}

require_cf_success() {
  local action="$1"
  local response="$2"
  if ! echo "$response" | jq -e '.success == true' >/dev/null 2>&1; then
    log_msg "错误: Cloudflare ${action}失败"
    print_json_errors "$response" >> "$LOG_FILE"
    return 1
  fi
}

delete_cf_record() {
  local zone_id="$1"
  local record_id="$2"
  local delete_result=""
  delete_result="$(
    cf_api \
      "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
      -X DELETE
  )" || {
    log_msg "错误: 删除重复 DNS 记录失败: $record_id"
    return 1
  }
  require_cf_success "重复 DNS 记录删除" "$delete_result"
}

# ========== DDNS 检测函数 ==========

do_ddns_check() {
  local ZONE_RESPONSE ZONE_ID R1 SHARES INSTANCE_ID REGION R2 RESPONSE NEW_IP
  local RECORD_INFO RECORD_COUNT RECORD_ID OLD_IP
  local -a EXTRA_RECORD_IDS=()
  local UPDATED="false"
  local METHOD="" URL=""

  ZONE_RESPONSE="$(
    cf_api \
      "https://api.cloudflare.com/client/v4/zones?name=$CF_ZONE_NAME"
  )" || {
    log_msg "错误: 无法查询 Cloudflare Zone"
    return 1
  }

  require_cf_success "Zone 查询" "$ZONE_RESPONSE" || return 1

  ZONE_ID="$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id // empty')"

  if [ -z "$ZONE_ID" ]; then
    log_msg "错误: 无法获取 Cloudflare Zone ID"
    return 1
  fi

  R1="$(random_suffix)"
  SHARES="$(
    curl_json \
      "https://api.aws.sb/ec2-instance-shares?r=${R1}" \
      -H "x-share-group-token: $AWS_SB_SGT" \
      -H "Referer: https://aws.sb/" \
      -H "Origin: https://aws.sb"
  )" || {
    log_msg "错误: 无法获取实例列表"
    return 1
  }

  INSTANCE_ID="$(echo "$SHARES" | jq -r '.[0].instanceId // empty')"
  REGION="$(echo "$SHARES" | jq -r '.[0].regionName // empty')"

  if [ -z "$INSTANCE_ID" ] || [ -z "$REGION" ]; then
    log_msg "错误: 无法获取实例信息"
    return 1
  fi

  R2="$(random_suffix)"
  RESPONSE="$(
    curl_json \
      "https://api.aws.sb/ec2-instances/${INSTANCE_ID}?r=${R2}" \
      -H "x-share-group-token: $AWS_SB_SGT" \
      -H "x-region-name: $REGION" \
      -H "Referer: https://aws.sb/" \
      -H "Origin: https://aws.sb"
  )" || {
    log_msg "错误: 无法获取实例详情"
    return 1
  }

  NEW_IP="$(echo "$RESPONSE" | jq -r '.publicIpAddress // .ipAddress // empty')"

  if [ -z "$NEW_IP" ]; then
    log_msg "错误: 无法获取实例 IP"
    return 1
  fi

  RECORD_INFO="$(
    cf_api \
      "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$CF_DOMAIN&type=A"
  )" || {
    log_msg "错误: 无法查询 Cloudflare DNS 记录"
    return 1
  }

  require_cf_success "DNS 记录查询" "$RECORD_INFO" || return 1

  RECORD_COUNT="$(echo "$RECORD_INFO" | jq -r '.result | length')"
  RECORD_ID="$(echo "$RECORD_INFO" | jq -r '.result[0].id // empty')"
  OLD_IP="$(echo "$RECORD_INFO" | jq -r '.result[0].content // empty')"
  mapfile -t EXTRA_RECORD_IDS < <(echo "$RECORD_INFO" | jq -r '.result[1:][]?.id')

  if [ "$RECORD_COUNT" -gt 1 ]; then
    log_msg "警告: 发现 $RECORD_COUNT 条同名 A 记录，更新后会清理重复项"
  fi

  if [ "$NEW_IP" = "$OLD_IP" ] && [ "$RECORD_COUNT" -le 1 ]; then
    log_msg "IP 未变化: $NEW_IP"
    return 0
  fi

  if [ "$NEW_IP" != "$OLD_IP" ] && [ -n "$RECORD_ID" ]; then
    log_msg "IP 变化: ${OLD_IP:-<空>} -> $NEW_IP，更新中..."
    METHOD="PUT"
    URL="https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID"
    UPDATED="true"
  elif [ "$NEW_IP" != "$OLD_IP" ]; then
    log_msg "IP 变化: ${OLD_IP:-<空>} -> $NEW_IP，创建记录中..."
    METHOD="POST"
    URL="https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records"
    UPDATED="true"
  else
    log_msg "IP 未变化，但存在重复记录，开始清理"
  fi

  if [ "$UPDATED" = "true" ]; then
    local RESULT
    RESULT="$(
      cf_api \
        "$URL" \
        -X "$METHOD" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"A\",\"name\":\"$CF_DOMAIN\",\"content\":\"$NEW_IP\",\"ttl\":60,\"proxied\":false}"
    )" || {
      log_msg "错误: Cloudflare 更新失败"
      return 1
    }
    require_cf_success "DNS 更新" "$RESULT" || return 1
  fi

  if [ "${#EXTRA_RECORD_IDS[@]}" -gt 0 ]; then
    for extra_record_id in "${EXTRA_RECORD_IDS[@]}"; do
      log_msg "删除重复 DNS 记录: $extra_record_id"
      delete_cf_record "$ZONE_ID" "$extra_record_id" || true
    done
  fi

  if [ "$UPDATED" = "true" ]; then
    log_msg "DNS 更新成功: $CF_DOMAIN -> $NEW_IP"
  elif [ "${#EXTRA_RECORD_IDS[@]}" -gt 0 ]; then
    log_msg "DNS 保持不变，但已清理重复记录: $CF_DOMAIN -> $NEW_IP"
  fi
}

# ========== 后台服务模式 ==========

run_daemon() {
  # 创建锁文件防止重复启动
  exec 200>"$LOCK_FILE"
  if ! flock -n 200; then
    log_msg "错误: DDNS 服务已经在运行中"
    exit 1
  fi

  # 写入 PID
  echo $$ > "$PID_FILE"

  log_msg "========== DDNS 服务启动 =========="
  log_msg "域名: $CF_DOMAIN"
  log_msg "日志文件: $LOG_FILE"
  log_msg "========================================"

  # 主循环
  while true; do
    log_msg "----- 开始检测 -----"
    
    # 执行检测
    if do_ddns_check; then
      :
    else
      log_msg "本次检测出现错误，继续下一次..."
    fi
    
    log_msg "----- 检测完成，60秒后再次检测 -----"
    log_msg ""
    
    # 睡眠60秒
    sleep 60
  done
}

# ========== 服务管理函数 ==========

is_service_running() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null)"
    # 验证 PID 是纯数字
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      # 检查是否真的是ddns进程
      if grep -q "ddns-vps-daemon" "/proc/$pid/cmdline" 2>/dev/null || \
         ps -p "$pid" -o comm= 2>/dev/null | grep -q "bash"; then
        return 0
      fi
    fi
  fi
  return 1
}

start_service() {
  # 使用 flock 原子锁防止并发启动
  exec 300>"$LOCK_FILE.start"
  if ! flock -n 300; then
    echo "DDNS 服务正在启动中，请稍候..."
    return 1
  fi

  if is_service_running; then
    echo "DDNS 服务已经在运行中 (PID: $(cat "$PID_FILE"))"
    return 1
  fi

  # 确保日志目录存在
  local log_dir
  log_dir="$(dirname "$LOG_FILE")"
  if [ ! -d "$log_dir" ]; then
    mkdir -p "$log_dir" 2>/dev/null || {
      echo "无法创建日志目录: $log_dir"
      return 1
    }
  fi

  echo "正在启动 DDNS 服务..."
  
  # 使用 nohup 启动后台进程
  nohup bash "$SCRIPT_PATH" --daemon >> "$LOG_FILE" 2>&1 &
  
  # 等待一下让进程启动
  sleep 1
  
  if is_service_running; then
    echo "DDNS 服务启动成功! (PID: $(cat "$PID_FILE"))"
    echo "日志文件: $LOG_FILE"
  else
    echo "DDNS 服务启动失败，请检查日志: $LOG_FILE"
    return 1
  fi
}

stop_service() {
  if ! is_service_running; then
    echo "DDNS 服务当前没有运行"
    # 清理残留文件
    rm -f "$PID_FILE" "$LOCK_FILE" "$LOCK_FILE.start"
    return 0
  fi

  local pid
  pid="$(cat "$PID_FILE")"
  
  # 再次验证 PID 格式
  if ! [[ "$pid" =~ ^[0-9]+$ ]]; then
    echo "PID 文件内容无效，清理残留文件"
    rm -f "$PID_FILE" "$LOCK_FILE" "$LOCK_FILE.start"
    return 1
  fi
  
  echo "正在停止 DDNS 服务 (PID: $pid)..."
  
  # 先尝试正常终止
  kill "$pid" 2>/dev/null
  
  # 等待最多5秒
  local waited=0
  while [ "$waited" -lt 5 ]; do
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done
  
  # 如果还在运行，强制终止
  if kill -0 "$pid" 2>/dev/null; then
    echo "服务未响应，强制终止..."
    kill -9 "$pid" 2>/dev/null
  fi
  
  # 清理文件
  rm -f "$PID_FILE" "$LOCK_FILE" "$LOCK_FILE.start"
  
  echo "DDNS 服务已停止"
}

show_logs() {
  if [ ! -f "$LOG_FILE" ]; then
    echo "日志文件不存在: $LOG_FILE"
    return 1
  fi
  
  echo "========== DDNS 日志 (最近 50 行) =========="
  tail -n 50 "$LOG_FILE"
  echo "=========================================="
  echo "提示: 按 Ctrl+C 退出日志查看"
}

show_status() {
  if is_service_running; then
    echo "状态: 【运行中】 (PID: $(cat "$PID_FILE"))"
  else
    echo "状态: 【已停止】"
  fi
}

# ========== 管理面板 ==========

show_menu() {
  clear
  echo "╔════════════════════════════════════════╗"
  echo "║         DDNS 服务管理面板              ║"
  echo "╠════════════════════════════════════════╣"
  show_status
  echo "╠════════════════════════════════════════╣"
  echo "║  1. 启动服务                           ║"
  echo "║  2. 停止服务                           ║"
  echo "║  3. 查看日志                           ║"
  echo "║  0. 退出面板 (后台服务继续运行)        ║"
  echo "╚════════════════════════════════════════╝"
  echo ""
}

run_menu() {
  while true; do
    show_menu
    read -p "请选择操作 [0-3]: " choice
    
    case "$choice" in
      1)
        echo ""
        start_service
        echo ""
        read -p "按回车键继续..."
        ;;
      2)
        echo ""
        stop_service
        echo ""
        read -p "按回车键继续..."
        ;;
      3)
        echo ""
        show_logs
        echo ""
        read -p "按回车键继续..."
        ;;
      0)
        echo ""
        echo "退出管理面板，DDNS 服务将继续在后台运行。"
        echo "如需重新打开面板，请运行: $SCRIPT_PATH"
        exit 0
        ;;
      *)
        echo ""
        echo "无效的选择，请重新输入"
        sleep 1
        ;;
    esac
  done
}

# ========== 主入口 ==========

# 检查依赖
if ! command -v jq >/dev/null 2>&1; then
  echo "错误: 缺少 jq 工具，请先安装: apt-get install jq 或 yum install jq"
  exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
  echo "错误: 缺少 curl 工具"
  exit 1
fi

# 参数处理
case "${1:-}" in
  --daemon)
    # 后台服务模式
    run_daemon
    ;;
  start)
    # 命令行启动
    start_service
    ;;
  stop)
    # 命令行停止
    stop_service
    ;;
  restart)
    # 命令行重启
    stop_service
    sleep 1
    start_service
    ;;
  status)
    # 查看状态
    show_status
    ;;
  log|logs)
    # 查看日志
    show_logs
    ;;
  *)
    # 默认打开管理面板
    run_menu
    ;;
esac
