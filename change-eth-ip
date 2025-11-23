#!/usr/bin/env bash
#
# 全自动公网 IP 轮换脚本
# - 自动识别默认网关
# - 自动识别所有有 IPv4 的物理网卡
# - 在多块网卡之间轮流切换默认路由
# - 保证只有一个实例在跑：新实例会干掉旧实例并接管
# ---------------------------------------------------------

LOCK_FILE="/tmp/ip_switch.lock"
LOG_FILE="/var/log/ip_switch.log"
INTERVAL=60     # 切换间隔（秒）

# 如果不是 root，就用 sudo；否则不用
if [[ $EUID -ne 0 ]]; then
  SUDO="sudo"
else
  SUDO=""
fi

log() {
  echo "[$(date '+%F %T')] $*" | tee -a "$LOG_FILE"
}

get_public_ip() {
  # 带超时 + 兜底的公网 IP 获取
  curl -m 5 -s -4 https://ifconfig.me \
    || curl -m 5 -s -4 https://api.ipify.org \
    || echo "unknown"
}

get_default_dev() {
  ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

get_default_gw() {
  ip route show default 2>/dev/null | awk '/default/ {print $3; exit}'
}

# 在 interfaces 数组中找到“当前网卡”的下一个，用来轮换
get_next_dev() {
  local cur="$1"
  local idx=""
  local i

  for i in "${!interfaces[@]}"; do
    if [[ "${interfaces[$i]}" == "$cur" ]]; then
      idx="$i"
      break
    fi
  done

  # 如果没找到当前网卡，就从第一个开始
  if [[ -z "$idx" ]]; then
    echo "${interfaces[0]}"
    return
  fi

  local next=$(( (idx + 1) % ${#interfaces[@]} ))
  echo "${interfaces[$next]}"
}

# ========== 单实例控制 ==========

if [[ -f "$LOCK_FILE" ]]; then
  old_pid=$(cat "$LOCK_FILE" 2>/dev/null || echo "")
  if [[ -n "$old_pid" ]] && kill -0 "$old_pid" 2>/dev/null; then
    log "检测到已有实例 (PID=$old_pid)，终止旧实例并接管..."
    kill "$old_pid" 2>/dev/null || true
    sleep 1
  fi
fi

echo $$ > "$LOCK_FILE"

cleanup() {
  rm -f "$LOCK_FILE"
}
trap cleanup EXIT INT TERM

# ========== 自动识别默认网关 ==========

GATEWAY=$(get_default_gw)
if [[ -z "$GATEWAY" ]]; then
  log "未检测到默认网关，无法自动配置路由，退出。"
  exit 1
fi
log "检测到默认网关: $GATEWAY"

# ========== 自动识别可用网卡 ==========

# 1. 把有 IPv4 地址的全局网卡捞出来
# 2. 排除 lo / docker / veth / 虚拟桥接等
mapfile -t interfaces < <(
  ip -4 -o addr show scope global \
  | awk '{print $2}' \
  | sort -u \
  | grep -Ev '^(lo|docker[0-9]*|veth.*|br-.*|virbr.*|wg.*|tun.*|tap.*)$'
)

# 只保留状态为 UP 的网卡
tmp=()
for dev in "${interfaces[@]}"; do
  state=$(ip link show "$dev" | awk '/state/ {print $9}')
  if [[ "$state" == "UP" ]]; then
    tmp+=("$dev")
  fi
done
interfaces=("${tmp[@]}")

if ((${#interfaces[@]} < 2)); then
  log "可用物理网卡（UP、有 IPv4）少于 2 个：${interfaces[*]:-无}，无法轮流切换，退出。"
  exit 1
fi

log "可用网卡列表: ${interfaces[*]}"
log "启动自动切换公网 IP，间隔 ${INTERVAL}s"

# ========== 主循环 ==========

while true; do
  cur_dev=$(get_default_dev)
  if [[ -z "$cur_dev" ]]; then
    cur_dev="${interfaces[0]}"
  fi

  next_dev=$(get_next_dev "$cur_dev")

  PRIV_IP=$(ip -4 addr show "$next_dev" | awk '/inet / {print $2}' | cut -d/ -f1 | head -n1)
  PUB_IP_BEFORE=$(get_public_ip)

  log "当前默认网卡: ${cur_dev:-无}，即将切换到: $next_dev (内网 IP: ${PRIV_IP:-N/A}, 切换前公网 IP: $PUB_IP_BEFORE)"

  # 清理所有默认路由
  $SUDO ip route del default 2>/dev/null || true

  # 为下一个网卡添加默认路由（主用）
  $SUDO ip route add default via "$GATEWAY" dev "$next_dev" metric 1

  # 其他网卡添加备份路由（更高 metric）
  for d in "${interfaces[@]}"; do
    if [[ "$d" != "$next_dev" ]]; then
      $SUDO ip route add default via "$GATEWAY" dev "$d" metric 100 2>/dev/null || true
    fi
  done

  sleep 3
  PUB_IP_AFTER=$(get_public_ip)
  log "切换完成，新公网 IP: $PUB_IP_AFTER"
  log "------------------------------------"

  sleep "$INTERVAL"
done
