#!/usr/bin/env bash
set -Eeuo pipefail

APP_NAME="bageddns"
INSTALL_DIR="/opt/bageddns"
CONF_DIR="/etc/bageddns"
RUN_DIR="/var/run/bageddns"
STATE_DIR="/var/lib/bageddns"
LOG_DIR="/var/log/bageddns"
BIN_PATH="/usr/local/bin/bageddns"
WORKER_PATH="$INSTALL_DIR/worker.sh"
CONF_PATH="$CONF_DIR/bageddns.conf"
STATE_PATH="$STATE_DIR/state.env"
SERVICE_NAME="bageddns.service"
SERVICE_PATH="/etc/systemd/system/$SERVICE_NAME"

API_KEY="${BAGEDDNS_API_KEY:-}"
API_URL="${BAGEDDNS_API_URL:-https://www.bagevm.com/index.php?m=hinet}"
API_ACTION="${BAGEDDNS_API_ACTION:-restip}"
CHECK_INTERVAL="${BAGEDDNS_CHECK_INTERVAL:-180}"
PING_TARGET="${BAGEDDNS_PING_TARGET:-223.5.5.5}"
PING_COUNT="${BAGEDDNS_PING_COUNT:-5}"
PING_WAIT="${BAGEDDNS_PING_WAIT:-2}"
PING_INTERVAL="${BAGEDDNS_PING_INTERVAL:-0.2}"
REQUEST_TIMEOUT="${BAGEDDNS_REQUEST_TIMEOUT:-12}"
ENABLE_ON_BOOT=0
START_AFTER_INSTALL=1
FORCE_INSTALL=0
USE_SYSTEMD="auto"

usage() {
  cat <<USAGE
用法:
  bash install_bageddns.sh [选项]

选项:
  --api-key <key>            设置 API Key
  --api-url <url>            设置 API 地址
  --action <action>          设置 API 动作, 默认: restip
  --check-interval <秒>      检测间隔, 默认: 180
  --ping-target <host>       Ping 目标, 默认: 223.5.5.5
  --ping-count <次数>        Ping 次数, 默认: 5
  --ping-wait <秒>           Ping 超时, 默认: 2
  --ping-interval <秒>       Ping 间隔, 默认: 0.2
  --request-timeout <秒>     Curl 超时, 默认: 12
  --enable                   安装后设置开机自启
  --no-start                 安装后不立即启动
  --force                    强制覆盖安装
  --systemd                  强制使用 systemd
  --no-systemd               禁用 systemd, 使用 nohup + PID 管理
  -h, --help                 显示帮助

环境变量也支持:
  BAGEDDNS_API_KEY, BAGEDDNS_API_URL, BAGEDDNS_CHECK_INTERVAL 等
USAGE
}

need_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    echo "[错误] 请使用 root 运行安装脚本。" >&2
    exit 1
  fi
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --api-key)
        API_KEY="${2:-}"
        shift 2
        ;;
      --api-url)
        API_URL="${2:-}"
        shift 2
        ;;
      --action)
        API_ACTION="${2:-}"
        shift 2
        ;;
      --check-interval)
        CHECK_INTERVAL="${2:-}"
        shift 2
        ;;
      --ping-target)
        PING_TARGET="${2:-}"
        shift 2
        ;;
      --ping-count)
        PING_COUNT="${2:-}"
        shift 2
        ;;
      --ping-wait)
        PING_WAIT="${2:-}"
        shift 2
        ;;
      --ping-interval)
        PING_INTERVAL="${2:-}"
        shift 2
        ;;
      --request-timeout)
        REQUEST_TIMEOUT="${2:-}"
        shift 2
        ;;
      --enable)
        ENABLE_ON_BOOT=1
        shift
        ;;
      --no-start)
        START_AFTER_INSTALL=0
        shift
        ;;
      --force)
        FORCE_INSTALL=1
        shift
        ;;
      --systemd)
        USE_SYSTEMD="yes"
        shift
        ;;
      --no-systemd)
        USE_SYSTEMD="no"
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      *)
        echo "[错误] 未知参数: $1" >&2
        usage >&2
        exit 1
        ;;
    esac
  done
}

require_command() {
  local name="$1"
  if ! command -v "$name" >/dev/null 2>&1; then
    echo "[错误] 缺少命令: $name" >&2
    exit 1
  fi
}

validate_number() {
  local label="$1"
  local value="$2"
  local pattern="$3"
  if ! printf '%s' "$value" | grep -Eq "$pattern"; then
    echo "[错误] $label 格式不正确: $value" >&2
    exit 1
  fi
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

write_config() {
  mkdir -p "$CONF_DIR"

  local existing_key=""
  if [ -f "$CONF_PATH" ]; then
    existing_key=$(sed -n 's/^API_KEY="\(.*\)"$/\1/p' "$CONF_PATH" | head -n 1)
  fi

  if [ -z "$API_KEY" ] && [ -n "$existing_key" ]; then
    API_KEY="$existing_key"
  fi

  cat > "$CONF_PATH" <<EOF_CONF
# $APP_NAME 配置文件
# 请勿把真实 API Key 提交到公开 GitHub 仓库

API_KEY="$API_KEY"
API_URL="$API_URL"
API_ACTION="$API_ACTION"
CHECK_INTERVAL="$CHECK_INTERVAL"
PING_TARGET="$PING_TARGET"
PING_COUNT="$PING_COUNT"
PING_WAIT="$PING_WAIT"
PING_INTERVAL="$PING_INTERVAL"
REQUEST_TIMEOUT="$REQUEST_TIMEOUT"
LOG_FILE="$LOG_DIR/worker.log"
PID_FILE="$RUN_DIR/bageddns.pid"
STATE_FILE="$STATE_PATH"
IP_SERVICES="https://api.ipify.org https://ifconfig.me https://icanhazip.com https://ipinfo.io/ip"
EOF_CONF

  chmod 600 "$CONF_PATH"
}

write_worker() {
  mkdir -p "$INSTALL_DIR"
  cat > "$WORKER_PATH" <<'EOF_WORKER'
#!/usr/bin/env bash
set -u

APP_NAME="bageddns"
CONF_PATH="/etc/bageddns/bageddns.conf"
DEFAULT_RUN_DIR="/var/run/bageddns"
DEFAULT_STATE_DIR="/var/lib/bageddns"
DEFAULT_LOG_DIR="/var/log/bageddns"

[ -r "$CONF_PATH" ] || {
  echo "$(date '+%F %T') - [错误] 配置文件不存在: $CONF_PATH" >&2
  exit 1
}

# shellcheck disable=SC1091
source "$CONF_PATH"

LOG_FILE="${LOG_FILE:-$DEFAULT_LOG_DIR/worker.log}"
PID_FILE="${PID_FILE:-$DEFAULT_RUN_DIR/bageddns.pid}"
STATE_FILE="${STATE_FILE:-$DEFAULT_STATE_DIR/state.env}"
API_KEY="${API_KEY:-}"
API_URL="${API_URL:-https://www.bagevm.com/index.php?m=hinet}"
API_ACTION="${API_ACTION:-restip}"
CHECK_INTERVAL="${CHECK_INTERVAL:-180}"
PING_TARGET="${PING_TARGET:-223.5.5.5}"
PING_COUNT="${PING_COUNT:-5}"
PING_WAIT="${PING_WAIT:-2}"
PING_INTERVAL="${PING_INTERVAL:-0.2}"
REQUEST_TIMEOUT="${REQUEST_TIMEOUT:-12}"
IP_SERVICES="${IP_SERVICES:-https://api.ipify.org https://ifconfig.me https://icanhazip.com https://ipinfo.io/ip}"

mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")" "$(dirname "$STATE_FILE")"
touch "$LOG_FILE"

log() {
  local now
  now="$(date '+%F %T')"
  printf '%s - %s\n' "$now" "$*" | tee -a "$LOG_FILE"
}

safe_source_state() {
  if [ -f "$STATE_FILE" ]; then
    # shellcheck disable=SC1090
    source "$STATE_FILE" || true
  fi
}

CHECK_COUNT=0
CHANGE_COUNT=0
LAST_IP=""
LAST_STATUS="init"
LAST_CHECK_AT=""
LAST_CHANGE_AT=""
LAST_PACKET_LOSS=""
LAST_API_STATUS=""
LAST_API_RESPONSE_B64=""
STARTED_AT="$(date '+%F %T')"

safe_source_state
STARTED_AT="$(date '+%F %T')"

write_state() {
  cat > "$STATE_FILE.tmp" <<EOF_STATE
CHECK_COUNT=${CHECK_COUNT:-0}
CHANGE_COUNT=${CHANGE_COUNT:-0}
LAST_IP='${LAST_IP:-}'
LAST_STATUS='${LAST_STATUS:-}'
LAST_CHECK_AT='${LAST_CHECK_AT:-}'
LAST_CHANGE_AT='${LAST_CHANGE_AT:-}'
LAST_PACKET_LOSS='${LAST_PACKET_LOSS:-}'
LAST_API_STATUS='${LAST_API_STATUS:-}'
LAST_API_RESPONSE_B64='${LAST_API_RESPONSE_B64:-}'
STARTED_AT='${STARTED_AT:-}'
PID='$$'
EOF_STATE
  mv "$STATE_FILE.tmp" "$STATE_FILE"
}

cleanup() {
  rm -f "$PID_FILE"
  LAST_STATUS="stopped"
  write_state
}
trap cleanup EXIT INT TERM

already_running() {
  if [ -f "$PID_FILE" ]; then
    local old_pid
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$old_pid" ] && kill -0 "$old_pid" >/dev/null 2>&1; then
      return 0
    fi
  fi
  return 1
}

if already_running; then
  log "检测到已有实例在运行, PID=$(cat "$PID_FILE" 2>/dev/null || echo '?'), 本次退出。"
  exit 0
fi

echo $$ > "$PID_FILE"
LAST_STATUS="starting"
write_state

require_runtime() {
  local missing=0
  for cmd in curl ping awk sed base64; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      log "[错误] 缺少运行依赖: $cmd"
      missing=1
    fi
  done
  [ "$missing" -eq 0 ]
}

trim() {
  printf '%s' "$1" | tr -d '[:space:]'
}

valid_ipv4() {
  local ip="$1"
  printf '%s' "$ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
}

get_public_ip() {
  local service raw ip
  for service in $IP_SERVICES; do
    raw="$(curl -fsS --max-time "$REQUEST_TIMEOUT" "$service" 2>/dev/null || true)"
    ip="$(trim "$raw")"
    if valid_ipv4 "$ip"; then
      printf '%s\n' "$ip"
      return 0
    fi
  done
  return 1
}

get_packet_loss() {
  local output loss
  output="$(ping -q -c "$PING_COUNT" -W "$PING_WAIT" -i "$PING_INTERVAL" "$PING_TARGET" 2>&1 || true)"
  loss="$(printf '%s\n' "$output" | awk -F', ' '/packet loss/ {gsub(/%/,"",$3); print $3; exit}')"
  if [ -z "$loss" ]; then
    loss="100"
  fi
  printf '%s\n' "$loss"
}

extract_json_string() {
  local key="$1"
  local data="$2"
  printf '%s' "$data" | sed -nE "s/.*\"${key}\":\"?([^\",}]*)\"?.*/\1/p" | head -n 1
}

build_api_url() {
  local ip="$1"
  local sep='?'
  case "$API_URL" in
    *\?*) sep='&' ;;
  esac
  printf '%s%svmip=%s&apikey=%s&action=%s' "$API_URL" "$sep" "$ip" "$API_KEY" "$API_ACTION"
}

change_ip() {
  local current_ip="$1"
  local url response status new_ip

  if [ -z "$API_KEY" ]; then
    LAST_STATUS="config_error"
    LAST_API_STATUS="missing_api_key"
    LAST_API_RESPONSE_B64="$(printf '%s' 'API_KEY is empty' | base64 | tr -d '\n')"
    log "[错误] 配置文件中的 API_KEY 为空, 无法执行更换 IP。"
    write_state
    return 1
  fi

  url="$(build_api_url "$current_ip")"
  response="$(curl -fsS --max-time "$REQUEST_TIMEOUT" "$url" 2>&1 || true)"
  status="$(extract_json_string status "$response")"
  new_ip="$(extract_json_string mainip "$response")"

  LAST_API_STATUS="$status"
  LAST_API_RESPONSE_B64="$(printf '%s' "$response" | base64 | tr -d '\n')"

  if [ "$status" = "1000" ]; then
    CHANGE_COUNT=$((CHANGE_COUNT + 1))
    LAST_CHANGE_AT="$(date '+%F %T')"
    LAST_STATUS="changed"
    if [ -n "$new_ip" ]; then
      LAST_IP="$new_ip"
      log "成功更换 IP, 新 IP: $new_ip"
    else
      log "成功更换 IP, 但接口未返回 mainip 字段。"
    fi
    write_state
    return 0
  fi

  LAST_STATUS="change_failed"
  log "更换 IP 失败, 接口返回: $response"
  write_state
  return 1
}

if ! require_runtime; then
  LAST_STATUS="runtime_error"
  write_state
  exit 1
fi

log "======================================================"
log "监控进程启动, PID=$$"
log "日志文件: $LOG_FILE"
log "检测间隔: ${CHECK_INTERVAL}s | Ping目标: ${PING_TARGET}"
log "======================================================"

while true; do
  CHECK_COUNT=$((CHECK_COUNT + 1))
  LAST_CHECK_AT="$(date '+%F %T')"

  if current_ip="$(get_public_ip)"; then
    LAST_IP="$current_ip"
  else
    LAST_STATUS="ip_error"
    LAST_PACKET_LOSS="unknown"
    log "第 ${CHECK_COUNT} 次检测: 无法获取公网 IP, 稍后重试。"
    write_state
    sleep "$CHECK_INTERVAL"
    continue
  fi

  packet_loss="$(get_packet_loss)"
  LAST_PACKET_LOSS="$packet_loss"

  if [ "$packet_loss" = "100" ]; then
    LAST_STATUS="blocked"
    log "第 ${CHECK_COUNT} 次检测: 当前 IP=$current_ip, 丢包率=${packet_loss}%, 判定为可能被封锁, 准备更换。"
    write_state
    change_ip "$current_ip" || true
  else
    LAST_STATUS="ok"
    log "第 ${CHECK_COUNT} 次检测: 当前 IP=$current_ip, 丢包率=${packet_loss}%, 状态正常。"
    write_state
  fi

  sleep "$CHECK_INTERVAL"
done
EOF_WORKER
  chmod 755 "$WORKER_PATH"
}

write_control() {
  cat > "$BIN_PATH" <<'EOF_CTL'
#!/usr/bin/env bash
set -u

APP_NAME="bageddns"
SERVICE_NAME="bageddns.service"
WORKER_PATH="/opt/bageddns/worker.sh"
CONF_PATH="/etc/bageddns/bageddns.conf"
STATE_PATH="/var/lib/bageddns/state.env"
LOG_FILE="/var/log/bageddns/worker.log"
PID_FILE="/var/run/bageddns/bageddns.pid"

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -f "/etc/systemd/system/$SERVICE_NAME" ]
}

service_manager() {
  if has_systemd && [ -d /run/systemd/system ]; then
    printf 'systemd\n'
  else
    printf 'local\n'
  fi
}

safe_source_state() {
  if [ -f "$STATE_PATH" ]; then
    # shellcheck disable=SC1090
    source "$STATE_PATH" || true
  fi
}

safe_source_config() {
  if [ -f "$CONF_PATH" ]; then
    # shellcheck disable=SC1091
    source "$CONF_PATH" || true
    [ -n "${LOG_FILE:-}" ] || LOG_FILE="/var/log/bageddns/worker.log"
    [ -n "${PID_FILE:-}" ] || PID_FILE="/var/run/bageddns/bageddns.pid"
  fi
}

mask_key() {
  local key="$1"
  local len=${#key}
  if [ -z "$key" ]; then
    printf '%s\n' '(empty)'
  elif [ "$len" -le 8 ]; then
    printf '%s\n' '********'
  else
    printf '%s****%s\n' "${key:0:4}" "${key:len-4:4}"
  fi
}

is_running_local() {
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    [ -n "$pid" ] && kill -0 "$pid" >/dev/null 2>&1
    return $?
  fi
  return 1
}

start_service() {
  safe_source_config
  if [ "$(service_manager)" = "systemd" ]; then
    systemctl daemon-reload
    systemctl start "$SERVICE_NAME"
    echo "已启动 $APP_NAME (systemd)"
  else
    if is_running_local; then
      echo "$APP_NAME 已在运行中, PID=$(cat "$PID_FILE" 2>/dev/null)"
      return 0
    fi
    mkdir -p "$(dirname "$LOG_FILE")" "$(dirname "$PID_FILE")"
    nohup "$WORKER_PATH" >/dev/null 2>&1 &
    sleep 1
    if is_running_local; then
      echo "已启动 $APP_NAME, PID=$(cat "$PID_FILE" 2>/dev/null)"
    else
      echo "启动失败, 请查看日志: $LOG_FILE"
      return 1
    fi
  fi
}

stop_service() {
  safe_source_config
  if [ "$(service_manager)" = "systemd" ]; then
    systemctl stop "$SERVICE_NAME"
    echo "已停止 $APP_NAME (systemd)"
  else
    if is_running_local; then
      local pid
      pid="$(cat "$PID_FILE" 2>/dev/null || true)"
      kill "$pid" >/dev/null 2>&1 || true
      sleep 1
      if kill -0 "$pid" >/dev/null 2>&1; then
        kill -9 "$pid" >/dev/null 2>&1 || true
      fi
      rm -f "$PID_FILE"
      echo "已停止 $APP_NAME"
    else
      rm -f "$PID_FILE"
      echo "$APP_NAME 当前未运行"
    fi
  fi
}

restart_service() {
  stop_service
  sleep 1
  start_service
}

status_service() {
  safe_source_config
  safe_source_state

  echo "========================================"
  echo "${APP_NAME} 状态"
  echo "========================================"
  echo "管理方式: $(service_manager)"
  echo "工作脚本: $WORKER_PATH"
  echo "配置文件: $CONF_PATH"
  echo "日志文件: $LOG_FILE"

  if [ "$(service_manager)" = "systemd" ]; then
    echo "运行状态: $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
    echo "开机自启: $(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || echo unknown)"
  else
    if is_running_local; then
      echo "运行状态: running"
      echo "进程 PID: $(cat "$PID_FILE" 2>/dev/null || true)"
    else
      echo "运行状态: stopped"
    fi
  fi

  echo "检测次数: ${CHECK_COUNT:-0}"
  echo "换 IP 次数: ${CHANGE_COUNT:-0}"
  echo "最后 IP: ${LAST_IP:-unknown}"
  echo "最后状态: ${LAST_STATUS:-unknown}"
  echo "最后检测时间: ${LAST_CHECK_AT:-unknown}"
  echo "最后更换时间: ${LAST_CHANGE_AT:-never}"
  echo "最近丢包率: ${LAST_PACKET_LOSS:-unknown}%"
  echo "========================================"
}

log_service() {
  safe_source_config
  mkdir -p "$(dirname "$LOG_FILE")"
  touch "$LOG_FILE"
  echo "日志文件: $LOG_FILE"
  echo "按 Ctrl+C 退出日志查看"
  tail -n 100 -f "$LOG_FILE"
}

doctor_service() {
  safe_source_config
  safe_source_state
  echo "========================================"
  echo "${APP_NAME} 自检"
  echo "========================================"
  for cmd in bash curl ping awk sed base64; do
    if command -v "$cmd" >/dev/null 2>&1; then
      echo "[OK] 命令存在: $cmd"
    else
      echo "[FAIL] 缺少命令: $cmd"
    fi
  done

  if [ -f "$CONF_PATH" ]; then
    echo "[OK] 配置文件存在: $CONF_PATH"
    # shellcheck disable=SC1091
    source "$CONF_PATH" || true
    if [ -n "${API_KEY:-}" ]; then
      echo "[OK] API_KEY 已配置: $(mask_key "$API_KEY")"
    else
      echo "[FAIL] API_KEY 未配置"
    fi
    echo "[OK] API_URL: ${API_URL:-unknown}"
    echo "[OK] CHECK_INTERVAL: ${CHECK_INTERVAL:-unknown}"
    echo "[OK] PING_TARGET: ${PING_TARGET:-unknown}"
  else
    echo "[FAIL] 配置文件不存在: $CONF_PATH"
  fi

  if [ -x "$WORKER_PATH" ]; then
    echo "[OK] 工作脚本存在: $WORKER_PATH"
  else
    echo "[FAIL] 工作脚本不存在或不可执行: $WORKER_PATH"
  fi

  if [ "$(service_manager)" = "systemd" ]; then
    echo "[OK] 使用 systemd 管理"
    echo "[OK] 服务状态: $(systemctl is-active "$SERVICE_NAME" 2>/dev/null || echo unknown)"
    echo "[OK] 开机自启: $(systemctl is-enabled "$SERVICE_NAME" 2>/dev/null || echo unknown)"
  else
    echo "[OK] 使用本地 nohup + PID 管理"
  fi
  echo "========================================"
}

enable_service() {
  if [ "$(service_manager)" = "systemd" ]; then
    systemctl daemon-reload
    systemctl enable "$SERVICE_NAME"
    echo "已设置开机自启"
  else
    echo "当前不是 systemd 环境, 暂不支持开机自启"
    return 1
  fi
}

disable_service() {
  if [ "$(service_manager)" = "systemd" ]; then
    systemctl disable "$SERVICE_NAME"
    echo "已取消开机自启"
  else
    echo "当前不是 systemd 环境, 无需取消"
  fi
}

show_config() {
  safe_source_config
  echo "配置文件: $CONF_PATH"
  if [ -f "$CONF_PATH" ]; then
    # shellcheck disable=SC1091
    source "$CONF_PATH" || true
    echo "API_KEY=$(mask_key "${API_KEY:-}")"
    echo "API_URL=${API_URL:-}"
    echo "API_ACTION=${API_ACTION:-}"
    echo "CHECK_INTERVAL=${CHECK_INTERVAL:-}"
    echo "PING_TARGET=${PING_TARGET:-}"
    echo "PING_COUNT=${PING_COUNT:-}"
    echo "PING_WAIT=${PING_WAIT:-}"
    echo "PING_INTERVAL=${PING_INTERVAL:-}"
    echo "REQUEST_TIMEOUT=${REQUEST_TIMEOUT:-}"
  else
    echo "配置文件不存在。"
  fi
}

pause_wait() {
  echo
  read -r -p "按回车返回菜单..." _
}

show_menu() {
  if [ -t 1 ] && command -v clear >/dev/null 2>&1; then
    clear 2>/dev/null || true
  fi
  echo "========================================"
  echo "           bageddns 管理面板"
  echo "========================================"
  echo "1. 启动监控"
  echo "2. 停止监控"
  echo "3. 重启监控"
  echo "4. 查看状态"
  echo "5. 查看实时日志"
  echo "6. 环境自检"
  echo "7. 开机自启"
  echo "8. 关闭自启"
  echo "9. 查看配置"
  echo "0. 退出"
  echo "========================================"
}

case "${1:-}" in
  start) start_service; exit $? ;;
  stop) stop_service; exit $? ;;
  restart) restart_service; exit $? ;;
  status) status_service; exit $? ;;
  log) log_service; exit $? ;;
  doctor) doctor_service; exit $? ;;
  enable) enable_service; exit $? ;;
  disable) disable_service; exit $? ;;
  config) show_config; exit $? ;;
  "") ;;
  *)
    echo "用法: bageddns {start|stop|restart|status|log|doctor|enable|disable|config}"
    exit 1
    ;;
esac

while true; do
  show_menu
  read -r -p "请输入选项: " choice
  choice="$(printf '%s' "$choice" | tr -d '[:space:]')"
  case "$choice" in
    1) start_service; pause_wait ;;
    2) stop_service; pause_wait ;;
    3) restart_service; pause_wait ;;
    4) status_service; pause_wait ;;
    5) log_service ;;
    6) doctor_service; pause_wait ;;
    7) enable_service; pause_wait ;;
    8) disable_service; pause_wait ;;
    9) show_config; pause_wait ;;
    0) exit 0 ;;
    "") ;;
    *)
      echo "无效选项, 请重新输入。"
      sleep 1
      ;;
  esac
done
EOF_CTL
  chmod 755 "$BIN_PATH"
}

write_service() {
  cat > "$SERVICE_PATH" <<EOF_SERVICE
[Unit]
Description=BageDDNS monitor service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$WORKER_PATH
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF_SERVICE
  chmod 644 "$SERVICE_PATH"
}

install_files() {
  mkdir -p "$INSTALL_DIR" "$CONF_DIR" "$RUN_DIR" "$STATE_DIR" "$LOG_DIR"

  write_config
  write_worker
  write_control

  if [ "$USE_SYSTEMD" = "yes" ] || { [ "$USE_SYSTEMD" = "auto" ] && has_systemd; }; then
    write_service
    systemctl daemon-reload || true
  fi
}

main() {
  need_root
  parse_args "$@"

  require_command bash
  require_command curl
  require_command ping
  require_command awk
  require_command sed
  require_command base64

  validate_number "CHECK_INTERVAL" "$CHECK_INTERVAL" '^[0-9]+$'
  validate_number "PING_COUNT" "$PING_COUNT" '^[0-9]+$'
  validate_number "PING_WAIT" "$PING_WAIT" '^[0-9]+$'
  validate_number "PING_INTERVAL" "$PING_INTERVAL" '^[0-9]+([.][0-9]+)?$'
  validate_number "REQUEST_TIMEOUT" "$REQUEST_TIMEOUT" '^[0-9]+$'

  if [ -f "$BIN_PATH" ] && [ "$FORCE_INSTALL" -ne 1 ]; then
    echo "[提示] 检测到已安装 $APP_NAME, 将执行覆盖更新。"
  fi

  install_files

  if [ "$ENABLE_ON_BOOT" -eq 1 ]; then
    if [ -f "$SERVICE_PATH" ] && has_systemd; then
      systemctl enable "$SERVICE_NAME" >/dev/null 2>&1 || true
    else
      echo "[提示] 当前环境未使用 systemd, 跳过开机自启设置。"
    fi
  fi

  if [ "$START_AFTER_INSTALL" -eq 1 ]; then
    "$BIN_PATH" restart || true
  fi

  echo
  echo "安装完成。"
  echo "命令: $BIN_PATH"
  echo "配置: $CONF_PATH"
  echo "日志: $LOG_DIR/worker.log"
  echo
  echo "常用命令:"
  echo "  bageddns                打开管理面板"
  echo "  bageddns start          启动监控"
  echo "  bageddns stop           停止监控"
  echo "  bageddns restart        重启监控"
  echo "  bageddns status         查看状态"
  echo "  bageddns log            查看实时日志"
  echo "  bageddns doctor         环境自检"
  echo "  bageddns config         查看配置"
  echo
  if [ -z "$API_KEY" ]; then
    echo "[提醒] 当前 API_KEY 为空, 请先编辑配置文件后再使用。"
  fi
}

main "$@"
