#!/usr/bin/env bash
# 腾讯云 DNSPod 香港 DDNS - AWS 开机小助手极速版
# 特点：
# 1) 密钥已内置到文件，适合无环境变量的开机小助手。
# 2) start 模式可快速返回，适合首次手工拉起或兼容旧调用。
# 3) 不使用 jq，不自动 apt/yum 安装依赖，避免开机阶段卡住。
# 4) install-service 会把脚本固定安装到 /usr/local/sbin，并交给 systemd 托管。

set -u
set -o pipefail

# ========== 用户配置区 ==========
# 已按你的要求：SecretId / SecretKey 直接写进脚本文件。
# 请只保存到可信服务器，并执行 chmod 700 限制权限。
SECRET_ID="AKIDW6SZR5ZqsfEajfR1NXTChy1rUu64nMwQ"
SECRET_KEY="VN8h2CAxYu1sUr0xlIciaFguvxpUxFNL"

INSTANCE_NAME="awshk"
DOMAIN="woainiliz.com"
RECORD_TYPE="A"

SUB_DOMAIN_1="swswsw"
FULL_DOMAIN_1="${SUB_DOMAIN_1}.${DOMAIN}"
RECORD_LINE_1="移动"
RECORD_REMARK_1="aws3whk"
# 填 RecordId 后速度最快；留空时会先 DescribeRecordList 查询。
RECORD_ID_1=""

SUB_DOMAIN_2="ahkwsddns"
FULL_DOMAIN_2="${SUB_DOMAIN_2}.${DOMAIN}"
RECORD_LINE_2="默认"
RECORD_REMARK_2="awshkddns"
RECORD_ID_2=""

# 后台重试：开机早期网络没准备好时，不阻塞开机小助手，由后台慢慢重试。
RETRY_TIMES=12
RETRY_SLEEP=5

# daemon 模式轮询间隔
CHECK_INTERVAL=60

# 为减少重复 API 调用，记录最近一次成功同步的 IP。
# 但只靠缓存会漏掉“记录被手工改坏/删除”的情况，所以每隔 FORCE_SYNC_INTERVAL
# 仍会强制同步一次。
IP_CACHE_FILE="/tmp/txcfddns-${INSTANCE_NAME}-lastip.txt"
LAST_SYNC_FILE="/tmp/txcfddns-${INSTANCE_NAME}-lastsync.txt"
FORCE_SYNC_INTERVAL=3600

# API 超时：start 不受这些影响，只有 worker/once 会使用。
IMDS_CONNECT_TIMEOUT="0.2"
IMDS_MAX_TIME="1.0"
API_CONNECT_TIMEOUT="1.0"
API_MAX_TIME="4.0"
# ================================

SERVICE="dnspod"
HOST="dnspod.tencentcloudapi.com"
VERSION="2021-03-23"
CONTENT_TYPE="application/json; charset=utf-8"
SCRIPT_PATH="$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")"
LOG_DIR="/var/log/txcfddns-${INSTANCE_NAME}"
[ -w /var/log ] || LOG_DIR="/tmp/txcfddns-${INSTANCE_NAME}"
LOG_FILE="${LOG_DIR}/txcfddns-fast.log"
PID_FILE="/tmp/txcfddns-${INSTANCE_NAME}-fast.pid"
LOCK_DIR="/tmp/txcfddns-${INSTANCE_NAME}-fast.lockdir"
INSTALL_PATH="/usr/local/sbin/txcfddns-${INSTANCE_NAME}-fast.sh"
UNIT_NAME="txcfddns-${INSTANCE_NAME}.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

mkdir -p "$LOG_DIR" 2>/dev/null || true

log() {
  local msg="[$(date '+%F %T')] $*"
  printf '%s\n' "$msg" >> "$LOG_FILE" 2>/dev/null || true
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1
}

service_installed() {
  [ -f "$UNIT_PATH" ]
}

service_is_active() {
  has_systemd && service_installed && systemctl is-active --quiet "$UNIT_NAME"
}

service_is_enabled() {
  has_systemd && service_installed && systemctl is-enabled --quiet "$UNIT_NAME"
}

latest_log_line() {
  tail -n 1 "$LOG_FILE" 2>/dev/null || true
}

sync_summary() {
  local last_ip="" last_sync="" now elapsed
  [ -f "$IP_CACHE_FILE" ] && last_ip="$(cat "$IP_CACHE_FILE" 2>/dev/null || true)"
  [ -f "$LAST_SYNC_FILE" ] && last_sync="$(cat "$LAST_SYNC_FILE" 2>/dev/null || true)"

  if [ -n "$last_ip" ]; then
    echo "最近成功 IP：$last_ip"
  fi

  if [[ "$last_sync" =~ ^[0-9]+$ ]]; then
    now="$(date +%s)"
    elapsed=$((now - last_sync))
    echo "最近成功同步：${elapsed}s 前"
  fi
}

need_cmds() {
  local c missing=0
  for c in bash curl openssl awk sed tr date od grep head; do
    if ! command -v "$c" >/dev/null 2>&1; then
      log "缺少命令：$c"
      missing=1
    fi
  done
  return "$missing"
}

is_ipv4() {
  local ip="$1" IFS=. a b c d x
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  read -r a b c d <<< "$ip"
  for x in "$a" "$b" "$c" "$d"; do
    [[ "$x" =~ ^[0-9]+$ ]] || return 1
    [ "$x" -ge 0 ] 2>/dev/null && [ "$x" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

sha256_hex() {
  printf '%s' "$1" | openssl dgst -sha256 -hex | awk '{print $NF}'
}

hmac_sha256_hex_with_key() {
  local key="$1" data="$2"
  printf '%s' "$data" | openssl dgst -sha256 -mac HMAC -macopt "key:${key}" -binary | od -An -vtx1 | tr -d ' \n'
}

hmac_sha256_hex_with_hexkey() {
  local hexkey="$1" data="$2"
  printf '%s' "$data" | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${hexkey}" -binary | od -An -vtx1 | tr -d ' \n'
}

build_authorization() {
  local action="$1" payload="$2" timestamp="$3" utc_date="$4"
  local algorithm="TC3-HMAC-SHA256" http_method="POST" canonical_uri="/"
  local canonical_query_string="" signed_headers="content-type;host;x-tc-action"
  local canonical_headers payload_hash canonical_request hashed_canonical_request credential_scope string_to_sign
  local secret_date secret_service secret_signing signature

  canonical_headers="content-type:${CONTENT_TYPE}
host:${HOST}
x-tc-action:$(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')
"

  payload_hash="$(sha256_hex "$payload")"
  canonical_request="$(printf '%s\n%s\n%s\n%s\n%s\n%s' \
    "$http_method" "$canonical_uri" "$canonical_query_string" "$canonical_headers" "$signed_headers" "$payload_hash")"
  hashed_canonical_request="$(sha256_hex "$canonical_request")"
  credential_scope="${utc_date}/${SERVICE}/tc3_request"
  string_to_sign="$(printf '%s\n%s\n%s\n%s' "$algorithm" "$timestamp" "$credential_scope" "$hashed_canonical_request")"

  secret_date="$(hmac_sha256_hex_with_key "TC3${SECRET_KEY}" "$utc_date")"
  secret_service="$(hmac_sha256_hex_with_hexkey "$secret_date" "$SERVICE")"
  secret_signing="$(hmac_sha256_hex_with_hexkey "$secret_service" "tc3_request")"
  signature="$(hmac_sha256_hex_with_hexkey "$secret_signing" "$string_to_sign")"

  printf '%s' "${algorithm} Credential=${SECRET_ID}/${credential_scope}, SignedHeaders=${signed_headers}, Signature=${signature}"
}

tc_api() {
  local action="$1" payload="$2" timestamp utc_date authorization response errmsg
  timestamp="$(date +%s)"
  utc_date="$(date -u +%F)"
  authorization="$(build_authorization "$action" "$payload" "$timestamp" "$utc_date")"

  response="$(curl -fsS \
    --connect-timeout "$API_CONNECT_TIMEOUT" --max-time "$API_MAX_TIME" \
    -X POST "https://${HOST}/" \
    -H "Authorization: ${authorization}" \
    -H "Content-Type: ${CONTENT_TYPE}" \
    -H "Host: ${HOST}" \
    -H "X-TC-Action: ${action}" \
    -H "X-TC-Timestamp: ${timestamp}" \
    -H "X-TC-Version: ${VERSION}" \
    -d "$payload" 2>/dev/null)" || {
      log "API 请求失败：${action}"
      return 1
    }

  if printf '%s' "$response" | grep -q '"Error"'; then
    errmsg="$(printf '%s' "$response" | sed -n 's/.*"Message":"\([^"]*\)".*/\1/p' | head -n 1)"
    log "API 返回错误：${action}${errmsg:+ | $errmsg}"
    return 1
  fi

  printf '%s' "$response"
}

get_aws_public_ipv4() {
  local token ip
  token="$(curl -fsS --connect-timeout "$IMDS_CONNECT_TIMEOUT" --max-time "$IMDS_MAX_TIME" \
    -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)"

  if [ -n "$token" ]; then
    ip="$(curl -fsS --connect-timeout "$IMDS_CONNECT_TIMEOUT" --max-time "$IMDS_MAX_TIME" \
      -H "X-aws-ec2-metadata-token: ${token}" \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  else
    ip="$(curl -fsS --connect-timeout "$IMDS_CONNECT_TIMEOUT" --max-time "$IMDS_MAX_TIME" \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  fi

  if [ -n "$ip" ] && is_ipv4 "$ip" && [[ ! "$ip" =~ ^127\. ]]; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
}

get_public_ip_fallback() {
  local ip
  ip="$(curl -fsS --connect-timeout 1 --max-time 2 "https://api.ipify.org" 2>/dev/null || true)"
  if [ -n "$ip" ] && is_ipv4 "$ip" && [[ ! "$ip" =~ ^127\. ]]; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
}

get_public_ipv4() {
  get_aws_public_ipv4 || get_public_ip_fallback
}

extract_record_id_by_remark() {
  local remark="$1"
  awk -v remark="$remark" '
    BEGIN { RS="[{}]" }
    index($0, "\"Remark\":\"" remark "\"") {
      if (match($0, /\"RecordId\":[0-9]+/)) {
        s=substr($0, RSTART, RLENGTH); sub(/.*:/, "", s); print s; exit
      }
    }
  ' | head -n 1
}

extract_first_record_id() {
  grep -o '"RecordId":[0-9]*' | head -n 1 | sed 's/[^0-9]//g'
}

describe_record_id() {
  local sub="$1" line="$2" remark="$3" payload response rid
  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"Subdomain\":\"$(json_escape "$sub")\",\"RecordType\":\"$(json_escape "$RECORD_TYPE")\",\"RecordLine\":\"$(json_escape "$line")\",\"Limit\":20,\"Offset\":0,\"ErrorOnEmpty\":\"no\"}"
  response="$(tc_api "DescribeRecordList" "$payload")" || return 1
  rid="$(printf '%s' "$response" | extract_record_id_by_remark "$remark")"
  [ -n "$rid" ] || rid="$(printf '%s' "$response" | extract_first_record_id)"
  [ -n "$rid" ] || return 1
  printf '%s' "$rid"
}

create_record() {
  local sub="$1" full="$2" line="$3" remark="$4" ip="$5" payload response rid
  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"SubDomain\":\"$(json_escape "$sub")\",\"RecordType\":\"$(json_escape "$RECORD_TYPE")\",\"RecordLine\":\"$(json_escape "$line")\",\"Value\":\"$(json_escape "$ip")\",\"Remark\":\"$(json_escape "$remark")\",\"Status\":\"ENABLE\"}"
  response="$(tc_api "CreateRecord" "$payload")" || return 1
  rid="$(printf '%s' "$response" | grep -o '"RecordId":[0-9]*' | head -n 1 | sed 's/[^0-9]//g')"
  log "已创建记录：${full} [${line}] -> ${ip}${rid:+ | RecordId=${rid}}"
}

modify_dynamic_dns() {
  local sub="$1" full="$2" line="$3" rid="$4" ip="$5" payload
  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"SubDomain\":\"$(json_escape "$sub")\",\"RecordId\":${rid},\"RecordLine\":\"$(json_escape "$line")\",\"Value\":\"$(json_escape "$ip")\"}"
  tc_api "ModifyDynamicDNS" "$payload" >/dev/null || return 1
  log "DDNS 更新成功：${full} [${line}] -> ${ip} | RecordId=${rid}"
}

sync_one_record() {
  local sub="$1" full="$2" line="$3" remark="$4" rid="$5" ip="$6"
  if [ -z "$rid" ]; then
    rid="$(describe_record_id "$sub" "$line" "$remark" || true)"
  fi

  if [ -n "$rid" ]; then
    modify_dynamic_dns "$sub" "$full" "$line" "$rid" "$ip"
  else
    create_record "$sub" "$full" "$line" "$remark" "$ip"
  fi
}

should_skip_update() {
  local current_ip="$1" last_ip="" last_sync="" now elapsed
  [ -f "$IP_CACHE_FILE" ] && last_ip="$(cat "$IP_CACHE_FILE" 2>/dev/null || true)"
  [ -f "$LAST_SYNC_FILE" ] && last_sync="$(cat "$LAST_SYNC_FILE" 2>/dev/null || true)"

  if [ "$current_ip" != "$last_ip" ]; then
    return 1
  fi

  if [[ ! "$last_sync" =~ ^[0-9]+$ ]]; then
    return 1
  fi

  now="$(date +%s)"
  elapsed=$((now - last_sync))
  if [ "$elapsed" -lt "$FORCE_SYNC_INTERVAL" ]; then
    log "IP 未变化 (${current_ip})，距离上次成功同步 ${elapsed}s，跳过更新"
    return 0
  fi

  log "IP 未变化 (${current_ip})，但已超过强制同步间隔 ${FORCE_SYNC_INTERVAL}s，继续校正记录"
  return 1
}

mark_sync_success() {
  local current_ip="$1" now
  now="$(date +%s)"
  printf '%s' "$current_ip" > "$IP_CACHE_FILE" 2>/dev/null || true
  printf '%s' "$now" > "$LAST_SYNC_FILE" 2>/dev/null || true
}

do_once() {
  local current_ip
  need_cmds || return 1

  if [ -z "$SECRET_ID" ] || [ -z "$SECRET_KEY" ]; then
    log "未配置腾讯云 SecretId/SecretKey"
    return 1
  fi

  current_ip="$(get_public_ipv4)" || {
    log "无法获取公网 IPv4"
    return 1
  }
  log "当前公网 IPv4：${current_ip}"

  if should_skip_update "$current_ip"; then
    return 0
  fi

  sync_one_record "$SUB_DOMAIN_1" "$FULL_DOMAIN_1" "$RECORD_LINE_1" "$RECORD_REMARK_1" "$RECORD_ID_1" "$current_ip" || return 1
  sync_one_record "$SUB_DOMAIN_2" "$FULL_DOMAIN_2" "$RECORD_LINE_2" "$RECORD_REMARK_2" "$RECORD_ID_2" "$current_ip" || return 1

  mark_sync_success "$current_ip"
  log "本轮 DDNS 完成"
}

worker_once_with_retry() {
  local i
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "已有 worker 在运行，本次退出"
    exit 0
  fi
  trap 'rmdir "$LOCK_DIR" 2>/dev/null || true; rm -f "$PID_FILE" 2>/dev/null || true' EXIT
  echo $$ > "$PID_FILE" 2>/dev/null || true

  for i in $(seq 1 "$RETRY_TIMES"); do
    log "后台同步尝试 ${i}/${RETRY_TIMES}"
    if do_once; then
      exit 0
    fi
    sleep "$RETRY_SLEEP"
  done
  log "多次重试后仍失败"
  exit 1
}

worker_daemon() {
  local interval="${CHECK_INTERVAL:-60}"
  if ! mkdir "$LOCK_DIR" 2>/dev/null; then
    log "已有 daemon 在运行，本次退出"
    exit 0
  fi
  trap 'rmdir "$LOCK_DIR" 2>/dev/null || true; rm -f "$PID_FILE" 2>/dev/null || true' EXIT
  echo $$ > "$PID_FILE" 2>/dev/null || true

  log "DDNS daemon 启动，检查间隔 ${interval} 秒，强制同步间隔 ${FORCE_SYNC_INTERVAL} 秒"
  while true; do
    do_once || true
    sleep "$interval"
  done
}

start_fast() {
  # 如果已经安装了 systemd service，优先让 systemd 接管启动。
  if has_systemd && service_installed; then
    if service_is_active; then
      echo "service 已在运行：$UNIT_NAME"
      return 0
    fi
    systemctl start "$UNIT_NAME"
    echo "started via systemd: $UNIT_NAME"
    return 0
  fi

  # 兼容旧场景：没有安装 service 时，仍支持快速后台拉起。
  if [ ! -f "$SCRIPT_PATH" ] || [ "$(basename "$SCRIPT_PATH")" = "bash" ] || [ "$(basename "$SCRIPT_PATH")" = "sh" ]; then
    echo "无法后台启动：脚本必须保存为本地文件，不能用 curl | bash 管道运行。"
    return 1
  fi

  mkdir -p "$LOG_DIR" 2>/dev/null || true
  if command -v setsid >/dev/null 2>&1; then
    setsid bash "$SCRIPT_PATH" daemon >> "$LOG_FILE" 2>&1 < /dev/null &
  else
    nohup bash "$SCRIPT_PATH" daemon >> "$LOG_FILE" 2>&1 < /dev/null &
  fi
  echo $! > "$PID_FILE" 2>/dev/null || true
  echo "started"
}

install_service() {
  local service_script="$INSTALL_PATH"

  if [ "$(id -u)" -ne 0 ]; then
    echo "install-service 需要 root 权限，请用 sudo 运行。"
    return 1
  fi
  if ! has_systemd; then
    echo "当前系统没有 systemctl，无法安装开机自启。"
    return 1
  fi
  if [ ! -f "$SCRIPT_PATH" ]; then
    echo "脚本文件不存在：$SCRIPT_PATH"
    return 1
  fi

  install -d -m 755 /usr/local/sbin
  install -m 700 "$SCRIPT_PATH" "$service_script"
  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=DNSPod DDNS for ${INSTANCE_NAME}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${service_script} daemon
Restart=always
RestartSec=10
TimeoutStopSec=15

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME"
  echo "已安装并启动：$UNIT_NAME"
  echo "脚本已固定到：$service_script"
}

uninstall_service() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall-service 需要 root 权限，请用 sudo 运行。"
    return 1
  fi
  if ! has_systemd; then
    echo "当前系统没有 systemctl，无法卸载开机自启。"
    return 1
  fi

  systemctl disable --now "$UNIT_NAME" 2>/dev/null || true
  rm -f "$UNIT_PATH"
  systemctl daemon-reload
  echo "已卸载：$UNIT_NAME"
}

status() {
  local pid=""
  [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  echo "脚本：$SCRIPT_PATH"
  echo "日志：$LOG_FILE"

  if has_systemd && service_installed; then
    echo "service：$UNIT_NAME"
    if service_is_active; then
      echo "service 状态：active"
    else
      echo "service 状态：inactive/failed"
    fi
    if service_is_enabled; then
      echo "开机自启：enabled"
    else
      echo "开机自启：disabled"
    fi
  fi

  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    echo "进程状态：运行中，PID=$pid"
  else
    echo "进程状态：未运行或已完成"
  fi

  sync_summary

  local last_line=""
  last_line="$(latest_log_line)"
  if [ -n "$last_line" ]; then
    echo "最近日志：$last_line"
  fi
}

stop() {
  local pid=""
  if has_systemd && service_installed; then
    systemctl stop "$UNIT_NAME"
    echo "stopped via systemd: $UNIT_NAME"
    return 0
  fi

  [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    echo "stopped"
  else
    echo "not running"
  fi
  rm -f "$PID_FILE"
  rmdir "$LOCK_DIR" 2>/dev/null || true
}

restart_service() {
  if has_systemd && service_installed; then
    systemctl restart "$UNIT_NAME"
    echo "restarted via systemd: $UNIT_NAME"
    return 0
  fi

  stop
  start_fast
}

case "${1:-start}" in
  start) start_fast ;;
  worker|--worker) worker_once_with_retry ;;
  daemon|--daemon) worker_daemon ;;
  once|--once) do_once ;;
  status) status ;;
  stop) stop ;;
  restart) restart_service ;;
  install-service) install_service ;;
  uninstall-service) uninstall_service ;;
  logs|log) tail -n 80 "$LOG_FILE" 2>/dev/null || true ;;
  follow) tail -n 50 -F "$LOG_FILE" ;;
  *)
    cat <<USAGE
用法：
  $0 start      # 极速启动后台 daemon，立即返回，适合开机小助手
  $0 once       # 前台执行一次 DDNS
  $0 daemon     # 前台常驻循环，CHECK_INTERVAL 默认 60s
  $0 status     # 查看 service、进程、最近同步和最近日志
  $0 logs       # 查看日志
  $0 stop       # 停止 service 或后台 daemon
  $0 restart    # 重启 service 或后台 daemon
  $0 install-service    # 安装并启用 systemd 开机自启
  $0 uninstall-service  # 卸载 systemd 开机自启
USAGE
    exit 1
    ;;
esac
