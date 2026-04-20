#!/usr/bin/env bash
# 腾讯云 DNSPod DDNS - awshk 最简后台版
# 目标：脚本 start 秒级返回，DDNS 在后台/ systemd 中自动运行。

if [ -z "${BASH_VERSION:-}" ]; then
  echo "错误：请用 bash 执行，不要用 sh。示例：bash txcfddns-awshk-simple.sh install" >&2
  exit 2
fi

set -u
set -o pipefail
umask 077

# ================== 用户配置区 ==================
# 按你的要求：密钥直接写进脚本文件。请确保脚本权限为 700。
SECRET_ID="AKIDW6SZR5ZqsfEajfR1NXTChy1rUu64nMwQ"
SECRET_KEY="VN8h2CAxYu1sUr0xlIciaFguvxpUxFNL"

INSTANCE_NAME="awshk"
DOMAIN="woainiliz.com"
RECORD_TYPE="A"

SUB_DOMAIN_1="swswsw"
FULL_DOMAIN_1="${SUB_DOMAIN_1}.${DOMAIN}"
RECORD_LINE_1="移动"
RECORD_REMARK_1="aws3whk"
RECORD_ID_1=""       # 可选：填入 RecordId 后更快

SUB_DOMAIN_2="ahkwsddns"
FULL_DOMAIN_2="${SUB_DOMAIN_2}.${DOMAIN}"
RECORD_LINE_2="默认"
RECORD_REMARK_2="awshkddns"
RECORD_ID_2=""       # 可选：填入 RecordId 后更快

CHECK_INTERVAL=60      # 成功后每 60 秒检查一次
RETRY_SLEEP=5          # 失败后每 5 秒重试
FORCE_SYNC_INTERVAL=3600

IMDS_CONNECT_TIMEOUT="0.5"
IMDS_MAX_TIME="1.5"
API_CONNECT_TIMEOUT="2"
API_MAX_TIME="8"
# =================================================

SERVICE="dnspod"
HOST="dnspod.tencentcloudapi.com"
VERSION="2021-03-23"
CONTENT_TYPE="application/json; charset=utf-8"
INSTALL_PATH="/usr/local/sbin/txcfddns-${INSTANCE_NAME}.sh"
PANEL_CMD="txcfddns"
PANEL_PATH="/usr/local/bin/${PANEL_CMD}"
UNIT_NAME="txcfddns-${INSTANCE_NAME}.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

script_path() {
  local src="${BASH_SOURCE[0]}"
  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$src" 2>/dev/null && return 0
  fi
  cd "$(dirname "$src")" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$(basename "$src")"
}
SCRIPT_PATH="$(script_path)"

if [ "$(id -u)" -eq 0 ]; then
  LOG_DIR="/var/log/txcfddns-${INSTANCE_NAME}"
  DATA_DIR="/var/lib/txcfddns-${INSTANCE_NAME}"
else
  LOG_DIR="/tmp/txcfddns-${INSTANCE_NAME}"
  DATA_DIR="/tmp/txcfddns-${INSTANCE_NAME}-data"
fi
LOG_FILE="${LOG_DIR}/txcfddns.log"
PID_FILE="${DATA_DIR}/txcfddns.pid"
LOCK_DIR="${DATA_DIR}/lock"
IP_CACHE_FILE="${DATA_DIR}/last_ip"
LAST_SYNC_FILE="${DATA_DIR}/last_sync"
RID_CACHE_1="${DATA_DIR}/record_id_1"
RID_CACHE_2="${DATA_DIR}/record_id_2"

mkdir -p "$LOG_DIR" "$DATA_DIR" 2>/dev/null || true

log() {
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

need_cmds() {
  local c ok=0
  for c in bash curl openssl awk sed tr date od grep head tail kill mkdir; do
    if ! command -v "$c" >/dev/null 2>&1; then
      echo "缺少命令：$c" >&2
      log "缺少命令：$c"
      ok=1
    fi
  done
  return "$ok"
}

has_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }
service_installed() { [ -f "$UNIT_PATH" ]; }
service_active() { has_systemd && service_installed && systemctl is-active --quiet "$UNIT_NAME"; }
service_enabled() { has_systemd && service_installed && systemctl is-enabled --quiet "$UNIT_NAME"; }

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

  response="$(curl -fsS --connect-timeout "$API_CONNECT_TIMEOUT" --max-time "$API_MAX_TIME" \
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
  token="$(curl -fsS --noproxy '*' --connect-timeout "$IMDS_CONNECT_TIMEOUT" --max-time "$IMDS_MAX_TIME" \
    -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)"

  if [ -n "$token" ]; then
    ip="$(curl -fsS --noproxy '*' --connect-timeout "$IMDS_CONNECT_TIMEOUT" --max-time "$IMDS_MAX_TIME" \
      -H "X-aws-ec2-metadata-token: ${token}" \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  else
    ip="$(curl -fsS --noproxy '*' --connect-timeout "$IMDS_CONNECT_TIMEOUT" --max-time "$IMDS_MAX_TIME" \
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
  [ -n "$rid" ] && printf '%s' "$rid"
}

modify_dynamic_dns() {
  local sub="$1" full="$2" line="$3" rid="$4" ip="$5" payload
  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"SubDomain\":\"$(json_escape "$sub")\",\"RecordId\":${rid},\"RecordLine\":\"$(json_escape "$line")\",\"Value\":\"$(json_escape "$ip")\"}"
  tc_api "ModifyDynamicDNS" "$payload" >/dev/null || return 1
  log "DDNS 更新成功：${full} [${line}] -> ${ip} | RecordId=${rid}"
}

load_record_id() {
  local fixed="$1" cache="$2"
  if [ -n "$fixed" ]; then
    printf '%s' "$fixed"
  elif [ -s "$cache" ]; then
    head -n 1 "$cache" | tr -cd '0-9'
  fi
}

save_record_id() {
  local rid="$1" cache="$2"
  [ -n "$rid" ] && printf '%s' "$rid" > "$cache" 2>/dev/null || true
}

sync_one_record() {
  local sub="$1" full="$2" line="$3" remark="$4" fixed_rid="$5" cache="$6" ip="$7"
  local rid
  rid="$(load_record_id "$fixed_rid" "$cache")"

  if [ -z "$rid" ]; then
    rid="$(describe_record_id "$sub" "$line" "$remark" || true)"
    save_record_id "$rid" "$cache"
  fi

  if [ -n "$rid" ]; then
    modify_dynamic_dns "$sub" "$full" "$line" "$rid" "$ip" || {
      rm -f "$cache" 2>/dev/null || true
      return 1
    }
  else
    rid="$(create_record "$sub" "$full" "$line" "$remark" "$ip" || true)"
    save_record_id "$rid" "$cache"
    [ -n "$rid" ] || return 1
  fi
}

should_skip_update() {
  local current_ip="$1" last_ip="" last_sync="" now elapsed
  [ -f "$IP_CACHE_FILE" ] && last_ip="$(cat "$IP_CACHE_FILE" 2>/dev/null || true)"
  [ -f "$LAST_SYNC_FILE" ] && last_sync="$(cat "$LAST_SYNC_FILE" 2>/dev/null || true)"

  [ "$current_ip" = "$last_ip" ] || return 1
  [[ "$last_sync" =~ ^[0-9]+$ ]] || return 1

  now="$(date +%s)"
  elapsed=$((now - last_sync))
  if [ "$elapsed" -lt "$FORCE_SYNC_INTERVAL" ]; then
    log "IP 未变化：${current_ip}，${elapsed}s 内已同步过，跳过"
    return 0
  fi
  return 1
}

mark_sync_success() {
  local ip="$1" now
  now="$(date +%s)"
  printf '%s' "$ip" > "$IP_CACHE_FILE" 2>/dev/null || true
  printf '%s' "$now" > "$LAST_SYNC_FILE" 2>/dev/null || true
}

do_once() {
  local ip
  need_cmds || return 1

  if [ -z "$SECRET_ID" ] || [ -z "$SECRET_KEY" ]; then
    log "未配置 SecretId/SecretKey"
    return 1
  fi

  ip="$(get_public_ipv4)" || {
    log "无法获取公网 IPv4"
    return 1
  }
  log "当前公网 IPv4：${ip}"

  if should_skip_update "$ip"; then
    return 0
  fi

  sync_one_record "$SUB_DOMAIN_1" "$FULL_DOMAIN_1" "$RECORD_LINE_1" "$RECORD_REMARK_1" "$RECORD_ID_1" "$RID_CACHE_1" "$ip" || return 1
  sync_one_record "$SUB_DOMAIN_2" "$FULL_DOMAIN_2" "$RECORD_LINE_2" "$RECORD_REMARK_2" "$RECORD_ID_2" "$RID_CACHE_2" "$ip" || return 1
  mark_sync_success "$ip"
  log "本轮 DDNS 完成"
}

acquire_lock() {
  mkdir -p "$DATA_DIR" 2>/dev/null || true
  if mkdir "$LOCK_DIR" 2>/dev/null; then
    return 0
  fi

  local oldpid=""
  [ -f "$PID_FILE" ] && oldpid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ "$oldpid" =~ ^[0-9]+$ ]] && kill -0 "$oldpid" 2>/dev/null; then
    return 1
  fi

  rm -rf "$LOCK_DIR" 2>/dev/null || true
  mkdir "$LOCK_DIR" 2>/dev/null
}

cleanup_lock() {
  rm -f "$PID_FILE" 2>/dev/null || true
  rmdir "$LOCK_DIR" 2>/dev/null || true
}

daemon_loop() {
  if ! acquire_lock; then
    log "已有 DDNS 后台进程在运行，本进程退出"
    exit 0
  fi
  echo $$ > "$PID_FILE" 2>/dev/null || true
  trap 'log "DDNS daemon 停止"; cleanup_lock; exit 0' INT TERM HUP
  trap 'cleanup_lock' EXIT

  log "DDNS daemon 启动，成功间隔 ${CHECK_INTERVAL}s，失败重试 ${RETRY_SLEEP}s"
  while true; do
    if do_once; then
      sleep "$CHECK_INTERVAL" || true
    else
      log "本轮 DDNS 失败，${RETRY_SLEEP}s 后重试"
      sleep "$RETRY_SLEEP" || true
    fi
  done
}

start_bg_without_systemd() {
  mkdir -p "$LOG_DIR" "$DATA_DIR" 2>/dev/null || true
  if [ -f "$PID_FILE" ]; then
    local pid
    pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
      echo "已在后台运行：PID=$pid"
      return 0
    fi
  fi

  if command -v setsid >/dev/null 2>&1; then
    setsid bash "$SCRIPT_PATH" daemon >> "$LOG_FILE" 2>&1 < /dev/null &
  else
    nohup bash "$SCRIPT_PATH" daemon >> "$LOG_FILE" 2>&1 < /dev/null &
  fi
  echo $! > "$PID_FILE" 2>/dev/null || true
  echo "started"
}

start_service() {
  if has_systemd && service_installed; then
    systemctl start "$UNIT_NAME" >/dev/null 2>&1 || {
      echo "启动 systemd 服务失败：$UNIT_NAME"
      return 1
    }
    echo "started: $UNIT_NAME"
    return 0
  fi
  start_bg_without_systemd
}

stop_service() {
  local pid=""
  if has_systemd && service_installed; then
    systemctl stop "$UNIT_NAME" >/dev/null 2>&1 || true
    echo "stopped: $UNIT_NAME"
    return 0
  fi

  [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    echo "stopped: PID=$pid"
  else
    echo "not running"
  fi
  cleanup_lock
}

restart_service() {
  stop_service >/dev/null 2>&1 || true
  start_service
}

install_service() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "install 需要 root 权限，请用 sudo/root 执行。"
    return 1
  fi
  if ! has_systemd; then
    echo "当前系统没有可用 systemd，无法安装开机自启。"
    return 1
  fi
  if [ ! -f "$SCRIPT_PATH" ] || [ ! -r "$SCRIPT_PATH" ]; then
    echo "当前脚本不是普通本地文件，请先 curl -o 下载到本地再 install。"
    return 1
  fi

  need_cmds || return 1
  install -d -m 755 /usr/local/sbin /usr/local/bin
  install -m 700 "$SCRIPT_PATH" "$INSTALL_PATH"
  mkdir -p "$LOG_DIR" "$DATA_DIR"
  chmod 700 "$DATA_DIR" 2>/dev/null || true

  cat > "$UNIT_PATH" <<EOF
[Unit]
Description=Tencent DNSPod DDNS (${INSTANCE_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_PATH} daemon
Restart=always
RestartSec=5
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

  cat > "$PANEL_PATH" <<EOF
#!/usr/bin/env bash
if [ "\$#" -eq 0 ]; then
  exec /bin/bash ${INSTALL_PATH} menu
else
  exec /bin/bash ${INSTALL_PATH} "\$@"
fi
EOF
  chmod 755 "$PANEL_PATH"

  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME" >/dev/null 2>&1 || {
    echo "systemctl enable --now 失败，请执行：systemctl status ${UNIT_NAME} --no-pager -l"
    return 1
  }

  echo "安装完成：${UNIT_NAME}"
  echo "开机自启：已启用"
  echo "控制面板命令：${PANEL_CMD}"
  echo "查看状态：${PANEL_CMD} status"
  echo "查看日志：${PANEL_CMD} logs"
}

uninstall_service() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall 需要 root 权限。"
    return 1
  fi
  if has_systemd; then
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
  fi
  rm -f "$PANEL_PATH"
  echo "已卸载 systemd 自启和控制面板命令；脚本文件保留：${INSTALL_PATH}"
}

show_status() {
  local pid="" last_ip="" last_sync="" elapsed="" last_line=""
  [ -f "$PID_FILE" ] && pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -f "$IP_CACHE_FILE" ] && last_ip="$(cat "$IP_CACHE_FILE" 2>/dev/null || true)"
  [ -f "$LAST_SYNC_FILE" ] && last_sync="$(cat "$LAST_SYNC_FILE" 2>/dev/null || true)"

  echo "脚本：$SCRIPT_PATH"
  echo "安装路径：$INSTALL_PATH"
  echo "日志：$LOG_FILE"
  echo "控制面板：$PANEL_CMD"
  echo "目标1：$FULL_DOMAIN_1 [$RECORD_LINE_1]"
  echo "目标2：$FULL_DOMAIN_2 [$RECORD_LINE_2]"

  if service_installed; then
    echo "service：$UNIT_NAME"
    if service_active; then echo "service状态：active"; else echo "service状态：inactive/failed"; fi
    if service_enabled; then echo "开机自启：enabled"; else echo "开机自启：disabled"; fi
  else
    echo "service：未安装"
  fi

  if [[ "$pid" =~ ^[0-9]+$ ]] && kill -0 "$pid" 2>/dev/null; then
    echo "后台进程：运行中 PID=$pid"
  else
    echo "后台进程：未运行或由 systemd 管理"
  fi

  [ -n "$last_ip" ] && echo "最近成功IP：$last_ip"
  if [[ "$last_sync" =~ ^[0-9]+$ ]]; then
    elapsed=$(($(date +%s) - last_sync))
    echo "最近成功同步：${elapsed}s 前"
  fi
  last_line="$(tail -n 1 "$LOG_FILE" 2>/dev/null || true)"
  [ -n "$last_line" ] && echo "最近日志：$last_line"
}

show_logs() {
  tail -n 80 "$LOG_FILE" 2>/dev/null || echo "暂无日志：$LOG_FILE"
}

follow_logs() {
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  touch "$LOG_FILE" 2>/dev/null || true
  tail -n 50 -F "$LOG_FILE"
}

diag() {
  echo "== 基础检查 =="
  echo "当前脚本：$SCRIPT_PATH"
  echo "Bash版本：${BASH_VERSION}"
  if need_cmds; then echo "依赖：OK"; else echo "依赖：FAIL"; fi
  echo
  echo "== IP 检查 =="
  local ip=""
  if ip="$(get_public_ipv4)"; then echo "公网IPv4：$ip"; else echo "公网IPv4：获取失败"; fi
  echo
  echo "== 状态 =="
  show_status
}

menu() {
  while true; do
    clear 2>/dev/null || true
    echo "====== txcfddns 控制面板 (${INSTANCE_NAME}) ======" 
    show_status
    echo "==============================================="
    echo "1. 启动"
    echo "2. 停止"
    echo "3. 重启"
    echo "4. 查看日志"
    echo "5. 实时日志"
    echo "6. 立即执行一次"
    echo "7. 安装/修复开机自启"
    echo "8. 卸载开机自启"
    echo "9. 诊断"
    echo "0. 退出"
    echo "==============================================="
    read -r -p "请选择 [0-9]: " choice
    case "$choice" in
      1) start_service ;;
      2) stop_service ;;
      3) restart_service ;;
      4) show_logs ;;
      5) follow_logs ;;
      6) do_once ;;
      7) install_service ;;
      8) uninstall_service ;;
      9) diag ;;
      0) return 0 ;;
      *) echo "无效选择" ;;
    esac
    echo
    read -r -p "按回车继续..." _
  done
}

usage() {
  cat <<USAGE
用法：
  bash $SCRIPT_PATH              启动后台 DDNS，秒级返回
  bash $SCRIPT_PATH start        启动后台 DDNS
  bash $SCRIPT_PATH stop         停止
  bash $SCRIPT_PATH restart      重启
  bash $SCRIPT_PATH status       状态
  bash $SCRIPT_PATH logs         最近日志
  bash $SCRIPT_PATH follow       实时日志
  bash $SCRIPT_PATH once         前台执行一次
  bash $SCRIPT_PATH install      安装/修复 systemd 开机自启，并创建 ${PANEL_CMD} 控制面板命令
  bash $SCRIPT_PATH uninstall    卸载 systemd 自启和控制面板命令
  bash $SCRIPT_PATH menu         控制面板
  bash $SCRIPT_PATH diag         诊断

安装后：
  ${PANEL_CMD}                   一键打开控制面板
  ${PANEL_CMD} status            查看状态
  ${PANEL_CMD} logs              查看日志
USAGE
}

case "${1:-start}" in
  start) start_service ;;
  daemon|--daemon) daemon_loop ;;
  stop) stop_service ;;
  restart) restart_service ;;
  status) show_status ;;
  logs|log) show_logs ;;
  follow) follow_logs ;;
  once|--once) do_once ;;
  install|install-service|enable) install_service ;;
  uninstall|uninstall-service|disable) uninstall_service ;;
  menu|panel|ui) menu ;;
  diag|doctor) diag ;;
  help|-h|--help) usage ;;
  *) usage; exit 1 ;;
esac
