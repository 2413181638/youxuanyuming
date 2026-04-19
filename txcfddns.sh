#!/usr/bin/env bash
#
# 腾讯云 DNSPod DDNS（极速完整版）
# - 单文件，支持后台守护 / 开机自启 / 管理菜单
# - 核心优化：并发IP获取、默认单次执行、缩短超时
#
# 用法：
#   bash txcfddns.sh              # 立即执行一次 DDNS（默认，1-2秒退出）
#   bash txcfddns.sh start        # 启动后台 DDNS
#   bash txcfddns.sh stop         # 停止后台 DDNS
#   bash txcfddns.sh restart      # 重启后台 DDNS
#   bash txcfddns.sh status       # 查看状态
#   bash txcfddns.sh logs         # 查看最近日志
#   bash txcfddns.sh follow       # 实时查看日志
#   bash txcfddns.sh once         # 立即执行一次 DDNS
#   bash txcfddns.sh menu         # 打开管理面板
#   bash txcfddns.sh install      # 安装 systemd 开机自启
#   bash txcfddns.sh uninstall    # 卸载 systemd 开机自启
#

set -u
set -o pipefail

# ========== 用户配置区 ==========
SECRET_ID="AKIDW6SZR5ZqsfEajfR1NXTChy1rUu64nMwQ"
SECRET_KEY="VN8h2CAxYu1sUr0xlIciaFguvxpUxFNL"

# 已不再使用外部 IP 查询，但保留原值
AWS_SB_SGT="4d48e86004924a0b9ce4a6c99816cee7"

INSTANCE_NAME="awshk"

DOMAIN="woainiliz.com"
SUB_DOMAIN="swswsw"
FULL_DOMAIN="${SUB_DOMAIN}.${DOMAIN}"
RECORD_TYPE="A"
RECORD_LINE="移动"
RECORD_REMARK="aws3whk"

SUB_DOMAIN_2="ahkwsddns"
FULL_DOMAIN_2="${SUB_DOMAIN_2}.${DOMAIN}"
RECORD_LINE_2="默认"
RECORD_REMARK_2="awshkddns"

CHECK_INTERVAL=60
DEBUG="false"
# ================================

[ "${SUB_DOMAIN}" = "@" ] || [ -n "${SUB_DOMAIN}" ] || FULL_DOMAIN="${DOMAIN}"
if [ "${SUB_DOMAIN}" = "@" ]; then FULL_DOMAIN="${DOMAIN}"; fi
[ "${SUB_DOMAIN_2}" = "@" ] || [ -n "${SUB_DOMAIN_2}" ] || FULL_DOMAIN_2="${DOMAIN}"
if [ "${SUB_DOMAIN_2}" = "@" ]; then FULL_DOMAIN_2="${DOMAIN}"; fi

SERVICE="dnspod"
HOST="dnspod.tencentcloudapi.com"
VERSION="2021-03-23"
CONTENT_TYPE="application/json; charset=utf-8"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
SCRIPT_NAME="$(basename "$0")"
SCRIPT_PATH="${SCRIPT_DIR}/${SCRIPT_NAME}"
LOG_DIR_CANDIDATE="${LOG_DIR:-${HOME:-/tmp}/.txcfddns-${INSTANCE_NAME}}"
LOG_FILE_CANDIDATE="${LOG_FILE:-}"
LOG_DIR=""
LOG_FILE=""
LOG_PATHS_READY=0
PID_FILE="/tmp/txcfddns-${INSTANCE_NAME}-daemon-$(id -u).pid"
LOCK_FILE="/tmp/txcfddns-${INSTANCE_NAME}-daemon-$(id -u).lock"
DAEMON_MARK="txcfddns-daemon-marker-${INSTANCE_NAME}"
SHORTCUT_CMD="txcfddns-${INSTANCE_NAME}"
SHORTCUT_PATH="/usr/local/bin/${SHORTCUT_CMD}"
STARTED_AT_FILE=""
IP_SOURCE=""
SYSTEMD_SERVICE_NAME="txcfddns-${INSTANCE_NAME}.service"
SYSTEMD_SERVICE_PATH="/etc/systemd/system/${SYSTEMD_SERVICE_NAME}"

# ---------- 日志系统 ----------
init_log_paths() {
  [ "${LOG_PATHS_READY:-0}" = "1" ] && return 0
  local candidates=() dir test_file
  if [ -n "${LOG_FILE_CANDIDATE}" ]; then
    candidates+=("$(dirname "$LOG_FILE_CANDIDATE")")
  fi
  [ -n "${LOG_DIR_CANDIDATE}" ] && candidates+=("${LOG_DIR_CANDIDATE}")
  candidates+=("/tmp/txcfddns-${INSTANCE_NAME}-$(id -u)")

  for dir in "${candidates[@]}"; do
    [ -n "$dir" ] || continue
    mkdir -p "$dir" 2>/dev/null || continue
    test_file="${dir}/.write_test.$$"
    if : > "$test_file" 2>/dev/null; then
      rm -f "$test_file"
      LOG_DIR="$dir"
      if [ -n "${LOG_FILE_CANDIDATE}" ] && [ "$(dirname "$LOG_FILE_CANDIDATE")" = "$dir" ]; then
        LOG_FILE="${LOG_FILE_CANDIDATE}"
      else
        LOG_FILE="${LOG_DIR}/txcfddns.log"
      fi
      STARTED_AT_FILE="${LOG_DIR}/txcfddns.started_at"
      LOG_PATHS_READY=1
      return 0
    fi
  done
  return 1
}

ensure_log_dir() {
  init_log_paths || return 1
  mkdir -p "$LOG_DIR" 2>/dev/null || return 1
  touch "$LOG_FILE" 2>/dev/null || true
}

log() {
  local msg="[$(date '+%F %T')] $*"
  echo "$msg" >&2
  if ensure_log_dir; then
    echo "$msg" >> "$LOG_FILE" 2>/dev/null || true
  fi
}

debug() {
  [ "$DEBUG" = "true" ] || return 0
  log "[DEBUG] $*"
}

# ---------- 依赖检查（极速，不安装） ----------
ensure_dependencies() {
  local missing=()
  for cmd in curl jq openssl awk sed tr date od flock nohup; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    log "缺少依赖: ${missing[*]}，请手动安装: apt install -y curl jq openssl gawk sed coreutils util-linux"
    return 1
  fi
}

# ---------- IP 获取（三源并发，极速） ----------
get_aws_metadata_ipv4() {
  local token="" ip=""
  token="$(curl -fsS --connect-timeout 1 --max-time 2 -X PUT \
    "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60" 2>/dev/null || true)"
  if [ -n "$token" ]; then
    ip="$(curl -fsS --connect-timeout 1 --max-time 2 \
      -H "X-aws-ec2-metadata-token: ${token}" \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  else
    ip="$(curl -fsS --connect-timeout 1 --max-time 2 \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  fi
  [ -n "$ip" ] && echo "$ip"
}

get_ip_ipip() {
  local raw ip
  raw="$(curl -fsS --connect-timeout 2 --max-time 3 "https://myip.ipip.net" 2>/dev/null || true)"
  ip="$(echo "$raw" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)"
  [ -n "$ip" ] && echo "$ip"
}

get_ip_ipify() {
  local ip
  ip="$(curl -fsS --connect-timeout 2 --max-time 3 "https://api.ipify.org" 2>/dev/null || true)"
  [ -n "$ip" ] && echo "$ip"
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  [[ ! "$ip" =~ ^127\. ]] || return 1
  local IFS='.' part
  read -r -a octets <<< "$ip"
  [ "${#octets[@]}" -eq 4 ] || return 1
  for part in "${octets[@]}"; do
    [ "$part" -ge 0 ] 2>/dev/null && [ "$part" -le 255 ] 2>/dev/null || return 1
  done
  return 0
}

get_local_ipv4() {
  local tmpdir="/tmp/.txcfddns_ip_$$"
  mkdir -p "$tmpdir"

  get_aws_metadata_ipv4 > "$tmpdir/ip1" 2>/dev/null & local p1=$!
  get_ip_ipip > "$tmpdir/ip2" 2>/dev/null & local p2=$!
  get_ip_ipify > "$tmpdir/ip3" 2>/dev/null & local p3=$!

  local waited=0 ip=""
  while [ "$waited" -lt 40 ]; do
    for f in "$tmpdir/ip1" "$tmpdir/ip2" "$tmpdir/ip3"; do
      if [ -s "$f" ]; then
        local candidate="$(head -n1 "$f" | tr -d ' \n\r')"
        if [ -n "$candidate" ] && is_ipv4 "$candidate"; then
          ip="$candidate"
          break 2
        fi
      fi
    done
    sleep 0.1
    waited=$((waited + 1))
  done

  kill "$p1" "$p2" "$p3" 2>/dev/null || true
  rm -rf "$tmpdir"

  if [ -n "$ip" ]; then
    printf '%s' "$ip"
    return 0
  fi
  log "无法获取有效公网 IPv4"
  return 1
}

# ---------- 腾讯云签名（优化版） ----------
sha256_hex() {
  printf '%s' "$1" | openssl dgst -sha256 -hex 2>/dev/null | awk '{print $NF}'
}

hmac_sha256() {
  printf '%s' "$2" | openssl dgst -sha256 -mac HMAC -macopt "${1}" -binary 2>/dev/null | od -An -vtx1 | tr -d ' \n'
}

build_authorization() {
  local action="$1" payload="$2" timestamp="$3" utc_date="$4"
  local algo="TC3-HMAC-SHA256"
  local payload_hash="$(sha256_hex "$payload")"
  local canonical_request="POST\n/\n\ncontent-type:${CONTENT_TYPE}\nhost:${HOST}\nx-tc-action:$(echo "$action" | tr '[:upper:]' '[:lower:]')\n\ncontent-type;host;x-tc-action\n${payload_hash}"
  local hashed_request="$(sha256_hex "$canonical_request")"
  local scope="${utc_date}/${SERVICE}/tc3_request"
  local string_to_sign="${algo}\n${timestamp}\n${scope}\n${hashed_request}"

  local sdate="$(hmac_sha256 "key:TC3${SECRET_KEY}" "$utc_date")"
  local sservice="$(hmac_sha256 "hexkey:${sdate}" "$SERVICE")"
  local ssigning="$(hmac_sha256 "hexkey:${sservice}" "tc3_request")"
  local signature="$(hmac_sha256 "hexkey:${ssigning}" "$string_to_sign")"

  debug "Action=$action CanonicalRequest=$canonical_request Signature=$signature"

  printf '%s' "${algo} Credential=${SECRET_ID}/${scope}, SignedHeaders=content-type;host;x-tc-action, Signature=${signature}"
}

# ---------- 腾讯云 API ----------
tc_api() {
  local action="$1" payload="$2"
  local timestamp="$(date +%s)"
  local utc_date="$(date -u +%F)"
  local authorization="$(build_authorization "$action" "$payload" "$timestamp" "$utc_date")"

  local response
  response="$(curl -fsS --connect-timeout 3 --max-time 10 \
    -X POST "https://${HOST}/" \
    -H "Authorization: ${authorization}" \
    -H "Content-Type: ${CONTENT_TYPE}" \
    -H "Host: ${HOST}" \
    -H "X-TC-Action: ${action}" \
    -H "X-TC-Timestamp: ${timestamp}" \
    -H "X-TC-Version: ${VERSION}" \
    -d "$payload")" || {
    log "API 调用失败: ${action}"
    return 1
  }

  debug "Response(${action})=$response"

  if echo "$response" | jq -e '.Response.Error' >/dev/null 2>&1; then
    log "API 错误: ${action} Code=$(echo "$response" | jq -r '.Response.Error.Code') Message=$(echo "$response" | jq -r '.Response.Error.Message')"
    return 1
  fi
  printf '%s' "$response"
}

# ---------- DNS 记录操作 ----------
get_target_record() {
  local sub_domain="$1" wanted_line="$2" wanted_remark="$3"
  local payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg sub "$sub_domain" \
    --arg type "$RECORD_TYPE" \
    --arg line "$wanted_line" \
    '{Domain:$domain,Subdomain:$sub,RecordType:$type,RecordLine:$line,Limit:100}')"

  local response
  response="$(tc_api "DescribeRecordList" "$payload")" || return 1

  printf '%s' "$response" | jq -c --arg remark "$wanted_remark" '
    (.Response.RecordList // []) as $list |
    ($list | map(select(.Remark == $remark))[0]) // ($list[0]) // empty
  '
}

create_record() {
  local sub_domain="$1" full_domain="$2" wanted_line="$3" wanted_remark="$4" ip="$5"
  local payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg sub "$sub_domain" \
    --arg type "$RECORD_TYPE" \
    --arg line "$wanted_line" \
    --arg value "$ip" \
    --arg remark "$wanted_remark" \
    '{Domain:$domain,SubDomain:$sub,RecordType:$type,RecordLine:$line,Value:$value,Remark:$remark,Status:"ENABLE"}')"

  local response record_id
  response="$(tc_api "CreateRecord" "$payload")" || return 1
  record_id="$(printf '%s' "$response" | jq -r '.Response.RecordId')"
  log "已创建记录: ${full_domain} [${wanted_line}] -> ${ip} (RecordId=${record_id})"
}

modify_dynamic_dns() {
  local sub_domain="$1" full_domain="$2" wanted_line="$3" record_id="$4" ip="$5"
  local payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg sub "$sub_domain" \
    --arg line "$wanted_line" \
    --arg value "$ip" \
    --argjson record_id "$record_id" \
    '{Domain:$domain,SubDomain:$sub,RecordId:$record_id,RecordLine:$line,Value:$value}')"

  tc_api "ModifyDynamicDNS" "$payload" >/dev/null || return 1
  log "DDNS 更新成功: ${full_domain} [${wanted_line}] -> ${ip} (RecordId=${record_id})"
}

modify_record_remark() {
  local record_id="$1" wanted_remark="$2"
  local payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg remark "$wanted_remark" \
    --argjson record_id "$record_id" \
    '{Domain:$domain,RecordId:$record_id,Remark:$remark}')"

  tc_api "ModifyRecordRemark" "$payload" >/dev/null || return 1
  log "已同步记录备注: ${wanted_remark} (RecordId=${record_id})"
}

sync_tencent_dns_record() {
  local sub_domain="$1" full_domain="$2" wanted_line="$3" wanted_remark="$4" current_ip="$5"
  local record_json record_id record_value current_remark

  record_json="$(get_target_record "$sub_domain" "$wanted_line" "$wanted_remark")" || return 1

  if [ -z "$record_json" ] || [ "$record_json" = "null" ]; then
    log "未找到 ${full_domain} [${wanted_line}] 的 A 记录，准备创建"
    create_record "$sub_domain" "$full_domain" "$wanted_line" "$wanted_remark" "$current_ip" || return 1
    return 0
  fi

  record_id="$(printf '%s' "$record_json" | jq -r '.RecordId // empty')"
  record_value="$(printf '%s' "$record_json" | jq -r '.Value // ""')"
  current_remark="$(printf '%s' "$record_json" | jq -r '.Remark // ""')"

  [ -n "$record_id" ] || { log "现有记录缺少 RecordId: ${full_domain}"; return 1; }

  if [ "$record_value" != "$current_ip" ]; then
    log "检测到 IP 变化: ${full_domain} | ${record_value:-<空>} -> ${current_ip}"
    modify_dynamic_dns "$sub_domain" "$full_domain" "$wanted_line" "$record_id" "$current_ip" || return 1
  else
    log "IP 未变化: ${full_domain} -> ${current_ip}，无需更新"
  fi

  if [ "$current_remark" != "$wanted_remark" ]; then
    modify_record_remark "$record_id" "$wanted_remark" || return 1
  fi
}

sync_tencent_dns() {
  local current_ip="$1"
  sync_tencent_dns_record "$SUB_DOMAIN" "$FULL_DOMAIN" "$RECORD_LINE" "$RECORD_REMARK" "$current_ip" || return 1
  sync_tencent_dns_record "$SUB_DOMAIN_2" "$FULL_DOMAIN_2" "$RECORD_LINE_2" "$RECORD_REMARK_2" "$current_ip" || return 1
}

validate_config() {
  local missing=() v
  for v in SECRET_ID SECRET_KEY DOMAIN SUB_DOMAIN RECORD_TYPE RECORD_LINE RECORD_REMARK SUB_DOMAIN_2 RECORD_LINE_2 RECORD_REMARK_2; do
    [ -n "${!v:-}" ] || missing+=("$v")
  done
  if [ "${#missing[@]}" -gt 0 ]; then
    log "配置缺失: ${missing[*]}"
    return 1
  fi
  if [[ "${SECRET_ID}" == REPLACE_WITH_* ]] || [[ "${SECRET_KEY}" == REPLACE_WITH_* ]]; then
    log "请先将 SECRET_ID / SECRET_KEY 改成你自己的腾讯云密钥"
    return 1
  fi
}

# ---------- DDNS 单次执行 ----------
do_ddns_once() {
  local current_ip
  log "=========================================="
  log "开始执行 DDNS 同步"
  log "目标1: ${FULL_DOMAIN} | 线路: ${RECORD_LINE} | 备注: ${RECORD_REMARK}"
  log "目标2: ${FULL_DOMAIN_2} | 线路: ${RECORD_LINE_2} | 备注: ${RECORD_REMARK_2}"
  validate_config || return 1
  current_ip="$(get_local_ipv4)" || return 1
  log "当前公网 IPv4: ${current_ip}"
  sync_tencent_dns "$current_ip" || return 1
  log "DDNS 同步完成"
}

# ---------- 进程管理 ----------
pid_is_running() { [[ "${1:-}" =~ ^[0-9]+$ ]] && kill -0 "$1" 2>/dev/null; }

pid_matches_daemon() {
  local pid="${1:-}" cmdline=""
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [ -r "/proc/${pid}/cmdline" ] || return 1
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  [[ "$cmdline" == *"${DAEMON_MARK}"* ]]
}

collect_existing_pids() {
  {
    if [ -f "$PID_FILE" ]; then
      local pid_from_file="$(cat "$PID_FILE" 2>/dev/null || true)"
      if [ "$pid_from_file" != "$$" ] && pid_is_running "$pid_from_file" && pid_matches_daemon "$pid_from_file"; then
        echo "$pid_from_file"
      fi
    fi
    for proc in /proc/[0-9]*; do
      [ -r "$proc/cmdline" ] || continue
      local pid="${proc##*/}"
      [ "$pid" = "$$" ] && continue
      pid_is_running "$pid" && pid_matches_daemon "$pid" && echo "$pid"
    done
  } | awk '!seen[$0]++'
}

count_existing_pids() {
  collect_existing_pids | awk 'NF {count++} END {print count+0}'
}

is_service_running() {
  local pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  [ -n "$pid" ] && pid_is_running "$pid" && pid_matches_daemon "$pid"
}

wait_pid_exit() {
  local pid="$1" waited=0 timeout="${2:-10}"
  while pid_is_running "$pid" && [ "$waited" -lt "$timeout" ]; do
    sleep 0.5
    waited=$((waited + 1))
  done
  ! pid_is_running "$pid"
}

stop_existing_daemons() {
  local pids pid
  pids="$(collect_existing_pids)"
  [ -n "$pids" ] || { rm -f "$PID_FILE" "$LOCK_FILE"; return 0; }
  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    pid_is_running "$pid" || continue
    kill "$pid" 2>/dev/null || true
    wait_pid_exit "$pid" 8 || { kill -9 "$pid" 2>/dev/null || true; wait_pid_exit "$pid" 2 || true; }
  done <<< "$pids"
  rm -f "$PID_FILE" "$LOCK_FILE"
}

# ---------- 单次安全执行（默认入口） ----------
run_once_safely() {
  ensure_log_dir
  ensure_dependencies || return 1
  do_ddns_once
}

# ---------- 后台守护 ----------
daemon_cleanup() {
  rm -f "$PID_FILE" "$LOCK_FILE" "$STARTED_AT_FILE"
}

run_daemon() {
  ensure_log_dir
  ensure_dependencies || { log "依赖检查失败，守护进程退出"; exit 1; }

  exec 200>"$LOCK_FILE"
  if ! flock -n 200; then
    log "已有后台进程在运行，当前进程退出"
    exit 0
  fi

  if is_service_running; then
    local existing_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing_pid" ] && [ "$existing_pid" != "$$" ] && pid_is_running "$existing_pid"; then
      log "检测到已有后台进程 (PID=${existing_pid})，当前进程退出"
      exit 0
    fi
  fi

  echo $$ > "$PID_FILE"
  date '+%F %T' > "$STARTED_AT_FILE"
  trap 'log "后台 DDNS 已停止"; daemon_cleanup; exit 0' SIGTERM SIGINT SIGHUP
  trap 'daemon_cleanup' EXIT

  log "=========================================="
  log "DDNS 后台服务已启动"
  log "实例: ${INSTANCE_NAME}"
  log "域名1: ${FULL_DOMAIN} | ${RECORD_LINE} | ${RECORD_REMARK}"
  log "域名2: ${FULL_DOMAIN_2} | ${RECORD_LINE_2} | ${RECORD_REMARK_2}"
  log "间隔: ${CHECK_INTERVAL}s | 日志: ${LOG_FILE}"
  log "PID: $$"
  log "=========================================="

  local round=0
  while true; do
    round=$((round + 1))
    log "---------- 第 ${round} 次检测 ----------"
    do_ddns_once && log "---------- 第 ${round} 次完成 ----------" \
                  || log "---------- 第 ${round} 次失败 ----------"
    sleep "$CHECK_INTERVAL" &
    wait $! 2>/dev/null || true
  done
}

# ---------- systemd 服务 ----------
write_systemd_unit() {
  cat > "${SYSTEMD_SERVICE_PATH}" <<EOF
[Unit]
Description=DNSPod DDNS (${INSTANCE_NAME})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/env bash "${SCRIPT_PATH}" --daemon "${DAEMON_MARK}"
ExecStop=/usr/bin/env bash "${SCRIPT_PATH}" stop
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF
}

install_autostart() {
  [ "$(id -u)" -ne 0 ] && { echo "install 需要 root 权限"; return 1; }
  ensure_dependencies || return 1
  chmod +x "${SCRIPT_PATH}" 2>/dev/null || true
  write_systemd_unit || { echo "写入 systemd 服务文件失败"; return 1; }
  systemctl daemon-reload
  systemctl enable --now "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1 || {
    echo "systemctl enable --now 失败"; return 1
  }
  systemctl is-active --quiet "${SYSTEMD_SERVICE_NAME}" && \
    echo "已安装开机自启并启动: ${SYSTEMD_SERVICE_NAME}" || \
    { echo "服务未成功启动"; systemctl status "${SYSTEMD_SERVICE_NAME}" --no-pager -l || true; return 1; }
}

uninstall_autostart() {
  [ "$(id -u)" -ne 0 ] && { echo "uninstall 需要 root 权限"; return 1; }
  systemctl stop "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1 || true
  systemctl disable "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1 || true
  rm -f "${SYSTEMD_SERVICE_PATH}"
  systemctl daemon-reload
  echo "已卸载开机自启"
}

# ---------- 日志查看 ----------
show_logs() {
  ensure_log_dir
  [ -f "$LOG_FILE" ] || { echo "日志不存在: ${LOG_FILE}"; return 1; }
  echo "========== 最近 80 行日志 =========="
  tail -n 80 "$LOG_FILE"
  echo "===================================="
}

follow_logs() {
  ensure_log_dir
  [ -f "$LOG_FILE" ] || { echo "日志不存在: ${LOG_FILE}"; return 1; }
  echo "按 Ctrl+C 退出实时日志"
  tail -n 50 -F "$LOG_FILE"
}

# ---------- 状态显示 ----------
show_status() {
  local pid started_at runtime memory existing_count
  existing_count="$(count_existing_pids)"
  echo "脚本: ${SCRIPT_PATH}"
  echo "实例: ${INSTANCE_NAME}"
  echo "域名1: ${FULL_DOMAIN} | 线路: ${RECORD_LINE} | 备注: ${RECORD_REMARK}"
  echo "域名2: ${FULL_DOMAIN_2} | 线路: ${RECORD_LINE_2} | 备注: ${RECORD_REMARK_2}"
  echo "间隔: ${CHECK_INTERVAL}s | 日志: ${LOG_FILE}"
  echo "systemd: ${SYSTEMD_SERVICE_NAME}"

  if is_service_running; then
    pid="$(cat "$PID_FILE")"
    started_at="$(cat "$STARTED_AT_FILE" 2>/dev/null || true)"
    echo "状态: 运行中"
    echo "PID : ${pid}"
    [ -n "$started_at" ] && echo "启动: ${started_at}"
    if command -v ps >/dev/null 2>&1; then
      runtime="$(ps -p "$pid" -o etime= 2>/dev/null | sed 's/^ *//' || true)"
      memory="$(ps -p "$pid" -o rss= 2>/dev/null | awk '{if ($1 != "") printf "%.1fMB", $1/1024}' || true)"
      [ -n "$runtime" ] && echo "运行: ${runtime}"
      [ -n "$memory" ] && echo "内存: ${memory}"
    fi
  else
    echo "状态: 已停止"
    rm -f "$STARTED_AT_FILE"
  fi

  if command -v systemctl >/dev/null 2>&1; then
    if systemctl is-enabled "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1; then
      echo "开机自启: 已启用"
      systemctl is-active "${SYSTEMD_SERVICE_NAME}" >/dev/null 2>&1 && \
        echo "systemd状态: active" || echo "systemd状态: inactive"
    else
      echo "开机自启: 未启用"
    fi
  fi

  [ "${existing_count}" -gt 1 ] 2>/dev/null && echo "告警: 检测到重复后台进程 (${existing_count} 个)"
}

# ---------- 菜单 ----------
show_menu_screen() {
  clear 2>/dev/null || printf '\033c'
  echo "============================================"
  echo "     腾讯云 DDNS 管理面板 (${INSTANCE_NAME})"
  echo "============================================"
  show_status
  echo "============================================"
  echo "  1. 启动后台 DDNS"
  echo "  2. 停止后台 DDNS"
  echo "  3. 重启后台 DDNS"
  echo "  4. 查看最近日志"
  echo "  5. 实时日志"
  echo "  6. 立即执行一次 DDNS"
  echo "  7. 安装开机自启"
  echo "  8. 卸载开机自启"
  echo "  0. 退出"
  echo "============================================"
}

run_menu() {
  ensure_dependencies || { echo "依赖检查失败"; return 1; }
  while true; do
    show_menu_screen
    read -rp "请选择 [0-8]: " choice
    case "$choice" in
      1) echo; start_service ;;
      2) echo; stop_service ;;
      3) echo; restart_service ;;
      4) echo; show_logs ;;
      5) echo; follow_logs ;;
      6) echo; run_once_safely ;;
      7) echo; install_autostart ;;
      8) echo; uninstall_autostart ;;
      0) echo "退出管理面板"; return 0 ;;
      *) echo "无效选择" ;;
    esac
    echo
    read -rp "按回车继续..." _unused
  done
}

# ---------- 服务控制 ----------
start_service() {
  ensure_log_dir
  ensure_dependencies || return 1
  install_shortcut

  local existing_pids existing_count
  existing_pids="$(collect_existing_pids)"
  existing_count="$(echo "$existing_pids" | awk 'NF {count++} END {print count+0}')"

  if [ "$existing_count" -gt 1 ] 2>/dev/null; then
    echo "检测到重复进程，先清理..."
    stop_existing_daemons
    sleep 0.5
  elif is_service_running; then
    echo "后台 DDNS 已在运行 (PID: $(cat "$PID_FILE"))"
    return 0
  elif [ -n "$existing_pids" ]; then
    echo "检测到残留旧进程，先清理..."
    stop_existing_daemons
    sleep 0.5
  fi

  echo "启动后台 DDNS..."
  nohup bash "$SCRIPT_PATH" --daemon "$DAEMON_MARK" >/dev/null 2>&1 &
  sleep 1

  if is_service_running; then
    echo "启动成功 (PID: $(cat "$PID_FILE"))"
  else
    echo "启动失败，请检查日志: ${LOG_FILE}"
    return 1
  fi
}

stop_service() {
  local pids="$(collect_existing_pids)"
  if [ -z "$pids" ]; then
    echo "当前没有后台 DDNS 进程"
    rm -f "$PID_FILE" "$LOCK_FILE" "$STARTED_AT_FILE"
    return 0
  fi
  echo "停止后台 DDNS..."
  stop_existing_daemons
  rm -f "$STARTED_AT_FILE"
  echo "已停止"
}

restart_service() {
  stop_service
  sleep 0.5
  start_service
}

# ---------- 快捷命令 ----------
install_shortcut() {
  local dir="$(dirname "$SHORTCUT_PATH")"
  [ -n "$dir" ] && mkdir -p "$dir" 2>/dev/null && [ -w "$dir" ] || return 0
  local tmp="${SHORTCUT_PATH}.tmp.$$"
  cat > "$tmp" <<EOF
#!/usr/bin/env bash
if [ "\$#" -eq 0 ]; then
  exec bash "${SCRIPT_PATH}" menu
else
  exec bash "${SCRIPT_PATH}" "\$@"
fi
EOF
  chmod +x "$tmp" 2>/dev/null || true
  mv -f "$tmp" "$SHORTCUT_PATH" 2>/dev/null || rm -f "$tmp"
}

show_quick_commands() {
  [ -x "$SHORTCUT_PATH" ] || return 0
  echo "快捷命令: ${SHORTCUT_CMD} [start|stop|restart|status|logs|follow|once|install|uninstall]"
}

# ---------- 帮助 ----------
usage() {
  cat <<EOF
用法:
  bash ${SCRIPT_NAME}              立即执行一次 DDNS (默认, 1-2秒)
  bash ${SCRIPT_NAME} start        启动后台 DDNS
  bash ${SCRIPT_NAME} stop         停止后台 DDNS
  bash ${SCRIPT_NAME} restart      重启后台 DDNS
  bash ${SCRIPT_NAME} status       查看状态
  bash ${SCRIPT_NAME} logs         查看最近日志
  bash ${SCRIPT_NAME} follow       实时查看日志
  bash ${SCRIPT_NAME} once         立即执行一次 DDNS
  bash ${SCRIPT_NAME} menu         打开管理面板
  bash ${SCRIPT_NAME} install      安装 systemd 开机自启
  bash ${SCRIPT_NAME} uninstall    卸载 systemd 开机自启
EOF
}

# ---------- 主入口（关键变更：默认执行 once） ----------
main() {
  ensure_log_dir
  install_shortcut

  case "${1:-}" in
    --daemon)
      run_daemon
      ;;
    --once|once)
      run_once_safely
      ;;
    start)
      start_service
      ;;
    stop)
      stop_service
      ;;
    restart)
      restart_service
      ;;
    status)
      show_status
      ;;
    logs|log)
      show_logs
      ;;
    follow)
      follow_logs
      ;;
    menu|panel|ui)
      run_menu
      ;;
    install|enable)
      install_autostart
      ;;
    uninstall|disable)
      uninstall_autostart
      ;;
    "")
      # 关键变更：默认执行一次 DDNS，而非启动后台
      run_once_safely
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
