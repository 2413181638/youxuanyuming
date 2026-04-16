#!/usr/bin/env bash
#
# 腾讯云 DNSPod 双记录 DDNS 脚本（直接获取公网 IPv4）
# 默认运行即启动后台服务，避免重复进程。
#
# 用法：
#   bash txcfddns.sh           # 直接启动后台服务（若已运行则不重复启动）
#   bash txcfddns.sh start     # 启动后台服务
#   bash txcfddns.sh stop      # 停止后台服务
#   bash txcfddns.sh restart   # 重启后台服务
#   bash txcfddns.sh status    # 查看状态
#   bash txcfddns.sh logs      # 查看最近日志
#   bash txcfddns.sh follow    # 实时查看日志
#   bash txcfddns.sh once      # 立即执行一次 DDNS
#   bash txcfddns.sh menu      # 打开管理面板
#

set -u
set -o pipefail

# ========== 用户配置区 ==========
SECRET_ID="AKIDW6SZR5ZqsfEajfR1NXTChy1rUu64nMwQ"
SECRET_KEY="VN8h2CAxYu1sUr0xlIciaFguvxpUxFNL"

# 已不再使用外部 IP 查询，但保留原值，避免误删。
AWS_SB_SGT="4d48e86004924a0b9ce4a6c99816cee7"

# 腾讯云 DNSPod（AWS 日本专用实例）
INSTANCE_NAME="awsjp"
DOMAIN="woainiliz.com"
SUB_DOMAIN="hahajp"
FULL_DOMAIN="${SUB_DOMAIN}.${DOMAIN}"
RECORD_TYPE="A"
RECORD_LINE="联通"
RECORD_REMARK="awsjp"

# 你给的新配置里没有写 SUB_DOMAIN_2；这里按现有命名风格补成日本 DDNS 专用二级域名
SUB_DOMAIN_2="ajpwsddns"
FULL_DOMAIN_2="${SUB_DOMAIN_2}.${DOMAIN}"
RECORD_LINE_2="默认"
RECORD_REMARK_2="awsjpddns"

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

detect_pkg_manager() {
  if command -v apt-get >/dev/null 2>&1; then echo "apt"
  elif command -v yum >/dev/null 2>&1; then echo "yum"
  elif command -v dnf >/dev/null 2>&1; then echo "dnf"
  elif command -v apk >/dev/null 2>&1; then echo "apk"
  elif command -v pacman >/dev/null 2>&1; then echo "pacman"
  elif command -v zypper >/dev/null 2>&1; then echo "zypper"
  else echo "unknown"; fi
}

install_package() {
  local pkg="$1" mgr
  mgr="$(detect_pkg_manager)"
  log "[依赖] 安装 $pkg ($mgr)"
  case "$mgr" in
    apt)
      apt-get update -qq >/dev/null 2>&1 && \
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$pkg" >/dev/null 2>&1
      ;;
    yum) yum install -y -q "$pkg" >/dev/null 2>&1 ;;
    dnf) dnf install -y -q "$pkg" >/dev/null 2>&1 ;;
    apk) apk add --no-cache "$pkg" >/dev/null 2>&1 ;;
    pacman) pacman -Sy --noconfirm "$pkg" >/dev/null 2>&1 ;;
    zypper) zypper install -y "$pkg" >/dev/null 2>&1 ;;
    *)
      log "❌ 未知包管理器，无法自动安装 $pkg"
      return 1
      ;;
  esac
}

ensure_dependencies() {
  local missing=() need=false cmd pkg
  for cmd in curl jq openssl awk sed tr date od flock nohup; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      missing+=("$cmd")
      need=true
    fi
  done

  [ "$need" = false ] && return 0

  log "检测到缺少依赖：${missing[*]}"
  for cmd in "${missing[@]}"; do
    case "$cmd" in
      curl|jq|openssl) pkg="$cmd" ;;
      awk) pkg="gawk" ;;
      sed) pkg="sed" ;;
      tr|date|od|nohup) pkg="coreutils" ;;
      flock) pkg="util-linux" ;;
      *) pkg="$cmd" ;;
    esac
    install_package "$pkg" || {
      log "❌ 自动安装失败，请手动安装：${missing[*]}"
      exit 1
    }
  done

  for cmd in curl jq openssl awk sed tr date od flock nohup; do
    command -v "$cmd" >/dev/null 2>&1 || {
      log "❌ 依赖安装后仍缺少：$cmd"
      exit 1
    }
  done
}

random_suffix() {
  tr -dc 'a-z0-9' < /dev/urandom | head -c 13
}

is_ipv4() {
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS='.' part
  read -r -a octets <<< "$ip"
  for part in "${octets[@]}"; do
    [[ "$part" =~ ^[0-9]{1,3}$ ]] || return 1
    [ "$part" -ge 0 ] 2>/dev/null || return 1
    [ "$part" -le 255 ] 2>/dev/null || return 1
  done
  return 0
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
  local algorithm="TC3-HMAC-SHA256"
  local http_method="POST"
  local canonical_uri="/"
  local canonical_query_string=""
  local signed_headers="content-type;host;x-tc-action"
  local canonical_headers payload_hash canonical_request hashed_canonical_request credential_scope string_to_sign
  local secret_date secret_service secret_signing signature

  canonical_headers="content-type:${CONTENT_TYPE}
host:${HOST}
x-tc-action:$(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')
"

  payload_hash="$(sha256_hex "$payload")"
  canonical_request="$(printf '%s\n%s\n%s\n%s\n%s\n%s' \
    "$http_method" \
    "$canonical_uri" \
    "$canonical_query_string" \
    "$canonical_headers" \
    "$signed_headers" \
    "$payload_hash")"
  hashed_canonical_request="$(sha256_hex "$canonical_request")"
  credential_scope="${utc_date}/${SERVICE}/tc3_request"
  string_to_sign="$(printf '%s\n%s\n%s\n%s' \
    "$algorithm" \
    "$timestamp" \
    "$credential_scope" \
    "$hashed_canonical_request")"

  secret_date="$(hmac_sha256_hex_with_key "TC3${SECRET_KEY}" "$utc_date")"
  secret_service="$(hmac_sha256_hex_with_hexkey "$secret_date" "$SERVICE")"
  secret_signing="$(hmac_sha256_hex_with_hexkey "$secret_service" "tc3_request")"
  signature="$(hmac_sha256_hex_with_hexkey "$secret_signing" "$string_to_sign")"

  debug "Action=$action"
  debug "Payload=$payload"
  debug "CanonicalRequest=$canonical_request"
  debug "StringToSign=$string_to_sign"
  debug "Signature=$signature"

  printf '%s' "${algorithm} Credential=${SECRET_ID}/${credential_scope}, SignedHeaders=${signed_headers}, Signature=${signature}"
}

tc_api() {
  local action="$1" payload="$2"
  local timestamp utc_date authorization response

  timestamp="$(date +%s)"
  utc_date="$(date -u +%F)"
  authorization="$(build_authorization "$action" "$payload" "$timestamp" "$utc_date")"

  response="$(curl -fsS --connect-timeout 10 --max-time 30 \
    -X POST "https://${HOST}/" \
    -H "Authorization: ${authorization}" \
    -H "Content-Type: ${CONTENT_TYPE}" \
    -H "Host: ${HOST}" \
    -H "X-TC-Action: ${action}" \
    -H "X-TC-Timestamp: ${timestamp}" \
    -H "X-TC-Version: ${VERSION}" \
    -d "$payload")" || {
      log "❌ 调用腾讯云 API 失败：${action}"
      return 1
    }

  debug "Response(${action})=$response"

  if ! printf '%s' "$response" | jq -e '.' >/dev/null 2>&1; then
    log "❌ 腾讯云 API 返回不是合法 JSON：${action}"
    return 1
  fi

  if printf '%s' "$response" | jq -e '.Response.Error' >/dev/null 2>&1; then
    log "❌ 腾讯云 API 报错：${action}"
    log "   Code: $(printf '%s' "$response" | jq -r '.Response.Error.Code')"
    log "   Message: $(printf '%s' "$response" | jq -r '.Response.Error.Message')"
    log "   RequestId: $(printf '%s' "$response" | jq -r '.Response.RequestId // ""')"
    return 1
  fi

  printf '%s' "$response"
}


get_aws_metadata_public_ipv4() {
  local token="" ip=""

  token="$(curl -fsS --connect-timeout 2 --max-time 3 -X PUT \
    "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 21600" 2>/dev/null || true)"

  if [ -n "$token" ]; then
    ip="$(curl -fsS --connect-timeout 2 --max-time 3 \
      -H "X-aws-ec2-metadata-token: ${token}" \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  else
    ip="$(curl -fsS --connect-timeout 2 --max-time 3 \
      "http://169.254.169.254/latest/meta-data/public-ipv4" 2>/dev/null || true)"
  fi

  if [ -n "$ip" ] && is_ipv4 "$ip" && [[ ! "$ip" =~ ^127\. ]]; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
}

get_ip_from_ipip() {
  local raw ip
  raw="$(curl -fsS --connect-timeout 5 --max-time 10 "https://myip.ipip.net" 2>/dev/null || true)"
  ip="$(printf '%s' "$raw" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)"

  if [ -n "$ip" ] && is_ipv4 "$ip" && [[ ! "$ip" =~ ^127\. ]]; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
}

get_ip_from_ipify() {
  local ip
  ip="$(curl -fsS --connect-timeout 5 --max-time 10 "https://api.ipify.org" 2>/dev/null || true)"
  if [ -n "$ip" ] && is_ipv4 "$ip" && [[ ! "$ip" =~ ^127\. ]]; then
    printf '%s' "$ip"
    return 0
  fi
  return 1
}

get_local_ipv4() {
  local ip=""
  IP_SOURCE=""

  if ip="$(get_aws_metadata_public_ipv4)"; then
    IP_SOURCE="AWS Metadata public-ipv4"
    printf '%s' "$ip"
    return 0
  fi

  if ip="$(get_ip_from_ipip)"; then
    IP_SOURCE="ipip.net"
    printf '%s' "$ip"
    return 0
  fi

  if ip="$(get_ip_from_ipify)"; then
    IP_SOURCE="api.ipify.org"
    printf '%s' "$ip"
    return 0
  fi

  log "❌ 无法获取有效公网 IPv4（已尝试 AWS Metadata、ipip.net、ipify）"
  return 1
}

get_target_record() {
  local sub_domain="$1" wanted_line="$2" wanted_remark="$3"
  local payload response
  payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg sub "$sub_domain" \
    --arg type "$RECORD_TYPE" \
    --arg line "$wanted_line" \
    '{Domain:$domain,Subdomain:$sub,RecordType:$type,RecordLine:$line,Limit:3000,Offset:0,ErrorOnEmpty:"no"}')"

  response="$(tc_api "DescribeRecordList" "$payload")" || return 1

  printf '%s' "$response" | jq -c --arg remark "$wanted_remark" '
    (.Response.RecordList // []) as $list |
    ($list | map(select(.Remark == $remark))[0]) // ($list[0]) // empty
  '
}

create_record() {
  local sub_domain="$1" full_domain="$2" wanted_line="$3" wanted_remark="$4" ip="$5" payload response record_id
  payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg sub "$sub_domain" \
    --arg type "$RECORD_TYPE" \
    --arg line "$wanted_line" \
    --arg value "$ip" \
    --arg remark "$wanted_remark" \
    '{Domain:$domain,SubDomain:$sub,RecordType:$type,RecordLine:$line,Value:$value,Remark:$remark,Status:"ENABLE"}')"

  response="$(tc_api "CreateRecord" "$payload")" || return 1
  record_id="$(printf '%s' "$response" | jq -r '.Response.RecordId')"
  log "✅ 腾讯云已创建记录：${full_domain} [${wanted_line}] -> ${ip} (RecordId=${record_id})"
}

modify_dynamic_dns() {
  local sub_domain="$1" full_domain="$2" wanted_line="$3" record_id="$4" ip="$5" payload
  payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg sub "$sub_domain" \
    --arg line "$wanted_line" \
    --arg value "$ip" \
    --argjson record_id "$record_id" \
    '{Domain:$domain,SubDomain:$sub,RecordId:$record_id,RecordLine:$line,Value:$value}')"

  tc_api "ModifyDynamicDNS" "$payload" >/dev/null || return 1
  log "✅ 腾讯云 DDNS 更新成功：${full_domain} [${wanted_line}] -> ${ip} (RecordId=${record_id})"
}

modify_record_remark() {
  local record_id="$1" wanted_remark="$2" payload
  payload="$(jq -cn \
    --arg domain "$DOMAIN" \
    --arg remark "$wanted_remark" \
    --argjson record_id "$record_id" \
    '{Domain:$domain,RecordId:$record_id,Remark:$remark}')"

  tc_api "ModifyRecordRemark" "$payload" >/dev/null || return 1
  log "✅ 腾讯云已同步记录备注：${wanted_remark} (RecordId=${record_id})"
}

sync_tencent_dns_record() {
  local sub_domain="$1" full_domain="$2" wanted_line="$3" wanted_remark="$4" current_ip="$5"
  local record_json record_id record_value current_remark

  record_json="$(get_target_record "$sub_domain" "$wanted_line" "$wanted_remark")" || return 1

  if [ -z "$record_json" ] || [ "$record_json" = "null" ]; then
    log "ℹ️ 腾讯云未找到 ${full_domain} [${wanted_line}] 的 A 记录，准备创建"
    create_record "$sub_domain" "$full_domain" "$wanted_line" "$wanted_remark" "$current_ip" || return 1
    return 0
  fi

  record_id="$(printf '%s' "$record_json" | jq -r '.RecordId // empty')"
  record_value="$(printf '%s' "$record_json" | jq -r '.Value // ""')"
  current_remark="$(printf '%s' "$record_json" | jq -r '.Remark // ""')"

  [ -n "$record_id" ] || {
    log "❌ 腾讯云现有记录缺少 RecordId：${full_domain}"
    return 1
  }

  if [ "$record_value" != "$current_ip" ]; then
    log "ℹ️ 腾讯云检测到 IP 变化：${full_domain} | ${record_value:-<空>} -> ${current_ip}"
    modify_dynamic_dns "$sub_domain" "$full_domain" "$wanted_line" "$record_id" "$current_ip" || return 1
  else
    log "ℹ️ 腾讯云 IP 未变化：${full_domain} -> ${current_ip}，无需更新"
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
    if [ -z "${!v:-}" ]; then
      missing+=("$v")
    fi
  done

  if [ "${#missing[@]}" -gt 0 ]; then
    log "❌ 配置缺失：${missing[*]}"
    return 1
  fi
}

do_ddns_once() {
  local current_ip

  log "=========================================="
  log "开始执行 DDNS 同步"
  log "腾讯云目标1: ${FULL_DOMAIN} | 线路: ${RECORD_LINE} | 备注: ${RECORD_REMARK}"
  log "腾讯云目标2: ${FULL_DOMAIN_2} | 线路: ${RECORD_LINE_2} | 备注: ${RECORD_REMARK_2}"

  validate_config || return 1

  current_ip="$(get_local_ipv4)" || return 1
  log "当前公网 IPv4: ${current_ip} | 来源: ${IP_SOURCE:-unknown}"

  sync_tencent_dns "$current_ip" || return 1

  log "DDNS 同步完成"
}

pid_is_running() {
  local pid="${1:-}"
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  kill -0 "$pid" 2>/dev/null
}

pid_matches_daemon() {
  local pid="${1:-}" cmdline=""
  [[ "$pid" =~ ^[0-9]+$ ]] || return 1
  [ -r "/proc/${pid}/cmdline" ] || return 1
  cmdline="$(tr '\0' ' ' < "/proc/${pid}/cmdline" 2>/dev/null || true)"
  case "$cmdline" in
    *"${DAEMON_MARK}"*) return 0 ;;
    *) return 1 ;;
  esac
}

list_matching_daemon_pids() {
  local proc pid
  for proc in /proc/[0-9]*; do
    [ -r "$proc/cmdline" ] || continue
    pid="${proc##*/}"
    [ "$pid" = "$$" ] && continue
    if pid_is_running "$pid" && pid_matches_daemon "$pid"; then
      echo "$pid"
    fi
  done | awk '!seen[$0]++'
}

collect_existing_pids() {
  {
    if [ -f "$PID_FILE" ]; then
      local pid_from_file
      pid_from_file="$(cat "$PID_FILE" 2>/dev/null || true)"
      if pid_is_running "$pid_from_file" && pid_matches_daemon "$pid_from_file" && [ "$pid_from_file" != "$$" ]; then
        echo "$pid_from_file"
      fi
    fi
    list_matching_daemon_pids
  } | awk '!seen[$0]++'
}

count_existing_pids() {
  collect_existing_pids | awk 'NF {count++} END {print count+0}'
}

refresh_pid_file() {
  local pid any_pid
  pid="$(cat "$PID_FILE" 2>/dev/null || true)"
  if pid_is_running "$pid" && pid_matches_daemon "$pid"; then
    return 0
  fi

  any_pid="$(collect_existing_pids | sed -n '1p')"
  if pid_is_running "$any_pid" && pid_matches_daemon "$any_pid"; then
    echo "$any_pid" > "$PID_FILE"
    return 0
  fi

  rm -f "$PID_FILE" "$LOCK_FILE"
  return 1
}

wait_pid_exit() {
  local pid="$1" waited=0 timeout="${2:-10}"
  while pid_is_running "$pid" && [ "$waited" -lt "$timeout" ]; do
    sleep 1
    waited=$((waited + 1))
  done
  ! pid_is_running "$pid"
}

stop_existing_daemons() {
  local pids pid found=false
  pids="$(collect_existing_pids)"

  [ -n "$pids" ] || {
    rm -f "$PID_FILE" "$LOCK_FILE"
    return 0
  }

  while IFS= read -r pid; do
    [ -n "$pid" ] || continue
    found=true
    if pid_is_running "$pid"; then
      echo "停止旧进程: PID ${pid}"
      kill "$pid" 2>/dev/null || true
      if ! wait_pid_exit "$pid" 10; then
        echo "强制结束旧进程: PID ${pid}"
        kill -9 "$pid" 2>/dev/null || true
        wait_pid_exit "$pid" 3 || true
      fi
    fi
  done <<< "$pids"

  rm -f "$PID_FILE" "$LOCK_FILE"
  [ "$found" = true ] || true
}

is_service_running() {
  refresh_pid_file
}

show_status() {
  local pid started_at runtime memory existing_count
  existing_count="$(count_existing_pids)"
  echo "脚本: ${SCRIPT_PATH}"
  echo "腾讯云域名1: ${FULL_DOMAIN} | 线路: ${RECORD_LINE} | 备注: ${RECORD_REMARK}"
  echo "腾讯云域名2: ${FULL_DOMAIN_2} | 线路: ${RECORD_LINE_2} | 备注: ${RECORD_REMARK_2}"
  echo "间隔: ${CHECK_INTERVAL}s"
  echo "日志: ${LOG_FILE}"

  if is_service_running; then
    pid="$(cat "$PID_FILE")"
    started_at="$(cat "$STARTED_AT_FILE" 2>/dev/null || true)"
    echo "状态: 🟢 运行中"
    echo "PID : ${pid}"
    [ -n "$started_at" ] && echo "启动: ${started_at}"
    if command -v ps >/dev/null 2>&1; then
      runtime="$(ps -p "$pid" -o etime= 2>/dev/null | sed 's/^ *//' || true)"
      memory="$(ps -p "$pid" -o rss= 2>/dev/null | awk '{if ($1 != "") printf "%.1fMB", $1/1024}' || true)"
      [ -n "$runtime" ] && echo "运行: ${runtime}"
      [ -n "$memory" ] && echo "内存: ${memory}"
    fi
  else
    echo "状态: 🔴 已停止"
    rm -f "$STARTED_AT_FILE"
  fi

  if [ "${existing_count}" -gt 1 ] 2>/dev/null; then
    echo "告警: ⚠️ 检测到重复后台进程 (${existing_count} 个)"
  fi
}

show_logs() {
  ensure_log_dir
  touch "$LOG_FILE" 2>/dev/null || true
  [ -f "$LOG_FILE" ] || {
    echo "日志不存在：${LOG_FILE}"
    return 1
  }
  echo "========== 最近 80 行日志 =========="
  tail -n 80 "$LOG_FILE"
  echo "===================================="
}

follow_logs() {
  ensure_log_dir
  touch "$LOG_FILE" 2>/dev/null || true
  [ -f "$LOG_FILE" ] || {
    echo "日志不存在：${LOG_FILE}"
    return 1
  }
  echo "按 Ctrl+C 退出实时日志"
  tail -n 50 -F "$LOG_FILE"
}

run_once_safely() {
  ensure_log_dir
  ensure_dependencies

  if is_service_running; then
    echo "后台 DDNS 正在运行，为避免叠加，本次单次执行已拒绝。"
    echo "请先停止后台服务后再执行一次性同步。"
    return 1
  fi

  do_ddns_once
}

daemon_cleanup() {
  rm -f "$PID_FILE" "$LOCK_FILE" "$STARTED_AT_FILE"
}

run_daemon() {
  ensure_log_dir
  ensure_dependencies

  exec 200>"$LOCK_FILE"
  if ! flock -n 200; then
    log "⚠️ 已有后台进程在运行，当前进程退出，避免叠加"
    exit 0
  fi

  if is_service_running; then
    local existing_pid
    existing_pid="$(cat "$PID_FILE" 2>/dev/null || true)"
    if [ -n "$existing_pid" ] && [ "$existing_pid" != "$$" ] && pid_is_running "$existing_pid"; then
      log "⚠️ 检测到已有后台进程在运行 (PID=${existing_pid})，当前进程退出，避免叠加"
      exit 0
    fi
  fi

  echo $$ > "$PID_FILE"
  date '+%F %T' > "$STARTED_AT_FILE"
  trap 'log "收到退出信号，后台 DDNS 已停止"; daemon_cleanup; exit 0' SIGTERM SIGINT SIGHUP
  trap 'daemon_cleanup' EXIT

  log "=========================================="
  log "腾讯云双记录 DDNS 后台服务已启动"
  log "腾讯云域名1: ${FULL_DOMAIN} | 线路: ${RECORD_LINE} | 备注: ${RECORD_REMARK}"
  log "腾讯云域名2: ${FULL_DOMAIN_2} | 线路: ${RECORD_LINE_2} | 备注: ${RECORD_REMARK_2}"
  log "检测间隔: ${CHECK_INTERVAL}s"
  log "日志文件: ${LOG_FILE}"
  log "获取 IP 方式: 公网 IPv4（优先 AWS Metadata，其次 ipip.net / ipify）"
  log "PID: $$"
  log "=========================================="

  local round=0
  while true; do
    round=$((round + 1))
    log "---------- 第 ${round} 次检测开始 ----------"
    do_ddns_once && log "---------- 第 ${round} 次检测完成 ----------" \
                  || log "---------- 第 ${round} 次检测失败 ----------"
    sleep "$CHECK_INTERVAL" &
    wait $! 2>/dev/null || true
  done
}

start_service() {
  ensure_log_dir
  ensure_dependencies
  install_shortcut_quietly

  local existing_pids existing_count
  existing_pids="$(collect_existing_pids)"
  existing_count="$(printf '%s\n' "$existing_pids" | awk 'NF {count++} END {print count+0}')"

  if [ "$existing_count" -gt 1 ] 2>/dev/null; then
    echo "检测到重复后台进程，先清理后再启动..."
    stop_existing_daemons
    sleep 1
  elif is_service_running; then
    touch "$LOG_FILE" 2>/dev/null || true
    echo "✅ 后台 DDNS 已在运行"
    echo "PID : $(cat "$PID_FILE")"
    echo "日志: ${LOG_FILE}"
    show_quick_commands
    return 0
  elif [ -n "$existing_pids" ]; then
    echo "检测到残留旧进程，先清理..."
    stop_existing_daemons
    sleep 1
  fi

  touch "$LOG_FILE" 2>/dev/null || true
  echo "启动后台 DDNS 中..."
  nohup bash "$SCRIPT_PATH" --daemon "$DAEMON_MARK" >/dev/null 2>&1 &
  sleep 2

  if is_service_running; then
    touch "$LOG_FILE" 2>/dev/null || true
    echo "✅ 启动成功"
    echo "PID : $(cat "$PID_FILE")"
    echo "日志: ${LOG_FILE}"
    show_quick_commands
  else
    echo "❌ 启动失败，请检查日志：${LOG_FILE}"
    return 1
  fi
}

stop_service() {
  local pids
  pids="$(collect_existing_pids)"

  if [ -z "$pids" ]; then
    echo "当前没有后台 DDNS 进程"
    rm -f "$PID_FILE" "$LOCK_FILE" "$STARTED_AT_FILE"
    return 0
  fi

  echo "停止后台 DDNS 中..."
  stop_existing_daemons
  rm -f "$STARTED_AT_FILE"
  echo "✅ 已停止"
}

restart_service() {
  stop_service
  sleep 1
  start_service
}

show_menu_screen() {
  if command -v clear >/dev/null 2>&1; then
    clear
  else
    printf '\033c'
  fi

  echo "╔══════════════════════════════════════════════╗"
  echo "║      腾讯云双记录 DDNS 管理面板      ║"
  echo "╠══════════════════════════════════════════════╣"
  show_status
  echo "╠══════════════════════════════════════════════╣"
  echo "║  1. 启动后台 DDNS                           ║"
  echo "║  2. 停止后台 DDNS                           ║"
  echo "║  3. 重启后台 DDNS                           ║"
  echo "║  4. 查看最近日志                            ║"
  echo "║  5. 实时日志                                ║"
  echo "║  6. 立即执行一次 DDNS                       ║"
  echo "║  0. 退出                                    ║"
  echo "╚══════════════════════════════════════════════╝"
}

run_menu() {
  ensure_dependencies
  while true; do
    show_menu_screen
    read -rp "请选择 [0-6]: " choice
    case "$choice" in
      1)
        echo
        start_service
        ;;
      2)
        echo
        stop_service
        ;;
      3)
        echo
        restart_service
        ;;
      4)
        echo
        show_logs
        ;;
      5)
        echo
        follow_logs
        ;;
      6)
        echo
        run_once_safely
        ;;
      0)
        echo
        echo "退出管理面板"
        return 0
        ;;
      *)
        echo
        echo "无效选择，请重新输入"
        ;;
    esac
    echo
    read -rp "按回车继续..." _unused
  done
}


show_quick_commands() {
  echo "快捷命令:"
  if [ -x "$SHORTCUT_PATH" ]; then
    echo "  ${SHORTCUT_CMD}           打开管理面板"
    echo "  ${SHORTCUT_CMD} start     启动后台"
    echo "  ${SHORTCUT_CMD} stop      停止后台"
    echo "  ${SHORTCUT_CMD} restart   重启后台"
    echo "  ${SHORTCUT_CMD} status    查看状态"
    echo "  ${SHORTCUT_CMD} logs      查看日志"
    echo "  ${SHORTCUT_CMD} follow    实时日志"
    echo "  ${SHORTCUT_CMD} once      立即执行一次 DDNS"
  fi
  echo "  bash ${SCRIPT_PATH} menu   打开管理面板"
}

install_shortcut_quietly() {
  local dir target tmp
  dir="$(dirname "$SHORTCUT_PATH")"
  [ -n "$dir" ] || return 0
  mkdir -p "$dir" 2>/dev/null || return 0
  [ -w "$dir" ] || return 0

  tmp="${SHORTCUT_PATH}.tmp.$$"
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

usage() {
  cat <<USAGE
用法：
  bash ${SCRIPT_NAME}             直接启动后台 DDNS（若已运行则不重复启动）
  bash ${SCRIPT_NAME} start       启动后台 DDNS
  bash ${SCRIPT_NAME} stop        停止后台 DDNS
  bash ${SCRIPT_NAME} restart     重启后台 DDNS
  bash ${SCRIPT_NAME} status      查看状态
  bash ${SCRIPT_NAME} logs        查看最近日志
  bash ${SCRIPT_NAME} follow      实时查看日志
  bash ${SCRIPT_NAME} once        立即执行一次 DDNS
  bash ${SCRIPT_NAME} menu        打开管理面板
  bash ${SCRIPT_NAME} panel       打开管理面板

快捷方式：
  txcfddns                        打开管理面板
  txcfddns start|stop|restart
  txcfddns status|logs|follow|once
USAGE
}

main() {
  ensure_log_dir
  install_shortcut_quietly

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
    "")
      start_service
      ;;
    *)
      usage
      exit 1
      ;;
  esac
}

main "$@"
