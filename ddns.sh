#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ---------- Cloudflare DDNS 配置 ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"   # 建议用环境变量注入
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"          # A / AAAA
CFTTL=120
PROXIED="${PROXIED:-false}" # "true" 或 "false"
FORCE=false
WANIPSITE="http://ipv4.icanhazip.com"

# ---------- 多 VPS 关键配置 ----------
VPS_ID="${VPS_ID:-$(hostname -s || echo vps)}"
STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"

# ---------- 连通性检测 ----------
TARGET_DOMAIN="email.163.com"
PING_COUNT=10
PING_GAP=3
CHECK_INTERVAL=30

if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="http://ipv6.icanhazip.com"
elif [ "$CF_RECORD_TYPE" != "A" ]; then
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA" >&2
  exit 2
fi

log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }

# 统一 Cloudflare API 调用：返回 "BODY|HTTP_CODE"
require_token() {
  if [ -z "${CF_API_TOKEN}" ] || [ "${CF_API_TOKEN}" = "REPLACE_WITH_TOKEN" ]; then
    log "❌ 缺少 CF_API_TOKEN，请通过环境变量提供：export CF_API_TOKEN=xxxxx"
    exit 2
  fi
}
_cf_api() {
  local method="$1" url="$2" data="${3:-}"
  require_token
  if [ -n "$data" ]; then
    curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "$data" \
      -w '|%{http_code}'
  else
    curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      -w '|%{http_code}'
  fi
}

api_get_zone_id() {
  log "查询 zone_id..."
  local out http body zid
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && { log "❌ 获取 zone 失败（HTTP ${http}）：$body"; return 1; }
  zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -z "$zid" ] && { log "❌ 未找到 zone_id"; return 1; }
  printf "%s" "$zid"
}

# 校验缓存的 record_id 是否仍存在
api_check_record_exists() {
  local zone_id="$1" record_id="$2"
  local out http body
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] && echo "$body" | grep -q '"success":true'
}

# 获取远端记录当前 IP（content）
api_get_record_ip() {
  local zone_id="$1" record_id="$2"
  local out http body rip
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && return 1
  rip=$(echo "$body" | grep -Po '(?<="content":")[^"]*' | head -1 || true)
  [ -z "$rip" ] && return 1
  printf "%s" "$rip"
}

# 创建专属记录（创建时就用真实公网 IP；失败回退到 0.0.0.0 / ::0）
api_create_own_record() {
  local zone_id="$1" resp http body rid ip fallback_ip
  fallback_ip=$([ "$CF_RECORD_TYPE" = "AAAA" ] && echo "::0" || echo "0.0.0.0")
  ip=$(curl -fsS "${WANIPSITE}" || echo "$fallback_ip")
  ip="${ip//$'\n'/}"; ip="${ip//$'\r'/}"
  log "未发现可用记录，为 VPS(${VPS_ID}) 创建专属记录（初始 IP=${ip}）..."

  local data
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  resp="$(_cf_api POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" "$data")"
  http="${resp##*|}"; body="${resp%|*}"
  if [ "$http" != "200" ] && [ "$http" != "201" ]; then
    log "❌ 创建记录失败（HTTP ${http}）：$body"
    return 1
  fi
  rid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -z "$rid" ] && { log "❌ 无法从返回中提取 record_id：$body"; return 1; }
  echo "$rid"
}

# 确保当前 VPS 的记录就绪：若缓存失效则重建
cf_ensure_record_ready() {
  local zone_id record_id
  zone_id="$(api_get_zone_id)" || return 1

  if [ -f "$ID_FILE" ]; then
    record_id="$(cat "$ID_FILE" || true)"
    if [ -n "$record_id" ] && api_check_record_exists "$zone_id" "$record_id"; then
      printf "%s|%s\n" "$zone_id" "$record_id"
      return 0
    else
      log "⚠️ 缓存的 record_id 不存在或无效，准备重新创建"
    fi
  fi

  record_id="$(api_create_own_record "$zone_id")" || return 1
  echo "$record_id" > "$ID_FILE"
  printf "%s|%s\n" "$zone_id" "$record_id"
}

# 仅更新必要字段（避免 400）：content / ttl / proxied
_cf_update_record() {
  local zone_id="$1" record_id="$2" ip="$3"
  local data resp http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  resp="$(_cf_api PATCH "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" "$data")"
  http="${resp##*|}"; body="${resp%|*}"
  echo "${http}|${body}"
}

cf_update_ddns() {
  local ids zone_id record_id
  ids="$(cf_ensure_record_ready)" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  # 本机 WAN IP
  local wan_ip old_ip
  wan_ip=$(curl -fsS "${WANIPSITE}" || true)
  [ -z "$wan_ip" ] && { log "❌ 无法获取公网 IP"; return 1; }
  wan_ip="${wan_ip//$'\n'/}"; wan_ip="${wan_ip//$'\r'/}"

  # 远端记录 IP（优先用它来避免不必要更新）
  local remote_ip
  remote_ip="$(api_get_record_ip "$zone_id" "$record_id" || true)"

  # 对齐本地缓存文件，避免因缓存缺失导致误判
  if [ -n "$remote_ip" ]; then
    echo "$remote_ip" > "$WAN_IP_FILE"
  fi

  [ -f "$WAN_IP_FILE" ] && old_ip="$(cat "$WAN_IP_FILE" || true)" || old_ip=""

  # 若远端已等于当前 WAN，则跳过更新
  if [ -n "$remote_ip" ] && [ "$remote_ip" = "$wan_ip" ]; then
    log "ℹ️ 云端记录已是当前 IP（$remote_ip），跳过更新"
    # 同步本地缓存
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  # 若本地缓存相等也跳过（双保险）
  if [ "$wan_ip" = "$old_ip" ]; then
    log "WAN IP 未改变（$wan_ip），且云端一致/已对齐，跳过更新"
    return 0
  fi

  log "准备更新（VPS=${VPS_ID}） ${CF_RECORD_NAME} -> ${wan_ip}  [record_id=${record_id}]"
  local out http body
  out="$(_cf_update_record "$zone_id" "$record_id" "$wan_ip")"
  http="${out%%|*}"; body="${out#*|}"

  if [ "$http" = "200" ]; then
    log "✅ 更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  log "❌ 更新失败（HTTP ${http}）：$body"
  log "🛠️ 自愈：重建记录并重试一次"
  record_id="$(api_create_own_record "$zone_id")" || { log "❌ 自愈创建失败"; return 1; }
  echo "$record_id" > "$ID_FILE"

  out="$(_cf_update_record "$zone_id" "$record_id" "$wan_ip")"
  http="${out%%|*}"; body="${out#*|}"
  if [ "$http" = "200" ]; then
    log "✅ 自愈后更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 自愈后仍失败（HTTP ${http}）：$body"
  fi
}

# ---------- 主循环 ----------
log "启动 DDNS 守护进程（多 VPS 友好：每台只维护自己的记录，互不影响）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

# 启动即确保记录存在，并先对齐缓存为云端值，避免误触发更新
cf_ensure_record_ready >/dev/null || true
# 读取一次远端并对齐本地缓存
{
  ids="$(cf_ensure_record_ready)" || exit 0
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"
  rip="$(api_get_record_ip "$zone_id" "$record_id" || true)"
  [ -n "$rip" ] && echo "$rip" > "$WAN_IP_FILE"
} || true

# 进入循环
while true; do
  if check_ip_reachable; then
    cf_update_ddns || true
  else
    change_ip
    sleep 10
    cf_update_ddns || true
  fi
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
