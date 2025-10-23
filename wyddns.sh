#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ---------- Cloudflare DDNS 配置 ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"  # 建议用环境变量注入
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="wyddns.5653111.xyz"
CF_RECORD_TYPE="A"          # A / AAAA
CFTTL=120
PROXIED="${PROXIED:-false}" # true/false（不加引号进 JSON）
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
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA"
  exit 2
fi

# 打印到 stderr，避免污染命令替换输出
log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }

check_ip_reachable() {
  log "🔍 检测当前公网IP是否能访问 ${TARGET_DOMAIN}..."
  local ok=false
  for ((i=1;i<=PING_COUNT;i++)); do
    if ping -c 1 -W 3 "$TARGET_DOMAIN" >/dev/null 2>&1; then
      log "✅ 第 ${i}/${PING_COUNT} 次 ping 成功 —— 网络正常"
      ok=true
      break
    else
      log "⚠️ 第 ${i}/${PING_COUNT} 次 ping 失败"
      if [ $i -lt $PING_COUNT ]; then
        sleep "$PING_GAP"
      fi
    fi
  done
  $ok
}

change_ip() {
  log "🚀 尝试更换 IP via curl 192.168.10.253 ..."
  curl -fsS 192.168.10.253 >/dev/null 2>&1 || log "⚠️ curl 请求失败（可能是局域网接口未响应）"
  sleep 10
  log "📶 已触发更换 IP"
}

# ---------- Cloudflare API ----------
require_token() {
  if [ -z "${CF_API_TOKEN}" ] || [ "${CF_API_TOKEN}" = "REPLACE_WITH_TOKEN" ]; then
    log "❌ 缺少 CF_API_TOKEN，请通过环境变量提供：export CF_API_TOKEN=xxxxx"
    exit 2
  fi
}

api_get_zone_id() {
  require_token
  log "查询 zone_id..."
  local zid
  zid=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
  [ -z "$zid" ] && { log "未找到 zone_id"; return 1; }
  printf "%s" "$zid"
}

# 校验缓存的 record_id 是否仍存在
api_check_record_exists() {
  local zone_id="$1" record_id="$2"
  curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    | grep -q '"success":true'
}

# 创建专属记录（创建时就用真实公网 IP；如取 IP 失败则回退到 0.0.0.0 / ::0）
api_create_own_record() {
  local zone_id="$1"

  # 先取当前公网 IP，尽量避免出现 0.0.0.0
  local current_ip fallback_ip
  if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
    fallback_ip="::0"
  else
    fallback_ip="0.0.0.0"
  fi
  current_ip=$(curl -fsS "${WANIPSITE}" || echo "$fallback_ip")
  # 去掉可能的换行符
  current_ip="${current_ip//$'\n'/}"
  current_ip="${current_ip//$'\r'/}"

  log "未发现可用记录，为 VPS(${VPS_ID}) 创建专属记录（初始 IP=${current_ip}）..."
  local resp rid
  resp=$(curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${current_ip}\",\"ttl\":${CFTTL},\"proxied\":${PROXIED},\"comment\":\"ddns:${VPS_ID}\"}") || true

  rid=$(echo "$resp" | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
  if [ -z "$rid" ]; then
    log "❌ 创建记录失败：$resp"
    return 1
  fi
  echo "$rid"
}

# 确保当前 VPS 的记录就绪：若缓存失效则重建
cf_ensure_record_ready() {
  local zone_id record_id
  zone_id="$(api_get_zone_id)" || return 1

  # 1) 有缓存 -> 校验是否仍存在
  if [ -f "$ID_FILE" ]; then
    record_id="$(cat "$ID_FILE" || true)"
    if [ -n "$record_id" ] && api_check_record_exists "$zone_id" "$record_id"; then
      printf "%s|%s" "$zone_id" "$record_id"
      return 0
    else
      log "⚠️ 缓存的 record_id 不存在或无效，准备重新创建"
    fi
  fi

  # 2) 无缓存或失效 -> 直接创建专属记录（创建时即写真实 IP）
  record_id="$(api_create_own_record "$zone_id")" || return 1
  echo "$record_id" > "$ID_FILE"
  printf "%s|%s" "$zone_id" "$record_id"
}

cf_update_ddns() {
  local force_flag="${1:-false}"

  # ☆ 先确保记录存在（即使 IP 没变也不跳过这一过程）
  local ids zone_id record_id
  ids="$(cf_ensure_record_ready)" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  # 再决定要不要更新 IP
  local wan_ip old_ip resp
  wan_ip=$(curl -fsS "${WANIPSITE}" || true)
  [ -z "$wan_ip" ] && { log "❌ 无法获取公网 IP"; return 1; }
  wan_ip="${wan_ip//$'\n'/}"
  wan_ip="${wan_ip//$'\r'/}"

  old_ip=""
  [ -f "$WAN_IP_FILE" ] && old_ip=$(cat "$WAN_IP_FILE" || true)
  if [ "$wan_ip" = "$old_ip" ] && [ "$FORCE" = false ] && [ "$force_flag" = false ]; then
    log "WAN IP 未改变（$wan_ip），跳过更新（但记录已确保存在）"
    return 0
  fi

  log "准备更新（VPS=${VPS_ID}） ${CF_RECORD_NAME} -> ${wan_ip}  [record_id=${record_id}]"
  resp=$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${wan_ip}\",\"ttl\":${CFTTL},\"proxied\":${PROXIED},\"comment\":\"ddns:${VPS_ID}\"}") || true

  if echo "$resp" | grep -q '"success":true'; then
    log "✅ Cloudflare 更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败，响应：$resp"
  fi
}

# ---------- 主循环 ----------
log "启动 DDNS 守护进程（多 VPS 友好：每台只维护自己的记录，互不影响）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

# ☆ 启动即确保记录存在；并立刻同步一次 IP（避免短暂出现 0.0.0.0）
cf_ensure_record_ready || true
cf_update_ddns true || true

while true; do
  if check_ip_reachable; then
    cf_update_ddns false || true
  else
    change_ip
    sleep 10
    cf_update_ddns true || true
  fi
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
