#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ---------- Cloudflare DDNS 配置 ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"  # 建议用环境变量注入
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="wyddns.5653111.xyz"
CF_RECORD_TYPE="A"           # A 或 AAAA
CFTTL=120
PROXIED="${PROXIED:-false}"  # true/false（不加引号注入 JSON）
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

# IPv6 适配
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="http://ipv6.icanhazip.com"
elif [ "$CF_RECORD_TYPE" != "A" ]; then
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA" >&2
  exit 2
fi

# 打印到 stderr，避免污染命令替换
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

# ---------- Cloudflare API 通用封装 ----------
require_token() {
  if [ -z "${CF_API_TOKEN}" ] || [ "${CF_API_TOKEN}" = "REPLACE_WITH_TOKEN" ]; then
    log "❌ 缺少 CF_API_TOKEN，请通过环境变量提供：export CF_API_TOKEN=xxxxx"
    exit 2
  fi
}

# 统一 Cloudflare API 调用：返回 "BODY|HTTP_CODE"
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
  if [ "$http" != "200" ]; then
    log "❌ 获取 zone 失败（HTTP ${http}）：$body"
    return 1
  fi
  zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -z "$zid" ] && { log "❌ 未找到 zone_id（域名是否归属此账号？）"; return 1; }
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

# 创建专属记录（创建即用真实公网 IP；若失败回退到 0.0.0.0/::0）
api_create_own_record() {
  local zone_id="$1"
  local fallback_ip current_ip
  fallback_ip=$([ "$CF_RECORD_TYPE" = "AAAA" ] && echo "::0" || echo "0.0.0.0")
  current_ip=$(curl -fsS "${WANIPSITE}" || echo "$fallback_ip")
  current_ip="${current_ip//$'\n'/}"; current_ip="${current_ip//$'\r'/}"
  log "未发现可用记录，为 VPS(${VPS_ID}) 创建专属记录（初始 IP=${current_ip}）..."

  local data resp http body rid
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$current_ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  resp="$(_cf_api POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" "$data")"
  http="${resp##*|}"; body="${resp%|*}"

  if [ "$http" != "200" ] && [ "$http" != "201" ]; then
    log "❌ 创建记录失败（HTTP ${http}）：$body"
    return 1
  fi
  rid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  if [ -z "$rid" ]; then
    log "❌ 未能从返回中提取 record_id：$body"
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
      printf "%s|%s\n" "$zone_id" "$record_id"
      return 0
    else
      log "⚠️ 缓存的 record_id 不存在或无效，准备重新创建"
    fi
  fi

  # 2) 无缓存或失效 -> 直接创建专属记录（创建时即写真实 IP）
  record_id="$(api_create_own_record "$zone_id")" || return 1
  echo "$record_id" > "$ID_FILE"
  printf "%s|%s\n" "$zone_id" "$record_id"
}

# 使用 PATCH 更新；返回 "HTTP|BODY"
_cf_update_record() {
  local zone_id="$1" record_id="$2" wan_ip="$3"
  local data resp http body
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$wan_ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  resp="$(_cf_api PATCH "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" "$data")"
  http="${resp##*|}"; body="${resp%|*}"
  echo "${http}|${body}"
}

cf_update_ddns() {
  local force_flag="${1:-false}"

  # 先确保记录存在
  local ids zone_id record_id
  ids="$(cf_ensure_record_ready)" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  # 取公网 IP
  local wan_ip old_ip
  wan_ip=$(curl -fsS "${WANIPSITE}" || true)
  [ -z "$wan_ip" ] && { log "❌ 无法获取公网 IP"; return 1; }
  wan_ip="${wan_ip//$'\n'/}"; wan_ip="${wan_ip//$'\r'/}"

  [ -f "$WAN_IP_FILE" ] && old_ip="$(cat "$WAN_IP_FILE" || true)" || old_ip=""

  if [ "$wan_ip" = "$old_ip" ] && [ "$FORCE" = false ] && [ "$force_flag" = false ]; then
    log "WAN IP 未改变（$wan_ip），跳过更新（记录已确保存在）"
    return 0
  fi

  log "准备更新（VPS=${VPS_ID}） ${CF_RECORD_NAME} -> ${wan_ip}  [record_id=${record_id}]"
  local out http body
  out="$(_cf_update_record "$zone_id" "$record_id" "$wan_ip")"
  http="${out%%|*}"; body="${out#*|}"

  if [ "$http" = "200" ]; then
    log "✅ Cloudflare 更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  # 打印 Cloudflare 具体错误
  log "❌ 更新失败（HTTP ${http}）：$body"

  # —— 自愈：若记录被改坏/删掉，重建一次再重试 ——
  log "🛠️ 尝试自愈：重新创建记录并重试一次更新"
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

# 启动即确保记录存在，并立刻同步一次 IP（避免短暂出现占位 IP）
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
