#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ===================== 基本配置（已写死 Token） =====================
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"   # 已写死
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"            # A 或 AAAA
CFTTL=120
PROXIED="false"               # true / false
WANIPSITE_IPV4="http://ipv4.icanhazip.com"
WANIPSITE_IPV6="http://ipv6.icanhazip.com"

# 多 VPS：每台机器的唯一标识（默认短主机名）
VPS_ID="${VPS_ID:-$(hostname -s || echo vps)}"
STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"

# 健康检查 & 轮询周期
TARGET_DOMAIN="email.163.com"
PING_COUNT=10
PING_GAP=3
CHECK_INTERVAL=30

# ===================== 工具与公共函数 =====================
log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }

# 只要变量非空即可（已写死，不再强制要求环境变量）
require_token() {
  if [ -z "${CF_API_TOKEN}" ]; then
    log "❌ CF_API_TOKEN 为空，请在脚本顶部写死或填入正确值"
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

# ===================== IP / 健康检查 =====================
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="$WANIPSITE_IPV6"
elif [ "$CF_RECORD_TYPE" = "A" ]; then
  WANIPSITE="$WANIPSITE_IPV4"
else
  echo "CF_RECORD_TYPE 仅支持 A 或 AAAA（当前：$CF_RECORD_TYPE）" >&2
  exit 2
fi

case "$PROXIED" in true|false) : ;; *) echo "PROXIED 必须为 true 或 false（当前：$PROXIED）" >&2; exit 2;; esac

_trim() { printf "%s" "$1" | tr -d '\r\n'; }

_get_wan_ip() {
  local ip
  ip=$(curl -fsS "$WANIPSITE" || true)
  [ -z "$ip" ] && return 1
  _trim "$ip"
}

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
      [ $i -lt $PING_COUNT ] && sleep "$PING_GAP"
    fi
  done
  $ok
}

change_ip() {
  log "🚀 尝试更换 IP via curl 192.168.10.253 ..."
  curl -fsS 192.168.10.253 >/dev/null 2>&1 || log "⚠️ 局域网切换接口未响应"
  sleep 10
  log "📶 已触发更换 IP"
}

# ===================== Cloudflare 逻辑 =====================
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
  [ -z "$zid" ] && { log "❌ 未找到 zone_id（域名不在该账户下？）"; return 1; }
  printf "%s" "$zid"
}

api_check_record_exists() {
  local zone_id="$1" record_id="$2"
  local out http body
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] && echo "$body" | grep -q '"success":true'
}

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
  local zone_id="$1" ip fallback_ip
  fallback_ip=$([ "$CF_RECORD_TYPE" = "AAAA" ] && echo "::0" || echo "0.0.0.0")
  ip="$(_get_wan_ip || echo "$fallback_ip")"
  log "为 VPS(${VPS_ID}) 创建专属记录（初始 IP=${ip}）..."

  local data resp http body rid
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
      log "⚠️ 缓存 record_id 不存在或无效，将重建"
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
  wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取公网 IP"; return 1; }

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

# ===================== 主循环（先检测墙，再处理 DDNS） =====================
log "启动 DDNS 守护进程（多 VPS 友好：每台只维护自己的记录，互不影响）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

while true; do
  if check_ip_reachable; then
    # 网络可达：确保记录存在 -> 若远端IP==本机IP则跳过，否则更新
    cf_update_ddns || true
  else
    # 网络不可达：先换IP，再确保记录存在并强制尝试一次更新
    change_ip
    sleep 10
    cf_update_ddns || true
  fi
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
