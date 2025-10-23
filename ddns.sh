#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ===================== 基本配置（写死 Token） =====================
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"   # 已写死（有风险，谨慎外泄）
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"  # 多 VPS 共用同名记录实现轮询
CF_RECORD_TYPE="A"                    # A / AAAA
CFTTL=120
PROXIED="false"                       # true / false

# WAN IP 获取
WANIPSITE_IPV4="http://ipv4.icanhazip.com"
WANIPSITE_IPV6="http://ipv6.icanhazip.com"

# ===================== 多 VPS 独立状态 =====================
VPS_ID="${VPS_ID:-$(hostname -s || echo vps)}"
STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"           # 本机专属 record_id
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"   # 本机上次 WAN
CHANGE_CNT_FILE="${STATE_DIR}/cf-change_count_${CF_RECORD_NAME}.txt"   # 换 IP 计数（全局/可共享）

# ===================== 连通性检测配置 =====================
TARGET_DOMAIN="email.163.com"  # 检测目标
PING_COUNT=10
PING_GAP=3
CHECK_INTERVAL=30

# ===================== 工具函数 =====================
log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }

require_token() {
  if [ -z "${CF_API_TOKEN}" ]; then
    log "❌ CF_API_TOKEN 为空（脚本顶部写死或者用环境变量）"
    exit 2
  fi
}

# 统一 Cloudflare API：返回 "BODY|HTTP_CODE"
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

_trim() { printf "%s" "$1" | tr -d '\r\n'; }

# 取当前公网 IP
_get_wan_ip() {
  local site ip
  if [ "$CF_RECORD_TYPE" = "AAAA" ]; then site="$WANIPSITE_IPV6"; else site="$WANIPSITE_IPV4"; fi
  ip=$(curl -fsS "$site" || true)
  [ -z "$ip" ] && return 1
  _trim "$ip"
}

# 连通性检测：可达返回 0，不可达返回 1
check_ip_reachable() {
  log "🔍 检测当前公网IP是否能访问 ${TARGET_DOMAIN}..."
  for ((i=1;i<=PING_COUNT;i++)); do
    if ping -c 1 -W 3 "$TARGET_DOMAIN" >/dev/null 2>&1; then
      log "✅ 第 ${i}/${PING_COUNT} 次 ping 成功 —— 网络正常"
      return 0
    else
      log "⚠️ 第 ${i}/${PING_COUNT} 次 ping 失败"
      [ $i -lt $PING_COUNT ] && sleep "$PING_GAP"
    fi
  done
  return 1
}

# 触发换 IP，并记录计数
change_ip() {
  log "🚀 更换 IP via curl 192.168.10.253 ..."
  curl -fsS 192.168.10.253 >/dev/null 2>&1 || log "⚠️ 局域网切换接口未响应"
  sleep 10
  # 计数
  local n=0
  [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
  n=$((n+1))
  echo "$n" > "$CHANGE_CNT_FILE"
  log "📶 已触发更换 IP；累计更换次数：${n}"
}

# ===================== Cloudflare 相关 =====================
api_get_zone_id() {
  log "查询 zone_id..."
  local out http body zid
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && { log "❌ 获取 zone 失败（HTTP ${http}）：$body"; return 1; }
  zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -z "$zid" ] && { log "❌ 未找到 zone_id（域名是否在该账户下？）"; return 1; }
  printf "%s" "$zid"
}

# 查找是否存在“同名 + 指定 content”的任意记录（用于避免 81058）
api_find_record_by_name_content() {
  local zone_id="$1" name="$2" content="$3"
  local out http body rid
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?name=${name}&type=${CF_RECORD_TYPE}&per_page=100")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && return 1
  rid=$(echo "$body" | jq -r --arg c "$content" '.result[] | select(.content==$c) | .id' 2>/dev/null | head -1 || true)
  [ -n "$rid" ] && printf "%s" "$rid" || return 1
}

# 校验本机缓存的 record_id 是否仍存在
api_check_record_exists() {
  local zone_id="$1" record_id="$2"
  local out http
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}")"
  http="${out##*|}"
  [ "$http" = "200" ]
}

# 读取本机记录当前 content
api_get_own_record_ip() {
  local zone_id="$1" record_id="$2"
  local out http body rip
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && return 1
  rip=$(echo "$body" | grep -Po '(?<="content":")[^"]*' | head -1 || true)
  [ -n "$rip" ] && printf "%s" "$rip" || return 1
}

# 创建“本机专属”记录（注释 ddns:VPS_ID，创建即写真实 IP；失败回退 0.0.0.0/::0）
api_create_own_record() {
  local zone_id="$1" ip fallback_ip data out http body rid
  fallback_ip=$([ "$CF_RECORD_TYPE" = "AAAA" ] && echo "::0" || echo "0.0.0.0")
  ip="$(_get_wan_ip || echo "$fallback_ip")"
  log "为 VPS(${VPS_ID}) 创建专属记录（初始 IP=${ip}）..."
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  out="$(_cf_api POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" "$data")"
  http="${out##*|}"; body="${out%|*}"
  if [ "$http" != "200" ] && [ "$http" != "201" ]; then
    log "❌ 创建记录失败（HTTP ${http}）：$body"
    return 1
  fi
  rid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -z "$rid" ] && { log "❌ 无法从返回中提取 record_id：$body"; return 1; }
  echo "$rid"
}

# 仅更新必要字段，避免 400
api_patch_record_content() {
  local zone_id="$1" record_id="$2" ip="$3" data out http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  out="$(_cf_api PATCH "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" "$data")"
  http="${out##*|}"; body="${out%|*}"
  echo "${http}|${body}"
}

# 确保“本机专属记录”存在：优先用缓存 record_id，不存在则创建
ensure_own_record_ready() {
  local zone_id record_id
  zone_id="$(api_get_zone_id)" || return 1
  if [ -f "$ID_FILE" ]; then
    record_id="$(cat "$ID_FILE" || true)"
    if [ -n "$record_id" ] && api_check_record_exists "$zone_id" "$record_id"; then
      printf "%s|%s\n" "$zone_id" "$record_id"
      return 0
    fi
    log "⚠️ 缓存 record_id 无效，将重建"
  fi
  record_id="$(api_create_own_record "$zone_id")" || return 1
  echo "$record_id" > "$ID_FILE"
  printf "%s|%s\n" "$zone_id" "$record_id"
}

# ===================== 主逻辑：按你的顺序执行 =====================
sync_dns_if_needed() {
  # 仅在“需要时”更新：会避免 81058
  local wan_ip zone_id record_id ids own_ip out http body dup_id
  wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取公网 IP"; return 1; }

  # 先看看 Cloudflare 是否已经存在“同名 + 同 IP”的任一记录（可能是别的 VPS）
  zone_id="$(api_get_zone_id)" || return 1
  if dup_id="$(api_find_record_by_name_content "$zone_id" "$CF_RECORD_NAME" "$wan_ip" 2>/dev/null)"; then
    log "ℹ️ Cloudflare 已存在同名且 IP=${wan_ip} 的记录（id=${dup_id}），本次跳过任何更新。"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  # 否则，仅维护“本机专属记录”：不存在则创建，存在则按需 PATCH
  ids="$(ensure_own_record_ready)" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  own_ip="$(api_get_own_record_ip "$zone_id" "$record_id" || echo "")"
  if [ "$own_ip" = "$wan_ip" ]; then
    log "ℹ️ 本机记录已是当前 IP（$wan_ip），无需更新。"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  log "📝 更新本机记录：${CF_RECORD_NAME} -> ${wan_ip}  [record_id=${record_id}]"
  out="$(api_patch_record_content "$zone_id" "$record_id" "$wan_ip")"
  http="${out%%|*}"; body="${out#*|}"
  if [ "$http" = "200" ]; then
    log "✅ 更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  else
    log "❌ 更新失败（HTTP ${http}）：$body"
    # 如果失败可能因为同名同值已被其他 VPS 抢先创建，此时再次查重，存在就跳过。
    if dup_id="$(api_find_record_by_name_content "$zone_id" "$CF_RECORD_NAME" "$wan_ip" 2>/dev/null)"; then
      log "ℹ️ 检测到别的记录已是 IP=${wan_ip}（id=${dup_id}），安全跳过。"
      echo "$wan_ip" > "$WAN_IP_FILE"
      return 0
    fi
    return 1
  fi
}

# ===================== 先检测墙 → 再按需处理 DDNS =====================
log "启动 DDNS 守护进程（多 VPS 友好：只维护本机记录，不删除他人）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

while true; do
  if check_ip_reachable; then
    # 通：只检查是否已有解析到当前 IP（任意记录）。有就跳过全部；无则只更新本机记录。
    sync_dns_if_needed || true
  else
    # 不通：先换 IP（累计次数），然后再按需同步 DNS
    change_ip
    sleep 10
    sync_dns_if_needed || true
  fi
  # 展示累计换 IP 次数
  if [ -f "$CHANGE_CNT_FILE" ]; then
    log "📊 累计更换 IP 次数：$(cat "$CHANGE_CNT_FILE" || echo 0)"
  fi
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
