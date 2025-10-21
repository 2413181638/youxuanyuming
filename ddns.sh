#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ---------- Cloudflare DDNS 配置 ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"  # 永远默认值
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"
CFTTL=120
FORCE=false
WANIPSITE="http://ipv4.icanhazip.com"

# ---------- 多 VPS 关键配置 ----------
# 用于区分每台 VPS 的唯一标识（建议保持稳定）。默认用短主机名。
VPS_ID="${VPS_ID:-$(hostname -s || echo vps)}"
# 为每台 VPS 单独保存其 record_id / 上次 WAN IP
STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"

# ---------- 连通性检测 ----------
TARGET_DOMAIN="email.163.com"   # 国内检测目标
PING_COUNT=10                   # ping 次数
PING_GAP=3                      # 每次间隔秒
CHECK_INTERVAL=30               # 每轮检测间隔秒

if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="http://ipv6.icanhazip.com"
elif [ "$CF_RECORD_TYPE" != "A" ]; then
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA"
  exit 2
fi

log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }

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

# ---------- Cloudflare API 封装 ----------
require_token() {
  if [ -z "${CF_API_TOKEN}" ] || [ "${CF_API_TOKEN}" = "REPLACE_WITH_TOKEN" ]; then
    log "❌ 缺少 CF_API_TOKEN，请通过环境变量提供：export CF_API_TOKEN=xxxxx"
    exit 2
  fi
}

get_zone_id() {
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

# 只为当前 VPS 创建/获取自己的 DNS 记录：
# - 如果有缓存的 record_id，直接返回
# - 否则：创建一条新的记录（带 comment=ddns:<VPS_ID>），并缓存 record_id
get_or_create_own_record_id() {
  local cfzone_id="$1"
  local record_id=""
  if [ -f "$ID_FILE" ]; then
    record_id="$(cat "$ID_FILE" || true)"
  fi

  if [ -n "$record_id" ]; then
    printf "%s" "$record_id"
    return 0
  fi

  log "未缓存 record_id，为 VPS(${VPS_ID}) 创建专属记录..."
  local create_resp
  # 注意：不去查找“第一个”现有记录，避免误操作别的 VPS 的记录
  create_resp=$(curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${cfzone_id}/dns_records" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"0.0.0.0\",\"ttl\":${CFTTL},\"comment\":\"ddns:${VPS_ID}\"}") || true

  record_id=$(echo "$create_resp" | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
  if [ -z "$record_id" ]; then
    log "❌ 创建记录失败：$create_resp"
    return 1
  fi
  echo "$record_id" > "$ID_FILE"
  printf "%s" "$record_id"
}

cf_update_ddns() {
  local force_flag="${1:-false}"
  local wan_ip
  wan_ip=$(curl -fsS "${WANIPSITE}" || true)
  [ -z "$wan_ip" ] && { log "❌ 无法获取公网 IP"; return 1; }

  local old_ip=""
  [ -f "$WAN_IP_FILE" ] && old_ip=$(cat "$WAN_IP_FILE" || true)
  if [ "$wan_ip" = "$old_ip" ] && [ "$FORCE" = false ] && [ "$force_flag" = false ]; then
    log "WAN IP 未改变（$wan_ip），跳过更新"
    return 0
  fi

  local zone_id record_id resp
  zone_id="$(get_zone_id)" || return 1
  record_id="$(get_or_create_own_record_id "$zone_id")" || return 1

  log "准备更新（VPS=${VPS_ID}） ${CF_RECORD_NAME} -> ${wan_ip}  [record_id=${record_id}]"
  resp=$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${wan_ip}\",\"ttl\":${CFTTL},\"comment\":\"ddns:${VPS_ID}\"}") || true

  if echo "$resp" | grep -q '"success":true'; then
    log "✅ Cloudflare 更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败，响应：$resp"
  fi
}

# ---------- 主循环 ----------
log "启动 DDNS 守护进程（多 VPS 友好：每台只维护自己的记录，互不影响）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s"
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
