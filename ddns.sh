#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ---------- Cloudflare DDNS 配置 ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"
CFTTL=120
FORCE=false
WANIPSITE="http://ipv4.icanhazip.com"

# ---------- 检测参数 ----------
TARGET_DOMAIN="email.163.com"   # 国内检测目标
PING_COUNT=10                   # ping 次数
PING_GAP=3                      # 每次间隔秒
CHECK_INTERVAL=30               # 每轮检测间隔秒
ID_FILE="$HOME/.cf-id_${CF_RECORD_NAME}.txt"
WAN_IP_FILE="$HOME/.cf-wan_ip_${CF_RECORD_NAME}.txt"

if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="http://ipv6.icanhazip.com"
elif [ "$CF_RECORD_TYPE" != "A" ]; then
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA"
  exit 2
fi

log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }

# ---------- 检测网络连通性 ----------
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

# ---------- 更换IP ----------
change_ip() {
  log "🚀 尝试更换 IP via curl 192.168.10.253 ..."
  curl -fsS 192.168.10.253 >/dev/null 2>&1 || log "⚠️ curl 请求失败（可能是局域网接口未响应）"
  sleep 10
  log "📶 已触发更换 IP"
}

# ---------- Cloudflare 更新函数 ----------
get_zone_and_record_ids() {
  local cfzone_id="" cfrecord_id=""
  if [ -f "$ID_FILE" ] && [ "$(wc -l < "$ID_FILE" || echo 0)" -eq 2 ]; then
    cfzone_id=$(sed -n '1p' "$ID_FILE")
    cfrecord_id=$(sed -n '2p' "$ID_FILE")
  else
    log "查询 zone_id..."
    cfzone_id=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
    [ -z "$cfzone_id" ] && { log "未找到 zone_id"; return 1; }

    log "查询记录 id..."
    cfrecord_id=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${cfzone_id}/dns_records?name=${CF_RECORD_NAME}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
    if [ -z "$cfrecord_id" ]; then
      log "记录不存在，创建中..."
      local create_resp
      create_resp=$(curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${cfzone_id}/dns_records" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"0.0.0.0\",\"ttl\":${CFTTL}}") || true
      cfrecord_id=$(echo "$create_resp" | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
      [ -z "$cfrecord_id" ] && { log "创建失败：$create_resp"; return 1; }
    fi
    printf "%s\n%s\n" "$cfzone_id" "$cfrecord_id" > "$ID_FILE"
  fi
  printf "%s|%s" "$cfzone_id" "$cfrecord_id"
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

  local ids zone_id record_id
  ids="$(get_zone_and_record_ids)" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  log "准备更新 ${CF_RECORD_NAME} -> ${wan_ip}"
  local resp
  resp=$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${wan_ip}\",\"ttl\":${CFTTL}}") || true

  if echo "$resp" | grep -q '"success":true'; then
    log "✅ Cloudflare 更新成功 -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败，响应：$resp"
  fi
}

# ---------- 主循环 ----------
log "启动 DDNS 检测守护进程（ping 10 次，3s 间隔，curl 192.168.10.253 切换 IP）"
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
