#!/usr/bin/env bash
# Taiwan DDNS + China reachability check + Cloudflare update (single script)
set -o errexit
set -o nounset
set -o pipefail

# ---------- Cloudflare DDNS 配置（你的原配置，已合入） ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"            # A 或 AAAA
CFTTL=120
FORCE=false                   # true=每次都强制更新；切换IP后会自动临时强制一次
WANIPSITE="http://ipv4.icanhazip.com"

# ---------- 其他参数 ----------
TARGET_DOMAIN="email.163.com" # 用于检测是否被墙的国内域名
PING_COUNT=3                  # 连续 ping 次数
PING_GAP=3                    # 每次 ping 间隔秒数（3 次共 9 秒）
CHECK_INTERVAL=30             # 每轮检测间隔秒数
ID_FILE="$HOME/.cf-id_${CF_RECORD_NAME}.txt"
WAN_IP_FILE="$HOME/.cf-wan_ip_${CF_RECORD_NAME}.txt"

# 根据记录类型选择取公网 IP 的站点
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="http://ipv6.icanhazip.com"
elif [ "$CF_RECORD_TYPE" != "A" ]; then
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA"
  exit 2
fi

log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*"; }

# ---------- 功能函数：国内连通性检测（连续 3 次、每次 -W 3，间隔 3 秒） ----------
check_ip_reachable() {
  log "检测当前公网IP是否能访问 ${TARGET_DOMAIN}（$PING_COUNT 次，间隔 ${PING_GAP}s）..."
  local ok=false
  for ((i=1;i<=PING_COUNT;i++)); do
    if ping -c 1 -W 3 "$TARGET_DOMAIN" >/dev/null 2>&1; then
      log "✅ 第 ${i}/${PING_COUNT} 次 ping 成功 —— 认为网络正常"
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

# ---------- 功能函数：换 IP（按你的环境修改） ----------
change_ip() {
  log "🚀 尝试更换 IP..."
  # === 请根据你的实际网络环境选择其一并取消注释 ===
  # 1) PPPoE 拨号：poff/pon
  # sudo poff dsl-provider || true
  # sleep 2
  # sudo pon dsl-provider || true

  # 2) Cloudflare WARP：
  # warp-cli disconnect || true
  # sleep 2
  # warp-cli connect || true

  # 3) 常规主机/部分云 VPS：重启网络（两者选其一，失败就忽略）
  sudo systemctl restart networking || sudo systemctl restart NetworkManager || true

  sleep 10
  log "📶 换 IP 操作完成，准备继续"
}

# ---------- Cloudflare：查询 zone_id / record_id（带缓存） ----------
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
    if [ -z "$cfzone_id" ]; then
      log "未找到 zone_id，请检查 CF_ZONE_NAME 或 token 权限"
      return 1
    fi

    log "查询记录 id..."
    cfrecord_id=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${cfzone_id}/dns_records?name=${CF_RECORD_NAME}" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)

    if [ -z "$cfrecord_id" ]; then
      log "记录不存在，创建中： ${CF_RECORD_NAME}"
      local create_resp
      create_resp=$(curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${cfzone_id}/dns_records" \
        -H "Authorization: Bearer ${CF_API_TOKEN}" \
        -H "Content-Type: application/json" \
        --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"0.0.0.0\",\"ttl\":${CFTTL}}") || true
      cfrecord_id=$(echo "$create_resp" | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
      if [ -z "$cfrecord_id" ]; then
        log "创建记录失败，响应： $create_resp"
        return 1
      fi
    fi
    printf "%s\n%s\n" "$cfzone_id" "$cfrecord_id" > "$ID_FILE"
  fi
  printf "%s|%s" "$cfzone_id" "$cfrecord_id"
}

# ---------- Cloudflare：根据当前 WAN IP 更新记录 ----------
cf_update_ddns() {
  local force_flag="${1:-false}"

  # 取 WAN IP
  local wan_ip
  wan_ip=$(curl -fsS "${WANIPSITE}" || true)
  if [ -z "$wan_ip" ]; then
    log "❌ 无法获取公网 IP，跳过本次 DDNS 更新"
    return 1
  fi

  # 是否需要更新
  local old_ip=""
  if [ -f "$WAN_IP_FILE" ]; then
    old_ip=$(cat "$WAN_IP_FILE" || true)
  fi
  if [ "$wan_ip" = "$old_ip" ] && [ "$FORCE" = false ] && [ "$force_flag" = false ]; then
    log "WAN IP 未改变（$wan_ip），不更新 DNS"
    return 0
  fi

  # 获取/缓存 zone 与 record id
  local ids zone_id record_id
  ids="$(get_zone_and_record_ids)" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  log "准备将 ${CF_RECORD_NAME} 更新为 ${wan_ip}"
  local resp
  resp=$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${wan_ip}\",\"ttl\":${CFTTL}}") || true

  if echo "$resp" | grep -q '"success":true'; then
    log "✅ 更新成功：${CF_RECORD_NAME} -> ${wan_ip}"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  else
    log "❌ 更新失败，响应： $resp"
    return 1
  fi
}

# ---------- 主循环 ----------
log "启动：国内连通性检测 + 自动换IP + Cloudflare DDNS 更新"
while true; do
  if check_ip_reachable; then
    # 网络正常：仅在 IP 变化或 FORCE=true 时更新
    cf_update_ddns false || true
  else
    # 网络异常：先换 IP，再强制更新一次
    change_ip
    # 等待网络回稳
    sleep 10
    cf_update_ddns true || true
  fi

  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
