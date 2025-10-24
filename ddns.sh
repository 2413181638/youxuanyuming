#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ===================== 基本配置（写死 Token，注意安全） =====================
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"   # 建议日后改为用环境变量注入
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"  # 多 VPS 共享同名记录实现轮询
CF_RECORD_TYPE="A"                    # A / AAAA
CFTTL=120
PROXIED="false"                       # true / false（不要带引号进 JSON）

# WAN IP 获取
WANIPSITE_IPV4="http://ipv4.icanhazip.com"
WANIPSITE_IPV6="http://ipv6.icanhazip.com"

# ===================== 多 VPS 独立状态 =====================
VPS_ID="${VPS_ID:-$(hostname -s || echo vps)}"
STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"           # 本机专属 record_id
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"   # 本机上次 WAN
CHANGE_CNT_FILE="${STATE_DIR}/cf-change_count_${CF_RECORD_NAME}.txt"   # 换 IP 计数

# ===================== 连通性检测配置 =====================
# 多目标：任意一个目标有一次 ping 成功 -> 视为“未被墙”
TARGET_DOMAINS=("email.163.com" "guanjia.qq.com" "weixin.qq.com")
PING_COUNT=10
PING_GAP=3
CHECK_INTERVAL=30

# ===================== 通用工具 =====================
log() { printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }

require_token() {
  if [ -z "${CF_API_TOKEN}" ]; then
    log "❌ CF_API_TOKEN 为空（脚本顶部写死或用环境变量）"
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

_trim() { printf "%s" "$1" | tr -d '\r\n'; }

# ===================== IP 与连接性 =====================
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="$WANIPSITE_IPV6"
elif [ "$CF_RECORD_TYPE" = "A" ]; then
  WANIPSITE="$WANIPSITE_IPV4"
else
  echo "CF_RECORD_TYPE 仅支持 A 或 AAAA（当前：$CF_RECORD_TYPE）" >&2
  exit 2
fi

case "$PROXIED" in true|false) : ;; *) echo "PROXIED 必须为 true 或 false（当前：$PROXIED）" >&2; exit 2;; esac

_get_wan_ip() {
  local ip
  ip=$(curl -fsS "$WANIPSITE" || true)
  [ -z "$ip" ] && return 1
  _trim "$ip"
}

# 多目标多次 ping：任意目标任意一次成功即返回 0；全部失败返回 1
check_ip_reachable() {
  log "🔍 连通性检测：目标=${TARGET_DOMAINS[*]}，每个目标最多 ${PING_COUNT} 次"
  local domain
  for domain in "${TARGET_DOMAINS[@]}"; do
    for ((i=1;i<=PING_COUNT;i++)); do
      if ping -c 1 -W 3 "$domain" >/dev/null 2>&1; then
        log "✅ ${domain}：第 ${i}/${PING_COUNT} 次 ping 成功 —— 网络判定为【正常】"
        return 0
      else
        log "⚠️  ${domain}：第 ${i}/${PING_COUNT} 次 ping 失败"
        [ $i -lt $PING_COUNT ] && sleep "$PING_GAP"
      fi
    done
  done
  log "❌ 所有目标均未 ping 通 —— 网络判定为【不通/被墙】"
  return 1
}

change_ip() {
  log "🚀 更换 IP via curl 192.168.10.253 ..."
  curl -fsS 192.168.10.253 >/dev/null 2>&1 || log "⚠️ 局域网切换接口未响应"
  sleep 10
  local n=0
  [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
  n=$((n+1))
  echo "$n" > "$CHANGE_CNT_FILE"
  log "📶 已触发更换 IP；累计更换次数：${n}"
}

# ===================== Cloudflare 逻辑 =====================
ZONE_ID_CACHE=""
api_get_zone_id() {
  if [ -n "$ZONE_ID_CACHE" ]; then
    printf "%s" "$ZONE_ID_CACHE"
    return 0
  fi
  log "查询 zone_id..."
  local out http body zid
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && { log "❌ 获取 zone 失败（HTTP ${http}）：$body"; return 1; }
  zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -z "$zid" ] && { log "❌ 未找到 zone_id（域名是否在该账户下？）"; return 1; }
  ZONE_ID_CACHE="$zid"
  printf "%s" "$zid"
}

# 是否存在“同名 + 指定 IP”的任意记录（避免 81058），纯文本查找，无 jq
api_any_record_has_ip() {
  local zone_id="$1" name="$2" ip="$3"
  local out http body
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=${CF_RECORD_TYPE}&name=${name}&per_page=100")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" != "200" ] && return 2
  echo "$body" | grep -F "\"content\":\"${ip}\"" >/dev/null 2>&1
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

# 创建“本机专属”记录（必须使用真实 WAN IP；不能用占位 0.0.0.0 或 ::0）
api_create_own_record() {
  local zone_id="$1" ip="$2" data out http body rid
  if [ -z "$ip" ]; then
    log "❌ 创建记录失败：未提供有效公网 IP"
    return 1
  fi
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

# 仅更新必要字段；若遇 81058（完全相同记录已存在）当作成功
api_patch_record_content() {
  local zone_id="$1" record_id="$2" ip="$3" data out http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  out="$(_cf_api PATCH "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${record_id}" "$data")"
  http="${out##*|}"; body="${out%|*}"

  if [ "$http" = "200" ]; then
    echo "OK|$body"
    return 0
  fi
  if echo "$body" | grep -q '"code":81058'; then
    echo "OK|$body"
    return 0
  fi
  echo "ERR|${http}|${body}"
  return 1
}

# 确保“本机专属记录”存在（必须传入真实 WAN IP，用它创建）
ensure_own_record_ready() {
  local zone_id="$1" ip="$2" record_id
  zone_id="$(api_get_zone_id)" || return 1
  if [ -f "$ID_FILE" ]; then
    record_id="$(cat "$ID_FILE" || true)"
    if [ -n "$record_id" ] && api_check_record_exists "$zone_id" "$record_id"; then
      printf "%s|%s\n" "$zone_id" "$record_id"
      return 0
    fi
    log "⚠️ 缓存 record_id 无效，将重建"
  fi
  record_id="$(api_create_own_record "$zone_id" "$ip")" || return 1
  echo "$record_id" > "$ID_FILE"
  printf "%s|%s\n" "$zone_id" "$record_id"
}

# ===================== 主逻辑（按你的顺序） =====================
sync_dns_if_needed() {
  local wan_ip zone_id record_id ids own_ip patch_msg

  # 真实公网 IP 必须获取成功，获取不到就直接返回（绝不写入 0.0.0.0 / ::0）
  wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取公网 IP，跳过本轮"; return 1; }

  # 1) 可达时：若“任意记录”已是目标 IP，直接跳过（避免 81058）
  zone_id="$(api_get_zone_id)" || return 1
  if api_any_record_has_ip "$zone_id" "$CF_RECORD_NAME" "$wan_ip"; then
    log "ℹ️ 云端已有同名且 IP=${wan_ip} 的记录，本次跳过所有操作"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  # 2) 仅维护本机记录：不存在则用“真实 WAN IP”创建；存在则按需 PATCH
  ids="$(ensure_own_record_ready "$zone_id" "$wan_ip")" || return 1
  zone_id="${ids%%|*}"
  record_id="${ids##*|}"

  own_ip="$(api_get_own_record_ip "$zone_id" "$record_id" || echo "")"
  if [ "$own_ip" = "$wan_ip" ]; then
    log "ℹ️ 本机记录已是当前 IP（$wan_ip），无需更新"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  log "📝 更新本机记录：${CF_RECORD_NAME} -> ${wan_ip}  [record_id=${record_id}]"
  patch_msg="$(api_patch_record_content "$zone_id" "$record_id" "$wan_ip")" || true
  if printf "%s" "$patch_msg" | grep -q '^OK|'; then
    log "✅ 更新完成（含 81058 视为已就绪）"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  else
    log "❌ 更新失败：${patch_msg}"
    return 1
  fi
}

# ===================== 先检测墙 → 再按需处理 DDNS =====================
log "启动 DDNS 守护进程（多 VPS 友好：只维护本机记录，不删除他人；创建/更新一律写真实公网 IP）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

while true; do
  if check_ip_reachable; then
    # 通：只检查是否已解析到当前 IP，有就跳过；否则仅更新/创建本机记录（写真实 IP）
    sync_dns_if_needed || true
  else
    # 不通：换 IP（累计），然后再按需同步（同样先查是否已有该 IP）
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
