#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ========== 固定配置（注意安全） ==========
CF_API_TOKEN="${CF_API_TOKEN:-"iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"}"  # 建议改为仅用环境变量
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"
CFTTL=120
PROXIED="false"

# ========== 外网 IP 源 ==========
WANIPSITES_IPV4=(
  "http://ipv4.icanhazip.com"
  "http://ip4.seeip.org"
  "http://v4.ident.me"
  "http://ipv4.myip.wtf/text"
)
WANIPSITES_IPV6=(
  "http://ipv6.icanhazip.com"
  "http://ip6.seeip.org"
  "http://v6.ident.me"
  "http://ipv6.myip.wtf/text"
)

# ========== 多 VPS 独立状态 ==========
HOST_SHORT="$(hostname -s 2>/dev/null || echo vps)"
HOST_FULL="$(hostname 2>/dev/null || echo "$HOST_SHORT")"
VPS_ID="${VPS_ID:-$HOST_SHORT}"

STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"
CHANGE_CNT_FILE="${STATE_DIR}/cf-change_count_${CF_RECORD_NAME}.txt"
PID_FILE="${STATE_DIR}/ddns_${VPS_ID}.pid"

# ========== 检测配置 ==========
CHECK_INTERVAL=60          # 检测间隔（秒）
PING_TARGET="www.itdog.cn" # 用于检测是否被大陆封锁的目标
PING_COUNT=5               # ping 次数
PING_TIMEOUT=2             # 每次等待秒数
PING_INTERVAL=0.2          # ping 间隔（秒）

# ========== 常用工具 ==========
log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }
require_token(){ [ -n "$CF_API_TOKEN" ] || { log "❌ CF_API_TOKEN 为空"; exit 2; }; }
_trim(){ printf "%s" "$1" | tr -d '\r\n'; }
_has(){ command -v "$1" >/dev/null 2>&1; }

# 防多开
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
  log "ℹ️ 已在运行 (pid=$(cat "$PID_FILE"))，本次退出"
  exit 0
fi
echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE" >/dev/null 2>&1 || true' EXIT

# IP 校验与获取
validate_ip(){
  local ip="$1"
  [[ "$ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]
}

_get_wan_ip(){
  local sites=("${WANIPSITES_IPV4[@]}") s ip
  for s in "${sites[@]}"; do
    ip="$(curl -fsS --retry 3 --retry-all-errors --connect-timeout 5 --max-time 10 "$s" || true)"
    ip="$(_trim "${ip:-}")"
    if [ -n "$ip" ] && validate_ip "$ip"; then
      printf "%s" "$ip"
      return 0
    fi
  done
  return 1
}

# ========== 检测台湾 IP 是否被大陆墙 + 自动换 IP ==========
check_ip_reachable(){
  local wan_ip ping_result
  wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取公网 IP"; return 1; }

  log "🔍 检测台湾 IP 是否被大陆墙：${wan_ip}"
  log "🌏 检测目标站点：${PING_TARGET}"

  # 执行 ping 检测
  ping_result="$(ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -i "$PING_INTERVAL" "$PING_TARGET" 2>/dev/null || true)"

  if echo "$ping_result" | grep -q "100% packet loss"; then
    log "❌ 当前 IP (${wan_ip}) 已被大陆封锁，尝试自动换 IP..."
    call_change_ip || log "⚠️ 调用换 IP 失败"
    log "⏳ 等待 10 秒后重新检测..."
    sleep 10

    # 再次检测是否恢复
    wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取新公网 IP"; return 1; }
    ping_result="$(ping -c "$PING_COUNT" -W "$PING_TIMEOUT" -i "$PING_INTERVAL" "$PING_TARGET" 2>/dev/null || true)"
    if echo "$ping_result" | grep -q "100% packet loss"; then
      log "🚫 新 IP (${wan_ip}) 仍被墙，等待下次循环重试"
      return 1
    else
      log "✅ 新 IP (${wan_ip}) 已恢复正常访问"
      return 0
    fi
  else
    log "✅ 当前 IP (${wan_ip}) 未被封锁，网络正常"
    return 0
  fi
}

# ========== Cloudflare 统一 API ==========
CF_API_BASE="https://api.cloudflare.com/client/v4"
CURL_API_COMMON=( -sS --connect-timeout 10 --max-time 30 --retry 3 --retry-all-errors --retry-delay 1 )

_cf_api(){
  local method="$1" url="$2" data="${3:-}"
  require_token
  if [ -n "$data" ]; then
    curl "${CURL_API_COMMON[@]}" -X "$method" "$url" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      --data "$data" -w '|%{http_code}'
  else
    curl "${CURL_API_COMMON[@]}" -X "$method" "$url" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" -H "Content-Type: application/json" \
      -w '|%{http_code}'
  fi
}

ZONE_ID_CACHE=""
HAVE_JQ=0; _has jq && HAVE_JQ=1

get_zone_id(){
  if [ -n "$ZONE_ID_CACHE" ]; then printf "%s" "$ZONE_ID_CACHE"; return 0; fi
  log "查询 zone_id..."
  local out http body zid
  out="$(_cf_api GET "${CF_API_BASE}/zones?name=${CF_ZONE_NAME}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] || { log "❌ 获取 zone 失败（HTTP ${http}）：$body"; return 1; }

  if [ $HAVE_JQ -eq 1 ]; then
    zid="$(printf "%s" "$body" | jq -r '.result[0].id // empty')"
  else
    zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  fi
  [ -n "$zid" ] || { log "❌ 未找到 zone_id"; return 1; }
  ZONE_ID_CACHE="$zid"; printf "%s" "$zid"
}

list_records_json(){
  local zone_id="$1"
  local out http body
  out="$(_cf_api GET "${CF_API_BASE}/zones/${zone_id}/dns_records?type=${CF_RECORD_TYPE}&name=${CF_RECORD_NAME}&per_page=100")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] && printf "%s" "$body" || { log "❌ 列表记录失败（HTTP ${http}）：$body"; return 1; }
}

any_record_has_ip(){
  local zone_id="$1" ip="$2" body
  body="$(list_records_json "$zone_id" || echo "")"
  [ -n "$body" ] || return 1
  echo "$body" | grep -F "\"content\":\"${ip}\"" >/dev/null 2>&1
}

record_exists(){
  local zone_id="$1" rid="$2" out http
  out="$(_cf_api GET "${CF_API_BASE}/zones/${zone_id}/dns_records/${rid}")"
  http="${out##*|}"
  [ "$http" = "200" ]
}

patch_record(){
  local zone_id="$1" rid="$2" ip="$3" data out http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  out="$(_cf_api PATCH "${CF_API_BASE}/zones/${zone_id}/dns_records/${rid}" "$data")"
  http="${out##*|}"; body="${out%|*}"
  if [ "$http" = "200" ] || echo "$body" | grep -q '"code":81058'; then return 0; fi
  log "❌ PATCH 失败（HTTP ${http}）：$body"; return 1
}

create_record_with_comment(){
  local zone_id="$1" ip="$2" data out http body rid
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  out="$(_cf_api POST "${CF_API_BASE}/zones/${zone_id}/dns_records" "$data")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] || [ "$http" = "201" ] || { log "❌ 创建失败（HTTP ${http}）：$body"; return 1; }

  if [ $HAVE_JQ -eq 1 ]; then
    rid="$(printf "%s" "$body" | jq -r '.result.id // empty')"
  else
    rid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  fi
  [ -n "$rid" ] || { log "❌ 创建返回无 id"; return 1; }
  printf "%s" "$rid"
}

get_or_create_own_record_id(){
  local zone_id="$1" wan_ip="$2" rid body id content comment
  if [ -f "$ID_FILE" ]; then
    rid="$(cat "$ID_FILE" || true)"
    if [ -n "$rid" ] && record_exists "$zone_id" "$rid"; then
      printf "%s" "$rid"; return 0
    fi
    log "⚠️ 缓存 record_id 不存在/无效，尝试按 comment 找回"
  fi

  body="$(list_records_json "$zone_id" || echo "")"
  if [ -n "$body" ]; then
    if [ $HAVE_JQ -eq 1 ]; then
      while IFS=$'\t' read -r id content comment; do
        if printf "%s" "$comment" | grep -q "ddns:${VPS_ID}"; then
          printf "%s" "$id" > "$ID_FILE"
          printf "%s" "$id"
          return 0
        fi
      done < <(printf "%s" "$body" | jq -r '.result[]|[.id,.content,((.comment//""))]|@tsv')
    else
      while IFS=$'\t' read -r id content comment; do
        if printf "%s" "$comment" | grep -q "ddns:${VPS_ID}"; then
          printf "%s" "$id" > "$ID_FILE"
          printf "%s" "$id"
          return 0
        fi
      done < <(printf "%s" "$body" | awk 'BEGIN{RS="{\"id\":\"";FS="\""} NR>1{ id=$1; match($0,/"comment":"([^"]+)"/,m); if(id!="")printf("%s\t%s\n",id,m[1]); }')
    fi
  fi

  rid="$(create_record_with_comment "$zone_id" "$wan_ip")" || return 1
  printf "%s" "$rid" > "$ID_FILE"
  printf "%s" "$rid"
}

# ========== 换 IP ==========
CHANGE_IP_HTTP_TIMEOUT=60
CHANGE_VERIFY_WINDOW=90
CHANGE_VERIFY_POLL=5
CHANGE_IP_MAX_ATTEMPTS=2
CHANGE_IP_REPEAT_DELAY=10

_change_ip_target_url(){
  local host_all="${HOST_SHORT} ${HOST_FULL}"
  case "$host_all" in
    (*xqtw1*) echo "http://192.168.10.253" ;;
    (*xqtw2*|*xqtw3*) echo "http://10.10.8.10/ip/change.php" ;;
    (*) echo "http://192.168.10.253" ;;
  esac
}

_trigger_change_ip(){
  local url; url="$(_change_ip_target_url)" || return 1
  log "↻ 触发换 IP：host='${HOST_SHORT}' -> ${url}"
  ( curl -sS --connect-timeout 3 --max-time "$CHANGE_IP_HTTP_TIMEOUT" "$url" >/dev/null 2>&1 ) &
  return 0
}

call_change_ip(){
  local before after deadline try_idx
  before="$(_get_wan_ip || echo "")"
  log "🚀 执行换 IP（主机=${HOST_SHORT}）..."

  for try_idx in $(seq 1 "$CHANGE_IP_MAX_ATTEMPTS"); do
    _trigger_change_ip || log "⚠️ 第 ${try_idx} 次触发失败"
    deadline=$(( $(date +%s) + CHANGE_VERIFY_WINDOW ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      sleep "$CHANGE_VERIFY_POLL"
      after="$(_get_wan_ip || echo "")"
      if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
        local n=0; [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
        n=$((n+1)); echo "$n" > "$CHANGE_CNT_FILE"
        log "📶 已更换 IP：${before} -> ${after}（累计 $n 次）"
        return 0
      fi
    done
    log "⏱️ ${CHANGE_VERIFY_WINDOW}s 内未变化，重试..."
    sleep "$CHANGE_IP_REPEAT_DELAY"
  done
  log "😶 未检测到 IP 变化"
  return 1
}

# ========== Cloudflare 同步 ==========
sync_dns_if_needed(){
  local wan_ip zone_id rid body own_ip
  wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取公网 IP"; return 1; }
  zone_id="$(get_zone_id)" || return 1

  if any_record_has_ip "$zone_id" "$wan_ip"; then
    log "ℹ️ 当前记录已是 ${wan_ip}，跳过更新"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  rid="$(get_or_create_own_record_id "$zone_id" "$wan_ip")" || return 1
  if patch_record "$zone_id" "$rid" "$wan_ip"; then
    log "✅ 已更新记录：${CF_RECORD_NAME} -> ${wan_ip} [id=${rid}]"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败"
  fi
}

# ========== 主循环 ==========
log "🚀 启动 DDNS（主机=${HOST_FULL} / VPS_ID=${VPS_ID}）"
log "记录=${CF_RECORD_NAME} 类型=${CF_RECORD_TYPE} TTL=${CFTTL}s PROXIED=${PROXIED}"

while true; do
  if check_ip_reachable; then
    sync_dns_if_needed || true
  else
    sync_dns_if_needed || true
  fi

  [ -f "$CHANGE_CNT_FILE" ] && log "📊 累计换 IP 次数：$(cat "$CHANGE_CNT_FILE")"
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
