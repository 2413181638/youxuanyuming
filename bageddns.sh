#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ========== 固定配置 ==========
# 建议用环境变量覆盖：export CF_API_TOKEN='你的 Cloudflare Token'
CF_API_TOKEN="${CF_API_TOKEN:-iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1}"
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
PING_TARGET="8.138.53.208" # 只用这个目标检测
PING_COUNT=5               # ping 次数
PING_TIMEOUT=2             # 每次等待秒数
PING_INTERVAL=0.2          # ping 间隔（秒）

# ========== 常用工具 ==========
log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }
require_token(){ [ -n "${CF_API_TOKEN:-}" ] || { log "❌ CF_API_TOKEN 为空，跳过 Cloudflare 同步"; return 2; }; }
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

# 从 ping 输出里只提取数字丢包率：0、20、100 等。
# 解析不到时按 100 处理，避免 ping 异常时漏换 IP。
get_packet_loss(){
  local output="${1:-}" loss
  loss="$({
    printf '%s\n' "$output" | awk '
      /packet loss/ {
        for (i=1; i<=NF; i++) {
          if ($i ~ /^[0-9]+(\.[0-9]+)?%$/) {
            gsub(/%/, "", $i)
            print $i
            exit
          }
        }
      }'
  } || true)"

  if [ -z "$loss" ]; then
    loss="100"
  fi
  printf '%s\n' "$loss"
}

is_loss_100(){
  local loss="${1:-100}"
  awk -v loss="$loss" 'BEGIN { exit !((loss + 0) >= 100) }'
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

  if [ -n "$before" ]; then
    log "🚀 执行换 IP（主机=${HOST_SHORT}，当前 IP=${before}）..."
  else
    log "🚀 执行换 IP（主机=${HOST_SHORT}，当前 IP 未知）..."
  fi

  for try_idx in $(seq 1 "$CHANGE_IP_MAX_ATTEMPTS"); do
    _trigger_change_ip || log "⚠️ 第 ${try_idx} 次触发失败"
    deadline=$(( $(date +%s) + CHANGE_VERIFY_WINDOW ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      sleep "$CHANGE_VERIFY_POLL"
      after="$(_get_wan_ip || echo "")"
      if [ -n "$after" ] && { [ -z "$before" ] || [ "$before" != "$after" ]; }; then
        local n=0
        [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
        n=$((n+1))
        echo "$n" > "$CHANGE_CNT_FILE"
        log "📶 已更换 IP：${before:-unknown} -> ${after}（累计 $n 次）"
        return 0
      fi
    done
    log "⏱️ ${CHANGE_VERIFY_WINDOW}s 内未检测到 IP 变化，重试..."
    sleep "$CHANGE_IP_REPEAT_DELAY"
  done

  log "😶 已触发换 IP，但未检测到公网 IP 变化"
  return 1
}

# ========== 检测：丢包率 100% 就换 IP ==========
check_ip_reachable(){
  local wan_ip ping_result packet_loss new_wan_ip new_ping_result new_packet_loss

  wan_ip="$(_get_wan_ip || echo "unknown")"
  log "🔍 当前公网 IP：${wan_ip}"
  log "🌏 Ping 检测目标：${PING_TARGET}"

  ping_result="$(ping -q -c "$PING_COUNT" -W "$PING_TIMEOUT" -i "$PING_INTERVAL" "$PING_TARGET" 2>&1 || true)"
  packet_loss="$(get_packet_loss "$ping_result")"
  log "📉 当前丢包率：${packet_loss}%"

  if is_loss_100 "$packet_loss"; then
    log "❌ 丢包率 100%，立即触发换 IP..."
    call_change_ip || log "⚠️ 调用换 IP 失败"

    log "⏳ 等待 10 秒后重新检测..."
    sleep 10

    new_wan_ip="$(_get_wan_ip || echo "unknown")"
    new_ping_result="$(ping -q -c "$PING_COUNT" -W "$PING_TIMEOUT" -i "$PING_INTERVAL" "$PING_TARGET" 2>&1 || true)"
    new_packet_loss="$(get_packet_loss "$new_ping_result")"
    log "📉 换 IP 后公网 IP：${new_wan_ip}，丢包率：${new_packet_loss}%"

    if is_loss_100 "$new_packet_loss"; then
      log "🚫 换 IP 后仍是 100% 丢包，等待下次循环继续换"
      return 1
    fi

    log "✅ 换 IP 后检测恢复"
    return 0
  fi

  log "✅ 丢包率不是 100%，不换 IP"
  return 0
}

# ========== Cloudflare 统一 API ==========
CF_API_BASE="https://api.cloudflare.com/client/v4"
CURL_API_COMMON=( -sS --connect-timeout 10 --max-time 30 --retry 3 --retry-all-errors --retry-delay 1 )

_cf_api(){
  local method="$1" url="$2" data="${3:-}"
  require_token || return 2
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
  if [ -n "$ZONE_ID_CACHE" ]; then
    printf "%s" "$ZONE_ID_CACHE"
    return 0
  fi
  log "查询 zone_id..."
  local out http body zid
  out="$(_cf_api GET "${CF_API_BASE}/zones?name=${CF_ZONE_NAME}")" || return 1
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] || { log "❌ 获取 zone 失败（HTTP ${http}）：$body"; return 1; }

  if [ $HAVE_JQ -eq 1 ]; then
    zid="$(printf "%s" "$body" | jq -r '.result[0].id // empty')"
  else
    zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  fi
  [ -n "$zid" ] || { log "❌ 未找到 zone_id"; return 1; }
  ZONE_ID_CACHE="$zid"
  printf "%s" "$zid"
}

list_records_json(){
  local zone_id="$1"
  local out http body
  out="$(_cf_api GET "${CF_API_BASE}/zones/${zone_id}/dns_records?type=${CF_RECORD_TYPE}&name=${CF_RECORD_NAME}&per_page=100")" || return 1
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] && printf "%s" "$body" || { log "❌ 列表记录失败（HTTP ${http}）：$body"; return 1; }
}

record_exists(){
  local zone_id="$1" rid="$2" out http
  out="$(_cf_api GET "${CF_API_BASE}/zones/${zone_id}/dns_records/${rid}")" || return 1
  http="${out##*|}"
  [ "$http" = "200" ]
}

patch_record(){
  local zone_id="$1" rid="$2" ip="$3" data out http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  out="$(_cf_api PATCH "${CF_API_BASE}/zones/${zone_id}/dns_records/${rid}" "$data")" || return 1
  http="${out##*|}"; body="${out%|*}"
  if [ "$http" = "200" ] || echo "$body" | grep -q '"code":81058'; then
    return 0
  fi
  log "❌ PATCH 失败（HTTP ${http}）：$body"
  return 1
}

create_record_with_comment(){
  local zone_id="$1" ip="$2" data out http body rid
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  out="$(_cf_api POST "${CF_API_BASE}/zones/${zone_id}/dns_records" "$data")" || return 1
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
  local zone_id="$1" wan_ip="$2" rid body id comment
  if [ -f "$ID_FILE" ]; then
    rid="$(cat "$ID_FILE" || true)"
    if [ -n "$rid" ] && record_exists "$zone_id" "$rid"; then
      printf "%s" "$rid"
      return 0
    fi
    log "⚠️ 缓存 record_id 不存在/无效，尝试按 comment 找回"
  fi

  body="$(list_records_json "$zone_id" || echo "")"
  if [ -n "$body" ]; then
    if [ $HAVE_JQ -eq 1 ]; then
      while IFS=$'\t' read -r id comment; do
        if printf "%s" "$comment" | grep -q "ddns:${VPS_ID}"; then
          printf "%s" "$id" > "$ID_FILE"
          printf "%s" "$id"
          return 0
        fi
      done < <(printf "%s" "$body" | jq -r '.result[]|[.id,((.comment//""))]|@tsv')
    else
      while IFS=$'\t' read -r id comment; do
        if printf "%s" "$comment" | grep -q "ddns:${VPS_ID}"; then
          printf "%s" "$id" > "$ID_FILE"
          printf "%s" "$id"
          return 0
        fi
      done < <(printf "%s" "$body" | awk '
        BEGIN{RS="{\"id\":\"";FS="\""}
        NR>1{
          id=$1
          comment=""
          if (match($0, /"comment":"[^"]*"/)) {
            comment=substr($0, RSTART+11, RLENGTH-12)
          }
          if(id!="") printf("%s\t%s\n", id, comment)
        }')
    fi
  fi

  rid="$(create_record_with_comment "$zone_id" "$wan_ip")" || return 1
  printf "%s" "$rid" > "$ID_FILE"
  printf "%s" "$rid"
}

# ========== Cloudflare 同步 ==========
sync_dns_if_needed(){
  local wan_ip zone_id rid
  wan_ip="$(_get_wan_ip)" || { log "❌ 无法获取公网 IP，跳过 Cloudflare 更新"; return 1; }

  if [ -f "$WAN_IP_FILE" ] && [ "$(cat "$WAN_IP_FILE" 2>/dev/null || echo "")" = "$wan_ip" ]; then
    log "ℹ️ 公网 IP 未变化（${wan_ip}），跳过 Cloudflare 更新"
    return 0
  fi

  zone_id="$(get_zone_id)" || return 1
  rid="$(get_or_create_own_record_id "$zone_id" "$wan_ip")" || return 1

  if patch_record "$zone_id" "$rid" "$wan_ip"; then
    log "✅ 已更新记录：${CF_RECORD_NAME} -> ${wan_ip} [id=${rid}]"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败"
    return 1
  fi
}

# ========== 主循环 ==========
log "🚀 启动 DDNS（主机=${HOST_FULL} / VPS_ID=${VPS_ID}）"
log "记录=${CF_RECORD_NAME} 类型=${CF_RECORD_TYPE} TTL=${CFTTL}s PROXIED=${PROXIED}"
log "检测目标=${PING_TARGET}；规则：丢包率 100% 就换 IP"

while true; do
  if check_ip_reachable; then
    sync_dns_if_needed || true
  else
    # 即使新 IP 仍 100% 丢包，也尝试同步 DNS，方便切 IP 后直接可用
    sync_dns_if_needed || true
  fi

  [ -f "$CHANGE_CNT_FILE" ] && log "📊 累计换 IP 次数：$(cat "$CHANGE_CNT_FILE")"
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
