#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ========== 固定配置（注意安全） ==========
CF_API_TOKEN="${CF_API_TOKEN:-"iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"}"  # 建议改为仅用环境变量
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"          # A / AAAA
CFTTL=120
PROXIED="false"             # true / false（不带引号进 JSON）

# ========== 外网 IP 源（多源兜底 + 重试） ==========
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
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"          # 本机专属 record_id
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"  # 上次已写入的 IP
CHANGE_CNT_FILE="${STATE_DIR}/cf-change_count_${CF_RECORD_NAME}.txt"  # 更换成功次数
PID_FILE="${STATE_DIR}/ddns_${VPS_ID}.pid"                            # 防多开

# ========== 连通性检测（更严格） ==========
TARGET_DOMAINS=(
  "xiaoshuo.wtzw.com"
  "email.163.com"
  "163.com"
  "baidu.com"
  "shui5.cn"
)
PING_COUNT=3                   # 对同一域名最多 ping 次数
PING_GAP=1                     # 同一域名 ping 间隔
PING_TIMEOUT=3                 # ping 单次等待秒数（-W）
PING_MIN_OK=1                  # ✅ 至少有 N 个不同站点各自成功一次才算“网络正常/没墙”
RANDOMIZE_DOMAINS=true         # 每轮随机检测顺序，减少偶发影响
CHECK_INTERVAL=30              # 主循环间隔

# （已弃用：旧版在触发后固定 sleep 再看 IP，会误判超时。现改为轮询确认。）
# CHANGE_IP_WAIT=10

# 可选：对“判定为可达的域名”，再做一次 HTTP 头部请求确认（能 ping 不代表业务可用）
PING_HTTP_CONFIRM="false"      # 默认为 false，需要时改为 true
HTTP_CHECK_TIMEOUT=5

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

# IP 源选择 & 校验
case "$PROXIED" in true|false) : ;; *) echo "PROXIED 必须为 true 或 false"; exit 2;; esac

validate_ip(){
  local ip="$1"
  if [ "$CF_RECORD_TYPE" = "A" ]; then
    [[ "$ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]
  else
    # 简化/稳健的 IPv6 判断
    [[ "$ip" =~ ^([0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}$ ]]
  fi
}

_get_wan_ip(){
  local sites=()
  if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
    sites=("${WANIPSITES_IPV6[@]}")
  else
    sites=("${WANIPSITES_IPV4[@]}")
  fi
  local s ip
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

_http_reachable(){
  # 对目标域名做一次轻量 HTTP 测试，HTTPS 优先
  local host="$1"
  curl -fsS -I --connect-timeout "$HTTP_CHECK_TIMEOUT" --max-time "$HTTP_CHECK_TIMEOUT" "https://$host" >/dev/null 2>&1 \
  || curl -fsS -I --connect-timeout "$HTTP_CHECK_TIMEOUT" --max-time "$HTTP_CHECK_TIMEOUT" "http://$host" >/dev/null 2>&1
}

check_ip_reachable(){
  # 至少有 PING_MIN_OK 个不同站点在本轮检测中各自成功 ping ≥ 1 次（可选 HTTP 确认）
  local domains=("${TARGET_DOMAINS[@]}")
  if $RANDOMIZE_DOMAINS && _has shuf; then
    IFS=$'\n' read -r -d '' -a domains < <(printf '%s\n' "${domains[@]}" | shuf && printf '\0')
  fi

  log "🔍 连通性检测：${#domains[@]} 个站点 × ${PING_COUNT} 次；至少 ${PING_MIN_OK} 个站点成功一次${PING_HTTP_CONFIRM:+（含 HTTP 确认）}"

  local success_hosts=0
  local d i ok_ping ok_http

  for d in "${domains[@]}"; do
    ok_ping=0
    for ((i=1;i<=PING_COUNT;i++)); do
      if ping -n -c 1 -W "$PING_TIMEOUT" "$d" >/dev/null 2>&1; then
        ok_ping=1
        log "✅ ${d}: 第 ${i}/${PING_COUNT} 次 ping 成功"
        break
      else
        log "⚠️  ${d}: 第 ${i}/${PING_COUNT} 次 ping 失败"
        [ $i -lt $PING_COUNT ] && sleep "$PING_GAP"
      fi
    done

    if [ $ok_ping -eq 1 ]; then
      if [ "$PING_HTTP_CONFIRM" = "true" ]; then
        ok_http=0
        if _http_reachable "$d"; then
          ok_http=1
          log "🌐 ${d}: HTTP 连通性确认成功"
        else
          log "🕳️  ${d}: HTTP 连通性确认失败（可能仅 ICMP 可达）"
        fi
        [ $ok_http -eq 1 ] && success_hosts=$((success_hosts+1))
      else
        success_hosts=$((success_hosts+1))
      fi
    fi

    if [ "$success_hosts" -ge "$PING_MIN_OK" ]; then
      log "✅ 连通性达标：本轮已统计到 ${success_hosts} 个站点可达（阈值 ${PING_MIN_OK}）—— 网络【正常】"
      return 0
    fi
  done

  log "❌ 连通性不足：仅 ${success_hosts} 个站点达标（阈值 ${PING_MIN_OK}）—— 网络【不通/被墙】"
  return 1
}

# ========== Cloudflare 统一 API（加重试/超时） ==========
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

extract_id_content_comment(){
  # jq 不可用时的回退
  awk 'BEGIN{RS="{\"id\":\"";FS="\""} NR>1{ id=$1; cmm=""; cnt="";
       match($0,/"content":"([^"]+)"/,m1); if(m1[1]!="")cnt=m1[1];
       match($0,/"comment":"([^"]+)"/,m2); if(m2[1]!="")cmm=m2[1];
       if(id!="")printf("%s\t%s\t%s\n",id,cnt,cmm); }'
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
      done < <(printf "%s" "$body" | extract_id_content_comment)
    fi
  fi

  rid="$(create_record_with_comment "$zone_id" "$wan_ip")" || return 1
  printf "%s" "$rid" > "$ID_FILE"
  printf "%s" "$rid"
}

# ========== 换 IP：非阻塞触发 + 轮询确认（更稳健） ==========
# 触发请求允许更长时间（网关脚本可能边拨号边输出）
CHANGE_IP_HTTP_TIMEOUT=60
# 轮询确认窗口与频率
CHANGE_VERIFY_WINDOW=90      # 触发后最多等待 90s 观察 IP 是否变化
CHANGE_VERIFY_POLL=5         # 轮询间隔 5s
CHANGE_IP_MAX_ATTEMPTS=2     # 未变更时最多再触发 1 次（共 2 次）
CHANGE_IP_REPEAT_DELAY=10    # 两次触发之间缓冲 10s

# 根据主机名选择对应的换 IP URL（含 xqtw3）
_change_ip_target_url(){
  local host_all="${HOST_SHORT} ${HOST_FULL}"
  case "$host_all" in
    (*xqtw1*) echo "http://192.168.10.253" ;;
    (*xqtw2*|*xqtw3*) echo "http://10.10.8.10/ip/change.php" ;;
    (*) echo "http://192.168.10.253" ;;   # 默认第一台逻辑；也可改为: echo ""; return 1
  esac
}

# 只负责发起一次触发（后台执行，避免阻塞/超时）
_trigger_change_ip(){
  local url; url="$(_change_ip_target_url)" || return 1
  log "↻ 触发换 IP：host='${HOST_SHORT}' -> ${url}"
  ( curl -sS --connect-timeout 3 --max-time "$CHANGE_IP_HTTP_TIMEOUT" "$url" >/dev/null 2>&1 ) &
  return 0
}

call_change_ip(){
  local before after deadline try_idx
  before="$(_get_wan_ip || echo "")"
  log "🚀 执行换 IP（按主机名：$HOST_SHORT）..."

  for try_idx in $(seq 1 "$CHANGE_IP_MAX_ATTEMPTS"); do
    if ! _trigger_change_ip; then
      log "⚠️ 第 ${try_idx} 次触发换 IP 调用失败（未能发起请求）"
    fi

    # 轮询等待外网 IP 变化
    deadline=$(( $(date +%s) + CHANGE_VERIFY_WINDOW ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      sleep "$CHANGE_VERIFY_POLL"
      after="$(_get_wan_ip || echo "")"
      if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
        local n=0; [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
        n=$((n+1)); echo "$n" > "$CHANGE_CNT_FILE"
        log "📶 判定为【已更换 IP】：${before} -> ${after}（累计 $n 次）"
        return 0
      fi
    done

    # 本次窗口内未变化：若还可重试，则等待一会儿再次触发
    if [ "$try_idx" -lt "$CHANGE_IP_MAX_ATTEMPTS" ]; then
      log "⏱️ ${CHANGE_VERIFY_WINDOW}s 内未检测到变化，${CHANGE_IP_REPEAT_DELAY}s 后进行第 $((try_idx+1)) 次触发..."
      sleep "$CHANGE_IP_REPEAT_DELAY"
    fi
  done

  log "😶 未检测到 IP 变化（before='${before}', after='${after}'，窗口 ${CHANGE_VERIFY_WINDOW}s × ${CHANGE_IP_MAX_ATTEMPTS} 次触发）"
  return 1
}

# ========== 同步核心：多 VPS 版 ==========
sync_dns_if_needed(){
  local wan_ip zone_id rid body own_ip

  wan_ip="$(_get_wan_ip)" || { log "❌ 未获合法公网 IP，跳过"; return 1; }
  zone_id="$(get_zone_id)" || return 1

  # 若任意同名记录已有当前 IP → 整轮跳过
  if any_record_has_ip "$zone_id" "$wan_ip"; then
    log "ℹ️ 已有同名记录等于当前 IP（$wan_ip），跳过本轮"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  # 只维护“本机这条”
  rid="$(get_or_create_own_record_id "$zone_id" "$wan_ip")" || return 1

  # 自己这条是否已等于当前 IP
  body="$(_cf_api GET "${CF_API_BASE}/zones/${zone_id}/dns_records/${rid}")"
  if [ "${body##*|}" = "200" ]; then
    if [ $HAVE_JQ -eq 1 ]; then
      own_ip="$(printf "%s" "${body%|*}" | jq -r '.result.content // empty')"
    else
      own_ip="$(printf "%s" "${body%|*}" | grep -Po '(?<="content":")[^"]*' | head -1 || true)"
    fi
    if [ "$own_ip" = "$wan_ip" ]; then
      log "ℹ️ 自身记录已是当前 IP（$wan_ip），跳过更新"
      echo "$wan_ip" > "$WAN_IP_FILE"
      return 0
    fi
  fi

  # 更新自己这条
  if patch_record "$zone_id" "$rid" "$wan_ip"; then
    log "✅ 已更新自身记录：${CF_RECORD_NAME} -> ${wan_ip}  [id=${rid}]"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败（不影响其它机器记录）"
  fi
}

# ========== 主循环 ==========
log "启动 DDNS（主机=${HOST_FULL} / VPS_ID=${VPS_ID}）"
log "记录=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

while true; do
  if check_ip_reachable; then
    # 可达：仅在需要时更新自己这条（若已有任意记录=当前IP则整轮跳过）
    sync_dns_if_needed || true
  else
    # 不可达：触发换 IP（后台）→ 轮询确认 → 再尝试同步
    call_change_ip || true
    sync_dns_if_needed || true
  fi

  # 展示累计换 IP 次数
  if [ -f "$CHANGE_CNT_FILE" ]; then
    log "📊 累计更换 IP 次数：$(cat "$CHANGE_CNT_FILE" || echo 0)"
  fi
  log "⏳ ${CHECK_INTERVAL}s 后再次检测..."
  sleep "$CHECK_INTERVAL"
done
