#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ========== 固定配置（注意安全） ==========
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"          # A / AAAA
CFTTL=120
PROXIED="false"             # true / false（不带引号进 JSON）

# WAN IP 源
WANIPSITE_IPV4="http://ipv4.icanhazip.com"
WANIPSITE_IPV6="http://ipv6.icanhazip.com"

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

# ========== 连通性检测 ==========
TARGET_DOMAINS=("email.163.com" "www.bilibili.com" "163.com","tieba.baidu.com")
PING_COUNT=3
PING_GAP=1
CHECK_INTERVAL=30
CHANGE_IP_WAIT=10

# ========== 常用工具 ==========
log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }
require_token(){ [ -n "$CF_API_TOKEN" ] || { log "❌ CF_API_TOKEN 为空"; exit 2; }; }
_trim(){ printf "%s" "$1" | tr -d '\r\n'; }

# 防多开
if [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; then
  log "ℹ️ 已在运行 (pid=$(cat "$PID_FILE"))，本次退出"
  exit 0
fi
echo $$ > "$PID_FILE"
trap 'rm -f "$PID_FILE" >/dev/null 2>&1 || true' EXIT

# IP 源选择 & 校验
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then WANIPSITE="$WANIPSITE_IPV6"; else WANIPSITE="$WANIPSITE_IPV4"; fi
case "$PROXIED" in true|false) : ;; *) echo "PROXIED 必须为 true 或 false"; exit 2;; esac

validate_ip(){
  local ip="$1"
  if [ "$CF_RECORD_TYPE" = "A" ]; then
    [[ "$ip" =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9]?[0-9])$ ]]
  else
    [[ "$ip" =~ ^(([0-9A-Fa-f]{1,4}:){1,7}:?|:((:[0-9A-Fa-f]{1,4}){1,7}))$|^(([0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4})$ ]]
  fi
}

_get_wan_ip(){
  local ip; ip=$(curl -fsS "$WANIPSITE" || true); ip="$(_trim "${ip:-}")"
  [ -n "$ip" ] && validate_ip "$ip" && { printf "%s" "$ip"; return 0; }
  return 1
}

# 多域名 ping：任意一次成功 -> 可达
check_ip_reachable(){
  log "🔍 连通性检测（${TARGET_DOMAINS[*]} × ${PING_COUNT}）"
  local d i
  for d in "${TARGET_DOMAINS[@]}"; do
    for ((i=1;i<=PING_COUNT;i++)); do
      if ping -c 1 -W 3 "$d" >/dev/null 2>&1; then
        log "✅ ${d}: 第 ${i}/${PING_COUNT} 次 ping 成功 —— 网络【正常】"
        return 0
      else
        log "⚠️  ${d}: 第 ${i}/${PING_COUNT} 次 ping 失败"
        [ $i -lt $PING_COUNT ] && sleep "$PING_GAP"
      fi
    done
  done
  log "❌ 所有目标均未通 —— 网络【不通/被墙】"
  return 1
}

# ========== Cloudflare 统一 API ==========
_cf_api(){
  local method="$1" url="$2" data="${3:-}"
  require_token
  if [ -n "$data" ]; then
    curl -sS -X "$method" "$url" -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" --data "$data" -w '|%{http_code}'
  else
    curl -sS -X "$method" "$url" -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" -w '|%{http_code}'
  fi
}

ZONE_ID_CACHE=""
get_zone_id(){
  if [ -n "$ZONE_ID_CACHE" ]; then printf "%s" "$ZONE_ID_CACHE"; return 0; fi
  log "查询 zone_id..."
  local out http body zid
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] || { log "❌ 获取 zone 失败（HTTP ${http}）：$body"; return 1; }
  zid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
  [ -n "$zid" ] || { log "❌ 未找到 zone_id"; return 1; }
  ZONE_ID_CACHE="$zid"; printf "%s" "$zid"
}

list_records_json(){
  local zone_id="$1"
  local out http body
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=${CF_RECORD_TYPE}&name=${CF_RECORD_NAME}&per_page=100")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] && printf "%s" "$body" || return 1
}

extract_id_content_comment(){
  awk 'BEGIN{RS="{\"id\":\"";FS="\""} NR>1{ id=$1; cmm=""; cnt="";
       match($0,/"content":"([^"]+)"/,m1); if(m1[1]!="")cnt=m1[1];
       match($0,/"comment":"([^"]+)"/,m2); if(m2[1]!="")cmm=m2[1];
       if(id!="")printf("%s\t%s\t%s\n",id,cnt,cmm); }'
}

any_record_has_ip(){
  local zone_id="$1" ip="$2"
  local body; body="$(list_records_json "$zone_id" || echo "")"
  [ -n "$body" ] || return 1
  echo "$body" | grep -F "\"content\":\"${ip}\"" >/dev/null 2>&1
}

record_exists(){
  local zone_id="$1" rid="$2"
  local out http
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}")"
  http="${out##*|}"
  [ "$http" = "200" ]
}

patch_record(){
  local zone_id="$1" rid="$2" ip="$3" data out http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  out="$(_cf_api PATCH "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}" "$data")"
  http="${out##*|}"; body="${out%|*}"
  if [ "$http" = "200" ] || echo "$body" | grep -q '"code":81058'; then return 0; fi
  log "❌ PATCH 失败（HTTP ${http}）：$body"; return 1
}

create_record_with_comment(){
  local zone_id="$1" ip="$2" data out http body rid
  data=$(printf '{"type":"%s","name":"%s","content":"%s","ttl":%s,"proxied":%s,"comment":"ddns:%s"}' \
        "$CF_RECORD_TYPE" "$CF_RECORD_NAME" "$ip" "$CFTTL" "$PROXIED" "$VPS_ID")
  out="$(_cf_api POST "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records" "$data")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] || [ "$http" = "201" ] || { log "❌ 创建失败（HTTP ${http}）：$body"; return 1; }
  rid=$(echo "$body" | grep -Po '(?<="id":")[^"]*' | head -1 || true)
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
    while IFS=$'\t' read -r id content comment; do
      if printf "%s" "$comment" | grep -q "ddns:${VPS_ID}"; then
        printf "%s" "$id" > "$ID_FILE"
        printf "%s" "$id"
        return 0
      fi
    done < <(printf "%s" "$body" | extract_id_content_comment)
  fi
  rid="$(create_record_with_comment "$zone_id" "$wan_ip")" || return 1
  printf "%s" "$rid" > "$ID_FILE"
  printf "%s" "$rid"
}

# ========== 主机名映射的“写死”换 IP 指令 ==========
_change_ip_by_host(){
  # 统一用 host 名判断；同时兼容用户提示里“root@xqtw1”的说法
  if [[ "$HOST_SHORT" == *xqtw1* ]] || [[ "$HOST_FULL" == *xqtw1* ]]; then
    # 第一台：xqtw1
    curl -fsS 192.168.10.253 >/dev/null
  elif [[ "$HOST_SHORT" == *xqtw2* ]] || [[ "$HOST_FULL" == *xqtw2* ]]; then
    # 第二台：xqtw2
    curl -fsS 'http://10.10.8.10/ip/change.php' >/dev/null
  else
    # 未匹配到时，默认走第一台逻辑（你也可改为直接 return 1）
    curl -fsS 192.168.10.253 >/dev/null
  fi
}

call_change_ip(){
  local before after
  before="$(_get_wan_ip || echo "")"
  log "🚀 执行换 IP（按主机名：$HOST_SHORT）..."
  if ! _change_ip_by_host; then
    log "⚠️ 换 IP 调用失败（命令返回非 0）"
  fi
  sleep "$CHANGE_IP_WAIT"
  after="$(_get_wan_ip || echo "")"
  if [ -n "$before" ] && [ -n "$after" ] && [ "$before" != "$after" ]; then
    local n=0; [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
    n=$((n+1)); echo "$n" > "$CHANGE_CNT_FILE"
    log "📶 判定为【已更换 IP】：${before} -> ${after}（累计 $n 次）"
    return 0
  else
    log "😶 未检测到 IP 变化（before='${before}', after='${after}'）"
    return 1
  fi
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
  body="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}")"
  if [ "${body##*|}" = "200" ]; then
    own_ip="$(printf "%s" "${body%|*}" | grep -Po '(?<="content":")[^"]*' | head -1 || true)"
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
    # 不可达：按主机名写死的换 IP → 再尝试同步
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
