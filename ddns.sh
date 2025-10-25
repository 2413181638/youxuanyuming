#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ========== 固定配置（注意安全） ==========
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"      # A / AAAA
CFTTL=120
PROXIED="false"         # true / false（不带引号进 JSON）

# WAN IP 源
WANIPSITE_IPV4="http://ipv4.icanhazip.com"
WANIPSITE_IPV6="http://ipv6.icanhazip.com"

# ========== 多 VPS 独立状态 ==========
VPS_ID="${VPS_ID:-$(hostname -s || echo vps)}"
STATE_DIR="${HOME}/.cf-ddns"
mkdir -p "${STATE_DIR}"
ID_FILE="${STATE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"    # 本机专属 record_id
WAN_IP_FILE="${STATE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"
CHANGE_CNT_FILE="${STATE_DIR}/cf-change_count_${CF_RECORD_NAME}.txt"

# ========== 连通性检测 ==========
TARGET_DOMAINS=("email.163.com" "guanjia.qq.com" "weixin.qq.com")
PING_COUNT=10
PING_GAP=3
CHECK_INTERVAL=30

# ========== 工具 ==========
log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*" >&2; }
require_token(){ [ -n "$CF_API_TOKEN" ] || { log "❌ CF_API_TOKEN 为空"; exit 2; }; }

# 统一 Cloudflare API：输出 "BODY|HTTP"
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

_trim(){ printf "%s" "$1" | tr -d '\r\n'; }

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

change_ip(){
  log "🚀 更换 IP via curl 192.168.10.253 ..."
  curl -fsS 192.168.10.253 >/dev/null 2>&1 || log "⚠️ 切换接口未响应"
  sleep 10
  local n=0; [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
  n=$((n+1)); echo "$n" > "$CHANGE_CNT_FILE"
  log "📶 已更换 IP；累计：$n"
}

# ========== Cloudflare 相关（多 VPS 互不影响） ==========
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

# 列出同名记录（JSON body）
list_records_json(){
  local zone_id="$1"
  local out http body
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records?type=${CF_RECORD_TYPE}&name=${CF_RECORD_NAME}&per_page=100")"
  http="${out##*|}"; body="${out%|*}"
  [ "$http" = "200" ] && printf "%s" "$body" || return 1
}

# 解析出 (id content comment) 三元组；输出：id<TAB>content<TAB>comment
extract_id_content_comment(){
  awk '
    BEGIN{ RS="{\"id\":\""; FS="\""; }
    NR>1 {
      id=$1; content=""; comment="";
      match($0, /"content":"([^"]+)"/, m1); if (m1[1]!="") content=m1[1];
      match($0, /"comment":"([^"]+)"/, m2); if (m2[1]!="") comment=m2[1];
      if (id!="") { printf("%s\t%s\t%s\n", id, content, comment); }
    }'
}

# 是否存在任意同名记录 content == ip（避免无意义更新/81058）
any_record_has_ip(){
  local zone_id="$1" ip="$2"
  local body; body="$(list_records_json "$zone_id" || echo "")"
  [ -n "$body" ] || return 1
  echo "$body" | grep -F "\"content\":\"${ip}\"" >/dev/null 2>&1
}

# 校验 record 是否存在
record_exists(){
  local zone_id="$1" rid="$2"
  local http out
  out="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}")"
  http="${out##*|}"
  [ "$http" = "200" ]
}

# PATCH 只改 content/ttl/proxied
patch_record(){
  local zone_id="$1" rid="$2" ip="$3" data out http body
  data=$(printf '{"content":"%s","ttl":%s,"proxied":%s}' "$ip" "$CFTTL" "$PROXIED")
  out="$(_cf_api PATCH "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}" "$data")"
  http="${out##*|}"; body="${out%|*}"
  if [ "$http" = "200" ] || echo "$body" | grep -q '"code":81058'; then return 0; fi
  log "❌ PATCH 失败（HTTP ${http}）：$body"; return 1
}

# POST 创建新记录（直接用真实 IP；添加 comment=ddns:VPS_ID）
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

# 找回“属于本机的记录”：先用缓存，其次在同名记录中按 comment=ddns:VPS_ID 匹配
get_or_create_own_record_id(){
  local zone_id="$1" wan_ip="$2" rid body line id content comment

  # 1) 缓存 id 可用就直接用
  if [ -f "$ID_FILE" ]; then
    rid="$(cat "$ID_FILE" || true)"
    if [ -n "$rid" ] && record_exists "$zone_id" "$rid"; then
      printf "%s" "$rid"; return 0
    fi
    log "⚠️ 缓存 record_id 不存在/无效，尝试按 comment 找回"
  fi

  # 2) 在现有同名记录里按 comment=ddns:VPS_ID 找回
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

  # 3) 没有就创建新记录（直接写真实 IP；绝不 0.0.0.0）
  rid="$(create_record_with_comment "$zone_id" "$wan_ip")" || return 1
  printf "%s" "$rid" > "$ID_FILE"
  printf "%s" "$rid"
}

# ========== 同步核心：多 VPS 版 ==========
sync_dns_if_needed(){
  local wan_ip zone_id rid body own_ip

  # 真实公网 IP 必须拿到且校验通过
  wan_ip="$(_get_wan_ip)" || { log "❌ 未获合法公网 IP，跳过"; return 1; }

  zone_id="$(get_zone_id)" || return 1

  # 可达时：若任意同名记录已等于该 IP，则本轮完全跳过
  if any_record_has_ip "$zone_id" "$wan_ip"; then
    log "ℹ️ 已有同名记录等于当前 IP（$wan_ip），跳过本轮"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi

  # 只维护“本机这条”：找回/创建自己的记录
  rid="$(get_or_create_own_record_id "$zone_id" "$wan_ip")" || return 1

  # 查询自己记录当前 content
  body="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}")"
  if [ "${body##*|}" != "200" ]; then
    log "⚠️ 获取自身记录失败，尝试直接 PATCH"
  else
    own_ip="$(printf "%s" "${body%|*}" | grep -Po '(?<="content":")[^"]*' | head -1 || true)"
    if [ "$own_ip" = "$wan_ip" ]; then
      log "ℹ️ 自身记录已是当前 IP（$wan_ip），跳过更新"
      echo "$wan_ip" > "$WAN_IP_FILE"
      return 0
    fi
  fi

  # 更新自己这条为当前 IP
  if patch_record "$zone_id" "$rid" "$wan_ip"; then
    log "✅ 已更新自身记录：${CF_RECORD_NAME} -> ${wan_ip}  [id=${rid}]"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败（但不会影响其它机器记录）"
  fi
}

# ========== 主循环 ==========
log "启动 DDNS（多 VPS 友好：每台只维护自己的记录；绝不写 0.0.0.0；不删他人记录）"
log "VPS_ID=${VPS_ID}  记录名=${CF_RECORD_NAME}  类型=${CF_RECORD_TYPE}  TTL=${CFTTL}s  PROXIED=${PROXIED}"

while true; do
  if check_ip_reachable; then
    # 可达：仅在需要时更新自己这条（若已有任意记录=当前IP则整轮跳过）
    sync_dns_if_needed || true
  else
    # 不可达：先换 IP，再同步
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
