#!/usr/bin/env bash
# ddns.sh — Cloudflare DDNS（多 VPS / 防多开 / TUI 面板 / 自定义换 IP / 在线更新 / 节点列表）
set -o errexit
set -o nounset
set -o pipefail

# ===================== 基本配置（可用环境变量覆盖） =====================
CF_API_TOKEN="${CF_API_TOKEN:-iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1}"
CF_ZONE_NAME="${CF_ZONE_NAME:-5653111.xyz}"
CF_RECORD_NAME="${CF_RECORD_NAME:-twddns.5653111.xyz}"
CF_RECORD_TYPE="${CF_RECORD_TYPE:-A}"    # A / AAAA
CFTTL="${CFTTL:-120}"
PROXIED="${PROXIED:-false}"              # true / false
CHECK_INTERVAL="${CHECK_INTERVAL:-30}"

UPDATE_URL_DEFAULT="https://raw.githubusercontent.com/2413181638/youxuanyuming/refs/heads/main/ddns.sh"

# WAN IP 源
WANIPSITE_IPV4="http://ipv4.icanhazip.com"
WANIPSITE_IPV6="http://ipv6.icanhazip.com"

# ===================== 状态/路径 =====================
VPS_ID="${VPS_ID:-$(hostname -s 2>/dev/null || echo vps)}"
BASE_DIR="${HOME}/.cf-ddns"
mkdir -p "${BASE_DIR}"
PID_FILE="${BASE_DIR}/ddns_${VPS_ID}.pid"
LOG_FILE="${BASE_DIR}/ddns_${VPS_ID}.log"
ID_FILE="${BASE_DIR}/cf-id_${CF_RECORD_NAME}_${VPS_ID}.txt"
WAN_IP_FILE="${BASE_DIR}/cf-wan_ip_${CF_RECORD_NAME}_${VPS_ID}.txt"
CHANGE_CNT_FILE="${BASE_DIR}/cf-change_count_${CF_RECORD_NAME}.txt"
CONF_FILE="${BASE_DIR}/config_${VPS_ID}.env"

# ===================== 连通性检测 =====================
TARGET_DOMAINS=("email.163.com" "guanjia.qq.com" "weixin.qq.com")
PING_COUNT=10
PING_GAP=3

# ===================== 工具函数 =====================
log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
require_token(){ [ -n "$CF_API_TOKEN" ] || { log "❌ CF_API_TOKEN 为空"; exit 2; }; }
_trim(){ printf "%s" "$1" | tr -d '\r\n'; }

# 载入/初始化配置
load_config(){
  CHANGE_IP_CMD_DEFAULT='curl -fsS 192.168.10.253 >/dev/null 2>&1 || true'
  UPDATE_URL="${UPDATE_URL:-$UPDATE_URL_DEFAULT}"
  CHANGE_IP_CMD="$CHANGE_IP_CMD_DEFAULT"
  if [ -f "$CONF_FILE" ]; then . "$CONF_FILE"; fi
  [ -z "${CHANGE_IP_CMD:-}" ] && CHANGE_IP_CMD="$CHANGE_IP_CMD_DEFAULT"
  [ -z "${UPDATE_URL:-}" ] && UPDATE_URL="$UPDATE_URL_DEFAULT"
}
save_config(){
  cat >"$CONF_FILE" <<EOF
VPS_ID="${VPS_ID}"
CHANGE_IP_CMD=${CHANGE_IP_CMD@Q}
UPDATE_URL=${UPDATE_URL@Q}
CHECK_INTERVAL="${CHECK_INTERVAL}"
EOF
  chmod 600 "$CONF_FILE" || true
}

# 统一 Cloudflare API：输出 "BODY|HTTP"
_cf_api(){
  local method="$1" url="$2" data="${3:-}"; require_token
  if [ -n "$data" ]; then
    curl -sS -X "$method" "$url" -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" --data "$data" -w '|%{http_code}'
  else
    curl -sS -X "$method" "$url" -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" -w '|%{http_code}'
  fi
}

# ===================== IP 与连接性 =====================
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then WANIPSITE="$WANIPSITE_IPV6"; else WANIPSITE="$WANIPSITE_IPV4"; fi
case "$PROXIED" in true|false) : ;; *) echo "PROXIED 必须为 true 或 false（当前：$PROXIED）" >&2; exit 2;; esac

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

# 自定义换 IP（来自配置）
change_ip(){
  load_config
  log "🚀 执行换 IP 命令：${CHANGE_IP_CMD}"
  bash -lc "$CHANGE_IP_CMD" || true
  sleep 10
  local n=0; [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
  n=$((n+1)); echo "$n" > "$CHANGE_CNT_FILE"
  log "📶 已触发更换 IP；累计更换次数：${n}"
}

# ===================== Cloudflare（多 VPS 互不影响） =====================
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

# 输出：id<TAB>content<TAB>comment
extract_id_content_comment(){
  awk 'BEGIN{RS="{\"id\":\"";FS="\""} NR>1{ id=$1; cmm=""; cnt=""; match($0,/"content":"([^"]+)"/,m1); if(m1[1]!="")cnt=m1[1]; match($0,/"comment":"([^"]+)"/,m2); if(m2[1]!="")cmm=m2[1]; if(id!="")printf("%s\t%s\t%s\n",id,cnt,cmm); }'
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

sync_dns_if_needed(){
  local wan_ip zone_id rid body own_ip
  wan_ip="$(_get_wan_ip)" || { log "❌ 未获合法公网 IP，跳过"; return 1; }
  zone_id="$(get_zone_id)" || return 1
  if any_record_has_ip "$zone_id" "$wan_ip"; then
    log "ℹ️ 已有同名记录等于当前 IP（$wan_ip），跳过本轮"
    echo "$wan_ip" > "$WAN_IP_FILE"
    return 0
  fi
  rid="$(get_or_create_own_record_id "$zone_id" "$wan_ip")" || return 1
  body="$(_cf_api GET "https://api.cloudflare.com/client/v4/zones/${zone_id}/dns_records/${rid}")"
  if [ "${body##*|}" = "200" ]; then
    own_ip="$(printf "%s" "${body%|*}" | grep -Po '(?<="content":")[^"]*' | head -1 || true)"
    if [ "$own_ip" = "$wan_ip" ]; then
      log "ℹ️ 自身记录已是当前 IP（$wan_ip），跳过更新"
      echo "$wan_ip" > "$WAN_IP_FILE"; return 0
    fi
  fi
  if patch_record "$zone_id" "$rid" "$wan_ip"; then
    log "✅ 已更新自身记录：${CF_RECORD_NAME} -> ${wan_ip}  [id=${rid}]"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败（不影响其它机器记录）"
  fi
}

# ===================== 集群节点列表（第 n 台 & 当前 IP） =====================
# 生成排序后的节点列表，行格式：序号<TAB>VPS_ID<TAB>IP<TAB>record_id
list_nodes_sorted(){
  local zone_id body
  zone_id="$(get_zone_id)" || return 1
  body="$(list_records_json "$zone_id" || echo "")"
  [ -n "$body" ] || return 0
  # 提取 -> 解析 VPS_ID -> 排序 -> 编号
  # 输出：序号\tVPS_ID\tIP\tRID
  printf "%s" "$body" | extract_id_content_comment \
  | awk -F'\t' '
      {
        id=$1; ip=$2; c=$3; v="unknown";
        if (c ~ /ddns:/) { split(c,a,"ddns:"); v=a[2]; sub(/[ ,;].*$/,"",v); }
        printf("%s\t%s\t%s\n", v, ip, id);
      }
    ' \
  | sort -t$'\t' -k1,1 \
  | awk -F'\t' '{printf("%d\t%s\t%s\t%s\n", NR, $1, $2, $3)}'
}

# 打印节点表，并返回：本机序号 + 总数
print_nodes_table(){
  local rows my_idx=0 total=0
  mapfile -t rows < <(list_nodes_sorted || true)
  total="${#rows[@]}"
  if [ "$total" -eq 0 ]; then
    echo "（无同名记录）"
    return 0
  fi
  printf "序号  VPS_ID                 当前IP             记录ID（后6位）\n"
  printf "----  --------------------   -----------------   --------------\n"
  local row idx vps ip rid mark
  for row in "${rows[@]}"; do
    idx="${row%%$'\t'*}"; rest="${row#*$'\t'}"
    vps="${rest%%$'\t'*}"; rest="${rest#*$'\t'}"
    ip="${rest%%$'\t'*}"; rid="${rest##*$'\t'}"
    mark=" "; if [ "$vps" = "$VPS_ID" ]; then mark="*"; my_idx="$idx"; fi
    printf "%-4s %-20s   %-17s   %s\n" "${idx}${mark}" "$vps" "$ip" "${rid: -6}"
  done
  # 返回值通过 echo
  echo "MY_INDEX=$my_idx TOTAL=$total"
}

# ===================== 防多开 / 守护进程 =====================
is_running(){ [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; }
KILL_DUPLICATES(){
  local key1="ddns.sh" key2="/usr/local/bin/ddns" me="$$"
  pgrep -f "$key1|$key2|${BASE_DIR}|${CF_RECORD_NAME}" 2>/dev/null | while read -r p; do
    [ "$p" = "$me" ] && continue
    if ps -o cmd= -p "$p" | grep -Eq "$key1|$key2|${BASE_DIR}|${CF_RECORD_NAME}"; then
      kill "$p" 2>/dev/null || true
    fi
  done
}
start_daemon(){
  load_config
  if is_running; then log "ℹ️ 守护进程已在运行 (pid=$(cat "$PID_FILE"))"; return 0; fi
  KILL_DUPLICATES
  log "▶️ 启动 DDNS 守护进程…（间隔 ${CHECK_INTERVAL}s）"
  nohup bash -lc "
    trap 'exit 0' TERM INT
    while true; do
      if check_ip_reachable; then
        sync_dns_if_needed || true
      else
        change_ip
        sleep 10
        sync_dns_if_needed || true
      fi
      if [ -f '$CHANGE_CNT_FILE' ]; then
        echo \"\$(date '+%F %T') 📊 累计更换 IP 次数：\$(cat '$CHANGE_CNT_FILE' || echo 0)\" >> '$LOG_FILE'
      fi
      echo \"\$(date '+%F %T') ⏳ ${CHECK_INTERVAL}s 后再次检测...\" >> '$LOG_FILE'
      sleep $CHECK_INTERVAL
    done
  " >>"$LOG_FILE" 2>&1 &
  echo $! > "$PID_FILE"
  disown || true
  log "✅ 已启动 (pid=$(cat "$PID_FILE"))；日志：$LOG_FILE"
}
stop_daemon(){
  if is_running; then
    kill "$(cat "$PID_FILE")" 2>/dev/null || true
    sleep 1
    is_running && kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true
    rm -f "$PID_FILE"
    log "🛑 已停止"
  else
    log "ℹ️ 未运行"
  fi
}
restart_daemon(){ stop_daemon; start_daemon; }

status_daemon(){
  load_config
  local ip last change_count="0" my_idx total out
  ip="$(_get_wan_ip 2>/dev/null || echo 'N/A')"
  [ -f "$WAN_IP_FILE" ] && last="$(cat "$WAN_IP_FILE")" || last="N/A"
  [ -f "$CHANGE_CNT_FILE" ] && change_count="$(cat "$CHANGE_CNT_FILE")"

  echo "================ DDNS 状态 (VPS_ID=$VPS_ID) ================"
  echo "域名:       $CF_RECORD_NAME"
  echo "类型:       $CF_RECORD_TYPE   PROXIED: $PROXIED   TTL: $CFTTL"
  echo "当前公网IP: $ip"
  echo "上次写入IP: $last"
  echo "换IP次数:   $change_count"
  echo "轮询间隔:   ${CHECK_INTERVAL}s"
  if is_running; then echo "守护进程:   运行中 (pid=$(cat "$PID_FILE"))"; else echo "守护进程:   未运行"; fi
  echo "换IP命令:   $CHANGE_IP_CMD"
  echo "更新地址:   ${UPDATE_URL:-$UPDATE_URL_DEFAULT}"
  echo
  echo "—— 节点列表（按 VPS_ID 排序，*为本机）——"
  out="$(print_nodes_table)"
  echo "$out" | sed -n '1,999p'
  my_idx="$(echo "$out" | awk '/^MY_INDEX=/{print $1}' | sed 's/MY_INDEX=//')"
  total="$(echo "$out"   | awk '/^MY_INDEX=/{print $2}' | sed 's/TOTAL=//')"
  if [ -n "$total" ] && [ "$total" -gt 0 ]; then
    if [ "${my_idx:-0}" -gt 0 ]; then
      echo
      echo "📌 本机为：第 ${my_idx} 台 / 共 ${total} 台"
    else
      echo
      echo "⚠️ 云端未找到标记为 ddns:${VPS_ID} 的记录（可能尚未创建或标记不同）"
    fi
  fi
  echo "==========================================================="
}
tail_log(){ tail -n 200 -f "$LOG_FILE"; }

# ===================== 安装 / 更新 =====================
install_cmd(){
  local target="/usr/local/bin/ddns"
  if [ "$(id -u)" -ne 0 ]; then echo "❌ 需要 root：sudo $0 install"; exit 1; fi
  cp -f "$0" "$target" && chmod +x "$target"
  echo "✅ 已安装为命令：ddns   （运行：ddns 打开面板）"
}
update_script(){
  load_config
  local target="/usr/local/bin/ddns" tmp; tmp="$(mktemp)"
  echo "⬇️ 从 $UPDATE_URL 拉取新脚本..."
  curl -fsSL "$UPDATE_URL" -o "$tmp" || { echo "❌ 下载失败"; rm -f "$tmp"; return 1; }
  grep -q "^#!/usr/bin/env bash" "$tmp" || { echo "❌ 文件异常"; rm -f "$tmp"; return 1; }
  local running=0; is_running && running=1
  [ "$running" -eq 1 ] && stop_daemon
  if [ -w "$target" ] || [ "$(id -u)" -eq 0 ]; then
    cp -f "$tmp" "$target" && chmod +x "$target" && echo "✅ 已更新：$target"
  else
    cp -f "$tmp" "$0" && chmod +x "$0" && echo "⚠️ 无法写入 $target，已替换当前脚本：$0"
  fi
  rm -f "$tmp"
  [ "$running" -eq 1 ] && start_daemon
}
uninstall_cmd(){
  local target="/usr/local/bin/ddns"
  [ -f "$target" ] && { [ "$(id -u)" -ne 0 ] && { echo "❌ 需要 sudo"; exit 1; }; rm -f "$target"; }
  echo "✅ 已卸载 ddns 命令（状态目录保留：$BASE_DIR）"
}

# ===================== TUI 面板 =====================
menu(){
  load_config
  while true; do
    clear
    status_daemon
    echo
    echo "========= DDNS 面板 ========="
    echo "1) 启动"
    echo "2) 停止"
    echo "3) 重启"
    echo "4) 立即同步一次"
    echo "5) 执行换 IP 一次"
    echo "6) 修改换 IP 命令"
    echo "7) 查看日志 (tail -f)"
    echo "8) 保存配置"
    echo "9) 更新脚本（拉取最新并重启守护）"
    echo "10) 查看节点列表（第 n 台 & 当前 IP）"
    echo "11) 退出"
    echo "============================="
    read -rp "请选择 [1-11]: " c
    case "$c" in
      1) start_daemon; read -rp "回车返回菜单..." _;;
      2) stop_daemon; read -rp "回车返回菜单..." _;;
      3) restart_daemon; read -rp "回车返回菜单..." _;;
      4) if check_ip_reachable; then sync_dns_if_needed || true; else echo "网络不通，先换 IP 再同步"; change_ip; sleep 10; sync_dns_if_needed || true; fi; read -rp "回车返回菜单..." _;;
      5) change_ip; read -rp "回车返回菜单..." _;;
      6) echo "当前换 IP 命令：$CHANGE_IP_CMD"; read -rp "输入新的换 IP 命令: " NEWCMD; [ -n "$NEWCMD" ] && CHANGE_IP_CMD="$NEWCMD" && echo "✅ 已设置（记得 8 保存）"; read -rp "回车返回菜单..." _;;
      7) echo "按 Ctrl+C 退出查看"; tail_log;;
      8) save_config; echo "✅ 已保存到 $CONF_FILE"; sleep 1;;
      9) update_script; read -rp "回车返回菜单..." _;;
      10) clear; echo "同名节点列表（* 为本机）:"; echo; print_nodes_table | sed -n '1,/^MY_INDEX=/p' | sed '/^MY_INDEX=/d'; echo; read -rp "回车返回菜单..." _;;
      11) exit 0;;
      *) echo "无效选择"; sleep 1;;
    esac
  done
}

# ===================== 命令入口 =====================
load_config
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

cmd="${1:-menu}"
case "$cmd" in
  start)       start_daemon ;;
  stop)        stop_daemon ;;
  restart)     restart_daemon ;;
  status)      status_daemon ;;
  sync)        sync_dns_if_needed ;;
  changeip)    change_ip ;;
  set-change)  shift; CHANGE_IP_CMD="$*"; [ -z "$CHANGE_IP_CMD" ] && { echo "用法: $0 set-change '<命令>'"; exit 2; }; save_config; echo "✅ 已保存：$CHANGE_IP_CMD" ;;
  set-update-url) shift; UPDATE_URL="${1:-}"; [ -z "$UPDATE_URL" ] && { echo "用法: $0 set-update-url <url>"; exit 2; }; save_config; echo "✅ 已保存：$UPDATE_URL" ;;
  update)      update_script ;;
  install)     install_cmd ;;
  uninstall)   uninstall_cmd ;;
  killdups)    KILL_DUPLICATES; echo "已杀死重复进程（如果有）" ;;
  nodes)       print_nodes_table | sed -n '1,/^MY_INDEX=/p' | sed '/^MY_INDEX=/d' ;;
  menu|ddns|"") menu ;;
  *) echo "用法: $0 {start|stop|restart|status|sync|changeip|set-change|set-update-url|update|install|uninstall|killdups|nodes|menu}"; exit 2 ;;
esac
