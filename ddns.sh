#!/usr/bin/env bash
# ddns.sh — 多 VPS 友好 Cloudflare DDNS 守护脚本（带 TUI 面板 / 防多开 / 自定义换 IP）
# 说明：
#  - 多域名 ping 判定“是否被墙”，任一通即可；
#  - 多 VPS 共用同一主机记录时：每台只维护“自己那一条”（通过 comment=ddns:VPS_ID 识别），不删别人；
#  - 绝不写入 0.0.0.0/::0；只有获取到“合法公网 IP”时才创建/更新；
#  - 可达时：如果“任意同名记录”已有当前 IP，本轮跳过（避免 81058/无意义更新）；
#  - 守护进程：start/stop/restart/status；防多开（PID 文件 + 杀重）；日志滚动；
#  - 自定义“换 IP 命令”：可在 TUI 里设置或改配置文件；
#  - 一键安装：sudo ./ddns.sh install  -> /usr/local/bin/ddns  （之后直接敲 ddns 弹出面板）
set -o errexit
set -o nounset
set -o pipefail

# ===================== 固定配置（注意安全） =====================
CF_API_TOKEN="${CF_API_TOKEN:-iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1}"
CF_ZONE_NAME="${CF_ZONE_NAME:-5653111.xyz}"
CF_RECORD_NAME="${CF_RECORD_NAME:-twddns.5653111.xyz}"
CF_RECORD_TYPE="${CF_RECORD_TYPE:-A}"    # A / AAAA
CFTTL="${CFTTL:-120}"
PROXIED="${PROXIED:-false}"              # true / false

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
CONF_FILE="${BASE_DIR}/config_${VPS_ID}.env"   # 用户可编辑，保存换 IP 命令等

# 默认换 IP 命令（可在 TUI 里修改后写入 CONF_FILE）
DEFAULT_CHANGE_IP_CMD='curl -fsS 192.168.10.253 >/dev/null 2>&1 || true'

# ===================== 连通性检测 =====================
TARGET_DOMAINS=("email.163.com" "guanjia.qq.com" "weixin.qq.com")
PING_COUNT=10
PING_GAP=3
CHECK_INTERVAL="${CHECK_INTERVAL:-30}"

# ===================== 公共工具 =====================
log(){ printf "[%s] %s\n" "$(date '+%F %T')" "$*" | tee -a "$LOG_FILE" >&2; }
require_token(){ [ -n "$CF_API_TOKEN" ] || { log "❌ CF_API_TOKEN 为空"; exit 2; }; }

# 载入/初始化配置
load_config(){
  if [ -f "$CONF_FILE" ]; then
    # shellcheck disable=SC1090
    . "$CONF_FILE"
  fi
  CHANGE_IP_CMD="${CHANGE_IP_CMD:-$DEFAULT_CHANGE_IP_CMD}"
}

save_config(){
  cat >"$CONF_FILE" <<EOF
# 自定义配置（本机专用）
# VPS_ID 会作为 Cloudflare 记录的标记（comment=ddns:\$VPS_ID）
VPS_ID="${VPS_ID}"
# 自定义换 IP 命令（下行可写你的脚本/命令，必须能非交互执行）
CHANGE_IP_CMD=${CHANGE_IP_CMD@Q}
# 守护轮询间隔（秒）
CHECK_INTERVAL="${CHECK_INTERVAL}"
EOF
  chmod 600 "$CONF_FILE" || true
}

_trim(){ printf "%s" "$1" | tr -d '\r\n'; }

# 统一 Cloudflare API：输出 "BODY|HTTP"
_cf_api(){
  local method="$1" url="$2" data="${3:-}"
  require_token
  if [ -n "$data" ]; then
    curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "$data" -w '|%{http_code}'
  else
    curl -sS -X "$method" "$url" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      -w '|%{http_code}'
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
  # shellcheck disable=SC2086
  bash -lc "$CHANGE_IP_CMD" || true
  sleep 10
  local n=0; [ -f "$CHANGE_CNT_FILE" ] && n="$(cat "$CHANGE_CNT_FILE" || echo 0)"
  n=$((n+1)); echo "$n" > "$CHANGE_CNT_FILE"
  log "📶 已触发更换 IP；累计更换次数：${n}"
}

# ===================== Cloudflare 相关（多 VPS 互不影响） =====================
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
  # 先用缓存
  if [ -f "$ID_FILE" ]; then
    rid="$(cat "$ID_FILE" || true)"
    if [ -n "$rid" ] && record_exists "$zone_id" "$rid"; then
      printf "%s" "$rid"; return 0
    fi
    log "⚠️ 缓存 record_id 不存在/无效，尝试按 comment 找回"
  fi
  # 按 comment 找回
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
  # 真没有就创建（写真实 IP）
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
      echo "$wan_ip" > "$WAN_IP_FILE"
      return 0
    fi
  fi

  if patch_record "$zone_id" "$rid" "$wan_ip"; then
    log "✅ 已更新自身记录：${CF_RECORD_NAME} -> ${wan_ip}  [id=${rid}]"
    echo "$wan_ip" > "$WAN_IP_FILE"
  else
    log "❌ 更新失败（不影响其它机器记录）"
  fi
}

# ===================== 守护进程 & 防多开 =====================
script_abs_path(){
  local src="${BASH_SOURCE[0]}"
  while [ -h "$src" ]; do
    local dir; dir="$(cd -P "$(dirname "$src")" && pwd)"
    src="$(readlink "$src")"
    [[ "$src" != /* ]] && src="$dir/$src"
  done
  cd -P "$(dirname "$src")" && pwd
}
KILL_DUPLICATES(){
  # 杀掉除当前外的同脚本守护进程
  local self="ddns.sh"
  pgrep -f "$self" | while read -r p; do
    if [ "$p" != "$$" ] && [ "$p" != "$PPID" ]; then
      # 避免误杀其它 shell，限定包含我们的 BASE_DIR/PID_FILE/LOG_FILE 关键字或 RECORD_NAME
      if ps -o cmd= -p "$p" | grep -Eq "ddns\.sh|${BASE_DIR}|${CF_RECORD_NAME}"; then
        kill "$p" 2>/dev/null || true
      fi
    fi
  done
}

is_running(){ [ -f "$PID_FILE" ] && kill -0 "$(cat "$PID_FILE" 2>/dev/null || echo 0)" 2>/dev/null; }

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
    if is_running; then kill -9 "$(cat "$PID_FILE")" 2>/dev/null || true; fi
    rm -f "$PID_FILE"
    log "🛑 已停止"
  else
    log "ℹ️ 未运行"
  fi
}

restart_daemon(){ stop_daemon; start_daemon; }

status_daemon(){
  load_config
  local ip last change_count="0"
  ip="$(_get_wan_ip 2>/dev/null || echo 'N/A')"
  [ -f "$WAN_IP_FILE" ] && last="$(cat "$WAN_IP_FILE")" || last="N/A"
  [ -f "$CHANGE_CNT_FILE" ] && change_count="$(cat "$CHANGE_CNT_FILE")"
  echo "================ DDNS 状态 (VPS_ID=$VPS_ID) ================"
  echo "域名:     $CF_RECORD_NAME"
  echo "类型:     $CF_RECORD_TYPE   PROXIED: $PROXIED   TTL: $CFTTL"
  echo "当前公网IP: $ip"
  echo "上次写入IP: $last"
  echo "换IP次数:   $change_count"
  echo "轮询间隔:   ${CHECK_INTERVAL}s"
  if is_running; then
    echo "守护进程: 运行中 (pid=$(cat "$PID_FILE"))"
  else
    echo "守护进程: 未运行"
  fi
  echo "日志文件:  $LOG_FILE"
  echo "配置文件:  $CONF_FILE"
  echo "==========================================================="
}

tail_log(){ tail -n 200 -f "$LOG_FILE"; }

# ===================== 安装 / 卸载 =====================
install_cmd(){
  local target="/usr/local/bin/ddns"
  cp -f "$0" "$target"
  chmod +x "$target"
  echo "#!/usr/bin/env bash" > "$target"
  cat "$0" >> "$target"
  chmod +x "$target"
  echo "✅ 已安装为命令：ddns"
  echo "现在直接运行：ddns  即可打开面板。"
}

uninstall_cmd(){
  local target="/usr/local/bin/ddns"
  [ -f "$target" ] && sudo rm -f "$target"
  echo "✅ 已卸载 ddns 命令（脚本本体和状态目录未删除）"
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
    echo "8) 退出"
    echo "============================="
    read -rp "请选择 [1-8]: " c
    case "$c" in
      1) start_daemon; read -rp "回车返回菜单..." _;;
      2) stop_daemon; read -rp "回车返回菜单..." _;;
      3) restart_daemon; read -rp "回车返回菜单..." _;;
      4) if check_ip_reachable; then sync_dns_if_needed || true; else echo "网络不通，已尝试更换 IP 后再同步"; change_ip; sleep 10; sync_dns_if_needed || true; fi; read -rp "回车返回菜单..." _;;
      5) change_ip; read -rp "回车返回菜单..." _;;
      6) echo "当前换 IP 命令：$CHANGE_IP_CMD"; read -rp "输入新的换 IP 命令: " NEWCMD; [ -n "$NEWCMD" ] && CHANGE_IP_CMD="$NEWCMD" && save_config && echo "✅ 已保存"; read -rp "回车返回菜单..." _;;
      7) echo "按 Ctrl+C 退出查看"; tail_log;;
      8) exit 0;;
      *) echo "无效选择"; sleep 1;;
    esac
  done
}

# ===================== 入口 =====================
load_config
mkdir -p "$(dirname "$LOG_FILE")"
touch "$LOG_FILE"

cmd="${1:-menu}"
case "$cmd" in
  start)   start_daemon ;;
  stop)    stop_daemon ;;
  restart) restart_daemon ;;
  status)  status_daemon ;;
  sync)    sync_dns_if_needed ;;
  changeip) change_ip ;;
  install) install_cmd ;;
  uninstall) uninstall_cmd ;;
  menu|ddns|"") menu ;;
  killdups) KILL_DUPLICATES; echo "已杀死重复进程（如果有）" ;;
  *) echo "用法: $0 {start|stop|restart|status|sync|changeip|menu|install|uninstall|killdups}"; exit 2 ;;
esac
