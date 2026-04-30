#!/usr/bin/env bash
# ==========================================================
# Tencent Cloud DNSPod DDNS - txcfddns.sh
#
# 首次部署：
#   bash txcfddns.sh install
#
# 后续打开面板：
#   txcfddns
#
# 功能：
#   1. 只管理 awshk1.woainiliz.com
#   2. A 记录
#   3. 线路：默认
#   4. 备注：awshk1
#   5. TTL：3600 秒 / 60 分钟
#   6. 不缓存 IP
#   7. 不缓存 RecordId
#   8. 每次实时查询 DNSPod 记录
#   9. systemd 后台守护
#   10. 开机自启
#   11. Restart=always，异常退出后自动重启
#   12. 后续输入 txcfddns 只打开面板，不重复安装
# ==========================================================

if [ -z "${BASH_VERSION:-}" ]; then
  echo "错误：请用 bash 执行，不要用 sh。"
  exit 2
fi

set -u
set -o pipefail
umask 077

# ================== 用户配置区：主要改这里 ==================

SECRET_ID="AKIDW6SZR5ZqsfEajfR1NXTChy1rUu64nMwQ"
SECRET_KEY="VN8h2CAxYu1sUr0xlIciaFguvxpUxFNL"

DOMAIN="woainiliz.com"
SUB_DOMAIN="awshk1"
FULL_DOMAIN="${SUB_DOMAIN}.${DOMAIN}"

RECORD_TYPE="A"
RECORD_LINE="默认"
RECORD_REMARK="awshk1"

# DNSPod TTL 单位是秒。 = 60 s
TTL=60

# 后台守护模式下，每隔多少秒执行一次 DDNS
CHECK_INTERVAL=60

# 执行失败后，多少秒后重试
RETRY_SLEEP=5

# 腾讯云 API 超时配置
API_CONNECT_TIMEOUT="3"
API_MAX_TIME="10"

# ================== 固定安装配置：一般不用改 ==================

INSTALL_PATH="/usr/local/sbin/txcfddns.sh"
UNIT_NAME="txcfddns.service"
UNIT_PATH="/etc/systemd/system/${UNIT_NAME}"

PANEL_CMD="txcfddns"
PANEL_PATH="/usr/local/bin/${PANEL_CMD}"

LOG_DIR="/var/log/txcfddns"
LOG_FILE="${LOG_DIR}/txcfddns.log"

# ==========================================================

SERVICE="dnspod"
HOST="dnspod.tencentcloudapi.com"
VERSION="2021-03-23"
CONTENT_TYPE="application/json; charset=utf-8"

mkdir -p "$LOG_DIR" 2>/dev/null || true

log() {
  mkdir -p "$LOG_DIR" 2>/dev/null || true
  printf '[%s] %s\n' "$(date '+%F %T')" "$*" >> "$LOG_FILE" 2>/dev/null || true
}

print_log() {
  echo "$*"
  log "$*"
}

need_cmds() {
  local c missing=0

  for c in bash curl openssl awk sed tr date od grep head tail mkdir cat id install chmod ps; do
    if ! command -v "$c" >/dev/null 2>&1; then
      echo "缺少命令：$c"
      log "缺少命令：$c"
      missing=1
    fi
  done

  return "$missing"
}

has_systemd() {
  command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]
}

script_path() {
  local src="${BASH_SOURCE[0]}"

  if command -v readlink >/dev/null 2>&1; then
    readlink -f "$src" 2>/dev/null && return 0
  fi

  cd "$(dirname "$src")" 2>/dev/null && printf '%s/%s\n' "$(pwd -P)" "$(basename "$src")"
}

SCRIPT_PATH="$(script_path)"

is_ipv4() {
  local ip="$1" IFS=. a b c d x

  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1

  read -r a b c d <<< "$ip"

  for x in "$a" "$b" "$c" "$d"; do
    [[ "$x" =~ ^[0-9]+$ ]] || return 1
    [ "$x" -ge 0 ] 2>/dev/null && [ "$x" -le 255 ] 2>/dev/null || return 1
  done

  return 0
}

json_escape() {
  printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g'
}

sha256_hex() {
  printf '%s' "$1" | openssl dgst -sha256 -hex | awk '{print $NF}'
}

hmac_sha256_hex_with_key() {
  local key="$1" data="$2"

  printf '%s' "$data" \
    | openssl dgst -sha256 -mac HMAC -macopt "key:${key}" -binary \
    | od -An -vtx1 \
    | tr -d ' \n'
}

hmac_sha256_hex_with_hexkey() {
  local hexkey="$1" data="$2"

  printf '%s' "$data" \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:${hexkey}" -binary \
    | od -An -vtx1 \
    | tr -d ' \n'
}

build_authorization() {
  local action="$1" payload="$2" timestamp="$3" utc_date="$4"

  local algorithm="TC3-HMAC-SHA256"
  local http_method="POST"
  local canonical_uri="/"
  local canonical_query_string=""
  local signed_headers="content-type;host;x-tc-action"

  local canonical_headers payload_hash canonical_request hashed_canonical_request
  local credential_scope string_to_sign
  local secret_date secret_service secret_signing signature

  canonical_headers="content-type:${CONTENT_TYPE}
host:${HOST}
x-tc-action:$(printf '%s' "$action" | tr '[:upper:]' '[:lower:]')
"

  payload_hash="$(sha256_hex "$payload")"

  canonical_request="$(printf '%s\n%s\n%s\n%s\n%s\n%s' \
    "$http_method" \
    "$canonical_uri" \
    "$canonical_query_string" \
    "$canonical_headers" \
    "$signed_headers" \
    "$payload_hash")"

  hashed_canonical_request="$(sha256_hex "$canonical_request")"
  credential_scope="${utc_date}/${SERVICE}/tc3_request"

  string_to_sign="$(printf '%s\n%s\n%s\n%s' \
    "$algorithm" \
    "$timestamp" \
    "$credential_scope" \
    "$hashed_canonical_request")"

  secret_date="$(hmac_sha256_hex_with_key "TC3${SECRET_KEY}" "$utc_date")"
  secret_service="$(hmac_sha256_hex_with_hexkey "$secret_date" "$SERVICE")"
  secret_signing="$(hmac_sha256_hex_with_hexkey "$secret_service" "tc3_request")"
  signature="$(hmac_sha256_hex_with_hexkey "$secret_signing" "$string_to_sign")"

  printf '%s' "${algorithm} Credential=${SECRET_ID}/${credential_scope}, SignedHeaders=${signed_headers}, Signature=${signature}"
}

tc_api() {
  local action="$1" payload="$2"
  local timestamp utc_date authorization response errmsg

  timestamp="$(date +%s)"
  utc_date="$(date -u +%F)"
  authorization="$(build_authorization "$action" "$payload" "$timestamp" "$utc_date")"

  response="$(curl -fsS \
    --connect-timeout "$API_CONNECT_TIMEOUT" \
    --max-time "$API_MAX_TIME" \
    -X POST "https://${HOST}/" \
    -H "Authorization: ${authorization}" \
    -H "Content-Type: ${CONTENT_TYPE}" \
    -H "Host: ${HOST}" \
    -H "X-TC-Action: ${action}" \
    -H "X-TC-Timestamp: ${timestamp}" \
    -H "X-TC-Version: ${VERSION}" \
    -d "$payload" 2>/dev/null)" || {
      print_log "API 请求失败：${action}"
      return 1
    }

  if printf '%s' "$response" | grep -q '"Error"'; then
    errmsg="$(printf '%s' "$response" | sed -n 's/.*"Message":"\([^"]*\)".*/\1/p' | head -n 1)"
    print_log "API 返回错误：${action}${errmsg:+ | $errmsg}"
    return 1
  fi

  printf '%s' "$response"
}

get_public_ipv4() {
  local ip url

  for url in \
    "https://api.ipify.org" \
    "https://checkip.amazonaws.com" \
    "https://ifconfig.me/ip"
  do
    ip="$(curl -4 -fsS --connect-timeout 2 --max-time 5 "$url" 2>/dev/null | tr -d '[:space:]' || true)"

    if [ -n "$ip" ] && is_ipv4 "$ip" && [[ ! "$ip" =~ ^127\. ]]; then
      printf '%s' "$ip"
      return 0
    fi
  done

  return 1
}

extract_record_id_exact() {
  local response="$1"

  printf '%s' "$response" | awk -v name="$SUB_DOMAIN" -v type="$RECORD_TYPE" -v line="$RECORD_LINE" '
    BEGIN { RS="[{}]" }
    index($0, "\"Name\":\"" name "\"") &&
    index($0, "\"Type\":\"" type "\"") &&
    index($0, "\"Line\":\"" line "\"") {
      if (match($0, /\"RecordId\":[0-9]+/)) {
        s = substr($0, RSTART, RLENGTH)
        sub(/.*:/, "", s)
        print s
        exit
      }
    }
  '
}

describe_record_id() {
  local payload response rid

  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"Subdomain\":\"$(json_escape "$SUB_DOMAIN")\",\"RecordType\":\"$(json_escape "$RECORD_TYPE")\",\"RecordLine\":\"$(json_escape "$RECORD_LINE")\",\"Limit\":100,\"Offset\":0,\"ErrorOnEmpty\":\"no\"}"

  response="$(tc_api "DescribeRecordList" "$payload")" || return 1
  rid="$(extract_record_id_exact "$response")"

  [ -n "$rid" ] || return 1

  printf '%s' "$rid"
}

create_record() {
  local ip="$1"
  local payload response rid

  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"SubDomain\":\"$(json_escape "$SUB_DOMAIN")\",\"RecordType\":\"$(json_escape "$RECORD_TYPE")\",\"RecordLine\":\"$(json_escape "$RECORD_LINE")\",\"Value\":\"$(json_escape "$ip")\",\"TTL\":${TTL},\"Remark\":\"$(json_escape "$RECORD_REMARK")\",\"Status\":\"ENABLE\"}"

  response="$(tc_api "CreateRecord" "$payload")" || return 1

  rid="$(printf '%s' "$response" | grep -o '"RecordId":[0-9]*' | head -n 1 | sed 's/[^0-9]//g')"

  if [ -z "$rid" ]; then
    print_log "创建失败：没有返回 RecordId"
    return 1
  fi

  print_log "已创建记录：${FULL_DOMAIN}"
  print_log "线路：${RECORD_LINE}"
  print_log "备注：${RECORD_REMARK}"
  print_log "TTL：${TTL}"
  print_log "IP：${ip}"
  print_log "RecordId：${rid}"
}

modify_record() {
  local rid="$1" ip="$2"
  local payload

  payload="{\"Domain\":\"$(json_escape "$DOMAIN")\",\"SubDomain\":\"$(json_escape "$SUB_DOMAIN")\",\"RecordType\":\"$(json_escape "$RECORD_TYPE")\",\"RecordLine\":\"$(json_escape "$RECORD_LINE")\",\"Value\":\"$(json_escape "$ip")\",\"RecordId\":${rid},\"TTL\":${TTL},\"Remark\":\"$(json_escape "$RECORD_REMARK")\",\"Status\":\"ENABLE\"}"

  tc_api "ModifyRecord" "$payload" >/dev/null || return 1

  print_log "更新成功：${FULL_DOMAIN}"
  print_log "线路：${RECORD_LINE}"
  print_log "备注：${RECORD_REMARK}"
  print_log "TTL：${TTL}"
  print_log "IP：${ip}"
  print_log "RecordId：${rid}"
}

run_once() {
  local ip rid

  need_cmds || return 1

  if [ -z "$SECRET_ID" ] || [ -z "$SECRET_KEY" ]; then
    print_log "错误：SECRET_ID 或 SECRET_KEY 为空"
    return 1
  fi

  print_log "正在获取公网 IPv4..."

  ip="$(get_public_ipv4)" || {
    print_log "错误：无法获取公网 IPv4"
    return 1
  }

  print_log "当前公网 IPv4：${ip}"

  if rid="$(describe_record_id 2>/dev/null)"; then
    print_log "找到已有记录：${FULL_DOMAIN}，RecordId=${rid}"
    modify_record "$rid" "$ip" || return 1
  else
    print_log "没有找到记录，准备创建：${FULL_DOMAIN}"
    create_record "$ip" || return 1
  fi

  print_log "本轮 DDNS 完成。只处理：${FULL_DOMAIN}"
}

daemon_loop() {
  print_log "DDNS 后台守护启动"
  print_log "只管理：${FULL_DOMAIN}"
  print_log "成功间隔：${CHECK_INTERVAL}s"
  print_log "失败重试：${RETRY_SLEEP}s"

  while true; do
    if run_once; then
      sleep "$CHECK_INTERVAL" || true
    else
      print_log "本轮失败，${RETRY_SLEEP}s 后重试"
      sleep "$RETRY_SLEEP" || true
    fi
  done
}

install_service() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "install 需要 root 权限，请用 root 或 sudo 执行。"
    return 1
  fi

  if ! has_systemd; then
    echo "当前系统没有可用 systemd，无法安装开机自启。"
    return 1
  fi

  need_cmds || return 1

  install -d -m 755 /usr/local/sbin /usr/local/bin
  install -d -m 755 "$LOG_DIR"

  if [ "$SCRIPT_PATH" != "$INSTALL_PATH" ]; then
    install -m 700 "$SCRIPT_PATH" "$INSTALL_PATH"
  else
    chmod 700 "$INSTALL_PATH"
  fi

  cat > "$UNIT_PATH" <<UNIT
[Unit]
Description=Tencent DNSPod DDNS ${FULL_DOMAIN}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/bin/bash ${INSTALL_PATH} daemon
Restart=always
RestartSec=5
TimeoutStopSec=10
KillSignal=SIGTERM

[Install]
WantedBy=multi-user.target
UNIT

  cat > "$PANEL_PATH" <<PANEL
#!/usr/bin/env bash
if [ "\$#" -eq 0 ]; then
  exec /bin/bash ${INSTALL_PATH} menu
else
  exec /bin/bash ${INSTALL_PATH} "\$@"
fi
PANEL

  chmod 755 "$PANEL_PATH"

  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME" >/dev/null 2>&1

  echo "安装完成 / 已修复：${UNIT_NAME}"
  echo "开机自启：已启用"
  echo "后台运行：已启动"
  echo "崩溃重启：Restart=always"
  echo "面板命令：${PANEL_CMD}"
  echo
  echo "以后直接输入下面命令打开面板："
  echo "  ${PANEL_CMD}"
}

uninstall_service() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "uninstall 需要 root 权限。"
    return 1
  fi

  if has_systemd; then
    systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
    rm -f "$UNIT_PATH"
    systemctl daemon-reload
  fi

  rm -f "$PANEL_PATH"

  echo "已卸载服务：${UNIT_NAME}"
  echo "脚本文件仍保留：${INSTALL_PATH}"
  echo "日志仍保留：${LOG_FILE}"
}

start_service() {
  if has_systemd && [ -f "$UNIT_PATH" ]; then
    if systemctl is-active --quiet "$UNIT_NAME"; then
      echo "服务已经在运行：${UNIT_NAME}"
    else
      systemctl start "$UNIT_NAME"
      echo "已启动：${UNIT_NAME}"
    fi
  else
    echo "服务未安装。请先执行：bash $SCRIPT_PATH install"
    return 1
  fi
}

stop_service() {
  if has_systemd && [ -f "$UNIT_PATH" ]; then
    systemctl stop "$UNIT_NAME" || true
    echo "已停止：${UNIT_NAME}"
  else
    echo "服务未安装。"
  fi
}

restart_service() {
  if has_systemd && [ -f "$UNIT_PATH" ]; then
    systemctl restart "$UNIT_NAME"
    echo "已重启：${UNIT_NAME}"
  else
    echo "服务未安装。请先执行 install。"
    return 1
  fi
}

show_status() {
  echo "======================================"
  echo " DNSPod DDNS 状态"
  echo "======================================"
  echo "脚本当前路径：$SCRIPT_PATH"
  echo "安装路径：$INSTALL_PATH"
  echo "服务名：$UNIT_NAME"
  echo "面板命令：$PANEL_CMD"
  echo "日志：$LOG_FILE"
  echo
  echo "只管理：$FULL_DOMAIN"
  echo "类型：$RECORD_TYPE"
  echo "线路：$RECORD_LINE"
  echo "备注：$RECORD_REMARK"
  echo "TTL：$TTL 秒 / 60 分钟"
  echo
  echo "缓存状态：无 IP 缓存，无 RecordId 缓存"
  echo

  if has_systemd && [ -f "$UNIT_PATH" ]; then
    systemctl status "$UNIT_NAME" --no-pager -l || true
  else
    echo "systemd 服务：未安装"
  fi

  echo
  echo "相关进程："
  ps aux | grep -Ei '[t]xcfddns|[d]nspod|awshk1' || true
}

show_logs() {
  tail -n 100 "$LOG_FILE" 2>/dev/null || echo "暂无日志：$LOG_FILE"
}

follow_logs() {
  mkdir -p "$LOG_DIR"
  touch "$LOG_FILE"
  tail -f "$LOG_FILE"
}

show_config() {
  echo "当前配置："
  echo "SECRET_ID：已写入脚本顶部"
  echo "SECRET_KEY：已写入脚本顶部"
  echo "域名：${FULL_DOMAIN}"
  echo "类型：${RECORD_TYPE}"
  echo "线路：${RECORD_LINE}"
  echo "备注：${RECORD_REMARK}"
  echo "TTL：${TTL} 秒 / 60 分钟"
  echo "后台检查间隔：${CHECK_INTERVAL} 秒"
  echo "失败重试间隔：${RETRY_SLEEP} 秒"
  echo
  echo "说明："
  echo "1. 不缓存 IP"
  echo "2. 不缓存 RecordId"
  echo "3. 每次执行都会实时查询 DNSPod 记录"
  echo "4. install 后自动开机自启并立即运行"
  echo "5. 后续输入 txcfddns 只打开面板"
  echo "6. systemd 设置 Restart=always，脚本异常退出后会自动拉起"
}

disable_other_ddns_services() {
  if ! has_systemd; then
    echo "当前系统没有 systemd。"
    return 1
  fi

  echo "将停止其他 txcfddns / ddns / dnspod 相关服务，但保留当前服务：${UNIT_NAME}"

  systemctl list-units --type=service --all --no-legend \
    | awk '{print $1}' \
    | grep -Ei 'txcfddns|ddns|dnspod' \
    | grep -v "^${UNIT_NAME}$" \
    | while read -r svc; do
        [ -n "$svc" ] || continue
        echo "停止并禁用：$svc"
        systemctl disable --now "$svc" >/dev/null 2>&1 || true
      done

  echo "其他 DDNS 相关 systemd 服务已处理。"
}

menu() {
  while true; do
    clear 2>/dev/null || true
    echo "======================================"
    echo " DNSPod DDNS 面板 - ${FULL_DOMAIN}"
    echo "======================================"
    echo "1. 立即执行一次 DDNS"
    echo "2. 安装 / 修复 systemd 开机自启"
    echo "3. 启动后台服务"
    echo "4. 停止后台服务"
    echo "5. 重启后台服务"
    echo "6. 查看服务状态"
    echo "7. 查看最近日志"
    echo "8. 实时日志"
    echo "9. 查看当前配置"
    echo "10. 停止其他 DDNS 相关 systemd 服务"
    echo "11. 卸载当前 systemd 服务"
    echo "0. 退出面板"
    echo "======================================"
    read -r -p "请选择 [0-11]: " choice

    case "$choice" in
      1)
        echo
        run_once
        echo
        read -r -p "按回车返回面板..." _
        ;;
      2)
        echo
        install_service
        echo
        read -r -p "按回车返回面板..." _
        ;;
      3)
        echo
        start_service
        echo
        read -r -p "按回车返回面板..." _
        ;;
      4)
        echo
        stop_service
        echo
        read -r -p "按回车返回面板..." _
        ;;
      5)
        echo
        restart_service
        echo
        read -r -p "按回车返回面板..." _
        ;;
      6)
        echo
        show_status
        echo
        read -r -p "按回车返回面板..." _
        ;;
      7)
        echo
        show_logs
        echo
        read -r -p "按回车返回面板..." _
        ;;
      8)
        echo "实时日志中，按 Ctrl+C 退出实时日志。"
        follow_logs
        ;;
      9)
        echo
        show_config
        echo
        read -r -p "按回车返回面板..." _
        ;;
      10)
        echo
        disable_other_ddns_services
        echo
        read -r -p "按回车返回面板..." _
        ;;
      11)
        echo
        uninstall_service
        echo
        read -r -p "按回车返回面板..." _
        ;;
      0)
        echo "已退出面板。"
        exit 0
        ;;
      *)
        echo "无效选择。"
        sleep 1
        ;;
    esac
  done
}

usage() {
  cat <<USAGE
用法：
  bash $SCRIPT_PATH                 打开面板
  bash $SCRIPT_PATH menu            打开面板
  bash $SCRIPT_PATH install         安装/修复 systemd 开机自启，并立即后台运行
  bash $SCRIPT_PATH once            立即执行一次 DDNS
  bash $SCRIPT_PATH daemon          前台进入守护循环
  bash $SCRIPT_PATH uninstall       卸载 systemd 服务
  bash $SCRIPT_PATH start           启动后台服务
  bash $SCRIPT_PATH stop            停止后台服务
  bash $SCRIPT_PATH restart         重启后台服务
  bash $SCRIPT_PATH status          查看状态
  bash $SCRIPT_PATH logs            查看最近日志
  bash $SCRIPT_PATH follow          实时日志
  bash $SCRIPT_PATH config          查看配置
  bash $SCRIPT_PATH disable-others  停止其他 DDNS 相关 systemd 服务

安装后面板命令：
  ${PANEL_CMD}

当前只管理：
  ${FULL_DOMAIN}
  类型：${RECORD_TYPE}
  线路：${RECORD_LINE}
  备注：${RECORD_REMARK}
  TTL：${TTL} 秒
USAGE
}

case "${1:-menu}" in
  menu)
    menu
    ;;
  once)
    run_once
    ;;
  daemon)
    daemon_loop
    ;;
  install)
    install_service
    ;;
  uninstall)
    uninstall_service
    ;;
  start)
    start_service
    ;;
  stop)
    stop_service
    ;;
  restart)
    restart_service
    ;;
  status)
    show_status
    ;;
  logs)
    show_logs
    ;;
  follow)
    follow_logs
    ;;
  config)
    show_config
    ;;
  disable-others)
    disable_other_ddns_services
    ;;
  help|-h|--help)
    usage
    ;;
  *)
    usage
    exit 1
    ;;
esac
