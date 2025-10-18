#!/usr/bin/env bash
set -o errexit
set -o nounset
set -o pipefail

# ---------- 配置区（可修改） ----------
CF_API_TOKEN="iG0a8KAsRhTW2-octTtLUlWNm8-tfRhcBr1h8ry1"
CF_ZONE_NAME="5653111.xyz"
CF_RECORD_NAME="twddns.5653111.xyz"
CF_RECORD_TYPE="A"
CFTTL=120
FORCE=false
WANIPSITE="http://ipv4.icanhazip.com"

# ---------- 自动注册 systemd 自启定时任务 ----------
AUTO_SYSTEMD_TIMER_NAME="cf-ddns"
SYSTEMD_SERVICE_FILE="/etc/systemd/system/${AUTO_SYSTEMD_TIMER_NAME}.service"
SYSTEMD_TIMER_FILE="/etc/systemd/system/${AUTO_SYSTEMD_TIMER_NAME}.timer"

register_systemd_timer() {
  if ! systemctl list-timers --all | grep -q "${AUTO_SYSTEMD_TIMER_NAME}.timer"; then
    echo "检测到未安装 systemd 定时器，正在自动创建..."
    sudo tee "${SYSTEMD_SERVICE_FILE}" >/dev/null <<EOF
[Unit]
Description=Cloudflare DDNS Update Service
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=$0
StandardOutput=append:/var/log/cf-ddns.log
StandardError=append:/var/log/cf-ddns.log
EOF

    sudo tee "${SYSTEMD_TIMER_FILE}" >/dev/null <<EOF
[Unit]
Description=Run Cloudflare DDNS update every minute

[Timer]
OnBootSec=10sec
OnUnitActiveSec=1min
Unit=${AUTO_SYSTEMD_TIMER_NAME}.service
Persistent=true

[Install]
WantedBy=timers.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable --now "${AUTO_SYSTEMD_TIMER_NAME}.timer"
    echo "✅ 已自动注册 systemd 定时器：每分钟运行一次"
  fi
}

# 尝试注册 systemd（仅在 root 下执行才有权限）
if [ "$(id -u)" -eq 0 ]; then
  register_systemd_timer
else
  echo "⚠️ 当前不是 root 用户，跳过自启注册（建议用 root 执行一次自动创建 systemd 定时器）"
fi

# ---------- 主逻辑 ----------
if [ "$CF_RECORD_TYPE" = "AAAA" ]; then
  WANIPSITE="http://ipv6.icanhazip.com"
elif [ "$CF_RECORD_TYPE" != "A" ]; then
  echo "$CF_RECORD_TYPE 指定无效，仅支持 A 或 AAAA"
  exit 2
fi

WAN_IP=$(curl -fsS "${WANIPSITE}" || true)
if [ -z "$WAN_IP" ]; then
  echo "无法获取公网 IP，退出"
  exit 1
fi

WAN_IP_FILE="$HOME/.cf-wan_ip_${CF_RECORD_NAME}.txt"
OLD_WAN_IP=""
if [ -f "$WAN_IP_FILE" ]; then
  OLD_WAN_IP=$(cat "$WAN_IP_FILE" || true)
fi

if [ "$WAN_IP" = "$OLD_WAN_IP" ] && [ "$FORCE" = false ]; then
  echo "WAN IP 未改变（$WAN_IP），不做更新"
  exit 0
fi

ID_FILE="$HOME/.cf-id_${CF_RECORD_NAME}.txt"
if [ -f "$ID_FILE" ] && [ "$(wc -l < "$ID_FILE" || echo 0)" -eq 2 ]; then
  CFZONE_ID=$(sed -n '1p' "$ID_FILE")
  CFRECORD_ID=$(sed -n '2p' "$ID_FILE")
else
  echo "查询 zone_id..."
  CFZONE_ID=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones?name=${CF_ZONE_NAME}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
  if [ -z "$CFZONE_ID" ]; then
    echo "未找到 zone_id，请检查 CF_ZONE_NAME 或 token 权限"
    exit 1
  fi

  echo "查询记录 id..."
  CFRECORD_ID=$(curl -fsS -X GET "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records?name=${CF_RECORD_NAME}" \
    -H "Authorization: Bearer ${CF_API_TOKEN}" \
    -H "Content-Type: application/json" \
    | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)

  if [ -z "$CFRECORD_ID" ]; then
    echo "记录不存在，创建中： ${CF_RECORD_NAME} -> ${WAN_IP}"
    CREATE_RESP=$(curl -fsS -X POST "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records" \
      -H "Authorization: Bearer ${CF_API_TOKEN}" \
      -H "Content-Type: application/json" \
      --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${WAN_IP}\",\"ttl\":${CFTTL}}") || true
    CFRECORD_ID=$(echo "$CREATE_RESP" | grep -Po '(?<=\"id\":\")[^\"]*' | head -1 || true)
    if [ -z "$CFRECORD_ID" ]; then
      echo "创建记录失败，响应： $CREATE_RESP"
      exit 1
    fi
  fi
  printf "%s\n%s\n" "$CFZONE_ID" "$CFRECORD_ID" > "$ID_FILE"
fi

echo "准备将 ${CF_RECORD_NAME} 更新为 ${WAN_IP}"
RESPONSE=$(curl -fsS -X PUT "https://api.cloudflare.com/client/v4/zones/${CFZONE_ID}/dns_records/${CFRECORD_ID}" \
  -H "Authorization: Bearer ${CF_API_TOKEN}" \
  -H "Content-Type: application/json" \
  --data "{\"type\":\"${CF_RECORD_TYPE}\",\"name\":\"${CF_RECORD_NAME}\",\"content\":\"${WAN_IP}\",\"ttl\":${CFTTL}}") || true

if echo "$RESPONSE" | grep -q '"success":true'; then
  echo "✅ 更新成功：${CF_RECORD_NAME} -> ${WAN_IP}"
  echo "$WAN_IP" > "$WAN_IP_FILE"
else
  echo "❌ 更新失败，响应： $RESPONSE"
  exit 1
fi
