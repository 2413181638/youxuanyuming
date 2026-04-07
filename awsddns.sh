#!/usr/bin/env bash

set -u
set -o pipefail

# 用户配置区，只改这里的 4 个值
CF_API_TOKEN="cfut_3ZR4ZFfakq5MJxApE6ZLokxFWGdvoGQY8XAMrkZAa5f2f2f8"
CF_DOMAIN="awshkniubi.77yun77.com"
CF_ZONE_NAME="77yun77.com"
AWS_SB_SGT="4d48e86004924a0b9ce4a6c99816cee7"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "$0")"
LOCK_DIR="/tmp/$(basename "$0").lock"
PID_FILE="$LOCK_DIR/pid"

cleanup_lock() {
  if [ -d "$LOCK_DIR" ] && [ -f "$PID_FILE" ] && [ "$(cat "$PID_FILE" 2>/dev/null || true)" = "$$" ]; then
    rm -rf "$LOCK_DIR"
  fi
}

is_same_script_running() {
  local pid="$1"
  [ -n "$pid" ] || return 1
  [ "$pid" != "$$" ] || return 1
  kill -0 "$pid" 2>/dev/null || return 1
  [ -r "/proc/$pid/cmdline" ] || return 1
  tr '\0' ' ' < "/proc/$pid/cmdline" | grep -F -- "$SCRIPT_PATH" >/dev/null 2>&1
}

take_over_previous_run() {
  local old_pid="$1"
  local waited=0

  echo "检测到旧进程正在运行，准备接管: PID=$old_pid"
  kill "$old_pid" 2>/dev/null || true

  while [ "$waited" -lt 5 ]; do
    if ! is_same_script_running "$old_pid"; then
      break
    fi
    sleep 1
    waited=$((waited + 1))
  done

  if is_same_script_running "$old_pid"; then
    echo "旧进程未退出，强制终止: PID=$old_pid"
    kill -9 "$old_pid" 2>/dev/null || true
  fi
}

acquire_lock() {
  local attempts=0
  local old_pid=""

  while ! mkdir "$LOCK_DIR" 2>/dev/null; do
    old_pid="$(cat "$PID_FILE" 2>/dev/null || true)"

    if is_same_script_running "$old_pid"; then
      take_over_previous_run "$old_pid"
    fi

    rm -rf "$LOCK_DIR" 2>/dev/null || true
    attempts=$((attempts + 1))

    if [ "$attempts" -ge 10 ]; then
      echo "错误: 无法获取脚本锁"
      exit 1
    fi

    sleep 1
  done

  printf '%s\n' "$$" > "$PID_FILE"
  trap 'status=$?; cleanup_lock; exit "$status"' EXIT INT TERM
}

require_env() {
  local name="$1"
  if [ -z "${!name:-}" ]; then
    echo "错误: 缺少必需的配置: $name"
    exit 1
  fi
}

random_suffix() {
  od -An -N16 -tx1 /dev/urandom | tr -d ' \n' | head -c 12
}

curl_json() {
  local url="$1"
  shift
  curl -sS --fail \
    --connect-timeout 10 \
    --max-time 20 \
    --retry 3 \
    --retry-delay 2 \
    --retry-all-errors \
    "$@" \
    "$url"
}

cf_api() {
  local url="$1"
  shift
  curl_json \
    "$url" \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    "$@"
}

print_json_errors() {
  local response="$1"
  echo "$response" | jq -c '.errors // .' 2>/dev/null || echo "$response"
}

require_cf_success() {
  local action="$1"
  local response="$2"
  if ! echo "$response" | jq -e '.success == true' >/dev/null 2>&1; then
    echo "错误: Cloudflare ${action}失败"
    print_json_errors "$response"
    exit 1
  fi
}

delete_cf_record() {
  local zone_id="$1"
  local record_id="$2"
  local delete_result=""
  delete_result="$(
    cf_api \
      "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records/$record_id" \
      -X DELETE
  )" || {
    echo "错误: 删除重复 DNS 记录失败: $record_id"
    exit 1
  }
  require_cf_success "重复 DNS 记录删除" "$delete_result"
}

acquire_lock

require_env CF_API_TOKEN
require_env CF_DOMAIN
require_env CF_ZONE_NAME
require_env AWS_SB_SGT

ZONE_RESPONSE="$(
  cf_api \
    "https://api.cloudflare.com/client/v4/zones?name=$CF_ZONE_NAME"
)" || {
  echo "错误: 无法查询 Cloudflare Zone"
  exit 1
}

require_cf_success "Zone 查询" "$ZONE_RESPONSE"

ZONE_ID="$(echo "$ZONE_RESPONSE" | jq -r '.result[0].id // empty')"

if [ -z "$ZONE_ID" ]; then
  echo "错误: 无法获取 Cloudflare Zone ID"
  exit 1
fi

echo "Cloudflare Zone 已确认"
echo ""
echo "===== 开始检测 [$(date '+%F %T')] ====="

R1="$(random_suffix)"
SHARES="$(
  curl_json \
    "https://api.aws.sb/ec2-instance-shares?r=${R1}" \
    -H "x-share-group-token: $AWS_SB_SGT" \
    -H "Referer: https://aws.sb/" \
    -H "Origin: https://aws.sb"
)" || {
  echo "错误: 无法获取实例列表"
  exit 1
}

INSTANCE_ID="$(echo "$SHARES" | jq -r '.[0].instanceId // empty')"
REGION="$(echo "$SHARES" | jq -r '.[0].regionName // empty')"

if [ -z "$INSTANCE_ID" ] || [ -z "$REGION" ]; then
  echo "错误: 无法获取实例信息"
  exit 1
fi

echo "发现实例: $INSTANCE_ID ($REGION)"

R2="$(random_suffix)"
RESPONSE="$(
  curl_json \
    "https://api.aws.sb/ec2-instances/${INSTANCE_ID}?r=${R2}" \
    -H "x-share-group-token: $AWS_SB_SGT" \
    -H "x-region-name: $REGION" \
    -H "Referer: https://aws.sb/" \
    -H "Origin: https://aws.sb"
)" || {
  echo "错误: 无法获取实例详情"
  exit 1
}

NEW_IP="$(echo "$RESPONSE" | jq -r '.publicIpAddress // .ipAddress // empty')"

if [ -z "$NEW_IP" ]; then
  echo "错误: 无法获取实例 IP"
  exit 1
fi

echo "aws.sb IP: $NEW_IP"

RECORD_INFO="$(
  cf_api \
    "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$CF_DOMAIN&type=A"
)" || {
  echo "错误: 无法查询 Cloudflare DNS 记录"
  exit 1
}

require_cf_success "DNS 记录查询" "$RECORD_INFO"

RECORD_COUNT="$(echo "$RECORD_INFO" | jq -r '.result | length')"
RECORD_ID="$(echo "$RECORD_INFO" | jq -r '.result[0].id // empty')"
OLD_IP="$(echo "$RECORD_INFO" | jq -r '.result[0].content // empty')"
mapfile -t EXTRA_RECORD_IDS < <(echo "$RECORD_INFO" | jq -r '.result[1:][]?.id')

if [ "$RECORD_COUNT" -gt 1 ]; then
  echo "警告: 发现 $RECORD_COUNT 条同名 A 记录，更新后会清理重复项"
fi

echo "CF 当前 IP: ${OLD_IP:-<空>}"

if [ "$NEW_IP" = "$OLD_IP" ] && [ "$RECORD_COUNT" -le 1 ]; then
  echo "IP 未变化，跳过"
  exit 0
fi

UPDATED="false"

if [ "$NEW_IP" != "$OLD_IP" ] && [ -n "$RECORD_ID" ]; then
  echo "IP 变化: ${OLD_IP:-<空>} -> $NEW_IP，更新中..."
  METHOD="PUT"
  URL="https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID"
  UPDATED="true"
elif [ "$NEW_IP" != "$OLD_IP" ]; then
  echo "IP 变化: ${OLD_IP:-<空>} -> $NEW_IP，创建记录中..."
  METHOD="POST"
  URL="https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records"
  UPDATED="true"
else
  echo "IP 未变化，但存在重复记录，开始清理"
fi

if [ "$UPDATED" = "true" ]; then
  RESULT="$(
    cf_api \
      "$URL" \
      -X "$METHOD" \
      -H "Content-Type: application/json" \
      --data "{\"type\":\"A\",\"name\":\"$CF_DOMAIN\",\"content\":\"$NEW_IP\",\"ttl\":60,\"proxied\":false}"
  )" || {
    echo "错误: Cloudflare 更新失败"
    exit 1
  }
  require_cf_success "DNS 更新" "$RESULT"
fi

if [ "${#EXTRA_RECORD_IDS[@]}" -gt 0 ]; then
  for extra_record_id in "${EXTRA_RECORD_IDS[@]}"; do
    echo "删除重复 DNS 记录: $extra_record_id"
    delete_cf_record "$ZONE_ID" "$extra_record_id"
  done
fi

if [ "$UPDATED" = "true" ]; then
  echo "DNS 更新成功: $CF_DOMAIN -> $NEW_IP"
elif [ "${#EXTRA_RECORD_IDS[@]}" -gt 0 ]; then
  echo "DNS 保持不变，但已清理重复记录: $CF_DOMAIN -> $NEW_IP"
fi

echo ""
echo "===== 单次检测结束 ====="
