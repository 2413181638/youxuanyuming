#!/bin/bash

# ============================================
# DDNS 脚本 - aws.sb IP → Cloudflare DNS
# ============================================

# Cloudflare 配置
CF_API_TOKEN="cfut_3ZR4ZFfakq5MJxApE6ZLokxFWGdvoGQY8XAMrkZAa5f2f2f8"
CF_EMAIL="h89600912@gmail.com"
CF_DOMAIN="awshkniubi.77yun77.com"
CF_ZONE_NAME="77yun77.com"

# aws.sb 配置（只需要 SGT，实例 ID 和 region 自动获取）
AWS_SB_SGT="4d48e86004924a0b9ce4a6c99816cee7"

# 日志函数
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# 1. 从 aws.sb 获取实例列表（自动发现实例 ID 和 region）
log "正在获取实例列表..."
R1=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-z0-9' | head -c 12)
SHARES=$(curl -s --max-time 10 \
    -H "x-share-group-token: $AWS_SB_SGT" \
    -H "Referer: https://aws.sb/" \
    -H "Origin: https://aws.sb" \
    "https://api.aws.sb/ec2-instance-shares?r=${R1}")

INSTANCE_ID=$(echo "$SHARES" | jq -r '.[0].instanceId')
REGION=$(echo "$SHARES" | jq -r '.[0].regionName')

if [ -z "$INSTANCE_ID" ] || [ "$INSTANCE_ID" = "null" ]; then
    log "错误: 无法获取实例信息，响应: $SHARES"
    exit 1
fi
log "发现实例: $INSTANCE_ID ($REGION)"

# 2. 获取该实例的 IP
R2=$(cat /dev/urandom | LC_ALL=C tr -dc 'a-z0-9' | head -c 12)
RESPONSE=$(curl -s --max-time 10 \
    -H "x-share-group-token: $AWS_SB_SGT" \
    -H "x-region-name: $REGION" \
    -H "Referer: https://aws.sb/" \
    -H "Origin: https://aws.sb" \
    "https://api.aws.sb/ec2-instances/${INSTANCE_ID}?r=${R2}")

NEW_IP=$(echo "$RESPONSE" | jq -r '.publicIpAddress // .ipAddress')
if [ -z "$NEW_IP" ] || [ "$NEW_IP" = "null" ]; then
    log "错误: 无法获取 IP，响应: $RESPONSE"
    exit 1
fi
log "aws.sb 当前 IP: $NEW_IP"

# 3. 获取 Zone ID
ZONE_ID=$(curl -s --max-time 10 \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" \
    "https://api.cloudflare.com/client/v4/zones?name=$CF_ZONE_NAME" \
    | jq -r '.result[0].id')

if [ -z "$ZONE_ID" ] || [ "$ZONE_ID" = "null" ]; then
    log "错误: 无法获取 Zone ID"
    exit 1
fi

# 4. 获取 CF 上当前的 DNS 记录（直接查 CF API，不依赖 dig）
RECORD_INFO=$(curl -s --max-time 10 \
    -H "Authorization: Bearer $CF_API_TOKEN" \
    -H "Content-Type: application/json" \
    "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records?name=$CF_DOMAIN&type=A")

RECORD_ID=$(echo "$RECORD_INFO" | jq -r '.result[0].id')
OLD_IP=$(echo "$RECORD_INFO" | jq -r '.result[0].content')
log "CF 当前 IP: ${OLD_IP:-无记录}"

# 5. 对比，一样就跳过
if [ "$NEW_IP" = "$OLD_IP" ]; then
    log "IP 未变化，跳过更新"
    exit 0
fi

log "IP 变化检测: $OLD_IP → $NEW_IP，开始更新 CF DNS..."

# 6. 更新或创建 DNS 记录
if [ -z "$RECORD_ID" ] || [ "$RECORD_ID" = "null" ]; then
    # 记录不存在，创建新的
    log "A 记录不存在，创建新记录..."
    RESULT=$(curl -s --max-time 10 -X POST \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records" \
        --data "{\"type\":\"A\",\"name\":\"$CF_DOMAIN\",\"content\":\"$NEW_IP\",\"ttl\":60,\"proxied\":false}")
else
    # 记录存在，更新
    log "更新 A 记录 (Record ID: $RECORD_ID)..."
    RESULT=$(curl -s --max-time 10 -X PUT \
        -H "Authorization: Bearer $CF_API_TOKEN" \
        -H "Content-Type: application/json" \
        "https://api.cloudflare.com/client/v4/zones/$ZONE_ID/dns_records/$RECORD_ID" \
        --data "{\"type\":\"A\",\"name\":\"$CF_DOMAIN\",\"content\":\"$NEW_IP\",\"ttl\":60,\"proxied\":false}")
fi

SUCCESS=$(echo "$RESULT" | jq -r '.success')
if [ "$SUCCESS" = "true" ]; then
    log "✓ DNS 更新成功: $CF_DOMAIN → $NEW_IP"
else
    log "✗ DNS 更新失败: $(echo "$RESULT" | jq -r '.errors')"
    exit 1
fi
