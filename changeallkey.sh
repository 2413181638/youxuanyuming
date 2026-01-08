
#!/bin/bash

# --- 1. 配置新值 (在这里修改即可) ---
NEW_URL="xianni04$&**(D())_E____++>?><>K$%^?>ASGHrexghn"
NEW_KEY='xianniK9#m&P!7q@Az^5*R_v2W=L+x8[Y]f{H}N|s?gJt>'

CONF="/etc/V2bX/config.json"

if [ ! -f "$CONF" ]; then
    echo "❌ 找不到配置文件: $CONF"
    exit 1
fi

echo "🔄 正在解锁并修正配置..."

# 解锁、备份、修改
chattr -i "$CONF" 2>/dev/null
cp -a "$CONF" "${CONF}.bak"

# 强力替换 ApiKey 和 ApiHost
export K="$NEW_KEY"
export U="$NEW_URL"
perl -i -pe 's|"ApiKey":\s*"[^"]*"|"ApiKey": "$ENV{K}"|g; s|"ApiHost":\s*"[^"]*"|"ApiHost": "$ENV{U}"|g' "$CONF"

# 验证
if grep -qF "$NEW_KEY" "$CONF"; then
    echo "✅ 替换成功！"
    v2bx restart
else
    echo "❌ 替换失败，请手动检查文件权限。"
fi
