#!/bin/bash

# 1. 禁用历史展开（防止感叹号报错）
set +o histexpand

# 2. 配置区域：使用【单引号】锁定字符串，防止 $ & * 被解析http://8.137.161.100:50000
TARGETS=(
  "/etc/V2bX/config.json"
  "/etc/XrayR/config.yml"
)

# 旧的 Token 和新的 Token
export OLD_TOKEN='xianniK9#m&P!7q@Az^5*R_v2W=L+x8[Y]f{H}N|s?gJt>'
export NEW_TOKEN='xianniK9a1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8S9t02026v2bx'

# 同时修改 IP 协议
OLD_URL='https://xnhttx.523562.xyz'
NEW_URL='https://xn-awsjp.6653222.xyz'

echo "🚀 开始执行强力替换..."

for FILE in "${TARGETS[@]}"; do
  if [ ! -f "$FILE" ]; then
    echo "❌ $FILE 不存在，跳过"
    continue
  fi

  # --- 少了这一步：解除文件只读锁定 ---
  chattr -i "$FILE" 2>/dev/null

  # --- 改进匹配逻辑：使用 -F (固定字符串) 确保特殊符号不被当成正则 ---
  if grep -Fq "$OLD_TOKEN" "$FILE" || grep -Fq "$OLD_URL" "$FILE"; then
    cp -a "$FILE" "$FILE.bak"

    # --- 核心改进：使用环境变量传参，完全避免 Shell 转义问题 ---
    # 这一步同时修改 URL 和 Token
    perl -i -pe "s|\Q$OLD_URL\E|$NEW_URL|g" "$FILE"
    perl -i -pe 'BEGIN { $old = $ENV{OLD_TOKEN}; $new = $ENV{NEW_TOKEN} } s/\Q$old\E/$new/g' "$FILE"

    # 验证是否包含新值
    if grep -Fq "$NEW_TOKEN" "$FILE"; then
      echo "✅ $FILE: 替换成功"
    else
      echo "⚠️ $FILE: 修改异常，请检查文件内容"
    fi
  else
    echo "ℹ️ $FILE: 未发现旧值（可能已修改或 Token 不匹配）"
  fi
done

echo "---"
v2bx restart && echo "✅ V2bX 重启完成"
xrayr restart 2>/dev/null || echo "ℹ️ XrayR 重启跳过（命令不存在）"
