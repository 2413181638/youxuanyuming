#!/bin/bash
set +o histexpand  # 避免历史展开

TARGETS=(
  "/etc/V2bX/config.json"
  "/etc/XrayR/config.yml"
)

OLD_TEXT='xnhttx.523562.xyz'
NEW_TEXT='8.137.161.100:50000'

for FILE in "${TARGETS[@]}"; do
  if [ ! -f "$FILE" ]; then
    echo "❌ $FILE 不存在，跳过"
    continue
  fi

  if grep -Fq "$OLD_TEXT" "$FILE"; then
    cp -a "$FILE" "$FILE.bak"
    perl -0777 -i -pe "s/\Q$OLD_TEXT\E/$NEW_TEXT/g" "$FILE"
    if grep -Fq "$NEW_TEXT" "$FILE"; then
      echo "✅ $FILE: 替换成功"
    else
      echo "⚠️ $FILE: 找到旧值，但替换后未检测到新值"
    fi
  else
    echo "ℹ️ $FILE: 未找到旧值（无需替换）"
  fi
done

v2bx restart
xrayr restart
