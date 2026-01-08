#!/bin/bash

# --- 只要修改这里的内容 ---
# 不管是 IP 还是 Token，通通写在单引号里
OLD='xianni04$&**(D())_E____++>?><>K$%^?>ASGHrexghn'
NEW='xianniK9#m&P!7q@Az^5*R_v2W=L+x8[Y]f{H}N|s?gJt>'

TARGETS=(
  "/etc/V2bX/config.json"
  "/etc/XrayR/config.yml"
)

# --------------------------
export OLD_STR="$OLD"
export NEW_STR="$NEW"

echo "🚀 正在执行 1:1 暴力替换..."

for FILE in "${TARGETS[@]}"; do
  if [ ! -f "$FILE" ]; then continue; fi

  # 解锁文件
  chattr -i "$FILE" 2>/dev/null

  # 使用 Perl 的 quotemeta 功能：
  # 它会自动把你 Token 里乱七八糟的 $ & * ( ) 全部转义，当成普通字符处理
  perl -i -pe 'BEGIN { $old = $ENV{OLD_STR}; $new = $ENV{NEW_STR} } s/\Q$old\E/$new/g' "$FILE"

  # 验证
  if grep -qF "$NEW" "$FILE"; then
    echo "✅ $FILE: 替换成功"
  else
    echo "❌ $FILE: 替换失败（可能是没找到旧字符串，或者文件被锁定）"
  fi
done

v2bx restart
