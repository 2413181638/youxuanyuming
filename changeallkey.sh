#!/bin/bash

# --- 1:1 匹配配置区 (请务必使用单引号) ---
# 旧字符串 (不管是 IP 还是 Token，只要是你想换掉的整段字符)
OLD_STR='xianni04$&**(D())_E____++>?><>K$%^?>ASGHrexghn'
# 新字符串
NEW_STR='xianniK9#m&P!7q@Az^5*R_v2W=L+x8[Y]f{H}N|s?gJt>'

FILE_PATH="/etc/V2bX/config.json"

# --- 执行逻辑 ---

if [ ! -f "$FILE_PATH" ]; then
    echo "❌ 找不到文件: $FILE_PATH"
    exit 1
fi

echo "🚀 开始强力修正..."

# 1. 解除所有可能的锁定属性 (i=不可变, a=仅追加)
chattr -ia "$FILE_PATH" 2>/dev/null

# 2. 修正文件权限 (确保当前 root 有写入权)
chmod 644 "$FILE_PATH"

# 3. 环境变量导出 (确保特殊字符不丢失)
export OLD_VAL="$OLD_STR"
export NEW_VAL="$NEW_STR"

# 4. 使用 Perl 1:1 替换 (Q/E 模式能无视所有乱七八糟的标点符号)
perl -i -pe 'BEGIN { $o = $ENV{OLD_VAL}; $n = $ENV{NEW_VAL} } s/\Q$o\E/$n/g' "$FILE_PATH"

# 5. 验证是否真的变了
if grep -qF "$NEW_STR" "$FILE_PATH"; then
    echo "✅ 修改成功！"
    # 同时把 https 换成 http (如果你还没换的话)
    sed -i 's|https://8.137.161.100:50000|http://8.137.161.100:50000|g' "$FILE_PATH"
else
    echo "❌ 仍然失败。正在尝试暴力重写方法..."
    # 备选方案：如果还是改不了，说明文件流损坏，尝试读取再重定向
    perl -pe 'BEGIN { $o = $ENV{OLD_VAL}; $n = $ENV{NEW_VAL} } s/\Q$o\E/$n/g' "$FILE_PATH" > "${FILE_PATH}.tmp" && mv -f "${FILE_PATH}.tmp" "$FILE_PATH"
fi

# 6. 重启并检查
v2bx restart
