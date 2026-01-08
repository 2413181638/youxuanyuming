#!/bin/bash

# =========================================================
# 配置区域
# =========================================================
TARGETS=(
  "/etc/V2bX/config.json"
  "/etc/XrayR/config.yml"
)

# 使用正则表达式兼容可能存在的末尾斜杠
OLD_PATTERN='https://8.137.161.100:50000'
NEW_TEXT='http://8.137.161.100:50000'

# =========================================================
# 执行逻辑
# =========================================================

# 确保以 root 权限运行
if [ "$EUID" -ne 0 ]; then 
  echo "❌ 请使用 sudo 或 root 用户运行此脚本"
  exit 1
fi

echo "🚀 开始检查并替换配置..."

for FILE in "${TARGETS[@]}"; do
  if [ ! -f "$FILE" ]; then
    echo "ℹ️  文件不存在: $FILE (跳过)"
    continue
  fi

  # 1. 尝试解除文件可能存在的“只读不可修改”属性 (部分镜像可能锁定配置)
  chattr -i "$FILE" > /dev/null 2>&1

  # 2. 检查是否真的包含旧文本 (不区分大小写)
  if grep -qiF "$OLD_PATTERN" "$FILE"; then
    echo "🔍 发现目标: $FILE"
    
    # 备份
    cp -a "$FILE" "$FILE.bak"
    
    # 3. 使用 sed 执行替换
    # 使用 | 作为分隔符，避免 URL 中 / 的转义麻烦
    sed -i "s|https://8.137.161.100:50000|http://8.137.161.100:50000|g" "$FILE"
    
    # 4. 验证结果
    if grep -qF "$NEW_TEXT" "$FILE"; then
      echo "✅ 修改成功: $FILE"
    else
      echo "❌ 修改失败: $FILE (可能是权限或编码问题)"
    fi
  else
    # 额外检查：是否已经是 http 了？
    if grep -qF "$NEW_TEXT" "$FILE"; then
      echo "ℹ️  无需修改: $FILE 已经是 http"
    else
      echo "❓ 未找到指定 IP: $FILE (请检查 IP 是否正确)"
    fi
  fi
done

echo "---"
echo "🔄 正在重启服务..."
v2bx restart && echo "✅ V2bX 已重启" || echo "⚠️ V2bX 重启失败"
xrayr restart && echo "✅ XrayR 已重启" || echo "⚠️ XrayR 重启失败"

echo "✨ 任务完成！"
