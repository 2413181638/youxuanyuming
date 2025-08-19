#!/usr/bin/env bash
# tune-node-menu.sh — 节点优化一键脚本

set -euo pipefail

GREEN="\033[1;32m"
NC="\033[0m" # no color

menu() {
  echo "=============================="
  echo -e "${GREEN}1) 应用【基线优化】 (稳妥推荐)${NC}"
  echo -e "${GREEN}2) 应用【进阶增强】 (激进，可能兼容性差)${NC}"
  echo -e "${GREEN}3) 设置【文件句柄上限】 (nofile=65535)${NC}"
  echo -e "${GREEN}q) 退出${NC}"
  echo "=============================="
}

baseline() {
  echo "[*] 写入基线优化参数..."
  cat >>/etc/sysctl.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 4096
net.ipv4.tcp_max_syn_backlog = 4096
net.core.netdev_max_backlog = 8192
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_fastopen = 1
net.ipv4.tcp_keepalive_time = 120
net.ipv4.tcp_keepalive_intvl = 30
net.ipv4.tcp_keepalive_probes = 5
EOF
  sysctl --system
}

advanced() {
  echo "[*] 写入进阶增强参数..."
  cat >>/etc/sysctl.conf <<'EOF'
net.core.netdev_max_backlog = 16384
net.ipv4.tcp_fastopen = 3
vm.swappiness = 40
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_ecn = 1
EOF
  sysctl --system
}

limits() {
  echo "[*] 设置文件句柄上限..."
  cat >>/etc/security/limits.conf <<'EOF'

# added by tune-node-menu.sh
* soft nofile 65535
* hard nofile 65535
root soft nofile 65535
root hard nofile 65535
EOF
  echo "已写入 /etc/security/limits.conf （需要重新登录或重启服务生效）"
}

# 显示菜单并执行一次
menu
read -rp "请输入选项 (1/2/3/q): " choice
case "$choice" in
  1) baseline ;;
  2) advanced ;;
  3) limits ;;
  q|Q) echo "退出."; exit 0 ;;
  *) echo "无效选项." ;;
esac

echo "✅ 操作完成，脚本已退出。"
