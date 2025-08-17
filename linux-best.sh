# 1. 创建备份文件，以防止丢失配置
cp /etc/sysctl.conf /etc/sysctl.conf.bak

# 2. 删除 /etc/sysctl.conf 文件中的重复配置，并保留唯一配置
awk '!seen[$0]++' /etc/sysctl.conf > /etc/sysctl.conf.tmp && mv /etc/sysctl.conf.tmp /etc/sysctl.conf

# 3. 配置系统优化 - 调整 TCP 协议栈与缓冲区
echo "net.ipv4.tcp_rmem = 4096 87380 16777216" >> /etc/sysctl.conf
echo "net.ipv4.tcp_wmem = 4096 65536 16777216" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 4096" >> /etc/sysctl.conf
echo "net.ipv4.tcp_fin_timeout = 15" >> /etc/sysctl.conf
echo "net.ipv4.tcp_tw_reuse = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_tw_recycle = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_sack = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_mtu_probing = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_congestion_control = bbr" >> /etc/sysctl.conf
echo "net.core.netdev_max_backlog = 5000" >> /etc/sysctl.conf
echo "net.core.rmem_max = 16777216" >> /etc/sysctl.conf
echo "net.core.wmem_max = 16777216" >> /etc/sysctl.conf
echo "net.ipv4.tcp_delack_min = 1000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_time = 600" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_intvl = 60" >> /etc/sysctl.conf
echo "net.ipv4.tcp_keepalive_probes = 5" >> /etc/sysctl.conf

# 4. 增加文件描述符限制
echo "ulimit -n 65535" >> /etc/security/limits.conf

# 5. 启用 TCP 快速打开 (TCP Fast Open)
echo "net.ipv4.tcp_fastopen = 3" >> /etc/sysctl.conf

# 6. 配置网络接口参数
echo "net.ipv4.conf.all.rp_filter = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.rp_filter = 0" >> /etc/sysctl.conf
echo "net.ipv4.conf.default.arp_announce = 2" >> /etc/sysctl.conf
echo "net.ipv4.conf.lo.arp_announce = 2" >> /etc/sysctl.conf
echo "net.ipv4.conf.all.arp_announce = 2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_tw_buckets = 5000" >> /etc/sysctl.conf
echo "net.ipv4.tcp_syncookies = 1" >> /etc/sysctl.conf
echo "net.ipv4.tcp_synack_retries = 2" >> /etc/sysctl.conf
echo "net.ipv4.tcp_slow_start_after_idle = 0" >> /etc/sysctl.conf

# 7. 调整 swap 参数
echo "vm.swappiness = 40" >> /etc/sysctl.conf

# 8. 更新并应用配置
sysctl -p

# 9. 验证配置是否生效
sysctl net.ipv4.tcp_rmem
sysctl net.ipv4.tcp_wmem
sysctl net.ipv4.tcp_max_syn_backlog
sysctl net.ipv4.tcp_fin_timeout
sysctl net.ipv4.tcp_tw_reuse
sysctl net.ipv4.tcp_tw_recycle
sysctl net.ipv4.tcp_sack
sysctl net.ipv4.tcp_mtu_probing
sysctl net.ipv4.tcp_congestion_control
sysctl net.core.netdev_max_backlog
sysctl net.core.rmem_max
sysctl net.core.wmem_max
sysctl net.ipv4.tcp_delack_min
sysctl net.ipv4.tcp_keepalive_time
sysctl net.ipv4.tcp_keepalive_intvl
sysctl net.ipv4.tcp_keepalive_probes
sysctl net.ipv4.tcp_fastopen
sysctl net.ipv4.conf.all.rp_filter
sysctl net.ipv4.conf.default.rp_filter
sysctl vm.swappiness
