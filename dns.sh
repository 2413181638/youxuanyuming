sudo systemctl disable --now systemd-resolved && \
sudo rm -f /etc/resolv.conf && \
printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\nnameserver 2606:4700:4700::1111\nnameserver 2001:4860:4860::8888\n" | sudo tee /etc/resolv.conf >/dev/null && \
sudo chattr +i /etc/resolv.conf && \
echo "[OK] systemd-resolved disabled and /etc/resolv.conf locked:" && cat /etc/resolv.conf
