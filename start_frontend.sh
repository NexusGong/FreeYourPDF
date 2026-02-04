#!/bin/bash
cd "$(dirname "$0")/frontend" || exit 1
PORT=8080

# 本机局域网 IP（WiFi 直连移动端用，仅限私网地址，如 192.168.x.x / 10.x.x.x）
LAN_IP=$(python3 - << 'EOF' 2>/dev/null
import socket
import ipaddress

candidates = set()
try:
    for info in socket.getaddrinfo(None, 0, family=socket.AF_INET):
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        # 只要私有地址，排除 127.0.0.1 等回环地址
        if addr.is_private and not addr.is_loopback:
            candidates.add(str(addr))
except Exception:
    pass

print(sorted(candidates)[0] if candidates else "")
EOF
)

# 在某些 macOS 环境上，上面方式可能拿不到私网 IP，补充用 ipconfig 尝试 Wi-Fi 网卡
if [ -z "$LAN_IP" ]; then
  if command -v ipconfig >/dev/null 2>&1; then
    LAN_IP=$(ipconfig getifaddr en0 2>/dev/null || true)
    if [ -z "$LAN_IP" ]; then
      LAN_IP=$(ipconfig getifaddr en1 2>/dev/null || true)
    fi
  fi
fi
echo "前端: http://localhost:$PORT"
if [ -n "$LAN_IP" ]; then
  echo "移动端（同一 WiFi）: http://$LAN_IP:$PORT"
else
  echo "提示: 未能自动检测到局域网 IP，可在「系统设置 -> 网络」中查看本机 IP，手机访问 http://本机IP:$PORT"
fi
echo "请确保后端已启动（如 ./start_backend.sh）"
echo "按 Ctrl+C 停止"
#
# 这里统一使用 python 内置 http.server 提供静态文件，
# 保证包含 .well-known 在内的所有目录都可正常访问（live-server 会忽略点目录，导致 DevTools 请求 404）。
python3 -m http.server "$PORT"
