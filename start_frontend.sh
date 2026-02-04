#!/bin/bash
cd "$(dirname "$0")/frontend" || exit 1
PORT=8080
# 本机局域网 IP（WiFi 直连移动端用）
LAN_IP=$(python3 -c "
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.connect(('8.8.8.8', 80))
    print(s.getsockname()[0])
except Exception:
    print('')
finally:
    s.close()
" 2>/dev/null)
echo "前端: http://localhost:$PORT"
if [ -n "$LAN_IP" ]; then
  echo "移动端（同一 WiFi）: http://$LAN_IP:$PORT"
fi
echo "请确保后端已启动（如 ./start_backend.sh）"
echo "按 Ctrl+C 停止"
#
# 这里统一使用 python 内置 http.server 提供静态文件，
# 保证包含 .well-known 在内的所有目录都可正常访问（live-server 会忽略点目录，导致 DevTools 请求 404）。
python3 -m http.server "$PORT"
