#!/bin/bash
cd "$(dirname "$0")"
PORT=8080
echo "前端: http://localhost:$PORT"
echo "请确保后端已启动（如 ./start_backend.sh）"
echo "按 Ctrl+C 停止"
python3 -m http.server "$PORT"
