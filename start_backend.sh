#!/bin/bash
cd "$(dirname "$0")/backend" || exit 1
CONDA_ENV="freeyourpdf"

# 加载 conda（与 conda init 一致）
CONDA_BASE=$(conda info --base 2>/dev/null)
if [ -z "$CONDA_BASE" ] || [ ! -f "$CONDA_BASE/etc/profile.d/conda.sh" ]; then
  echo "未检测到 conda，请先安装 Anaconda/Miniconda，或在本机已激活的 conda 环境中执行："
  echo "  pip install -r requirements.txt && python app.py"
  exit 1
fi
source "$CONDA_BASE/etc/profile.d/conda.sh"

if ! conda activate "$CONDA_ENV" 2>/dev/null; then
  echo "conda 环境 \"$CONDA_ENV\" 不存在，正在创建（仅此一次）..."
  conda env create -f environment.yml
  conda activate "$CONDA_ENV"
fi

echo "安装/更新依赖..."
pip install -q -r requirements.txt
echo "后端 API: http://localhost:5001"
echo "按 Ctrl+C 停止"
python app.py
