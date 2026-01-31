# FreeYourPDF

PDF 加密 / 解密 / 解除权限限制的 Web 小工具。前后端分离：后端提供 API，前端静态页；后端不可用时自动回退到前端逻辑。

## 功能

- **需打开密码** → 破解打开密码（后端暴力破解常见密码）
- **无密码、有权限限制** → 解除复制/打印等限制
- **无密码无限制** → 加密（设置打开密码与权限）
- **缩小体积**：压缩未加密 PDF（对象流 / 图片重采样）
- 加密/解密与缩小体积各 10 次免费（localStorage）

## 快速开始

**1. 启动后端**（终端一）

```bash
cd backend
conda env create -f environment.yml   # 仅首次
./start_backend.sh
```

后端：http://localhost:5001

**2. 启动前端**（终端二）

```bash
./start_frontend.sh
# 或 python3 -m http.server 8080
```

前端：http://localhost:8080 → 在浏览器打开即可使用。

**仅前端**：不启后端也可用，检测与解锁会走前端逻辑，部分“仅权限加密”的 PDF 可能被误判。

修改后端地址：在 `index.html` 中改 `window.FREEYOURPDF_API_BASE`。

## 技术

- 前端：HTML/CSS/JS，[pdf-lib-with-encrypt](https://www.npmjs.com/package/pdf-lib-with-encrypt)（CDN）
- 后端：Python Flask + [pypdf](https://pypdf.readthedocs.io/)，CORS 已开

## 项目结构

```
├── index.html, css/, js/
├── start_backend.sh, start_frontend.sh
└── backend/
    ├── app.py              # /api/detect, /api/unlock, /api/crack-and-unlock
    ├── environment.yml
    └── requirements.txt
```

## API（后端）

| 接口 | 说明 |
|------|------|
| `POST /api/detect` | 上传 PDF，返回是否加密、是否有权限限制 |
| `POST /api/unlock` | 上传 PDF + 可选密码，返回解锁后的 PDF |
| `POST /api/crack-and-unlock` | 上传 PDF，后端暴力破解密码后返回 PDF |

所有处理在本地完成，不涉及外网上传。
