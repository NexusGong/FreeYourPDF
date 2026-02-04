# FreeYourPDF

PDF 加密 / 解密 / 解除权限限制 / 体积优化 的 Web 小工具。前后端分离：后端提供 API 完成所有 PDF 处理逻辑，前端只负责界面与交互。

## 功能一览

- **需打开密码** → 后端暴力破解常见密码 / 数字密码，并解密为无密码 PDF
- **无密码、有权限限制** → 解除复制 / 打印 / 编辑等权限限制
- **无密码无限制** → 加密（设置打开密码与权限，兼容 Adobe / 预览等阅读器）
- **缩小体积**：由后端使用 Ghostscript + pypdf 对未加密 PDF 进行体积优化（图片重采样 + 结构优化）
- **登录/注册**：邮箱验证码登录与注册，JWT 默认有效期 7 天
- **配额**：登录用户每项 10 次，未登录 5 次；可通过充值三档套餐增加次数
- **个人资料**：昵称、头像（Emoji 或自定义图片）、修改密码
- **管理后台**：管理员访问 `/#admin` 或 `/admin`，含数据概览、访问/使用记录、用户管理、支付记录、实时监控、成本监控等

## 快速开始

**1. 启动后端**（终端一，项目根目录）

```bash
./start_backend.sh
```

- 后端 API：http://localhost:5001  
- 脚本会进入 `backend/` 并激活 conda 环境 `freeyourpdf`；无 conda 时可在 `backend/` 下执行 `pip install -r requirements.txt && python app.py`
- **开发**：后端已开启热重载，修改 `backend/` 下 Python 代码并保存后会自动重启，无需手动重启

**2. 启动前端**（终端二，项目根目录）

```bash
./start_frontend.sh
```

- 前端：http://localhost:8080 → 在浏览器打开即可使用
- **开发**：脚本使用 `python3 -m http.server` 提供静态文件，修改前端 HTML/CSS/JS 后需手动刷新浏览器

> 注意：现在所有加密 / 解锁 / 体积优化逻辑都在后端完成，**必须启动后端** 才能正常使用这些功能。

**修改后端地址**：在 `frontend/index.html` 中修改 `window.FREEYOURPDF_API_BASE`。

## 技术栈

- **前端**：原生 HTML / CSS / JavaScript，纯静态页面，无构建链路
- **后端**：
  - Python Flask
  - [pypdf](https://pypdf.readthedocs.io/) + [pikepdf](https://pikepdf.readthedocs.io/)：检测 / 解锁 / 加密 / 结构优化
  - [Ghostscript](https://www.ghostscript.com/)：配合后端脚本进行 PDF 体积优化（类似 [`pdfc`](https://github.com/theeko74/pdfc) 的压缩效果）
  - SQLite：本地数据库
  - JWT 认证、CORS 已开启，支持前后端分离部署

## 项目结构

```
├── frontend/                 # 前端
│   ├── index.html            # 主页
│   ├── css/style.css
│   ├── js/app.js
│   └── admin/index.html      # /admin 跳转到 /#admin
├── backend/
│   ├── app.py                # API 入口（检测/解锁/加密、认证、配额、支付、管理）
│   ├── auth.py               # 登录/注册、JWT
│   ├── config.py             # 配置（数据库、密钥、套餐等）
│   ├── models.py             # 用户、配额、支付、访问/使用记录
│   ├── environment.yml       # conda 环境
│   └── requirements.txt
├── start_backend.sh
├── start_frontend.sh
└── README.md
```

## API 概览（后端）

| 分类 | 接口 | 说明 |
|------|------|------|
| 认证 | `POST /api/auth/send-code` | 发送邮箱验证码 |
| | `POST /api/auth/register` | 注册 |
| | `POST /api/auth/login` | 密码登录 |
| | `POST /api/auth/login-by-code` | 验证码登录 |
| | `GET /api/me` | 当前用户信息 |
| 用户 | `GET/PUT /api/user/profile` | 个人资料（昵称、头像） |
| | `POST /api/user/change-password` | 修改密码 |
| 访问 | `POST /api/visit` | 记录页面访问（含 IP/地理位置） |
| 配额 | `GET /api/quota` | 当前剩余次数 |
| | `POST /api/quota/consume` | 扣减次数（type: encrypt/unlock/compress） |
| 支付 | `GET /api/payment/packs` | 套餐列表 |
| | `POST /api/payment/create` | 创建订单 |
| | `POST /api/payment/confirm` | 确认已支付 |
| | `GET /api/payment/orders` | 当前用户订单列表 |
| PDF | `POST /api/detect` | 检测是否加密/有权限限制 |
| | `POST /api/unlock` | 解密/解除限制 |
| | `POST /api/crack-and-unlock` | 暴力破解密码后解锁 |
| 管理 | `GET /api/admin/stats` | 数据概览 |
| | `GET /api/admin/monitor/realtime` | 实时监控 |
| | `GET /api/admin/access-logs` | 访问记录 |
| | `GET /api/admin/usage-logs` | 使用记录 |
| | `GET /api/admin/users` | 用户列表 |
| | `GET /api/admin/payments` | 支付记录 |
| | `POST /api/admin/payment-test` | 支付测试（管理员加次数） |

所有 PDF 文件通过后端在本机服务器上处理，不会持久保存到外部服务；仅存储必要的统计数据（如访问记录 / 使用记录），不存储文件内容。
