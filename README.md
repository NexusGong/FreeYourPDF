# FreeYourPDF

PDF 加密 / 解密 / 解除权限限制 / 体积优化 的 Web 小工具。前后端分离：后端提供 API 完成所有 PDF 处理逻辑，前端只负责界面与交互。

## 功能一览

- **需打开密码** → 后端暴力破解常见密码 / 数字密码 / 日期格式 / 短字母数字组合，并解密为无密码 PDF（SSE 流式进度显示）
- **无密码、有权限限制** → 解除复制 / 打印 / 编辑等权限限制
- **无密码无限制** → 加密（设置打开密码与权限，兼容 Adobe / 预览等阅读器）
- **缩小体积**：由后端使用 Ghostscript（优先，图片重采样）或 pypdf（回退，结构优化）对未加密 PDF 进行体积优化
- **登录/注册**：手机号+短信验证码登录与注册，支持密码登录，JWT 默认有效期 7 天
- **配额**：登录用户每项 10 次，未登录用户（匿名）每项 5 次；可通过充值三档套餐增加次数
- **个人资料**：昵称、头像（Emoji 或自定义图片）、修改密码
- **管理后台**：管理员访问 `/#admin` 或 `/admin`，含数据概览、访问/使用记录、用户管理（增删改查、配额调整）、支付记录、实时监控、成本监控等
- **支付验证**：支持支付宝自动验证到账（需配置 Cookie），手动确认支付后自动增加配额

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
  - [Ghostscript](https://www.ghostscript.com/)：PDF 体积优化（图片重采样，类似 [`pdfc`](https://github.com/theeko74/pdfc) 的压缩效果）
  - SQLite：本地数据库（用户、配额、支付、访问/使用记录）
  - JWT 认证（7 天有效期）、CORS 已开启，支持前后端分离部署
  - 短信验证码（手机号登录/注册）、支付宝支付验证（自动到账确认）

## 项目结构

```
├── frontend/                 # 前端
│   ├── index.html            # 主页
│   ├── css/style.css
│   ├── js/app.js
│   └── admin/index.html      # /admin 跳转到 /#admin
├── backend/
│   ├── app.py                # API 入口（检测/解锁/加密、认证、配额、支付、管理）
│   ├── auth.py               # 登录/注册（手机号+短信/密码）、JWT
│   ├── config.py             # 配置（数据库、密钥、套餐、短信、支付等）
│   ├── models.py             # 数据模型（用户、配额、支付、访问/使用记录）
│   ├── sms.py                # 短信验证码发送
│   ├── alipay_verifier.py    # 支付宝支付验证（自动到账确认）
│   ├── alert_email.py        # 告警邮件（支付验证失败通知）
│   ├── .env                  # 环境变量配置（需自行创建）
│   ├── environment.yml       # conda 环境配置
│   └── requirements.txt      # Python 依赖
├── start_backend.sh
├── start_frontend.sh
└── README.md
```

## API 概览（后端）

| 分类 | 接口 | 说明 |
|------|------|------|
| 认证 | `POST /api/auth/sms/send` | 发送短信验证码 |
| | `POST /api/auth/sms/submit` | 提交验证码（登录/注册） |
| | `POST /api/auth/sms/register` | 短信验证码注册 |
| | `POST /api/auth/sms/login` | 短信验证码登录 |
| | `POST /api/auth/password/login` | 密码登录 |
| | `POST /api/auth/password/set` | 设置密码 |
| | `POST /api/auth/password/change` | 修改密码（需短信验证） |
| | `GET /api/auth/password/status` | 查询密码设置状态 |
| | `GET /api/me` | 当前用户信息 |
| 用户 | `GET/PUT /api/user/profile` | 个人资料（昵称、头像、用户名） |
| | `POST /api/user/change-password` | 修改密码（需当前密码） |
| 访问 | `POST /api/visit` | 记录页面访问（含 IP/地理位置/设备信息） |
| 配额 | `GET /api/quota` | 当前剩余次数（支持登录用户和匿名用户） |
| | `POST /api/quota/consume` | 扣减次数（type: encrypt/unlock/compress） |
| 支付 | `GET /api/payment/packs` | 套餐列表 |
| | `POST /api/payment/create` | 创建订单 |
| | `POST /api/payment/confirm` | 确认已支付（自动验证支付宝到账） |
| | `GET /api/payment/orders` | 当前用户订单列表 |
| PDF | `POST /api/detect` | 检测是否加密/有权限限制（不扣配额） |
| | `POST /api/unlock` | 解密/解除限制（需提供密码） |
| | `POST /api/crack-and-unlock` | 暴力破解密码后解锁（SSE 流式进度） |
| | `POST /api/encrypt` | 加密 PDF（设置打开密码与权限） |
| | `POST /api/compress` | 体积优化（Ghostscript + pypdf） |
| 管理 | `GET /api/admin/stats` | 数据概览（用户数、支付、收入、趋势） |
| | `GET /api/admin/monitor/realtime` | 实时监控（近 1h/24h 指标） |
| | `GET /api/admin/access-logs` | 访问记录（分页） |
| | `GET /api/admin/usage-logs` | 使用记录（分页） |
| | `GET /api/admin/users` | 用户列表（搜索、分页） |
| | `GET /api/admin/users/<id>` | 用户详情（配额、支付记录） |
| | `PUT /api/admin/users/<id>` | 更新用户（配额、权限等） |
| | `DELETE /api/admin/users/<id>` | 删除用户 |
| | `GET /api/admin/payments` | 支付记录（分页、状态筛选） |
| | `POST /api/admin/payment-test` | 支付测试（管理员加次数） |
| 静态 | `GET /api/static/payment/<filename>` | 支付收款码图片 |
| | `GET /api/health` | 健康检查 |

所有 PDF 文件通过后端在本机服务器上处理，不会持久保存到外部服务；仅存储必要的统计数据（如访问记录 / 使用记录），不存储文件内容。

## 环境配置

后端需要配置环境变量（在 `backend/.env` 文件中）：

- `SECRET_KEY`：Flask 密钥（至少 32 字节，用于 JWT 签名）
- `SQLITE_PATH`：数据库路径（可选，默认 `backend/data/freeyourpdf.db`）
- `SMS_*`：短信服务配置（发送验证码）
- `ALIPAY_COOKIE`、`ALIPAY_CTOKEN`、`ALIPAY_BILL_USER_ID`：支付宝支付验证（可选，用于自动到账确认）
- `SMTP_*`：SMTP 配置（可选，用于告警邮件）
- `INITIAL_ADMIN_PHONE`、`INITIAL_ADMIN_PASSWORD`：初始管理员账号（首次启动时自动创建）

详细配置说明请参考 `backend/config.py` 中的注释。

## 注意事项

- **文件大小限制**：单文件最大 30MB，PDF 最大页数 1000 页（可在 `config.py` 中调整）
- **内存限制**：暴力破解密码最大尝试 50000 次（防止内存耗尽）
- **暴力破解**：仅适用于简单密码（常见密码、1-6 位数字、日期格式、3 位以内字母数字组合），复杂密码无法破解
- **支付验证**：若配置了支付宝 Cookie，系统会自动验证到账；未配置时需手动确认支付
- **开发模式**：后端已开启热重载，修改代码后自动重启；前端需手动刷新浏览器
