# Render 部署说明

## 启动命令

在 Render 的 Web Service 设置中，**Start Command** 应设置为：

```bash
cd backend && gunicorn -c gunicorn_config.py app:app
```

或者如果 Root Directory 已设置为 `backend`：

```bash
gunicorn -c gunicorn_config.py app:app
```

**重要**：必须使用 `-c gunicorn_config.py` 参数，这样才能过滤掉健康检查日志。

## 必需的环境变量

### 基础配置
- `SECRET_KEY` - JWT 签名密钥（至少 32 字符）
- `INITIAL_ADMIN_PHONE` - 初始管理员手机号（11 位）
- `INITIAL_ADMIN_PASSWORD` - 初始管理员密码
- `INITIAL_ADMIN_USERNAME` - （可选）初始管理员用户名

### 短信服务（互亿无线）
- `SMS_ENABLED=true`
- `SMS_ACCOUNT` - APIID（如 C94003786）
- `SMS_PASSWORD` - APIKEY
- `SMS_TEMPLATE_ID=1` - （可选）模板 ID
- `SMS_API_URL=https://api.ihuyi.com/sms/Submit.json` - （可选）API 地址

### 可选：支付宝支付验证
- `ALIPAY_COOKIE` - 支付宝 Cookie
- `ALIPAY_CTOKEN` - ctoken
- `ALIPAY_BILL_USER_ID` - 账单用户 ID
- `ALIPAY_ALERT_EMAIL` - Cookie 过期告警邮箱

## 功能说明

### 体积优化
- **优先使用 Ghostscript**：如果 Render 环境安装了 `gs` 命令，会使用 Ghostscript 进行有损压缩
- **自动回退**：如果 Ghostscript 不可用，会自动回退到 pypdf 结构优化（无损）
- **日志输出**：所有操作都会输出到 stdout，可在 Render 的 Logs 页面查看

### 暴力破解密码
- 使用常见密码列表 + 1-4 位数字组合
- 所有尝试过程会输出到日志（前 5 次和每 10 次）
- 失败时会输出最后错误和完整堆栈

### 日志查看
所有错误和关键操作都会输出到 stdout，格式为 `[FreeYourPDF] ...`，可在 Render Dashboard → Logs 页面查看。

## 健康检查日志过滤

`gunicorn_config.py` 会自动过滤掉 `GET /api/health` 的访问日志，减少日志噪音。

## 数据库

Render 的持久化磁盘会自动挂载，SQLite 数据库文件会保存在 `backend/data/freeyourpdf.db`。
