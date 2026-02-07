# Cloudflare 配置指南

当你的域名通过 Cloudflare 代理时，可能会遇到以下问题。本文档提供解决方案。

## 常见问题

### 1. 502 Bad Gateway 错误
**原因**：Cloudflare 的 SSL/TLS 模式设置不当，或后端服务未正确响应。

**解决方案**：
- 在 Cloudflare Dashboard → SSL/TLS → 概述中，将 SSL/TLS 加密模式设置为 **"完全"** 或 **"完全（严格）"**
- 确保后端服务支持 HTTPS（如果使用"完全（严格）"模式）
- 检查后端服务是否正常运行

### 2. API 请求被拦截或返回错误
**原因**：Cloudflare 的防火墙规则、WAF 或安全设置拦截了请求。

**解决方案**：
- Cloudflare Dashboard → 安全 → WAF → 创建规则，允许你的 API 路径：
  ```
  路径包含：/api/
  操作：允许
  ```
- 或者将 API 路径添加到"安全" → "WAF" → "自定义规则"的允许列表

### 3. CORS 错误
**原因**：Cloudflare 可能修改了 CORS 响应头。

**解决方案**：
- 确保后端正确设置了 CORS 响应头（代码已包含）
- 在 Cloudflare Dashboard → 规则 → 转换规则 → 修改响应头，确保不覆盖 CORS 头
- 或者添加页面规则：`www.freeyourpdf.top/api/*` → 设置：缓存级别 → 绕过

### 4. API 响应被缓存
**原因**：Cloudflare 默认会缓存某些响应，导致 API 返回旧数据。

**解决方案**：
- Cloudflare Dashboard → 规则 → 页面规则
- 创建规则：`www.freeyourpdf.top/api/*`
- 设置：
  - 缓存级别：**绕过**
  - 边缘缓存 TTL：**绕过**
  - 浏览器缓存 TTL：**尊重现有标头**

### 5. 大文件上传失败
**原因**：Cloudflare 对请求大小有限制（免费版 100MB）。

**解决方案**：
- 确保文件大小在限制内（你的代码已限制为 30MB，应该没问题）
- 如果仍有问题，考虑使用 Cloudflare Workers 或直接访问源服务器

### 6. SSE（Server-Sent Events）连接失败
**原因**：Cloudflare 可能关闭了长时间连接。

**解决方案**：
- 在页面规则中为 SSE 端点设置：`www.freeyourpdf.top/api/crack-and-unlock`
- 设置：缓存级别 → 绕过
- 或者考虑使用 WebSocket（需要额外配置）

## 推荐的 Cloudflare 设置

### SSL/TLS 设置
- **加密模式**：完全（如果后端支持 HTTPS）或 完全（严格）
- **始终使用 HTTPS**：开启
- **自动 HTTPS 重写**：开启

### 缓存设置
- **缓存级别**：标准（对静态资源）
- **浏览器缓存 TTL**：尊重现有标头
- **为 API 路径创建页面规则**：`/api/*` → 缓存级别：绕过

### 安全设置
- **安全级别**：中等（避免过于严格导致误拦截）
- **WAF**：开启，但添加自定义规则允许 `/api/*` 路径
- **Bot 管理**：根据需求设置（免费版可能不可用）

### 速度设置
- **自动压缩**：开启（但确保不影响 API 响应）
- **Brotli**：开启
- **HTTP/2**：开启
- **HTTP/3 (QUIC)**：开启（可选）

### 网络设置
- **WebSockets**：开启（如果使用 SSE）
- **IP 地理位置**：根据需要设置

## 测试步骤

1. **测试 API 是否可访问**：
   ```bash
   curl -I https://www.freeyourpdf.top/api/health
   ```

2. **测试 CORS**：
   在浏览器控制台运行：
   ```javascript
   fetch('https://www.freeyourpdf.top/api/health', {
     method: 'GET',
     headers: { 'Origin': 'https://www.freeyourpdf.top' }
   }).then(r => console.log(r.headers.get('Access-Control-Allow-Origin')))
   ```

3. **检查响应头**：
   确保响应包含正确的 CORS 头：
   - `Access-Control-Allow-Origin`
   - `Access-Control-Allow-Methods`
   - `Access-Control-Allow-Headers`

## 调试技巧

1. **查看 Cloudflare 日志**：
   - Cloudflare Dashboard → Analytics → Logs（需要付费版）

2. **使用开发模式**：
   - Cloudflare Dashboard → 缓存 → 配置 → 开发模式
   - 临时禁用缓存进行测试

3. **检查源服务器响应**：
   - 直接访问源服务器 IP（绕过 Cloudflare）测试功能是否正常

4. **查看浏览器控制台**：
   - 检查网络请求的详细信息
   - 查看是否有 CORS 错误或其他错误

## 如果问题仍然存在

1. **临时禁用 Cloudflare 代理**：
   - 在 DNS 设置中，将代理状态从"已代理"（橙色云朵）改为"仅 DNS"（灰色云朵）
   - 测试功能是否正常
   - 如果正常，说明问题确实在 Cloudflare 配置

2. **联系 Cloudflare 支持**：
   - 如果使用付费版，可以联系技术支持
   - 免费版可以在社区论坛提问

3. **考虑使用 Cloudflare Workers**：
   - 对于复杂的 API 代理需求，可以考虑使用 Workers
