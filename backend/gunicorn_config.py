# -*- coding: utf-8 -*-
"""Gunicorn 配置。用于生产（如 Render）时减少访问日志噪音，只保留关键 API 请求。"""
import logging
from gunicorn import glogging


class _AccessLogFilter(logging.Filter):
    """
    过滤访问日志，只保留关键的 API 请求，过滤掉：
    - 健康检查请求 (/api/health)
    - 静态资源请求 (CSS、JS、图片、字体等)
    - 根路径请求 (GET /)
    """
    def filter(self, record):
        try:
            msg = record.getMessage()
            if not msg:
                return True
            
            # 过滤健康检查
            if '/api/health' in msg:
                return False
            
            # 过滤静态资源请求
            static_paths = [
                '/css/', '/js/', '/assets/', '/.well-known/',
                '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico',
                '.ttf', '.woff', '.woff2', '.eot', '.otf'
            ]
            for path in static_paths:
                if path in msg:
                    return False
            
            # 过滤根路径 GET 请求（首页）
            if 'GET / HTTP' in msg or 'GET / " HTTP' in msg:
                return False
            
            # 只保留 API 请求（/api/ 开头的请求）
            if '/api/' in msg:
                return True
            
            # 其他请求也过滤掉（如 /admin 等）
            return False
        except Exception:
            pass
        return True


class CustomGunicornLogger(glogging.Logger):
    def setup(self, cfg):
        super().setup(cfg)
        logger = logging.getLogger("gunicorn.access")
        logger.addFilter(_AccessLogFilter())


# 使用自定义 logger，只记录关键 API 请求
logger_class = CustomGunicornLogger

# 超时设置：暴力破解可能需要较长时间，设置为 5 分钟（300 秒）
# Render 默认超时是 30 秒，这里增加到 300 秒以支持暴力破解
timeout = 300
keepalive = 5

# 访问日志级别：设置为 WARNING，只记录错误和警告
# 注意：access log 由上面的 Filter 控制，这里主要控制 error log
loglevel = 'info'
accesslog = '-'  # 输出到 stdout，由 Filter 控制内容
errorlog = '-'   # 输出到 stderr
access_log_format = '%(h)s - %(t)s "%(r)s" %(s)s %(b)s'
