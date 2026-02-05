# -*- coding: utf-8 -*-
"""Gunicorn 配置。用于生产（如 Render）时减少健康检查请求的访问日志噪音。"""
import logging
from gunicorn import glogging


class _HealthCheckFilter(logging.Filter):
    """过滤掉对 /api/health 的访问日志（Render/负载均衡等健康检查），避免日志刷屏。"""
    def filter(self, record):
        try:
            msg = record.getMessage()
            if not msg:
                return True
            # 匹配多种可能的日志格式：GET /api/health, "/api/health, /api/health HTTP/1.1 等
            if '/api/health' in msg and ('GET' in msg or '200' in msg or 'Render' in msg):
                return False
        except Exception:
            pass
        return True


class CustomGunicornLogger(glogging.Logger):
    def setup(self, cfg):
        super().setup(cfg)
        logger = logging.getLogger("gunicorn.access")
        logger.addFilter(_HealthCheckFilter())


# 使用自定义 logger，其它保持默认
logger_class = CustomGunicornLogger

# 超时设置：暴力破解可能需要较长时间，设置为 5 分钟（300 秒）
# Render 默认超时是 30 秒，这里增加到 300 秒以支持暴力破解
timeout = 300
keepalive = 5
