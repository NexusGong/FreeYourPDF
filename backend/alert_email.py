# -*- coding: utf-8 -*-
"""
告警邮件：支付宝 Cookie 过期时发送到指定邮箱（复用 SMTP 配置，带限流）
"""
import logging
import time
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate

logger = logging.getLogger(__name__)

# 限流：同一告警 key 上次发送时间
_alert_last_sent = {}
_alert_throttle_hours = 24


def _get_config():
    import config as config_module
    return config_module


def _should_throttle(alert_key):
    cfg = _get_config()
    throttle = getattr(cfg, 'ALERT_THROTTLE_HOURS', 24)
    last = _alert_last_sent.get(alert_key)
    if last is None:
        return False
    return (time.time() - last) < (throttle * 3600)


def _record_sent(alert_key):
    _alert_last_sent[alert_key] = time.time()


def notify_alipay_cookie_invalid(error_message=None):
    """
    支付宝 Cookie 过期或无效时发送告警邮件到 ALIPAY_ALERT_EMAIL。
    使用与验证码相同的 SMTP 配置；限流内只发一封。
    """
    cfg = _get_config()
    to_email = getattr(cfg, 'ALIPAY_ALERT_EMAIL', '').strip()
    if not to_email:
        return False
    if _should_throttle('ALIPAY_COOKIE_EXPIRED'):
        logger.debug('支付宝 Cookie 告警限流中，跳过发送')
        return False
    host = getattr(cfg, 'SMTP_HOST', None)
    user = getattr(cfg, 'SMTP_USER', None)
    password = getattr(cfg, 'SMTP_PASSWORD', None)
    port = int(getattr(cfg, 'SMTP_PORT', 587) or 587)
    use_tls = getattr(cfg, 'SMTP_USE_TLS', True)
    if not host or not user or not password:
        logger.warning('告警邮件未发送：SMTP 未配置')
        return False
    from datetime import datetime
    now_str = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    title = 'FreeYourPDF：支付宝 Cookie 已过期'
    message = (
        '支付宝支付验证功能的 Cookie 已过期或无效，用户点击「我已支付」时将无法自动到账。\n\n'
        '请按 backend/ALIPAY_VERIFY_CONFIG.md 重新获取 Cookie、ctoken、billUserId 并更新 backend/.env。\n\n'
    )
    if error_message:
        message += '错误信息：%s\n\n' % error_message
    message += '检测时间：%s' % now_str
    html = (
        '<!DOCTYPE html><html><head><meta charset="UTF-8"></head><body style="font-family:Arial,sans-serif;line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">'
        '<div style="background:#FF9800;color:#fff;padding:12px;border-radius:5px 5px 0 0;">'
        '<strong>%s</strong></div>'
        '<div style="background:#f9f9f9;padding:20px;border:1px solid #ddd;border-top:none;border-radius:0 0 5px 5px;">'
        '<p>%s</p>'
        '%s'
        '<p style="color:#666;font-size:14px;">检测时间：%s</p>'
        '<p style="color:#999;font-size:12px;">此邮件由 FreeYourPDF 自动发送，请勿直接回复。</p>'
        '</div></body></html>'
    ) % (
        title,
        message.replace('\n', '<br>\n'),
        ('<p style="background:#fff;padding:10px;border-left:4px solid #FF9800;margin:10px 0;"><strong>错误信息：</strong>%s</p>' % (error_message or '').replace('<', '&lt;').replace('>', '&gt;') if error_message else ''),
        now_str,
    )
    try:
        msg = MIMEMultipart('alternative')
        msg['Subject'] = '[FreeYourPDF] ' + title
        msg['From'] = user
        msg['To'] = to_email
        msg['Date'] = formatdate(localtime=True)
        msg['MIME-Version'] = '1.0'
        msg.attach(MIMEText(message, 'plain', 'utf-8'))
        msg.attach(MIMEText(html, 'html', 'utf-8'))
        with smtplib.SMTP(host, port) as s:
            if use_tls:
                s.starttls()
            s.login(user, password)
            s.sendmail(user, [to_email], msg.as_string())
        _record_sent('ALIPAY_COOKIE_EXPIRED')
        logger.info('支付宝 Cookie 过期告警邮件已发送至 %s', to_email)
        return True
    except Exception as e:
        logger.warning('支付宝 Cookie 告警邮件发送失败: %s', e)
        return False
