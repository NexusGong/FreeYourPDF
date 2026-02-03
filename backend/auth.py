# -*- coding: utf-8 -*-
"""认证：发送验证码、注册、登录（密码/验证码）。"""
import os
import re
import random
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, current_app

from models import db, User, Quota, VerificationCode
import config as config_module

# 内存限流：同一邮箱最近发送时间 { email: timestamp }
_send_code_last = {}


def _user_to_dict(user):
    """与 app.api_me 一致的当前用户信息，供登录/注册返回，含头像等。"""
    return {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'nickname': getattr(user, 'nickname', None) or user.username,
        'avatar': getattr(user, 'avatar', None),
        'is_admin': getattr(user, 'is_admin', False),
        'created_at': user.created_at.isoformat() if getattr(user, 'created_at', None) else None,
    }


def _verification_email_body_plain(code, expire_minutes):
    """验证码邮件纯文本正文。"""
    return (
        'FreeYourPDF 邮箱验证码\n'
        '────────────────────────\n\n'
        f'验证码：{code}\n'
        f'有效期：{expire_minutes} 分钟\n\n'
        '请勿将验证码告知他人。如非本人操作，请忽略本邮件。\n\n'
        '此邮件由系统自动发送，请勿直接回复。\n'
        '────────────────────────\n'
        'FreeYourPDF · PDF 加密 / 解锁 / 体积优化'
    )


def _verification_email_body_html(code, expire_minutes):
    """验证码邮件 HTML 正文（邮件客户端兼容 + 强设计感）。"""
    # 使用 .format 避免 f-string 中花括号被误解析；code/expire_minutes 在调用处安全
    return '''<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="zh-CN">
<head>
  <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>FreeYourPDF 验证码</title>
</head>
<body style="margin:0;padding:0;background-color:#f0f0f5;font-family:Arial,Helvetica,sans-serif;font-size:16px;color:#333;line-height:1.5;">
  <table width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color:#f0f0f5;padding:32px 16px;">
    <tr>
      <td align="center">
        <table width="560" cellpadding="0" cellspacing="0" border="0" align="center" style="background-color:#ffffff;border:1px solid #e0e0e5;">
          <tr>
            <td bgcolor="#7c3aed" style="height:8px;font-size:0;line-height:0;">&#160;</td>
          </tr>
          <tr>
            <td style="padding:32px 40px 24px 40px;">
              <table width="100%" cellpadding="0" cellspacing="0" border="0">
                <tr>
                  <td>
                    <p style="margin:0;font-size:24px;font-weight:bold;color:#1a1a2e;">FreeYourPDF</p>
                    <p style="margin:6px 0 0;font-size:13px;color:#6b7280;">PDF 加密 &#183; 解锁 &#183; 体积优化</p>
                  </td>
                </tr>
              </table>
            </td>
          </tr>
          <tr>
            <td style="padding:0 40px 32px 40px;">
              <p style="margin:0 0 6px;font-size:14px;font-weight:bold;color:#374151;">邮箱验证码</p>
              <p style="margin:0 0 20px;font-size:14px;color:#6b7280;">请将下方验证码填入页面中，完成登录或注册。</p>
              <table width="100%" cellpadding="0" cellspacing="0" border="0" bgcolor="#f8f4ff" style="border-left:4px solid #7c3aed;">
                <tr>
                  <td style="padding:28px 24px;text-align:center;">
                    <span style="font-size:36px;font-weight:bold;letter-spacing:10px;color:#1a1a2e;font-family:Consolas,Monaco,monospace;">''' + code + '''</span>
                  </td>
                </tr>
              </table>
              <p style="margin:20px 0 0;font-size:13px;color:#6b7280;">有效期 <strong>''' + str(expire_minutes) + ''' 分钟</strong>，请勿泄露给他人。</p>
            </td>
          </tr>
          <tr>
            <td style="padding:24px 40px 32px 40px;border-top:1px solid #e5e7eb;">
              <p style="margin:0;font-size:12px;color:#9ca3af;">如非本人操作，请忽略本邮件。</p>
              <p style="margin:8px 0 0;font-size:12px;color:#9ca3af;">此邮件由系统自动发送，请勿直接回复。</p>
              <p style="margin:20px 0 0;font-size:11px;color:#d1d5db;">&#169; FreeYourPDF</p>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>'''


def _send_email(to_email, subject, body_text, body_html=None):
    """通过环境变量配置的 SMTP 发送邮件。失败抛异常。"""
    host = config_module.SMTP_HOST
    user = config_module.SMTP_USER
    password = config_module.SMTP_PASSWORD
    port = config_module.SMTP_PORT
    use_tls = config_module.SMTP_USE_TLS
    if not host or not user or not password:
        raise RuntimeError('邮件服务未配置')
    # multipart/alternative：RFC 规定从“最不丰富”到“最丰富”排列，即先 plain 再 html，
    # 客户端会选自己支持的最后一种，这样 QQ 邮箱等才会显示 HTML 而不是纯文本
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = user
    msg['To'] = to_email
    msg['Date'] = formatdate(localtime=True)
    msg['MIME-Version'] = '1.0'
    msg.attach(MIMEText(body_text, 'plain', 'utf-8'))
    if body_html:
        html_part = MIMEText(body_html, 'html', 'utf-8')
        html_part.set_charset('utf-8')
        msg.attach(html_part)
    with smtplib.SMTP(host, port) as s:
        if use_tls:
            s.starttls()
        s.login(user, password)
        s.sendmail(user, [to_email], msg.as_string())


def send_code():
    """POST /api/auth/send-code { email }"""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'error': '请填写邮箱'}), 400
    if not re.match(r'^[^@]+@[^@]+\.[^@]+$', email):
        return jsonify({'error': '邮箱格式不正确'}), 400

    now = datetime.utcnow()
    last = _send_code_last.get(email)
    if last and (now - last).total_seconds() < config_module.CODE_COOLDOWN_SECONDS:
        return jsonify({'error': '发送过于频繁，请稍后再试'}), 429

    code = ''.join(str(random.randint(0, 9)) for _ in range(6))
    expires_at = now + timedelta(minutes=config_module.CODE_EXPIRE_MINUTES)
    rec = VerificationCode(email=email, code=code, expires_at=expires_at)
    db.session.add(rec)
    db.session.commit()

    try:
        expire_min = config_module.CODE_EXPIRE_MINUTES
        _send_email(
            email,
            '【FreeYourPDF】您的验证码',
            _verification_email_body_plain(code, expire_min),
            _verification_email_body_html(code, expire_min),
        )
    except Exception as e:
        current_app.logger.warning('send_code email failed: %s', e)
        return jsonify({'error': '邮件发送失败，请检查邮件服务配置或稍后重试'}), 503

    _send_code_last[email] = now
    return jsonify({'ok': True})


def _validate_username(username):
    if not username or len(username) < config_module.USERNAME_MIN_LEN or len(username) > config_module.USERNAME_MAX_LEN:
        return False, f'用户名长度为 {config_module.USERNAME_MIN_LEN}～{config_module.USERNAME_MAX_LEN} 个字符'
    if not re.match(r'^[a-zA-Z0-9_\u4e00-\u9fa5]+$', username):
        return False, '用户名仅支持字母、数字、下划线和中文'
    reserved = {'admin', 'root', 'system', 'freeyourpdf'}
    if username.lower() in reserved:
        return False, '该用户名不可用'
    return True, None


def register():
    """POST /api/auth/register { email, code, username, password }"""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    code = (data.get('code') or '').strip()
    username = (data.get('username') or '').strip()
    password = data.get('password') or ''

    if not email:
        return jsonify({'error': '请填写邮箱'}), 400
    if not code:
        return jsonify({'error': '请填写验证码'}), 400
    ok, err = _validate_username(username)
    if not ok:
        return jsonify({'error': err}), 400
    if not password or len(password) < 6:
        return jsonify({'error': '密码至少 6 位'}), 400

    now = datetime.utcnow()
    rec = VerificationCode.query.filter_by(email=email).order_by(VerificationCode.created_at.desc()).first()
    if not rec or rec.code != code or rec.expires_at < now:
        return jsonify({'error': '验证码错误或已过期'}), 400

    if User.query.filter_by(email=email).first():
        return jsonify({'error': '该邮箱已注册'}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({'error': '用户名已被使用'}), 400

    user = User(email=email, username=username)
    user.set_password(password)
    if config_module.INITIAL_ADMIN_EMAIL and email == config_module.INITIAL_ADMIN_EMAIL:
        user.is_admin = True
    db.session.add(user)
    db.session.flush()
    quota = Quota(
        user_id=user.id,
        encrypt_remaining=config_module.DEFAULT_QUOTA_ENCRYPT,
        unlock_remaining=config_module.DEFAULT_QUOTA_UNLOCK,
        compress_remaining=config_module.DEFAULT_QUOTA_COMPRESS,
    )
    db.session.add(quota)
    db.session.commit()

    token = _make_token(user.id)
    import sys
    print('[FreeYourPDF] 注册成功 user_id=%s email=%s' % (user.id, user.email), flush=True)
    sys.stdout.flush()
    return jsonify({
        'access_token': token,
        'user': _user_to_dict(user),
    })


def login():
    """POST /api/auth/login { login, password }"""
    data = request.get_json(silent=True) or {}
    login_str = (data.get('login') or '').strip()
    password = data.get('password') or ''

    if not login_str or not password:
        return jsonify({'error': '请填写用户名/邮箱和密码'}), 400

    user = User.query.filter(
        (User.username == login_str) | (User.email == login_str)
    ).first()
    if not user or not user.check_password(password):
        return jsonify({'error': '用户名或密码错误'}), 401

    token = _make_token(user.id)
    import sys
    print('[FreeYourPDF] 登录成功 user_id=%s' % user.id, flush=True)
    sys.stdout.flush()
    return jsonify({
        'access_token': token,
        'user': _user_to_dict(user),
    })


def login_by_code():
    """POST /api/auth/login-by-code { email, code }"""
    data = request.get_json(silent=True) or {}
    email = (data.get('email') or '').strip().lower()
    code = (data.get('code') or '').strip()

    if not email or not code:
        return jsonify({'error': '请填写邮箱和验证码'}), 400

    now = datetime.utcnow()
    rec = VerificationCode.query.filter_by(email=email).order_by(VerificationCode.created_at.desc()).first()
    if not rec or rec.code != code or rec.expires_at < now:
        return jsonify({'error': '验证码错误或已过期'}), 400

    user = User.query.filter_by(email=email).first()
    if not user:
        return jsonify({'error': '该邮箱尚未注册'}), 400

    token = _make_token(user.id)
    import sys
    print('[FreeYourPDF] 验证码登录成功 user_id=%s' % user.id, flush=True)
    sys.stdout.flush()
    return jsonify({
        'access_token': token,
        'user': _user_to_dict(user),
    })


def _make_token(user_id):
    secret = current_app.config.get('SECRET_KEY') or os.environ.get('SECRET_KEY') or config_module.SECRET_KEY
    exp = datetime.utcnow() + timedelta(days=config_module.JWT_EXPIRATION_DAYS)
    # JWT 规范要求 sub 为字符串，否则 PyJWT 解码会报 InvalidSubjectError
    token = jwt.encode(
        {'sub': str(user_id), 'exp': exp},
        secret,
        algorithm=config_module.JWT_ALGORITHM
    )
    return token.decode('utf-8') if isinstance(token, bytes) else str(token)


def decode_token(token):
    """解码 JWT，成功返回 user_id（整数），失败返回 None。"""
    if not token:
        return None
    secret = current_app.config.get('SECRET_KEY') or os.environ.get('SECRET_KEY') or config_module.SECRET_KEY
    try:
        payload = jwt.decode(token, secret, algorithms=[config_module.JWT_ALGORITHM])
        sub = payload.get('sub')
        if sub is None:
            return None
        return int(sub) if isinstance(sub, str) else sub
    except Exception as e:
        import sys
        print('[FreeYourPDF] JWT 解码失败', flush=True)
        sys.stdout.flush()
        return None
