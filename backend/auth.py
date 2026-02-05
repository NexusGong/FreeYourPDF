# -*- coding: utf-8 -*-
"""认证：手机号+短信/密码（与 2Vision 一致），仅保留短信验证码与密码登录/注册。"""
import os
import re
import secrets
from datetime import datetime, timedelta

import jwt
from flask import request, jsonify, current_app

from models import db, User, Quota
import config as config_module


def _user_to_dict(user):
    """与 app.api_me 一致的当前用户信息，供登录/注册返回，含头像、手机号、密码状态（与 2Vision 一致）。"""
    return {
        'id': user.id,
        'email': user.email,
        'username': user.username,
        'nickname': getattr(user, 'nickname', None) or user.username,
        'avatar': getattr(user, 'avatar', None),
        'is_admin': getattr(user, 'is_admin', False),
        'phone': getattr(user, 'phone', None),
        'password_set': getattr(user, 'password_set', False),
        'created_at': user.created_at.isoformat() + 'Z' if getattr(user, 'created_at', None) else None,
    }


def _validate_username(username):
    if not username or len(username) < config_module.USERNAME_MIN_LEN or len(username) > config_module.USERNAME_MAX_LEN:
        return False, f'用户名长度为 {config_module.USERNAME_MIN_LEN}～{config_module.USERNAME_MAX_LEN} 个字符'
    if not re.match(r'^[a-zA-Z0-9_\u4e00-\u9fa5]+$', username):
        return False, '用户名仅支持字母、数字、下划线和中文'
    reserved = {'admin', 'root', 'system', 'freeyourpdf'}
    if username.lower() in reserved:
        return False, '该用户名不可用'
    return True, None


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


# ---------- 手机号 + 短信/密码（与 2Vision 一致）----------

def _get_user_by_phone(phone):
    return User.query.filter_by(phone=phone).first()


def _create_user_by_phone(username, phone, password=None):
    """手机号注册：虚拟邮箱。password 若传入则设置并 password_set=True，否则随机密码且 password_set=False。"""
    virtual_email = "phone_%s@sms.user" % phone
    n = 0
    while User.query.filter_by(email=virtual_email).first():
        n += 1
        virtual_email = "phone_%s_%s@sms.user" % (phone, n)
    user = User(
        username=username,
        email=virtual_email,
        phone=phone,
        password_set=bool(password),
    )
    if password:
        user.set_password(password)
    else:
        from werkzeug.security import generate_password_hash
        user.password_hash = generate_password_hash(secrets.token_urlsafe(32))
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
    return user


def sms_send():
    """POST /api/auth/sms/send { phone }"""
    import sms as sms_module
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("-", "")
    if not sms_module.is_valid_phone(phone):
        return jsonify({"error": "手机号格式不正确，请输入以1开头的11位数字"}), 400
    remaining = sms_module.get_sms_remaining_seconds(phone)
    if remaining > 0:
        return jsonify({"error": "发送过于频繁，请 %s 秒后再试" % remaining}), 429
    if not sms_module.send_sms_code(phone):
        return jsonify({"error": "验证码发送失败，请稍后重试"}), 500
    user_exists = _get_user_by_phone(phone) is not None
    return jsonify({
        "message": "验证码已发送",
        "phone": phone,
        "expire_minutes": config_module.SMS_CODE_EXPIRE_MINUTES,
        "user_exists": user_exists,
    })


def sms_register():
    """POST /api/auth/sms/register { username, phone, code, password } -> token + user（新用户验证码通过后设置用户名和密码，密码为必填）"""
    import sms as sms_module
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("-", "")
    username = (data.get("username") or "").strip()
    code = (data.get("code") or "").strip()
    password = (data.get("password") or "").strip()
    if not sms_module.is_valid_phone(phone):
        return jsonify({"error": "手机号格式不正确"}), 400
    if not sms_module.verify_sms_code(phone, code, consume=True):
        return jsonify({"error": "验证码错误或已过期"}), 400
    if _get_user_by_phone(phone):
        return jsonify({"error": "该手机号已被注册"}), 400
    if not username:
        return jsonify({"error": "用户名不能为空"}), 400
    ok, err = _validate_username(username)
    if not ok:
        return jsonify({"error": err}), 400
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "用户名已存在"}), 400
    if not password:
        return jsonify({"error": "密码不能为空"}), 400
    if len(password) < 6:
        return jsonify({"error": "密码至少 6 位"}), 400
    user = _create_user_by_phone(username, phone, password=password)
    token = _make_token(user.id)
    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "user": _user_to_dict(user),
    }), 201


def sms_submit():
    """
    统一入口：POST /api/auth/sms/submit { phone, code }
    - 验证码正确且已注册：消耗验证码并返回 token（直接登录）。
    - 验证码正确且未注册：不消耗验证码，返回 need_register: true，前端弹窗让用户设置用户名和密码后调 register。
    """
    import sms as sms_module
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("-", "")
    code = (data.get("code") or "").strip()
    if not sms_module.is_valid_phone(phone):
        return jsonify({"error": "手机号格式不正确"}), 400
    if not sms_module.verify_sms_code(phone, code, consume=False):
        return jsonify({"error": "验证码错误或已过期"}), 400
    user = _get_user_by_phone(phone)
    if user:
        sms_module.verify_sms_code(phone, code, consume=True)
        token = _make_token(user.id)
        return jsonify({
            "access_token": token,
            "token_type": "bearer",
            "user": _user_to_dict(user),
        })
    return jsonify({"need_register": True, "phone": phone})


def sms_login():
    """POST /api/auth/sms/login { phone, code } -> token（保留供兼容）"""
    import sms as sms_module
    data = request.get_json(silent=True) or {}
    phone = (data.get("phone") or "").strip().replace(" ", "").replace("-", "")
    code = (data.get("code") or "").strip()
    if not sms_module.is_valid_phone(phone):
        return jsonify({"error": "手机号格式不正确"}), 400
    if not sms_module.verify_sms_code(phone, code):
        return jsonify({"error": "验证码错误或已过期"}), 400
    user = _get_user_by_phone(phone)
    if not user:
        return jsonify({"error": "该手机号未注册，请先注册"}), 404
    token = _make_token(user.id)
    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "user": _user_to_dict(user),
    })


def password_login():
    """POST /api/auth/password/login { username, password } -> token（支持用户名或手机号登录）"""
    import sms as sms_module
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    if not username:
        return jsonify({"error": "请输入用户名"}), 400
    if not password:
        return jsonify({"error": "请输入密码"}), 400
    # 优先按用户名查找，如果用户名是手机号格式则也支持按手机号查找
    user = User.query.filter_by(username=username).first()
    if not user and sms_module.is_valid_phone(username):
        user = _get_user_by_phone(username)
    if not user:
        return jsonify({"error": "用户名或密码错误"}), 401
    if not getattr(user, "password_set", False):
        return jsonify({"error": "该账号未设置密码，请使用验证码登录"}), 400
    if not user.check_password(password):
        return jsonify({"error": "用户名或密码错误"}), 401
    token = _make_token(user.id)
    return jsonify({
        "access_token": token,
        "token_type": "bearer",
        "user": _user_to_dict(user),
    })


def _current_user_id():
    """从 Authorization: Bearer 解析出 user_id，无效返回 None。"""
    h = request.headers.get("Authorization")
    if not h or not h.startswith("Bearer "):
        return None
    return decode_token(h[7:].strip())


def password_set():
    """POST /api/auth/password/set { password, confirm_password } 需登录"""
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    confirm = data.get("confirm_password") or ""
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"error": "请先登录"}), 401
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    if getattr(user, "password_set", False):
        return jsonify({"error": "密码已设置，如需修改请使用修改密码功能"}), 400
    if password != confirm:
        return jsonify({"error": "两次输入的密码不一致"}), 400
    if len(password) < 6:
        return jsonify({"error": "密码长度至少6位"}), 400
    user.set_password(password)
    db.session.commit()
    return jsonify({"message": "密码设置成功"})


def password_change_sms():
    """POST /api/auth/password/change { old_password, new_password, confirm_password } 需登录（与 2Vision 一致）"""
    data = request.get_json(silent=True) or {}
    old_pwd = data.get("old_password") or ""
    new_pwd = data.get("new_password") or ""
    confirm = data.get("confirm_password") or ""
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"error": "请先登录"}), 401
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    if not getattr(user, "password_set", False):
        return jsonify({"error": "请先设置密码"}), 400
    if not user.check_password(old_pwd):
        return jsonify({"error": "原密码错误"}), 400
    if new_pwd != confirm:
        return jsonify({"error": "两次输入的密码不一致"}), 400
    if len(new_pwd) < 6:
        return jsonify({"error": "新密码至少6位"}), 400
    user.set_password(new_pwd)
    db.session.commit()
    return jsonify({"message": "密码修改成功"})


def password_status():
    """GET /api/auth/password/status 需登录，返回是否已设置密码、手机号"""
    user_id = _current_user_id()
    if user_id is None:
        return jsonify({"error": "请先登录"}), 401
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"error": "用户不存在"}), 404
    return jsonify({
        "password_set": getattr(user, "password_set", False),
        "phone": getattr(user, "phone", None),
    })
