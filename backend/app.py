# -*- coding: utf-8 -*-
"""
PDF 检测与解锁后端：仅提供 API，与前端分开启动；需配置 CORS。
认证与配额在后端校验。
"""
import io
import os
from flask import Flask, request, jsonify, send_file
from pypdf import PdfReader, PdfWriter

import uuid
from datetime import datetime, timedelta
import config as config_module
from models import db, User, Quota, AnonymousQuota, Payment, PageVisit, UsageRecord
import auth as auth_module

app = Flask(__name__)
app.config['SECRET_KEY'] = config_module.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = config_module.SQLITE_PATH
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = config_module.MAX_CONTENT_LENGTH

db.init_app(app)
with app.app_context():
    db.create_all()


@app.after_request
def _cors(resp):
    origin = request.headers.get('Origin')
    if origin:
        resp.headers['Access-Control-Allow-Origin'] = origin
    resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
    # 预检时回显浏览器请求的头部，确保 x-anonymous-id 等被允许
    acrh = request.headers.get('Access-Control-Request-Headers')
    if acrh:
        resp.headers['Access-Control-Allow-Headers'] = acrh
    else:
        resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-anonymous-id'
    return resp


@app.before_request
def _cors_preflight():
    if request.method == 'OPTIONS':
        resp = app.make_response(('', 204))
        origin = request.headers.get('Origin')
        if origin:
            resp.headers['Access-Control-Allow-Origin'] = origin
        resp.headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS'
        acrh = request.headers.get('Access-Control-Request-Headers')
        if acrh:
            resp.headers['Access-Control-Allow-Headers'] = acrh
        else:
            resp.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, x-anonymous-id'
        return resp
    return None


def _log(msg):
    """调试用：后端 console 输出，便于排查 401 等。"""
    import sys
    print('[FreeYourPDF]', msg, flush=True)
    sys.stdout.flush()


def _get_current_user_id():
    """从 Authorization: Bearer <token> 解析出 user_id，无效返回 None。"""
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        _log('auth: 无 Authorization 或非 Bearer')
        return None
    token = auth_header[7:].strip()
    user_id = auth_module.decode_token(token)
    if user_id is None:
        _log('auth: JWT 解码失败或已过期 (token 长度=%s)' % len(token))
    else:
        _log('auth: user_id=%s' % user_id)
    return user_id


def _get_anonymous_id():
    """从 X-Anonymous-Id 头获取匿名 ID，无或空返回 None。"""
    aid = (request.headers.get('X-Anonymous-Id') or request.headers.get('x-anonymous-id') or '').strip()
    return aid if len(aid) <= 64 and aid else None


def _get_client_ip():
    """获取客户端 IP。"""
    forwarded = request.headers.get('X-Forwarded-For')
    if forwarded:
        return forwarded.split(',')[0].strip()
    return request.headers.get('X-Real-IP') or (request.remote_addr or 'unknown')


def _get_location_from_ip(ip):
    """
    根据 IP 解析地理位置（国家/省/市/时区）。
    使用 ip-api.com 免费接口（45 次/分钟），无 key。
    本地/内网 IP 或失败时返回空字典。
    """
    if not ip or ip in ('unknown', '127.0.0.1', 'localhost'):
        return {}
    if ip.startswith('192.168.') or ip.startswith('10.') or ip.startswith('172.'):
        return {}
    try:
        from urllib.request import urlopen, Request
        from urllib.error import URLError, HTTPError
        from urllib.parse import quote
        url = 'http://ip-api.com/json/%s?fields=status,country,regionName,city,timezone&lang=zh-CN' % quote(ip)
        req = Request(url, headers={'User-Agent': 'FreeYourPDF/1.0'})
        with urlopen(req, timeout=3) as resp:
            data = resp.read().decode('utf-8', errors='ignore')
        import json
        obj = json.loads(data) if data else {}
        if obj.get('status') != 'success':
            return {}
        return {
            'country': (obj.get('country') or '')[:100],
            'region': (obj.get('regionName') or '')[:100],
            'city': (obj.get('city') or '')[:100],
            'timezone': (obj.get('timezone') or '')[:50],
        }
    except Exception as e:
        _log('get_location_from_ip %s: %s' % (ip, e))
        return {}


def _format_location(country=None, region=None, city=None):
    """将国家/省/市拼成「位置」显示字符串。"""
    parts = [p for p in (country, region, city) if p and str(p).strip()]
    return ' '.join(parts) if parts else '—'


def _parse_device(user_agent_str):
    """从 User-Agent 简单解析设备类型。无依赖时返回 unknown。"""
    if not user_agent_str:
        return {'device_type': 'unknown', 'browser': None, 'os': None}
    ua = (user_agent_str or '').lower()
    if 'mobile' in ua and 'tablet' not in ua and 'ipad' not in ua:
        device_type = 'mobile'
    elif 'tablet' in ua or 'ipad' in ua:
        device_type = 'tablet'
    else:
        device_type = 'desktop'
    browser = None
    if 'chrome' in ua:
        browser = 'Chrome'
    elif 'firefox' in ua:
        browser = 'Firefox'
    elif 'safari' in ua and 'chrome' not in ua:
        browser = 'Safari'
    elif 'edge' in ua:
        browser = 'Edge'
    os_str = None
    if 'windows' in ua:
        os_str = 'Windows'
    elif 'mac os' in ua or 'macintosh' in ua:
        os_str = 'macOS'
    elif 'linux' in ua:
        os_str = 'Linux'
    elif 'android' in ua:
        os_str = 'Android'
    elif 'iphone' in ua or 'ipad' in ua:
        os_str = 'iOS'
    return {'device_type': device_type, 'browser': browser, 'os': os_str}


def _record_usage(user_id, anonymous_id, usage_type, api_endpoint, response_status=200):
    """记录一次使用（加密/解锁/体积优化），含 IP 与地理位置。"""
    try:
        ip = _get_client_ip()
        geo = _get_location_from_ip(ip)
        ua = request.headers.get('User-Agent') or ''
        parsed = _parse_device(ua)
        rec = UsageRecord(
            user_id=user_id,
            session_id=anonymous_id,
            usage_type=usage_type,
            api_endpoint=api_endpoint,
            api_method=request.method,
            response_status=response_status,
            ip_address=ip,
            country=geo.get('country'),
            region=geo.get('region'),
            city=geo.get('city'),
            timezone=geo.get('timezone'),
            user_agent=ua[:500] if ua else None,
            device_type=parsed.get('device_type'),
            browser=parsed.get('browser'),
            os=parsed.get('os'),
        )
        db.session.add(rec)
        db.session.commit()
    except Exception as e:
        _log('record_usage failed: %s' % e)
        try:
            db.session.rollback()
        except Exception:
            pass


def _require_auth():
    """需要登录的接口：返回 (user_id, None) 或 (None, (json_response, status_code))。"""
    user_id = _get_current_user_id()
    if user_id is None:
        return None, (jsonify({'error': '请先登录'}), 401)
    return user_id, None


def _require_admin():
    """需要管理员：返回 (user, None) 或 (None, (json_response, status_code))。"""
    user_id, err = _require_auth()
    if err is not None:
        return None, err
    user = db.session.get(User, user_id)
    if not user:
        return None, (jsonify({'error': '用户不存在'}), 404)
    if not getattr(user, 'is_admin', False):
        return None, (jsonify({'error': '需要管理员权限'}), 403)
    return user, None


def _quota_identity():
    """配额接口用：有 JWT 用 user_id，否则用 anonymous_id。返回 (user_id, anonymous_id)，都无则 (None, None)。"""
    user_id = _get_current_user_id()
    if user_id is not None:
        return user_id, None
    aid = _get_anonymous_id()
    return None, aid


def _quota_dict(quota):
    """Quota 模型转 { encrypt, unlock, compress }。"""
    if quota is None:
        return None
    return {
        'encrypt': max(0, quota.encrypt_remaining),
        'unlock': max(0, quota.unlock_remaining),
        'compress': max(0, quota.compress_remaining),
    }


def _anon_quota_dict(anon):
    """AnonymousQuota 转 { encrypt, unlock, compress }。"""
    if anon is None:
        return None
    return {
        'encrypt': max(0, anon.encrypt_remaining),
        'unlock': max(0, anon.unlock_remaining),
        'compress': max(0, anon.compress_remaining),
    }


def _consume_quota(user_id, quota_type):
    """
    扣减用户配额。quota_type 为 'encrypt' | 'unlock' | 'compress'。
    成功返回 (True, quota_dict)，不足返回 (False, '解锁次数不足' 等)。
    """
    quota = Quota.query.filter_by(user_id=user_id).first()
    if not quota:
        return False, '配额不存在'
    if quota_type == 'encrypt':
        if quota.encrypt_remaining <= 0:
            return False, '加密次数不足'
        quota.encrypt_remaining -= 1
    elif quota_type == 'unlock':
        if quota.unlock_remaining <= 0:
            return False, '解锁次数不足'
        quota.unlock_remaining -= 1
    elif quota_type == 'compress':
        if quota.compress_remaining <= 0:
            return False, '体积优化次数不足'
        quota.compress_remaining -= 1
    else:
        return False, '无效类型'
    db.session.commit()
    return True, _quota_dict(quota)


def _get_or_create_anonymous_quota(anonymous_id):
    """获取或创建匿名配额（每项 5 次）。"""
    anon = db.session.get(AnonymousQuota, anonymous_id)
    if anon is not None:
        return anon
    anon = AnonymousQuota(
        anonymous_id=anonymous_id,
        encrypt_remaining=config_module.DEFAULT_QUOTA_ANONYMOUS_ENCRYPT,
        unlock_remaining=config_module.DEFAULT_QUOTA_ANONYMOUS_UNLOCK,
        compress_remaining=config_module.DEFAULT_QUOTA_ANONYMOUS_COMPRESS,
    )
    db.session.add(anon)
    db.session.commit()
    return anon


def _consume_anonymous_quota(anonymous_id, quota_type):
    """扣减匿名配额。成功返回 (True, quota_dict)，不足返回 (False, msg)。"""
    anon = _get_or_create_anonymous_quota(anonymous_id)
    if quota_type == 'encrypt':
        if anon.encrypt_remaining <= 0:
            return False, '加密次数不足'
        anon.encrypt_remaining -= 1
    elif quota_type == 'unlock':
        if anon.unlock_remaining <= 0:
            return False, '解锁次数不足'
        anon.unlock_remaining -= 1
    elif quota_type == 'compress':
        if anon.compress_remaining <= 0:
            return False, '体积优化次数不足'
        anon.compress_remaining -= 1
    else:
        return False, '无效类型'
    db.session.commit()
    return True, _anon_quota_dict(anon)


# ----- 认证路由 -----
@app.route('/api/auth/send-code', methods=['POST'])
def api_send_code():
    return auth_module.send_code()


@app.route('/api/auth/register', methods=['POST'])
def api_register():
    return auth_module.register()


@app.route('/api/auth/login', methods=['POST'])
def api_login():
    return auth_module.login()


@app.route('/api/auth/login-by-code', methods=['POST'])
def api_login_by_code():
    return auth_module.login_by_code()


@app.route('/api/visit', methods=['POST'])
def api_visit():
    """记录一次页面访问（公开，可选 session_id），含 IP 与地理位置。"""
    data = request.get_json(silent=True) or {}
    session_id = (data.get('session_id') or '').strip() or None
    if session_id and len(session_id) > 100:
        session_id = session_id[:100]
    user_id = _get_current_user_id()
    ip = _get_client_ip()
    geo = _get_location_from_ip(ip)
    ua = request.headers.get('User-Agent') or ''
    parsed = _parse_device(ua)
    visit = PageVisit(
        session_id=session_id,
        user_id=user_id,
        ip_address=ip,
        country=geo.get('country'),
        region=geo.get('region'),
        city=geo.get('city'),
        timezone=geo.get('timezone'),
        user_agent=ua[:500] if ua else None,
        device_type=parsed.get('device_type'),
        browser=parsed.get('browser'),
        os=parsed.get('os'),
    )
    db.session.add(visit)
    db.session.commit()
    return jsonify({'status': 'ok', 'message': '访问已记录'})


# ----- 当前用户（需登录）-----
@app.route('/api/me', methods=['GET'])
def api_me():
    """返回当前登录用户信息（含资料与是否管理员）。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    return jsonify({
        'user': {
            'id': user.id,
            'email': user.email,
            'username': user.username,
            'nickname': getattr(user, 'nickname', None) or user.username,
            'avatar': getattr(user, 'avatar', None),
            'is_admin': getattr(user, 'is_admin', False),
            'created_at': user.created_at.isoformat() if user.created_at else None,
        }
    })


# ----- 个人资料（需登录）-----
@app.route('/api/user/profile', methods=['GET'])
def api_user_profile_get():
    """获取当前用户资料。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    quota = Quota.query.filter_by(user_id=user_id).first()
    q = _quota_dict(quota) if quota else None
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'nickname': getattr(user, 'nickname', None) or user.username,
        'avatar': getattr(user, 'avatar', None),
        'is_admin': getattr(user, 'is_admin', False),
        'quota': q,
        'created_at': user.created_at.isoformat() if user.created_at else None,
    })


@app.route('/api/user/profile', methods=['PUT'])
def api_user_profile_put():
    """更新当前用户资料（昵称、头像）。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    data = request.get_json(silent=True) or {}
    if 'nickname' in data:
        nickname = (data.get('nickname') or '').strip()
        if len(nickname) > 50:
            return jsonify({'error': '昵称长度不能超过50个字符'}), 400
        user.nickname = nickname if nickname else None
    if 'avatar' in data:
        avatar = data.get('avatar')
        if avatar is not None and isinstance(avatar, str) and avatar.startswith('data:image'):
            import base64
            try:
                part = avatar.split(',')[1] if ',' in avatar else avatar
                raw = base64.b64decode(part)
                if len(raw) > 2 * 1024 * 1024:
                    return jsonify({'error': '头像大小不能超过2MB'}), 400
            except Exception:
                return jsonify({'error': '头像格式无效'}), 400
        elif avatar is not None and isinstance(avatar, str) and len(avatar) > 200:
            return jsonify({'error': '头像内容无效'}), 400
        user.avatar = avatar
    if 'username' in data and data.get('username'):
        new_username = (data['username'] or '').strip()
        if len(new_username) < 2 or len(new_username) > 32:
            return jsonify({'error': '用户名长度为 2～32 个字符'}), 400
        if new_username != user.username:
            other = User.query.filter(User.username == new_username).first()
            if other:
                return jsonify({'error': '用户名已被使用'}), 400
            user.username = new_username
    db.session.commit()
    return jsonify({
        'id': user.id,
        'username': user.username,
        'email': user.email,
        'nickname': getattr(user, 'nickname', None) or user.username,
        'avatar': getattr(user, 'avatar', None),
        'is_admin': getattr(user, 'is_admin', False),
    })


@app.route('/api/user/change-password', methods=['POST'])
def api_user_change_password():
    """修改密码：需提供当前密码和新密码。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    data = request.get_json(silent=True) or {}
    current = data.get('current_password') or ''
    new_pwd = data.get('new_password') or ''
    if not current:
        return jsonify({'error': '请填写当前密码'}), 400
    if not user.check_password(current):
        return jsonify({'error': '当前密码错误'}), 400
    if len(new_pwd) < 6:
        return jsonify({'error': '新密码至少 6 位'}), 400
    user.set_password(new_pwd)
    db.session.commit()
    return jsonify({'status': 'success', 'message': '密码已修改'})


# ----- 充值支付（需登录）-----
def _payment_pack_by_index(pack_index):
    """根据套餐下标(0,1,2)返回套餐 dict，无效返回 None。"""
    packs = getattr(config_module, 'PAYMENT_PACKS', [])
    if not isinstance(packs, list) or pack_index < 0 or pack_index >= len(packs):
        return None
    return packs[pack_index]


def _add_quota_after_payment(user_id, pack_type, quantity):
    """支付完成后增加用户配额。"""
    quota = Quota.query.filter_by(user_id=user_id).first()
    if not quota:
        quota = Quota(
            user_id=user_id,
            encrypt_remaining=0,
            unlock_remaining=0,
            compress_remaining=0,
        )
        db.session.add(quota)
        db.session.flush()
    if pack_type == 'unlock':
        quota.unlock_remaining = (quota.unlock_remaining or 0) + quantity
    elif pack_type == 'encrypt':
        quota.encrypt_remaining = (quota.encrypt_remaining or 0) + quantity
    elif pack_type == 'compress':
        quota.compress_remaining = (quota.compress_remaining or 0) + quantity
    elif pack_type == 'combo':
        quota.unlock_remaining = (quota.unlock_remaining or 0) + quantity
        quota.encrypt_remaining = (quota.encrypt_remaining or 0) + quantity
        quota.compress_remaining = (quota.compress_remaining or 0) + quantity
    db.session.commit()


@app.route('/api/payment/packs', methods=['GET'])
def api_payment_packs():
    """获取可购买的套餐列表（三档组合套餐，不鉴权）。"""
    packs = getattr(config_module, 'PAYMENT_PACKS', [])
    if not isinstance(packs, list):
        packs = []
    out = [
        {'index': i, 'encrypt': p.get('encrypt', 0), 'unlock': p.get('unlock', 0), 'compress': p.get('compress', 0), 'amount': float(p.get('amount', 0))}
        for i, p in enumerate(packs)
    ]
    return jsonify({'packs': out})


@app.route('/api/payment/create', methods=['POST'])
def api_payment_create():
    """创建支付订单。body: pack_index (0/1/2)。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    data = request.get_json(silent=True) or {}
    pack_index = data.get('pack_index')
    if pack_index is None:
        pack_index = int(data.get('pack_index') or 0)
    else:
        pack_index = int(pack_index)
    pack = _payment_pack_by_index(pack_index)
    if not pack:
        return jsonify({'error': '该套餐不存在'}), 400
    quantity = pack.get('encrypt', 0)  # 三种次数一致，存一份即可
    amount = float(pack.get('amount', 0))
    if quantity <= 0 or amount <= 0:
        return jsonify({'error': '套餐配置无效'}), 400
    transaction_id = 'TXN_' + uuid.uuid4().hex[:16].upper()
    payment = Payment(
        user_id=user_id,
        pack_type='combo',
        amount=amount,
        quantity=quantity,
        status='pending',
        payment_method=data.get('payment_method') or 'alipay',
        transaction_id=transaction_id,
    )
    db.session.add(payment)
    db.session.commit()
    account_name = getattr(config_module, 'ALIPAY_ACCOUNT_NAME', '支付宝收款')
    return jsonify({
        'order_id': payment.id,
        'transaction_id': payment.transaction_id,
        'amount': payment.amount,
        'quantity': payment.quantity,
        'pack_type': payment.pack_type,
        'status': payment.status,
        'payment_method': payment.payment_method,
        'payment_info': {
            'account_name': account_name,
            'amount': payment.amount,
            'transaction_id': payment.transaction_id,
            'remark': '订单号：' + payment.transaction_id,
        },
        'created_at': payment.created_at.isoformat() if payment.created_at else None,
    })


@app.route('/api/payment/confirm', methods=['POST'])
def api_payment_confirm():
    """用户确认已支付（手动到账后点击确认）。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    data = request.get_json(silent=True) or {}
    transaction_id = (data.get('transaction_id') or '').strip()
    if not transaction_id:
        return jsonify({'error': '缺少 transaction_id'}), 400
    payment = Payment.query.filter_by(transaction_id=transaction_id, user_id=user_id).first()
    if not payment:
        return jsonify({'error': '订单不存在'}), 404
    if payment.status == 'completed':
        return jsonify({
            'status': 'success',
            'message': '支付已完成',
            'payment': {
                'order_id': payment.id,
                'transaction_id': payment.transaction_id,
                'amount': payment.amount,
                'quantity': payment.quantity,
                'pack_type': payment.pack_type,
                'status': payment.status,
            },
        })
    if payment.status != 'pending':
        return jsonify({'error': '订单状态不可确认'}), 400
    from datetime import datetime
    payment.status = 'completed'
    payment.completed_at = datetime.utcnow()
    _add_quota_after_payment(user_id, payment.pack_type, payment.quantity)
    db.session.commit()
    return jsonify({
        'status': 'success',
        'message': '支付成功',
        'payment': {
            'order_id': payment.id,
            'transaction_id': payment.transaction_id,
            'amount': payment.amount,
            'quantity': payment.quantity,
            'pack_type': payment.pack_type,
            'status': payment.status,
        },
    })


@app.route('/api/payment/orders', methods=['GET'])
def api_payment_orders():
    """当前用户的支付订单列表。"""
    user_id, err = _require_auth()
    if err is not None:
        return err[0], err[1]
    page = max(1, int(request.args.get('page') or 1))
    page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
    offset = (page - 1) * page_size
    q = Payment.query.filter_by(user_id=user_id).order_by(Payment.created_at.desc())
    total = q.count()
    items = q.offset(offset).limit(page_size).all()
    return jsonify({
        'status': 'success',
        'data': [
            {
                'order_id': p.id,
                'transaction_id': p.transaction_id,
                'amount': p.amount,
                'quantity': p.quantity,
                'pack_type': p.pack_type,
                'status': p.status,
                'payment_method': p.payment_method,
                'created_at': p.created_at.isoformat() if p.created_at else None,
                'completed_at': p.completed_at.isoformat() if p.completed_at else None,
            }
            for p in items
        ],
        'total': total,
        'page': page,
        'page_size': page_size,
    })


# ----- 配额路由（登录 10 次 / 匿名 5 次）-----
@app.route('/api/quota', methods=['GET'])
def api_quota_get():
    user_id, anonymous_id = _quota_identity()
    _log('GET /api/quota: user_id=%s anonymous_id=%s' % (user_id, (anonymous_id[:8] + '...' if anonymous_id and len(anonymous_id) > 8 else anonymous_id)))
    if user_id is not None:
        quota = Quota.query.filter_by(user_id=user_id).first()
        if not quota:
            _log('GET /api/quota: 用户配额不存在 user_id=%s' % user_id)
            return jsonify({'error': '配额不存在'}), 404
        return jsonify(_quota_dict(quota))
    if anonymous_id is not None:
        anon = _get_or_create_anonymous_quota(anonymous_id)
        return jsonify(_anon_quota_dict(anon))
    _log('GET /api/quota: 401 无登录凭证且无 X-Anonymous-Id')
    return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401


@app.route('/api/quota/consume', methods=['POST'])
def api_quota_consume():
    user_id, anonymous_id = _quota_identity()
    data = request.get_json(silent=True) or {}
    quota_type = (data.get('type') or '').strip().lower()
    if quota_type not in ('encrypt', 'unlock', 'compress'):
        return jsonify({'error': '无效的 type，应为 encrypt / unlock / compress'}), 400
    if user_id is not None:
        ok, result = _consume_quota(user_id, quota_type)
    elif anonymous_id is not None:
        ok, result = _consume_anonymous_quota(anonymous_id, quota_type)
    else:
        return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401
    if not ok:
        return jsonify({'error': result}), 403
    # 加密/体积优化在前端本地完成，在此记录使用；解锁在 /api/unlock 中记录
    if quota_type in ('encrypt', 'compress'):
        _record_usage(user_id, anonymous_id, quota_type, '/api/quota/consume', 200)
    return jsonify(result)


# ----- 后台管理（仅管理员）-----
@app.route('/api/admin/users', methods=['GET'])
def api_admin_users():
    """用户列表（分页、搜索）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    page = max(1, int(request.args.get('page') or 1))
    page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
    search = (request.args.get('search') or '').strip()
    q = User.query
    if search:
        from sqlalchemy import or_
        cond = User.username.contains(search) | User.email.contains(search)
        if hasattr(User, 'nickname'):
            cond = cond | User.nickname.contains(search)
        q = q.filter(cond)
    total = q.count()
    users = q.order_by(User.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    out = []
    for u in users:
        quota = Quota.query.filter_by(user_id=u.id).first()
        out.append({
            'id': u.id,
            'username': u.username,
            'email': u.email,
            'nickname': getattr(u, 'nickname', None),
            'is_admin': getattr(u, 'is_admin', False),
            'quota': _quota_dict(quota) if quota else None,
            'created_at': u.created_at.isoformat() if u.created_at else None,
        })
    return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})


@app.route('/api/admin/users/<int:user_id>', methods=['GET'])
def api_admin_user_detail(user_id):
    """用户详情（含配额、支付记录）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    quota = Quota.query.filter_by(user_id=user_id).first()
    payments = Payment.query.filter_by(user_id=user_id).order_by(Payment.created_at.desc()).limit(50).all()
    return jsonify({
        'status': 'success',
        'data': {
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'nickname': getattr(user, 'nickname', None),
                'is_admin': getattr(user, 'is_admin', False),
                'created_at': user.created_at.isoformat() if user.created_at else None,
            },
            'quota': _quota_dict(quota) if quota else None,
            'payments': [
                {'id': p.id, 'pack_type': p.pack_type, 'amount': p.amount, 'quantity': p.quantity, 'status': p.status, 'created_at': (p.created_at.isoformat() if p.created_at else None)}
                for p in payments
            ],
        },
    })


@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
def api_admin_user_update(user_id):
    """更新用户（管理员）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    data = request.get_json(silent=True) or {}
    if 'username' in data and data['username']:
        other = User.query.filter(User.username == data['username'].strip(), User.id != user_id).first()
        if other:
            return jsonify({'error': '用户名已存在'}), 400
        user.username = data['username'].strip()
    if 'email' in data and data['email']:
        other = User.query.filter(User.email == data['email'].strip().lower(), User.id != user_id).first()
        if other:
            return jsonify({'error': '邮箱已存在'}), 400
        user.email = data['email'].strip().lower()
    if 'nickname' in data:
        user.nickname = (data['nickname'] or '').strip() or None
    if 'is_admin' in data:
        user.is_admin = bool(data['is_admin'])
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    if 'encrypt_remaining' in data and data.get('encrypt_remaining') is not None:
        quota = Quota.query.filter_by(user_id=user_id).first()
        if quota:
            quota.encrypt_remaining = int(data['encrypt_remaining'])
    if 'unlock_remaining' in data and data.get('unlock_remaining') is not None:
        quota = Quota.query.filter_by(user_id=user_id).first()
        if quota:
            quota.unlock_remaining = int(data['unlock_remaining'])
    if 'compress_remaining' in data and data.get('compress_remaining') is not None:
        quota = Quota.query.filter_by(user_id=user_id).first()
        if quota:
            quota.compress_remaining = int(data['compress_remaining'])
    db.session.commit()
    quota = Quota.query.filter_by(user_id=user_id).first()
    return jsonify({
        'status': 'success',
        'data': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'nickname': getattr(user, 'nickname', None),
            'is_admin': getattr(user, 'is_admin', False),
            'quota': _quota_dict(quota) if quota else None,
        },
    })


@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
def api_admin_user_delete(user_id):
    """删除用户（不能删自己）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    if user_id == admin_user.id:
        return jsonify({'error': '不能删除自己'}), 400
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({'error': '用户不存在'}), 404
    db.session.delete(user)
    db.session.commit()
    return jsonify({'status': 'success', 'message': '用户已删除'})


@app.route('/api/admin/payments', methods=['GET'])
def api_admin_payments():
    """支付记录列表（分页、状态筛选）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    page = max(1, int(request.args.get('page') or 1))
    page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
    status_filter = (request.args.get('status') or '').strip()
    q = Payment.query
    if status_filter:
        q = q.filter(Payment.status == status_filter)
    total = q.count()
    items = q.order_by(Payment.created_at.desc()).offset((page - 1) * page_size).limit(page_size).all()
    out = []
    for p in items:
        u = db.session.get(User, p.user_id)
        out.append({
            'id': p.id,
            'user_id': p.user_id,
            'username': u.username if u else None,
            'email': u.email if u else None,
            'pack_type': p.pack_type,
            'amount': p.amount,
            'quantity': p.quantity,
            'status': p.status,
            'transaction_id': p.transaction_id,
            'created_at': p.created_at.isoformat() if p.created_at else None,
            'completed_at': p.completed_at.isoformat() if p.completed_at else None,
        })
    return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})


@app.route('/api/admin/stats', methods=['GET'])
def api_admin_stats():
    """数据概览：用户、支付、收入、访问量、使用量、近 7 日趋势。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    from sqlalchemy import func
    total_users = User.query.count()
    total_payments = Payment.query.filter(Payment.status == 'completed').count()
    revenue = db.session.query(func.sum(Payment.amount)).filter(Payment.status == 'completed').scalar() or 0
    total_visits = PageVisit.query.count()
    total_usage_count = UsageRecord.query.count()
    # 近 7 日使用趋势（按天）
    usage_trend = []
    today = datetime.utcnow().date()
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_start = datetime(day.year, day.month, day.day, 0, 0, 0)
        day_end = day_start + timedelta(days=1)
        cnt = UsageRecord.query.filter(
            UsageRecord.created_at >= day_start,
            UsageRecord.created_at < day_end
        ).count()
        usage_trend.append({'date': day.isoformat(), 'count': cnt})
    # 近 7 日访问趋势
    visit_trend = []
    for i in range(6, -1, -1):
        day = today - timedelta(days=i)
        day_start = datetime(day.year, day.month, day.day, 0, 0, 0)
        day_end = day_start + timedelta(days=1)
        cnt = PageVisit.query.filter(
            PageVisit.created_at >= day_start,
            PageVisit.created_at < day_end
        ).count()
        visit_trend.append({'date': day.isoformat(), 'count': cnt})
    return jsonify({
        'status': 'success',
        'data': {
            'total_users': total_users,
            'total_payments': total_payments,
            'total_revenue': float(revenue or 0),
            'total_cost': 0,
            'total_visits': total_visits,
            'total_usage_count': total_usage_count,
            'usage_trend': usage_trend,
            'visit_trend': visit_trend,
        },
    })


@app.route('/api/admin/monitor/realtime', methods=['GET'])
def api_admin_monitor_realtime():
    """实时监控：近 1h/24h 使用量、最近访问与使用记录。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    now = datetime.utcnow()
    last_1h = now - timedelta(hours=1)
    last_24h = now - timedelta(hours=24)
    recent_usage_1h = UsageRecord.query.filter(UsageRecord.created_at >= last_1h).count()
    recent_usage_24h = UsageRecord.query.filter(UsageRecord.created_at >= last_24h).count()
    recent_visits_1h = PageVisit.query.filter(PageVisit.created_at >= last_1h).count()
    recent_visits_24h = PageVisit.query.filter(PageVisit.created_at >= last_24h).count()
    # 最近 10 条访问
    visits = PageVisit.query.order_by(PageVisit.created_at.desc()).limit(10).all()
    recent_visits = []
    for v in visits:
        u = db.session.get(User, v.user_id) if v.user_id else None
        recent_visits.append({
            'id': v.id,
            'created_at': v.created_at.isoformat() + 'Z' if v.created_at else None,
            'ip_address': v.ip_address,
            'location': _format_location(v.country, v.region, v.city),
            'device_type': v.device_type or 'unknown',
            'username': u.username if u else ('ID:%s' % v.user_id if v.user_id else '匿名'),
        })
    # 最近 10 条使用
    usages = UsageRecord.query.order_by(UsageRecord.created_at.desc()).limit(10).all()
    recent_usage = []
    for r in usages:
        u = db.session.get(User, r.user_id) if r.user_id else None
        type_label = {'encrypt': '加密', 'unlock': '解锁', 'compress': '体积优化'}.get(r.usage_type, r.usage_type or '—')
        recent_usage.append({
            'id': r.id,
            'created_at': r.created_at.isoformat() + 'Z' if r.created_at else None,
            'username': u.username if u else ('ID:%s' % r.user_id if r.user_id else '匿名'),
            'type': type_label,
            'usage_type': r.usage_type,
            'ip_address': r.ip_address,
            'location': _format_location(getattr(r, 'country', None), getattr(r, 'region', None), getattr(r, 'city', None)),
        })
    return jsonify({
        'status': 'success',
        'data': {
            'recent_usage_1h': recent_usage_1h,
            'recent_usage_24h': recent_usage_24h,
            'recent_visits_1h': recent_visits_1h,
            'recent_visits_24h': recent_visits_24h,
            'recent_visits': recent_visits,
            'recent_usage': recent_usage,
        },
    })


@app.route('/api/admin/access-logs', methods=['GET'])
def api_admin_access_logs():
    """访问记录（分页）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    page = max(1, int(request.args.get('page') or 1))
    page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
    offset = (page - 1) * page_size
    q = PageVisit.query.order_by(PageVisit.created_at.desc())
    total = q.count()
    items = q.offset(offset).limit(page_size).all()
    out = []
    for v in items:
        path = v.ip_address or '—'
        if v.device_type:
            path = '%s · %s' % (v.device_type, path)
        user_display = None
        if v.user_id:
            u = db.session.get(User, v.user_id)
            user_display = u.username if u else ('ID:%s' % v.user_id)
        else:
            user_display = '匿名'
        out.append({
            'id': v.id,
            'created_at': v.created_at.isoformat() + 'Z' if v.created_at else None,
            'path': path,
            'ip_address': v.ip_address,
            'location': _format_location(v.country, v.region, v.city),
            'user_id': v.user_id,
            'username': user_display,
            'device_type': v.device_type or 'unknown',
            'user_agent': (v.user_agent[:80] + '…') if v.user_agent and len(v.user_agent) > 80 else v.user_agent,
        })
    return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})


@app.route('/api/admin/usage-logs', methods=['GET'])
def api_admin_usage_logs():
    """使用记录（分页）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    page = max(1, int(request.args.get('page') or 1))
    page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
    offset = (page - 1) * page_size
    q = UsageRecord.query.order_by(UsageRecord.created_at.desc())
    total = q.count()
    items = q.offset(offset).limit(page_size).all()
    out = []
    for r in items:
        user_display = None
        if r.user_id:
            u = db.session.get(User, r.user_id)
            user_display = u.username if u else ('ID:%s' % r.user_id)
        else:
            user_display = '匿名'
        type_label = {'encrypt': '加密', 'unlock': '解锁', 'compress': '体积优化'}.get(r.usage_type, r.usage_type or '—')
        out.append({
            'id': r.id,
            'created_at': r.created_at.isoformat() + 'Z' if r.created_at else None,
            'user_id': r.user_id,
            'username': user_display,
            'type': type_label,
            'usage_type': r.usage_type,
            'api_endpoint': r.api_endpoint,
            'ip_address': r.ip_address,
            'location': _format_location(getattr(r, 'country', None), getattr(r, 'region', None), getattr(r, 'city', None)),
        })
    return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})


@app.route('/api/admin/payment-test', methods=['POST'])
def api_admin_payment_test():
    """支付测试：为当前管理员增加套餐配额（测试用）。"""
    admin_user, err = _require_admin()
    if err is not None:
        return err[0], err[1]
    quota = Quota.query.filter_by(user_id=admin_user.id).first()
    if not quota:
        quota = Quota(user_id=admin_user.id, encrypt_remaining=0, unlock_remaining=0, compress_remaining=0)
        db.session.add(quota)
        db.session.flush()
    add = 10
    quota.encrypt_remaining = (quota.encrypt_remaining or 0) + add
    quota.unlock_remaining = (quota.unlock_remaining or 0) + add
    quota.compress_remaining = (quota.compress_remaining or 0) + add
    db.session.commit()
    return jsonify({
        'status': 'success',
        'message': '测试到账成功，已增加加密/解锁/体积优化各 %d 次' % add,
        'quota': _quota_dict(quota),
    })


# ----- PDF 检测（不鉴权）-----
# 常见密码 + 1～4 位数字，用于暴力破解
COMMON_PASSWORDS = [
    '', '123456', 'password', '12345678', '1234', '12345', 'qwerty', '123456789',
    '1234567', '111111', '000000', '123123', 'abc123', 'password1', 'admin', 'root',
    'pdf', 'PDF', 'Pdf', 'pass', 'Pass', 'open', 'Open', 'secret', 'changeme'
]


def _password_list():
    seen = set()
    out = []
    for p in COMMON_PASSWORDS:
        if p not in seen:
            seen.add(p)
            out.append(p)
    for length in range(1, 5):
        for n in range(10 ** length):
            s = str(n).zfill(length)
            if s not in seen:
                seen.add(s)
                out.append(s)
    return out


def _can_open(stream, password=None):
    """尝试用给定密码打开 PDF，成功返回 True。"""
    stream.seek(0)
    try:
        reader = PdfReader(stream)
        if not reader.is_encrypted:
            return True
        pwd = password if password is not None else ''
        reader.decrypt(pwd)
        return len(reader.pages) > 0
    except Exception:
        return False


def _has_encrypt_in_bytes(data):
    return b'/Encrypt' in data


@app.route('/api/detect', methods=['POST'])
def api_detect():
    """检测 PDF：是否需要打开密码、是否有权限限制。不鉴权、不扣配额。"""
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    data = f.read()
    stream = io.BytesIO(data)
    has_encrypt_meta = _has_encrypt_in_bytes(data)
    encrypted = True
    has_restrictions = False
    if has_encrypt_meta:
        if _can_open(stream, ''):
            encrypted = False
            has_restrictions = True
    if encrypted:
        if _can_open(stream, None):
            encrypted = False
            has_restrictions = has_encrypt_meta
        elif _can_open(stream, ''):
            encrypted = False
            has_restrictions = True
    return jsonify({'encrypted': encrypted, 'hasRestrictions': has_restrictions})


# ----- 解锁（登录 10 次 / 匿名 5 次，先扣 unlock 再处理）-----
@app.route('/api/unlock', methods=['POST'])
def api_unlock():
    """解除权限或解密：登录或匿名，先扣 unlock 配额再处理。"""
    user_id, anonymous_id = _quota_identity()
    if user_id is not None:
        ok, result = _consume_quota(user_id, 'unlock')
    elif anonymous_id is not None:
        ok, result = _consume_anonymous_quota(anonymous_id, 'unlock')
    else:
        return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401
    if not ok:
        return jsonify({'error': result}), 403
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    password = request.form.get('password') or ''
    data = f.read()
    stream = io.BytesIO(data)
    try:
        reader = PdfReader(stream)
        if reader.is_encrypted:
            reader.decrypt(password)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        out = io.BytesIO()
        writer.write(out)
        out.seek(0)
        _record_usage(user_id, anonymous_id, 'unlock', '/api/unlock', 200)
        return send_file(
            out,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=(f.filename or 'output.pdf').replace('.pdf', '_unlocked.pdf')
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'error': '解锁失败：' + str(e)}), 400


@app.route('/api/crack-and-unlock', methods=['POST'])
def api_crack_and_unlock():
    """暴力破解打开密码后解锁：登录或匿名，先扣 unlock 配额再处理。"""
    user_id, anonymous_id = _quota_identity()
    if user_id is not None:
        ok, result = _consume_quota(user_id, 'unlock')
    elif anonymous_id is not None:
        ok, result = _consume_anonymous_quota(anonymous_id, 'unlock')
    else:
        return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401
    if not ok:
        return jsonify({'error': result}), 403
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    data = f.read()
    stream = io.BytesIO(data)
    passwords = _password_list()
    for pwd in passwords:
        stream.seek(0)
        try:
            reader = PdfReader(stream)
            if not reader.is_encrypted:
                break
            reader.decrypt(pwd)
            if len(reader.pages) > 0:
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                out = io.BytesIO()
                writer.write(out)
                out.seek(0)
                _record_usage(user_id, anonymous_id, 'unlock', '/api/crack-and-unlock', 200)
                return send_file(
                    out,
                    mimetype='application/pdf',
                    as_attachment=True,
                    download_name=(f.filename or 'output.pdf').replace('.pdf', '_unlocked.pdf')
                )
        except Exception:
            continue
    return jsonify({'error': '未能破解密码'}), 400


# 启动时确认关键路由已注册（便于排查 404）
with app.app_context():
    _rules = [r.rule for r in app.url_map.iter_rules() if r.rule.startswith('/api/')]
    _key = [x for x in _rules if 'payment' in x or 'user' in x]
    print('[FreeYourPDF] API routes (payment/user):', _key, flush=True)

@app.route('/api/health', methods=['GET'])
def api_health():
    """健康检查，确认服务与路由正常。"""
    return jsonify({'status': 'ok', 'service': 'freeyourpdf'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
