# -*- coding: utf-8 -*-
"""
PDF 检测与解锁后端：仅提供 API，与前端分开启动；需配置 CORS。
认证与配额在后端校验。
"""
import io
import os
import sys
import gc
import resource
import threading
from contextlib import redirect_stderr, redirect_stdout
from flask import Flask, request, jsonify, send_file, send_from_directory, Response, stream_with_context
import json
from pypdf import PdfReader, PdfWriter

try:
    import pikepdf
except ImportError:
    import subprocess
    import sys
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', 'pikepdf>=8.0.0'], cwd=os.path.dirname(os.path.abspath(__file__)))
    import pikepdf

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
    # 为已有 usage_record 表补全缺失列（保留地理、设备等有用字段）
    try:
        conn = db.engine.raw_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(usage_record)")
        existing = {row[1] for row in cur.fetchall()}
        for col, sql_type in [
            ('country', 'VARCHAR(100)'),
            ('region', 'VARCHAR(100)'),
            ('city', 'VARCHAR(100)'),
            ('timezone', 'VARCHAR(50)'),
            ('device_type', 'VARCHAR(20)'),
            ('browser', 'VARCHAR(100)'),
            ('os', 'VARCHAR(100)'),
        ]:
            if col not in existing:
                cur.execute("ALTER TABLE usage_record ADD COLUMN %s %s" % (col, sql_type))
                conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        import sys
        print('[FreeYourPDF] usage_record 表补列:', e, flush=True)
        sys.stdout.flush()

    # 为已有 user 表补全 phone、password_set（与 2Vision 一致的手机号登录）
    try:
        conn = db.engine.raw_connection()
        cur = conn.cursor()
        cur.execute("PRAGMA table_info(user)")
        existing_user_cols = {row[1] for row in cur.fetchall()}
        for col, sql_type in [('phone', 'VARCHAR(20)'), ('password_set', 'INTEGER')]:
            if col not in existing_user_cols:
                cur.execute("ALTER TABLE user ADD COLUMN %s %s" % (col, sql_type))
                conn.commit()
        cur.close()
        conn.close()
    except Exception as e:
        import sys
        print('[FreeYourPDF] user 表补列:', e, flush=True)
        sys.stdout.flush()

    # 启动时自动创建或提升初始管理员（Render 等线上环境配置 INITIAL_ADMIN_PHONE + INITIAL_ADMIN_PASSWORD）
    def _ensure_initial_admin():
        import re
        phone = (config_module.INITIAL_ADMIN_PHONE or '').strip().replace(' ', '').replace('-', '')
        password = (config_module.INITIAL_ADMIN_PASSWORD or '').strip()
        username_cfg = (config_module.INITIAL_ADMIN_USERNAME or '').strip()
        if not phone or not re.match(r'^1\d{10}$', phone):
            return
        existing_admin = User.query.filter_by(is_admin=True).first()
        u = User.query.filter_by(phone=phone).first()
        if existing_admin:
            if u and not u.is_admin:
                u.is_admin = True
                if password:
                    u.set_password(password)
                db.session.commit()
                print('[FreeYourPDF] 初始管理员：已将已有用户（手机号 %s***）提升为管理员' % phone[:3], flush=True)
            return
        if u:
            u.is_admin = True
            if password:
                u.set_password(password)
            db.session.commit()
            print('[FreeYourPDF] 初始管理员：已将已有用户（手机号 %s***）提升为管理员' % phone[:3], flush=True)
            return
        if not password:
            print('[FreeYourPDF] 初始管理员：未配置 INITIAL_ADMIN_PASSWORD，无法自动创建新管理员账号', flush=True)
            return
        base_username = (username_cfg or 'admin')[:32] or 'admin'
        username = base_username
        n = 0
        while User.query.filter_by(username=username).first():
            n += 1
            username = (base_username + '_%d' % n)[:32]
        virtual_email = 'phone_%s@admin.user' % phone
        k = 0
        while User.query.filter_by(email=virtual_email).first():
            k += 1
            virtual_email = 'phone_%s_%s@admin.user' % (phone, k)
        new_user = User(
            email=virtual_email,
            username=username,
            phone=phone,
            password_set=True,
            is_admin=True,
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.flush()
        quota = Quota(
            user_id=new_user.id,
            encrypt_remaining=config_module.DEFAULT_QUOTA_ENCRYPT,
            unlock_remaining=config_module.DEFAULT_QUOTA_UNLOCK,
            compress_remaining=config_module.DEFAULT_QUOTA_COMPRESS,
        )
        db.session.add(quota)
        db.session.commit()
        print('[FreeYourPDF] 初始管理员：已自动创建管理员账号（手机号 %s***，用户名 %s）' % (phone[:3], new_user.username), flush=True)

    try:
        _ensure_initial_admin()
    except Exception as e:
        print('[FreeYourPDF] 初始管理员执行失败: %s' % e, flush=True)
        try:
            db.session.rollback()
        except Exception:
            pass

# 预加载支付宝验证器（仅在实际对外服务的进程中执行，避免 reloader 时重复日志）
if os.environ.get('WERKZEUG_RUN_MAIN', 'true') != 'false':
    try:
        from alipay_verifier import get_alipay_verifier
        get_alipay_verifier()
    except Exception:
        pass


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
    # Cloudflare 兼容性：添加这些头确保 Cloudflare 不会缓存 API 响应
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
    resp.headers['Pragma'] = 'no-cache'
    resp.headers['Expires'] = '0'
    # 允许凭据（如果需要）
    resp.headers['Access-Control-Allow-Credentials'] = 'true'
    # 暴露自定义响应头（供前端读取）
    resp.headers['Access-Control-Expose-Headers'] = 'X-Original-Size, X-Compressed-Size, X-Compression-Ratio, X-Compression-Method'
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
        # Cloudflare 兼容性：确保预检请求不被缓存
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        resp.headers['Access-Control-Allow-Credentials'] = 'true'
        resp.headers['Access-Control-Max-Age'] = '86400'  # 24小时
        return resp
    return None


def _log(msg):
    """调试用：后端 console 输出，便于排查 401 等。"""
    import sys
    print('[FreeYourPDF]', msg, flush=True)
    sys.stdout.flush()


def _log_error(operation, error, details=None):
    """统一错误日志输出，确保在 Render 等生产环境可见。"""
    msg = '[FreeYourPDF] %s 错误: %s' % (operation, str(error))
    if details:
        msg += ' | 详情: ' + str(details)
    print(msg, flush=True)
    sys.stdout.flush()
    import traceback
    traceback.print_exc(file=sys.stdout)
    sys.stdout.flush()

class _suppress_pdf_warnings:
    """临时屏蔽底层 PDF 库在 stdout/stderr 上的噪音日志，只保留我们自己的 _log 输出。"""

    def __enter__(self):
        self._null = open(os.devnull, 'w')
        self._cm_out = redirect_stdout(self._null)
        self._cm_err = redirect_stderr(self._null)
        self._cm_out.__enter__()
        self._cm_err.__enter__()
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            self._cm_err.__exit__(exc_type, exc, tb)
            self._cm_out.__exit__(exc_type, exc, tb)
        finally:
            self._null.close()


def _check_memory_usage():
    """
    检查当前内存使用情况（仅 Linux/macOS）。
    返回 (used_mb, limit_mb) 或 (None, None) 如果不支持。
    """
    try:
        if sys.platform == 'linux' or sys.platform == 'darwin':
            # 获取当前进程的内存使用（RSS，单位 KB）
            usage = resource.getrusage(resource.RUSAGE_SELF)
            used_mb = usage.ru_maxrss / 1024.0  # macOS 返回字节，Linux 返回 KB
            if sys.platform == 'darwin':
                used_mb = used_mb / 1024.0  # macOS 返回字节，需要再除以 1024
            # Render 免费版通常有 512MB 内存限制
            limit_mb = 400  # 设置 400MB 作为安全阈值
            return used_mb, limit_mb
    except Exception:
        pass
    return None, None


def _cleanup_memory():
    """强制垃圾回收，释放内存。"""
    gc.collect()


def _get_current_user_id(silent=False):
    """从 Authorization: Bearer <token> 解析出 user_id，无效返回 None。
    silent=True 时不打印「认证失败」日志，适用于支持匿名访问的接口。
    """
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        if not silent:
            _log('认证失败：缺少或无效的 Authorization')
        return None
    token = auth_header[7:].strip()
    user_id = auth_module.decode_token(token)
    if user_id is None:
        _log('认证失败：JWT 无效或已过期')
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


def _get_location_from_ip(ip, timeout=1.5):
    """
    根据 IP 解析地理位置（国家/省/市/时区）。
    使用 ip-api.com 免费接口（45 次/分钟），无 key。
    本地/内网 IP 或失败时返回空字典。
    优化：缩短超时时间到 1.5 秒，避免阻塞主流程。
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
        # 缩短超时时间，避免阻塞上传响应
        with urlopen(req, timeout=timeout) as resp:
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
        # 静默失败，不打印日志（避免日志刷屏）
        return {}


def _get_location_from_ip_async(ip, callback):
    """
    异步获取地理位置信息，不阻塞主流程。
    在后台线程中执行，完成后调用 callback(geo_dict)。
    """
    def _fetch():
        geo = _get_location_from_ip(ip)
        try:
            callback(geo)
        except Exception as e:
            _log('异步更新地理位置回调失败: %s' % e)
    
    thread = threading.Thread(target=_fetch, daemon=True)
    thread.start()


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
    """
    记录一次使用（加密/解锁/体积优化），含 IP 与地理位置。
    优化：先快速写入数据库（不等待地理位置查询），然后异步更新地理位置信息。
    """
    ip = _get_client_ip()
    ua = request.headers.get('User-Agent') or ''
    parsed = _parse_device(ua)
    
    # 先快速创建记录（不等待地理位置查询，避免阻塞上传响应）
    try:
        rec = UsageRecord(
            user_id=user_id,
            session_id=anonymous_id,
            usage_type=usage_type,
            api_endpoint=api_endpoint,
            api_method=request.method,
            response_status=response_status,
            ip_address=ip,
            country=None,  # 先设为 None，异步更新
            region=None,
            city=None,
            timezone=None,
            user_agent=ua[:500] if ua else None,
            device_type=parsed.get('device_type'),
            browser=parsed.get('browser'),
            os=parsed.get('os'),
        )
        db.session.add(rec)
        db.session.flush()  # flush 获取 rec.id，但不提交
        record_id = rec.id
        
        # 提交记录（快速响应）
        db.session.commit()
        
        # 异步更新地理位置信息（不阻塞响应）
        def _update_geo(geo):
            try:
                # 需要在新的应用上下文中操作数据库
                with app.app_context():
                    rec = db.session.get(UsageRecord, record_id)
                    if rec:
                        # 只更新非空的地理位置信息
                        if geo.get('country'):
                            rec.country = geo.get('country')
                        if geo.get('region'):
                            rec.region = geo.get('region')
                        if geo.get('city'):
                            rec.city = geo.get('city')
                        if geo.get('timezone'):
                            rec.timezone = geo.get('timezone')
                        db.session.commit()
                    # 如果记录不存在（可能被删除），静默忽略
            except Exception as e:
                # 静默失败，避免日志刷屏（地理位置更新失败不影响主要功能）
                pass
        
        # 异步获取地理位置
        _get_location_from_ip_async(ip, _update_geo)
        
    except Exception as e:
        _log_error('记录使用量失败', e, {
            'user_id': user_id,
            'usage_type': usage_type,
            'api_endpoint': api_endpoint
        })
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
    # 匿名也合法，这里静默解析 JWT，避免终端充斥认证失败日志
    user_id = _get_current_user_id(silent=True)
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


# ----- 认证路由（手机号+短信/密码，与 2Vision 一致）-----
@app.route('/api/auth/sms/send', methods=['POST'])
def api_sms_send():
    return auth_module.sms_send()


@app.route('/api/auth/sms/submit', methods=['POST'])
def api_sms_submit():
    return auth_module.sms_submit()


@app.route('/api/auth/sms/register', methods=['POST'])
def api_sms_register():
    return auth_module.sms_register()


@app.route('/api/auth/sms/login', methods=['POST'])
def api_sms_login():
    return auth_module.sms_login()


@app.route('/api/auth/password/login', methods=['POST'])
def api_password_login():
    return auth_module.password_login()


@app.route('/api/auth/password/set', methods=['POST'])
def api_password_set():
    return auth_module.password_set()


@app.route('/api/auth/password/change', methods=['POST'])
def api_password_change_sms():
    return auth_module.password_change_sms()


@app.route('/api/auth/password/status', methods=['GET'])
def api_password_status():
    return auth_module.password_status()


@app.route('/api/visit', methods=['POST'])
def api_visit():
    """
    记录一次页面访问（公开，可选 session_id），含 IP 与地理位置。
    优化：先快速写入数据库（不等待地理位置查询），然后异步更新地理位置信息。
    """
    data = request.get_json(silent=True) or {}
    session_id = (data.get('session_id') or '').strip() or None
    if session_id and len(session_id) > 100:
        session_id = session_id[:100]
    # 访问记录允许匿名，这里静默解析 JWT，避免未登录时刷屏日志
    user_id = _get_current_user_id(silent=True)
    ip = _get_client_ip()
    ua = request.headers.get('User-Agent') or ''
    parsed = _parse_device(ua)
    
    try:
        # 先快速创建记录（不等待地理位置查询）
        visit = PageVisit(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip,
            country=None,  # 先设为 None，异步更新
            region=None,
            city=None,
            timezone=None,
            user_agent=ua[:500] if ua else None,
            device_type=parsed.get('device_type'),
            browser=parsed.get('browser'),
            os=parsed.get('os'),
        )
        db.session.add(visit)
        db.session.flush()  # flush 获取 visit.id，但不提交
        visit_id = visit.id
        
        # 提交记录（快速响应）
        db.session.commit()
        
        # 异步更新地理位置信息（不阻塞响应）
        def _update_geo(geo):
            try:
                # 需要在新的应用上下文中操作数据库
                with app.app_context():
                    v = db.session.get(PageVisit, visit_id)
                    if v:
                        # 只更新非空的地理位置信息
                        if geo.get('country'):
                            v.country = geo.get('country')
                        if geo.get('region'):
                            v.region = geo.get('region')
                        if geo.get('city'):
                            v.city = geo.get('city')
                        if geo.get('timezone'):
                            v.timezone = geo.get('timezone')
                        db.session.commit()
                    # 如果记录不存在（可能被删除），静默忽略
            except Exception as e:
                # 静默失败，避免日志刷屏（地理位置更新失败不影响主要功能）
                pass
        
        # 异步获取地理位置
        _get_location_from_ip_async(ip, _update_geo)
        
    except Exception as e:
        _log_error('记录访问失败', e, {
            'user_id': user_id,
            'session_id': session_id
        })
        try:
            db.session.rollback()
        except Exception:
            pass
    
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
            'created_at': user.created_at.isoformat() + 'Z' if user.created_at else None,
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
        'phone': getattr(user, 'phone', None),
        'password_set': getattr(user, 'password_set', False),
        'is_admin': getattr(user, 'is_admin', False),
        'quota': q,
        'created_at': user.created_at.isoformat() + 'Z' if user.created_at else None,
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
        'created_at': payment.created_at.isoformat() + 'Z' if payment.created_at else None,
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

    # 支付宝验证：若已配置 ALIPAY_COOKIE，则必须通过验证器查询到匹配账单才可完成，否则一律 503
    if (payment.payment_method or 'alipay') == 'alipay':
        try:
            alipay_cookie_configured = bool(getattr(config_module, 'ALIPAY_COOKIE', '') or '')
            from alipay_verifier import get_alipay_verifier
            verifier = get_alipay_verifier()
            enabled = verifier.is_enabled()
            if alipay_cookie_configured and not enabled:
                _log('支付确认：支付宝验证未就绪（Cookie/ctoken 不完整），请检查 .env')
                try:
                    from alert_email import notify_alipay_cookie_invalid
                    notify_alipay_cookie_invalid('用户点击「我已支付」时验证器未就绪（Cookie/ctoken/billUserId 不完整或 requests 未安装）')
                except Exception:
                    pass
                return jsonify({
                    'error': '支付宝查询服务暂时不可用（如 Cookie 已过期或未正确配置），请联系管理员更新配置。',
                    'detail': 'alipay_unavailable',
                }), 503
            if enabled:
                matching, api_reachable, auth_denied = verifier.find_matching_order(
                    float(payment.amount),
                    payment.transaction_id or '',
                    payment.created_at or datetime.utcnow(),
                )
                if auth_denied:
                    _log('支付确认：支付宝 Cookie 已过期，请按文档更新 .env 后重启')
                    return jsonify({
                        'error': '支付宝登录已过期，暂无法核验到账。请管理员按「支付宝验证配置」文档重新获取 Cookie 并更新 .env 后重启服务。',
                        'detail': 'alipay_auth_denied',
                    }), 503
                if not matching:
                    # 已成功拿到账单数据但无匹配：直接 400，避免再调 is_cookie_valid() 多一次请求导致首次点击很慢
                    if api_reachable:
                        _log('支付确认：未查到匹配订单（金额/备注订单号不符或未付款）')
                        return jsonify({
                            'error': '未找到匹配的支付宝收款记录。请确认已付款且在备注中填写了订单号，或稍后再试。',
                            'detail': 'no_matching_order',
                        }), 400
                    cookie_valid = verifier.is_cookie_valid()
                    if not cookie_valid:
                        try:
                            from alert_email import notify_alipay_cookie_invalid
                            notify_alipay_cookie_invalid('用户点击「我已支付」时校验失败，Cookie 无效或已过期')
                        except Exception:
                            pass
                        _log('支付确认：支付宝 Cookie 已过期，请按文档更新 .env 后重启')
                        return jsonify({
                            'error': '支付宝查询服务暂时不可用（如 Cookie 已过期），请联系管理员更新配置。',
                            'detail': 'alipay_unavailable',
                        }), 503
                    _log('支付确认：未查到匹配订单（金额/备注订单号不符或未付款）')
                    return jsonify({
                        'error': '未找到匹配的支付宝收款记录。请确认已付款且在备注中填写了订单号，或稍后再试。',
                        'detail': 'no_matching_order',
                    }), 400
                _log('支付确认：匹配成功，订单 %s 已到账' % transaction_id)
            else:
                pass  # 未配置 Cookie，直接到账
        except Exception as e:
            _log('支付确认：验证异常 - %s' % e)
            import traceback
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            return jsonify({'error': '支付验证异常，请稍后再试。', 'detail': str(e)}), 500

    _log('支付确认：已完成到账，订单 %s' % transaction_id)
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
                'created_at': p.created_at.isoformat() + 'Z' if p.created_at else None,
                'completed_at': p.completed_at.isoformat() + 'Z' if p.completed_at else None,
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
    if user_id is not None:
        quota = Quota.query.filter_by(user_id=user_id).first()
        if not quota:
            _log('配额：用户 %s 配额不存在' % user_id)
            return jsonify({'error': '配额不存在'}), 404
        return jsonify(_quota_dict(quota))
    if anonymous_id is not None:
        anon = _get_or_create_anonymous_quota(anonymous_id)
        return jsonify(_anon_quota_dict(anon))
    _log('配额：未提供登录或匿名凭证')
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
        if hasattr(User, 'phone') and User.phone is not None:
            cond = cond | User.phone.contains(search)
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
            'phone': getattr(u, 'phone', None),
            'password_set': getattr(u, 'password_set', False),
            'is_admin': getattr(u, 'is_admin', False),
            'quota': _quota_dict(quota) if quota else None,
            'created_at': u.created_at.isoformat() + 'Z' if u.created_at else None,
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
                'phone': getattr(user, 'phone', None),
                'password_set': getattr(user, 'password_set', False),
                'is_admin': getattr(user, 'is_admin', False),
                'created_at': user.created_at.isoformat() + 'Z' if user.created_at else None,
            },
            'quota': _quota_dict(quota) if quota else None,
            'payments': [
                {'id': p.id, 'pack_type': p.pack_type, 'amount': p.amount, 'quantity': p.quantity, 'status': p.status, 'created_at': (p.created_at.isoformat() + 'Z' if p.created_at else None)}
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
    if 'phone' in data:
        phone_val = (data.get('phone') or '').strip().replace(' ', '').replace('-', '') or None
        if phone_val:
            other = User.query.filter(User.phone == phone_val, User.id != user_id).first()
            if other:
                return jsonify({'error': '该手机号已被其他用户使用'}), 400
            user.phone = phone_val
        else:
            user.phone = None
    if 'is_admin' in data:
        user.is_admin = bool(data['is_admin'])
    if 'password' in data and data['password']:
        user.set_password(data['password'])
    if 'avatar' in data:
        avatar = data.get('avatar')
        if avatar is not None and isinstance(avatar, str) and avatar.startswith('data:image'):
            # Base64 图片数据
            try:
                part = avatar.split(',')[1] if ',' in avatar else avatar
                user.avatar = part
            except Exception:
                pass
        elif avatar is not None and isinstance(avatar, str) and len(avatar) > 200:
            # 长字符串可能是 Base64（无 data:image 前缀）
            user.avatar = avatar
        elif avatar is None or avatar == '':
            user.avatar = None
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
            'phone': getattr(user, 'phone', None),
            'password_set': getattr(user, 'password_set', False),
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
    try:
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
            try:
                u = db.session.get(User, p.user_id)
                out.append({
                    'id': p.id,
                    'user_id': p.user_id,
                    'username': u.username if u else None,
                    'email': u.email if u else None,
                    'phone': getattr(u, 'phone', None) if u else None,
                    'pack_type': p.pack_type,
                    'amount': p.amount,
                    'quantity': p.quantity,
                    'status': p.status,
                    'transaction_id': p.transaction_id,
                    'created_at': p.created_at.isoformat() + 'Z' if p.created_at else None,
                    'completed_at': p.completed_at.isoformat() + 'Z' if p.completed_at else None,
                })
            except Exception as e:
                print('[FreeYourPDF] api_admin_payments 处理单条记录异常:', str(e), flush=True)
                # 即使单条记录出错，也继续处理其他记录
                out.append({
                    'id': p.id,
                    'user_id': p.user_id,
                    'username': None,
                    'email': None,
                    'phone': None,
                    'pack_type': p.pack_type,
                    'amount': p.amount,
                    'quantity': p.quantity,
                    'status': p.status,
                    'transaction_id': p.transaction_id,
                    'created_at': p.created_at.isoformat() + 'Z' if p.created_at else None,
                    'completed_at': p.completed_at.isoformat() + 'Z' if p.completed_at else None,
                })
        return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})
    except Exception as e:
        import traceback
        err_msg = '获取支付记录失败：' + str(e)
        print('[FreeYourPDF] api_admin_payments 异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'status': 'error', 'error': err_msg}), 500


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
    try:
        admin_user, err = _require_admin()
        if err is not None:
            return err[0], err[1]
        now = datetime.utcnow()
        last_1h = now - timedelta(hours=1)
        last_24h = now - timedelta(hours=24)
        try:
            recent_usage_1h = UsageRecord.query.filter(UsageRecord.created_at >= last_1h).count()
            recent_usage_24h = UsageRecord.query.filter(UsageRecord.created_at >= last_24h).count()
            recent_visits_1h = PageVisit.query.filter(PageVisit.created_at >= last_1h).count()
            recent_visits_24h = PageVisit.query.filter(PageVisit.created_at >= last_24h).count()
        except Exception as e:
            print('[FreeYourPDF] api_admin_monitor_realtime 统计查询异常:', str(e), flush=True)
            recent_usage_1h = recent_usage_24h = recent_visits_1h = recent_visits_24h = 0
        # 最近 10 条访问
        recent_visits = []  # 提前初始化，确保总是有值
        try:
            visits = PageVisit.query.order_by(PageVisit.created_at.desc()).limit(10).all()
            print('[FreeYourPDF] api_admin_monitor_realtime 查询到 %d 条访问记录' % len(visits), flush=True)
        except Exception as e:
            print('[FreeYourPDF] api_admin_monitor_realtime 访问记录查询异常:', str(e), flush=True)
            import traceback
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            visits = []
        
        for v in visits:
            try:
                u = db.session.get(User, v.user_id) if v.user_id else None
                # 确保所有字段都有值，避免前端显示问题
                visit_item = {
                    'id': v.id,
                    'created_at': v.created_at.isoformat() + 'Z' if v.created_at else None,
                    'ip_address': v.ip_address or '—',
                    'location': _format_location(v.country, v.region, v.city),
                    'device_type': v.device_type or 'unknown',
                    'username': u.username if u else ('ID:%s' % v.user_id if v.user_id else '匿名'),
                    'phone': getattr(u, 'phone', None) if u else None,
                }
                recent_visits.append(visit_item)
            except Exception as e:
                print('[FreeYourPDF] api_admin_monitor_realtime 处理单条访问记录异常:', str(e), flush=True)
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                # 即使出错也添加一条记录，避免前端显示问题
                try:
                    recent_visits.append({
                        'id': getattr(v, 'id', None),
                        'created_at': v.created_at.isoformat() + 'Z' if v.created_at else None,
                        'ip_address': getattr(v, 'ip_address', '—'),
                        'location': '—',
                        'device_type': getattr(v, 'device_type', 'unknown'),
                        'username': '—',
                        'phone': None,
                    })
                except Exception as e2:
                    print('[FreeYourPDF] api_admin_monitor_realtime 添加错误记录也失败:', str(e2), flush=True)
        
        print('[FreeYourPDF] api_admin_monitor_realtime 最终返回 %d 条访问记录' % len(recent_visits), flush=True)
        # 最近 10 条使用
        recent_usage = []  # 提前初始化，确保总是有值
        try:
            usages = UsageRecord.query.order_by(UsageRecord.created_at.desc()).limit(10).all()
            print('[FreeYourPDF] api_admin_monitor_realtime 查询到 %d 条使用记录' % len(usages), flush=True)
        except Exception as e:
            print('[FreeYourPDF] api_admin_monitor_realtime 使用记录查询异常:', str(e), flush=True)
            import traceback
            traceback.print_exc(file=sys.stdout)
            sys.stdout.flush()
            usages = []
        for r in usages:
            try:
                u = db.session.get(User, r.user_id) if r.user_id else None
                type_label = {'encrypt': '加密', 'unlock': '解锁', 'compress': '体积优化'}.get(r.usage_type, r.usage_type or '—')
                recent_usage.append({
                    'id': r.id,
                    'created_at': r.created_at.isoformat() + 'Z' if r.created_at else None,
                    'username': u.username if u else ('ID:%s' % r.user_id if r.user_id else '匿名'),
                    'phone': getattr(u, 'phone', None) if u else None,
                    'type': type_label,
                    'usage_type': r.usage_type,
                    'ip_address': r.ip_address,
                    'location': _format_location(getattr(r, 'country', None), getattr(r, 'region', None), getattr(r, 'city', None)),
                })
            except Exception as e:
                print('[FreeYourPDF] api_admin_monitor_realtime 处理单条使用记录异常:', str(e), flush=True)
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
        
        print('[FreeYourPDF] api_admin_monitor_realtime 最终返回 %d 条使用记录' % len(recent_usage), flush=True)
        # 确保所有字段都存在，即使为空数组
        result_data = {
            'recent_usage_1h': recent_usage_1h,
            'recent_usage_24h': recent_usage_24h,
            'recent_visits_1h': recent_visits_1h,
            'recent_visits_24h': recent_visits_24h,
            'recent_visits': recent_visits if 'recent_visits' in locals() else [],
            'recent_usage': recent_usage if 'recent_usage' in locals() else [],
        }
        print('[FreeYourPDF] api_admin_monitor_realtime 返回数据: visits=%d, usage=%d' % (len(result_data['recent_visits']), len(result_data['recent_usage'])), flush=True)
        return jsonify({
            'status': 'success',
            'data': result_data,
        })
    except Exception as e:
        import traceback
        err_msg = '获取实时监控数据失败：' + str(e)
        print('[FreeYourPDF] api_admin_monitor_realtime 异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'status': 'error', 'error': err_msg}), 500


@app.route('/api/admin/access-logs', methods=['GET'])
def api_admin_access_logs():
    """访问记录（分页）。"""
    try:
        admin_user, err = _require_admin()
        if err is not None:
            return err[0], err[1]
        page = max(1, int(request.args.get('page') or 1))
        page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
        offset = (page - 1) * page_size
        q = PageVisit.query.order_by(PageVisit.created_at.desc())
        try:
            total = q.count()
        except Exception as e:
            print('[FreeYourPDF] api_admin_access_logs count 异常:', str(e), flush=True)
            total = 0
        try:
            items = q.offset(offset).limit(page_size).all()
        except Exception as e:
            print('[FreeYourPDF] api_admin_access_logs query 异常:', str(e), flush=True)
            items = []
        out = []
        for v in items:
            try:
                path = v.ip_address or '—'
                if v.device_type:
                    path = '%s · %s' % (v.device_type, path)
                user_display = None
                if v.user_id:
                    u = db.session.get(User, v.user_id)
                    user_display = u.username if u else ('ID:%s' % v.user_id)
                    user_phone = getattr(u, 'phone', None) if u else None
                else:
                    user_display = '匿名'
                    user_phone = None
                # 确保所有字段都有值，避免前端显示问题
                out.append({
                    'id': v.id,
                    'created_at': v.created_at.isoformat() + 'Z' if v.created_at else None,
                    'path': path or '—',
                    'ip_address': v.ip_address or '—',
                    'location': _format_location(v.country, v.region, v.city),
                    'user_id': v.user_id,
                    'username': user_display or '匿名',
                    'phone': user_phone or None,
                    'device_type': v.device_type or 'unknown',
                    'user_agent': (v.user_agent[:80] + '…') if v.user_agent and len(v.user_agent) > 80 else (v.user_agent or '—'),
                })
            except Exception as e:
                print('[FreeYourPDF] api_admin_access_logs 处理单条记录异常:', str(e), flush=True)
                # 即使单条记录出错，也继续处理其他记录
                out.append({
                    'id': v.id,
                    'created_at': v.created_at.isoformat() + 'Z' if v.created_at else None,
                    'path': getattr(v, 'ip_address', '—'),
                    'ip_address': getattr(v, 'ip_address', None),
                    'location': '—',
                    'user_id': getattr(v, 'user_id', None),
                    'username': '—',
                    'phone': None,
                    'device_type': getattr(v, 'device_type', 'unknown'),
                    'user_agent': None,
                })
        return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})
    except Exception as e:
        import traceback
        err_msg = '获取访问记录失败：' + str(e)
        print('[FreeYourPDF] api_admin_access_logs 异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'status': 'error', 'error': err_msg}), 500


@app.route('/api/admin/usage-logs', methods=['GET'])
def api_admin_usage_logs():
    """使用记录（分页）。"""
    try:
        admin_user, err = _require_admin()
        if err is not None:
            return err[0], err[1]
        page = max(1, int(request.args.get('page') or 1))
        page_size = min(50, max(1, int(request.args.get('page_size') or 20)))
        offset = (page - 1) * page_size
        q = UsageRecord.query.order_by(UsageRecord.created_at.desc())
        try:
            total = q.count()
        except Exception as e:
            print('[FreeYourPDF] api_admin_usage_logs count 异常:', str(e), flush=True)
            total = 0
        try:
            items = q.offset(offset).limit(page_size).all()
        except Exception as e:
            print('[FreeYourPDF] api_admin_usage_logs query 异常:', str(e), flush=True)
            items = []
        out = []
        for r in items:
            try:
                user_display = None
                if r.user_id:
                    u = db.session.get(User, r.user_id)
                    user_display = u.username if u else ('ID:%s' % r.user_id)
                    user_phone = getattr(u, 'phone', None) if u else None
                else:
                    user_display = '匿名'
                    user_phone = None
                type_label = {'encrypt': '加密', 'unlock': '解锁', 'compress': '体积优化'}.get(r.usage_type, r.usage_type or '—')
                # 确保所有字段都有值，避免前端显示问题
                out.append({
                    'id': r.id,
                    'created_at': r.created_at.isoformat() + 'Z' if r.created_at else None,
                    'user_id': r.user_id,
                    'username': user_display or '匿名',
                    'phone': user_phone or None,
                    'type': type_label or '—',
                    'usage_type': r.usage_type or '—',
                    'api_endpoint': r.api_endpoint or '—',
                    'ip_address': r.ip_address or '—',
                    'location': _format_location(getattr(r, 'country', None), getattr(r, 'region', None), getattr(r, 'city', None)),
                })
            except Exception as e:
                print('[FreeYourPDF] api_admin_usage_logs 处理单条记录异常:', str(e), flush=True)
                # 即使单条记录出错，也继续处理其他记录
                out.append({
                    'id': r.id,
                    'created_at': r.created_at.isoformat() + 'Z' if r.created_at else None,
                    'user_id': r.user_id,
                    'username': '—',
                    'phone': None,
                    'type': '—',
                    'usage_type': getattr(r, 'usage_type', None),
                    'api_endpoint': getattr(r, 'api_endpoint', None),
                    'ip_address': getattr(r, 'ip_address', None),
                    'location': '—',
                })
        return jsonify({'status': 'success', 'data': out, 'total': total, 'page': page, 'page_size': page_size})
    except Exception as e:
        import traceback
        err_msg = '获取使用记录失败：' + str(e)
        print('[FreeYourPDF] api_admin_usage_logs 异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'status': 'error', 'error': err_msg}), 500


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
# 常见密码列表，用于暴力破解（参考 pdfrip 项目）
COMMON_PASSWORDS = [
    '', '123', '1234', '12345', '123456', '1234567', '12345678', '123456789', '1234567890',
    '0000', '00000', '000000', '1111', '11111', '111111', '123123',
    'password', 'password1', 'password123', 'pass', 'pass123', '123pass', '123password',
    'qwerty', 'abc123', 'admin', 'admin123', 'root', 'root123',
    'pdf', 'PDF', 'Pdf', 'open', 'Open', 'secret', 'changeme'
]


def _password_generator():
    """
    密码生成器，完全参考 pdfrip 项目的方法（使用生成器避免内存问题）：
    1. 常见密码（字典攻击的基础）
    2. 1-6 位数字（带前导零）- pdfrip 的 range 功能
    3. 日期格式 DDMMYYYY（最近 10 年）- pdfrip 的 date bruteforce 功能
    4. 字母数字组合（长度 3，a-zA-Z0-9）- pdfrip 的 default-query 功能（限制长度避免过多）
    
    注意：使用生成器模式，按需生成密码，避免一次性加载所有密码到内存。
    完全参考 pdfrip 的密码生成策略。
    """
    from datetime import datetime
    import calendar
    import string
    import itertools
    seen = set()
    
    # 1. 常见密码（字典攻击的基础）- pdfrip 的 wordlist 功能
    for p in COMMON_PASSWORDS:
        if p not in seen:
            seen.add(p)
            yield p
    
    # 2. 1-6 位数字（带前导零）- pdfrip 的 range 功能
    # pdfrip: range 1000 9999 可以指定数字范围
    # 这里生成 1-6 位所有数字（带前导零）
    for length in range(1, 7):
        for n in range(10 ** length):
            s = str(n).zfill(length)
            if s not in seen:
                seen.add(s)
                yield s
    
    # 3. 日期格式 DDMMYYYY（最近 10 年）- pdfrip 的 date bruteforce 功能
    # pdfrip: date 1900 2000 可以指定年份范围
    # 这里生成最近 10 年的所有日期（DDMMYYYY 格式）
    current_year = datetime.now().year
    for year in range(current_year - 10, current_year + 1):
        for month in range(1, 13):
            days_in_month = calendar.monthrange(year, month)[1]
            for day in range(1, days_in_month + 1):
                # DDMMYYYY 格式（pdfrip 默认格式）
                date_str = f"{day:02d}{month:02d}{year}"
                if date_str not in seen:
                    seen.add(date_str)
                    yield date_str
                # MMDDYYYY 格式（另一种常见格式）
                date_str2 = f"{month:02d}{day:02d}{year}"
                if date_str2 not in seen:
                    seen.add(date_str2)
                    yield date_str2
    
    # 4. 字母数字组合（pdfrip 的 default-query 功能）
    # pdfrip: default-query --max-length 8 --min-length 3
    # 生成 a-zA-Z0-9 的组合
    # 注意：长度 3 的组合有 62^3 = 238,328 种，已经很多了
    # 为了平衡性能和覆盖率，只生成长度 3 的组合，并限制常见模式
    chars = string.ascii_letters + string.digits  # a-zA-Z0-9
    
    # 长度 3 的组合（常见密码长度）
    length = 3
    max_attempts = 100000  # 最多尝试 10 万个
    
    # 优先尝试常见模式：
    # 1. 全小写字母（常见）
    count = 0
    for combo in itertools.product(string.ascii_lowercase, repeat=length):
        if count >= max_attempts:
            break
        pwd = ''.join(combo)
        if pwd not in seen:
            seen.add(pwd)
            yield pwd
            count += 1
    
    # 2. 全大写字母
    count = 0
    for combo in itertools.product(string.ascii_uppercase, repeat=length):
        if count >= max_attempts:
            break
        pwd = ''.join(combo)
        if pwd not in seen:
            seen.add(pwd)
            yield pwd
            count += 1
    
    # 3. 数字 + 小写字母混合（常见模式：1位数字+2位字母，或2位字母+1位数字）
    count = 0
    # 1位数字 + 2位字母
    for digit in string.digits:
        for combo in itertools.product(string.ascii_lowercase, repeat=length-1):
            if count >= max_attempts:
                break
            pwd = digit + ''.join(combo)
            if pwd not in seen:
                seen.add(pwd)
                yield pwd
                count += 1
            # 字母 + 数字
            pwd2 = ''.join(combo) + digit
            if pwd2 not in seen:
                seen.add(pwd2)
                yield pwd2
                count += 1
        if count >= max_attempts:
            break
    
    # 4. 2位数字 + 1位字母
    count = 0
    for digits in itertools.product(string.digits, repeat=2):
        for letter in string.ascii_lowercase:
            if count >= max_attempts:
                break
            pwd = ''.join(digits) + letter
            if pwd not in seen:
                seen.add(pwd)
                yield pwd
                count += 1
            pwd2 = letter + ''.join(digits)
            if pwd2 not in seen:
                seen.add(pwd2)
                yield pwd2
                count += 1
        if count >= max_attempts:
            break


def _password_list():
    """
    返回密码生成器（不转换为列表，避免内存问题）。
    注意：直接返回生成器，使用时按需生成密码。
    """
    return _password_generator()


def _can_open(stream, password=None):
    """尝试用给定密码打开 PDF，成功返回 True。"""
    stream.seek(0)
    try:
        with _suppress_pdf_warnings():
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
    """
    检测 PDF：是否需要打开密码、是否有权限限制。不鉴权、不扣配额。
    优化：添加超时处理，避免大文件检测时间过长。
    """
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    
    try:
        data = f.read()
        
        # 检查文件大小（防止内存耗尽）
        file_size_mb = len(data) / (1024 * 1024)
        if file_size_mb > config_module.MAX_FILE_SIZE_MB:
            return jsonify({'error': f'文件过大（{file_size_mb:.1f}MB），最大支持 {config_module.MAX_FILE_SIZE_MB}MB'}), 400
        
        # 优化：对于大文件（>10MB），只做快速检测，不尝试打开
        if file_size_mb > 10:
            # 大文件只检测元数据，不尝试打开（避免超时）
            has_encrypt_meta = _has_encrypt_in_bytes(data)
            return jsonify({
                'encrypted': has_encrypt_meta,  # 有加密元数据就认为加密了
                'hasRestrictions': has_encrypt_meta
            })
        
        stream = io.BytesIO(data)
        has_encrypt_meta = _has_encrypt_in_bytes(data)
        encrypted = True
        has_restrictions = False
        
        # 优化：对于中等大小的文件，限制检测时间
        # 使用简单的快速检测，避免长时间等待
        try:
            if has_encrypt_meta:
                # 先尝试空密码（快速）
                if _can_open(stream, ''):
                    encrypted = False
                    has_restrictions = True
            if encrypted:
                # 尝试无密码打开（快速）
                if _can_open(stream, None):
                    encrypted = False
                    has_restrictions = has_encrypt_meta
                elif _can_open(stream, ''):
                    encrypted = False
                    has_restrictions = True
        except Exception as e:
            # 检测过程中出错，返回元数据检测结果
            _log('PDF检测过程异常（不影响结果）: %s' % str(e))
            encrypted = has_encrypt_meta
            has_restrictions = has_encrypt_meta
        
        return jsonify({'encrypted': encrypted, 'hasRestrictions': has_restrictions})
    except TimeoutError:
        # 超时时的降级处理：只返回元数据检测结果
        has_encrypt_meta = _has_encrypt_in_bytes(data)
        return jsonify({
            'encrypted': has_encrypt_meta,
            'hasRestrictions': has_encrypt_meta
        })
    except Exception as e:
        _log_error('PDF检测异常', e)
        # 出错时返回默认值，让前端可以继续处理
        return jsonify({'encrypted': False, 'hasRestrictions': False})


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
    password = _normalize_pdf_password(request.form.get('password') or '')
    data = f.read()
    
    # 检查文件大小（防止内存耗尽）
    file_size_mb = len(data) / (1024 * 1024)
    if file_size_mb > config_module.MAX_FILE_SIZE_MB:
        return jsonify({'error': f'文件过大（{file_size_mb:.1f}MB），最大支持 {config_module.MAX_FILE_SIZE_MB}MB'}), 400
    
    stream = io.BytesIO(data)
    try:
        reader = PdfReader(stream)
        # 检查页数（防止超大文件）
        if len(reader.pages) > config_module.MAX_PAGES_LIMIT:
            return jsonify({'error': f'PDF 页数过多（{len(reader.pages)}页），最大支持 {config_module.MAX_PAGES_LIMIT} 页'}), 400
        if reader.is_encrypted:
            reader.decrypt(password)
        writer = PdfWriter()
        for page in reader.pages:
            writer.add_page(page)
        out = io.BytesIO()
        writer.write(out)
        out.seek(0)
        
        # 清理内存
        del reader, writer
        _cleanup_memory()
        
        _record_usage(user_id, anonymous_id, 'unlock', '/api/unlock', 200)
        return send_file(
            out,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=(f.filename or 'output.pdf').replace('.pdf', '_unlocked.pdf')
        )
    except Exception as e:
        import traceback
        err_msg = '解锁失败：' + str(e)
        print('[FreeYourPDF] 解锁异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'error': err_msg}), 400


# PDF 权限位（Table 3.20）：与 pypdf.constants.UserAccessPermissions 一致
_ENC_PRINT_LOW = 4
_ENC_MODIFY = 8
_ENC_EXTRACT = 16
_ENC_ADD_OR_MODIFY = 32
_ENC_FILL_FORMS = 256
_ENC_EXTRACT_TEXT_GRAPHICS = 512
_ENC_ASSEMBLE = 1024
_ENC_PRINT_HIGH = 2048


def _encrypt_permissions_flag(perms):
    """根据前端权限对象计算 PDF P 值。前端勾选=禁止该权限，PDF 位 1=允许。
    未传的项视为不禁止（允许）。全部禁止时返回 0，全部允许时返回 -1（pypdf 全开）。"""
    if not perms:
        return -1  # 全部允许
    flag = 0
    # 勾选=禁止 → 不设置对应位；未勾选=允许 → 设置对应位
    if not perms.get('modifying', False):
        flag |= _ENC_MODIFY
    if not perms.get('copying', False):
        flag |= _ENC_EXTRACT
    if not perms.get('annotating', False):
        flag |= _ENC_ADD_OR_MODIFY
    if not perms.get('documentAssembly', False):
        flag |= _ENC_ASSEMBLE
    if not perms.get('fillingForms', False):
        flag |= _ENC_FILL_FORMS
    if not perms.get('contentAccessibility', False):
        flag |= _ENC_EXTRACT_TEXT_GRAPHICS
    if perms.get('printing', False) is True:
        pass  # 禁止打印：不设置打印位
    else:
        flag |= _ENC_PRINT_LOW
        flag |= _ENC_PRINT_HIGH
    # 全部禁止时 flag=0，必须返回 0，不能返回 -1（-1 表示全部允许）
    return flag


def _pikepdf_permissions(perms):
    """根据前端权限对象构造 pikepdf.Permissions。前端勾选=禁止，pikepdf True=允许。"""
    if not perms:
        return None  # 全部允许，不传 allow
    return pikepdf.Permissions(
        modify_other=not perms.get('modifying', False),
        extract=not perms.get('copying', False),
        modify_annotation=not perms.get('annotating', False),
        modify_assembly=not perms.get('documentAssembly', False),
        modify_form=not perms.get('fillingForms', False),
        accessibility=not perms.get('contentAccessibility', False),
        print_lowres=not perms.get('printing', False),
        print_highres=not perms.get('printing', False),
    )


def _normalize_pdf_password(s):
    """PDF 标准使用 Latin-1 编码密码。将字符串规范为仅含 Latin-1 字符，保证加密后用同一密码可打开。"""
    if s is None:
        return ''
    s = str(s).strip()
    try:
        return s.encode('latin-1').decode('latin-1')
    except (UnicodeEncodeError, UnicodeDecodeError):
        return ''.join(c for c in s if ord(c) < 256)


def _compress_pdf_with_ghostscript(data, quality='/ebook'):
    """
    使用 Ghostscript 压缩 PDF（类似 pdfc 项目），返回压缩后的 bytes。
    需要系统已安装 gs 命令；失败或未安装时抛异常，由调用方兜底。
    quality 可选：/screen, /ebook, /printer, /prepress 等。
    """
    import subprocess
    import tempfile

    if not data:
        raise ValueError('empty pdf data')

    with tempfile.TemporaryDirectory() as tmpdir:
        in_path = os.path.join(tmpdir, 'input.pdf')
        out_path = os.path.join(tmpdir, 'output.pdf')
        with open(in_path, 'wb') as f_in:
            f_in.write(data)
        # 参考 https://github.com/theeko74/pdfc 使用的 Ghostscript 参数
        # 增加超时时间到180秒，支持大文件压缩
        # 添加更多压缩优化参数
        cmd = [
            'gs',
            '-sDEVICE=pdfwrite',
            '-dCompatibilityLevel=1.4',
            f'-dPDFSETTINGS={quality}',
            '-dNOPAUSE',
            '-dQUIET',
            '-dBATCH',
            '-dDetectDuplicateImages=true',  # 检测并移除重复图片
            '-dColorImageResolution=150',  # 彩色图片分辨率（/ebook默认150dpi）
            '-dGrayImageResolution=150',   # 灰度图片分辨率
            '-dMonoImageResolution=300',    # 单色图片分辨率
            '-dDownsampleColorImages=true', # 启用彩色图片降采样
            '-dDownsampleGrayImages=true',  # 启用灰度图片降采样
            '-dDownsampleMonoImages=false', # 不降采样单色图片（保持清晰度）
            '-dAutoRotatePages=/None',      # 不自动旋转页面
            '-dEmbedAllFonts=true',         # 嵌入所有字体
            '-dSubsetFonts=true',           # 子集化字体（只嵌入使用的字符）
            '-dCompressFonts=true',         # 压缩字体
            '-dOptimize=true',              # 优化PDF结构
            f'-sOutputFile={out_path}',
            in_path,
        ]
        # 根据质量级别调整参数
        if quality == '/screen':
            # /screen: 72dpi，最大压缩
            cmd = [
                'gs',
                '-sDEVICE=pdfwrite',
                '-dCompatibilityLevel=1.4',
                '-dPDFSETTINGS=/screen',
                '-dNOPAUSE',
                '-dQUIET',
                '-dBATCH',
                '-dDetectDuplicateImages=true',
                '-dColorImageResolution=72',
                '-dGrayImageResolution=72',
                '-dMonoImageResolution=300',
                '-dDownsampleColorImages=true',
                '-dDownsampleGrayImages=true',
                '-dDownsampleMonoImages=false',
                '-dAutoRotatePages=/None',
                '-dEmbedAllFonts=true',
                '-dSubsetFonts=true',
                '-dCompressFonts=true',
                '-dOptimize=true',
                f'-sOutputFile={out_path}',
                in_path,
            ]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=180)
        if proc.returncode != 0 or not os.path.exists(out_path):
            stderr_msg = proc.stderr.decode('utf-8', errors='ignore')[:500] if proc.stderr else ''
            err_detail = 'returncode=%d, stderr=%s' % (proc.returncode, stderr_msg)
            print('[FreeYourPDF] Ghostscript 压缩失败:', err_detail, flush=True)
            sys.stdout.flush()
            raise RuntimeError('ghostscript compress failed: %s' % (stderr_msg or proc.returncode))
        with open(out_path, 'rb') as f_out:
            out_bytes = f_out.read()
        if not out_bytes:
            raise RuntimeError('ghostscript produced empty output')
        return out_bytes


@app.route('/api/encrypt', methods=['POST'])
def api_encrypt():
    """加密 PDF：登录或匿名。先校验文件且未加密再扣配额，用 pypdf 加密后返回。"""
    user_id, anonymous_id = _quota_identity()
    if user_id is None and anonymous_id is None:
        return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    # 先取 form 再读 file，避免部分环境下 form 未解析完整
    user_password = (request.form.get('user_password') or '').strip()
    owner_password = (request.form.get('owner_password') or '').strip()
    perms_json = request.form.get('permissions')
    data = f.read()
    if not data:
        return jsonify({'error': '文件为空'}), 400
    
    # 检查文件大小（防止内存耗尽）
    file_size_mb = len(data) / (1024 * 1024)
    if file_size_mb > config_module.MAX_FILE_SIZE_MB:
        return jsonify({'error': f'文件过大（{file_size_mb:.1f}MB），最大支持 {config_module.MAX_FILE_SIZE_MB}MB'}), 400
    
    stream = io.BytesIO(data)
    try:
        reader = PdfReader(stream)
        # 检查页数（防止超大文件）
        if len(reader.pages) > config_module.MAX_PAGES_LIMIT:
            return jsonify({'error': f'PDF 页数过多（{len(reader.pages)}页），最大支持 {config_module.MAX_PAGES_LIMIT} 页'}), 400
        if reader.is_encrypted:
            return jsonify({'error': '请先解锁已加密的 PDF 再使用加密功能'}), 400
        if len(reader.pages) == 0:
            return jsonify({'error': 'PDF 无有效页面'}), 400
    except Exception as e:
        return jsonify({'error': '无法读取 PDF：' + str(e)}), 400
    if user_id is not None:
        ok, result = _consume_quota(user_id, 'encrypt')
    else:
        ok, result = _consume_anonymous_quota(anonymous_id, 'encrypt')
    if not ok:
        return jsonify({'error': result}), 403
    permissions_flag = -1
    if perms_json:
        try:
            import json
            perms = json.loads(perms_json)
            permissions_flag = _encrypt_permissions_flag(perms)
        except Exception:
            pass
    try:
        out = None
        # 有打开密码：用 pikepdf，user=owner=打开密码；仅权限无打开密码：用 pikepdf，user=''、owner=权限密码，保证 Acrobat 中「操作权限密码」正确
        use_pikepdf = bool(user_password) or (permissions_flag != -1)
        if use_pikepdf:
            try:
                stream_in = io.BytesIO(data)
                pdf = pikepdf.Pdf.open(stream_in)
                # 检查页数（防止超大文件）
                if len(pdf.pages) > config_module.MAX_PAGES_LIMIT:
                    pdf.close()
                    return jsonify({'error': f'PDF 页数过多（{len(pdf.pages)}页），最大支持 {config_module.MAX_PAGES_LIMIT} 页'}), 400
                out = io.BytesIO()
                allow = None
                if perms_json:
                    try:
                        import json as _json
                        perms = _json.loads(perms_json)
                        allow = _pikepdf_permissions(perms)
                    except Exception as perm_err:
                        print('[FreeYourPDF] 加密：解析权限 JSON 失败:', str(perm_err), flush=True)
                        sys.stdout.flush()
                if user_password:
                    # 打开需要密码：user 与 owner 同密码，用该密码打开即拥有全部权限
                    enc = pikepdf.Encryption(user=user_password, owner=user_password, R=4, allow=allow)
                else:
                    # 仅权限、无打开密码：user 为空（任何人可打开），owner 为前端传的权限密码（在阅读器中修改安全设置时输入）
                    enc = pikepdf.Encryption(user='', owner=owner_password, R=4, allow=allow)
                pdf.save(out, encryption=enc)
                pdf.close()
                out.seek(0)
                
                # 清理内存
                del pdf, stream_in
                _cleanup_memory()
                
                print('[FreeYourPDF] 加密：pikepdf 加密成功', flush=True)
            except Exception as pikepdf_err:
                print('[FreeYourPDF] 加密：pikepdf 失败，回退到 pypdf:', str(pikepdf_err), flush=True)
                import traceback
                traceback.print_exc(file=sys.stdout)
                sys.stdout.flush()
                use_pikepdf = False
                out = None
        if out is None:
            # 无权限限制且无密码：用 pypdf 做无加密或仅占位
            stream2 = io.BytesIO(data)
            reader = PdfReader(stream2)
            # 检查页数（防止超大文件）
            if len(reader.pages) > config_module.MAX_PAGES_LIMIT:
                return jsonify({'error': f'PDF 页数过多（{len(reader.pages)}页），最大支持 {config_module.MAX_PAGES_LIMIT} 页'}), 400
            writer = PdfWriter()
            for page in reader.pages:
                writer.add_page(page)
            owner_pwd = user_password or owner_password or None
            writer.encrypt(
                user_password,
                owner_pwd,
                use_128bit=True,
                permissions_flag=permissions_flag,
            )
            out = io.BytesIO()
            writer.write(out)
            out.seek(0)
            
            # 清理内存（保留 out，因为需要返回）
            del reader, writer, stream2
            _cleanup_memory()
            
        _record_usage(user_id, anonymous_id, 'encrypt', '/api/encrypt', 200)
        base_name = (f.filename or 'output.pdf').replace('.pdf', '')
        return send_file(
            out,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=base_name + '_encrypted.pdf',
        )
    except Exception as e:
        import traceback
        err_msg = '加密失败：' + str(e)
        print('[FreeYourPDF] 加密异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'error': err_msg}), 400


@app.route('/api/compress', methods=['POST'])
def api_compress():
    """体积优化：登录或匿名，先校验再扣 compress 配额。
    优先使用 Ghostscript 压缩（图片重采样等），失败时退回 pypdf 结构优化。
    """
    user_id, anonymous_id = _quota_identity()
    if user_id is None and anonymous_id is None:
        return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    data = f.read()
    if not data:
        return jsonify({'error': '文件为空'}), 400
    
    # 检查文件大小（防止内存耗尽）
    file_size_mb = len(data) / (1024 * 1024)
    if file_size_mb > config_module.MAX_FILE_SIZE_MB:
        return jsonify({'error': f'文件过大（{file_size_mb:.1f}MB），最大支持 {config_module.MAX_FILE_SIZE_MB}MB'}), 400
    
    stream = io.BytesIO(data)
    try:
        with _suppress_pdf_warnings():
            reader = PdfReader(stream)
            # 检查页数（防止超大文件）
            if len(reader.pages) > config_module.MAX_PAGES_LIMIT:
                return jsonify({'error': f'PDF 页数过多（{len(reader.pages)}页），最大支持 {config_module.MAX_PAGES_LIMIT} 页'}), 400
            if reader.is_encrypted:
                return jsonify({'error': '请先解锁已加密的 PDF 再使用体积优化'}), 400
            if len(reader.pages) == 0:
                return jsonify({'error': 'PDF 无有效页面'}), 400
    except Exception as e:
        return jsonify({'error': '无法读取 PDF：' + str(e)}), 400
    if user_id is not None:
        ok, result = _consume_quota(user_id, 'compress')
    else:
        ok, result = _consume_anonymous_quota(anonymous_id, 'compress')
    if not ok:
        return jsonify({'error': result}), 403
    try:
        original_size = len(data)
        compressed_bytes = None
        compression_method = None
        
        # 1) 优先尝试用 Ghostscript 进行有损压缩
        # 先尝试 /ebook（150dpi，平衡质量与体积）
        try:
            compressed_bytes = _compress_pdf_with_ghostscript(data, quality='/ebook')
            compression_method = 'ghostscript_ebook'
            compression_ratio = len(compressed_bytes) / original_size if original_size > 0 else 1.0
            
            # 如果压缩效果不好（减少<5%），尝试更激进的 /screen 压缩
            if compression_ratio > 0.95:
                print('[FreeYourPDF] 体积优化：/ebook 压缩效果不佳（%.1f%%），尝试 /screen 压缩' % (compression_ratio * 100), flush=True)
                try:
                    compressed_bytes_screen = _compress_pdf_with_ghostscript(data, quality='/screen')
                    compression_ratio_screen = len(compressed_bytes_screen) / original_size if original_size > 0 else 1.0
                    # 如果 /screen 效果更好，使用它
                    if compression_ratio_screen < compression_ratio:
                        compressed_bytes = compressed_bytes_screen
                        compression_method = 'ghostscript_screen'
                        compression_ratio = compression_ratio_screen
                        print('[FreeYourPDF] 体积优化：/screen 压缩效果更好（%.1f%%）' % (compression_ratio * 100), flush=True)
                except Exception as screen_err:
                    print('[FreeYourPDF] 体积优化：/screen 压缩失败，使用 /ebook 结果:', str(screen_err), flush=True)
            
            # 清理内存
            del data, stream
            _cleanup_memory()
            
            print('[FreeYourPDF] 体积优化：Ghostscript 压缩成功，原始大小 %d 字节，压缩后 %d 字节，压缩率 %.1f%%' % 
                  (original_size, len(compressed_bytes), compression_ratio * 100), flush=True)
        except Exception as gs_err:
            print('[FreeYourPDF] 体积优化：Ghostscript 不可用或失败，回退到 pypdf 结构优化:', str(gs_err), flush=True)
            sys.stdout.flush()
            # 2) Ghostscript 不可用或失败时，退回到 pypdf 结构优化（无损或轻微压缩）
            stream2 = io.BytesIO(data)
            with _suppress_pdf_warnings():
                reader = PdfReader(stream2)
                writer = PdfWriter()
                for page in reader.pages:
                    writer.add_page(page)
                writer.compress_identical_objects(remove_identicals=True, remove_orphans=True)
                out_buf = io.BytesIO()
                writer.write(out_buf)
                out_buf.seek(0)
                compressed_bytes = out_buf.getvalue()
                compression_method = 'pypdf'
                
                # 清理内存
                del reader, writer, out_buf
                _cleanup_memory()
                
                compression_ratio = len(compressed_bytes) / original_size if original_size > 0 else 1.0
                print('[FreeYourPDF] 体积优化：pypdf 结构优化完成，原始大小 %d 字节，压缩后 %d 字节，压缩率 %.1f%%' % 
                      (original_size, len(compressed_bytes), compression_ratio * 100), flush=True)
        
        # 检查压缩效果，如果效果很差（减少<1%），在响应头中添加提示
        compression_ratio = len(compressed_bytes) / original_size if original_size > 0 else 1.0
        reduction_pct = (1 - compression_ratio) * 100
        
        _record_usage(user_id, anonymous_id, 'compress', '/api/compress', 200)
        base_name = (f.filename or 'output.pdf').replace('.pdf', '')
        
        response = send_file(
            io.BytesIO(compressed_bytes),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=base_name + '_compressed.pdf',
        )
        
        # 在响应头中添加压缩信息，前端可以读取并显示
        response.headers['X-Original-Size'] = str(original_size)
        response.headers['X-Compressed-Size'] = str(len(compressed_bytes))
        response.headers['X-Compression-Ratio'] = f'{compression_ratio:.4f}'
        response.headers['X-Compression-Method'] = compression_method or 'unknown'
        
        return response
    except Exception as e:
        import traceback
        err_msg = '体积优化失败：' + str(e)
        print('[FreeYourPDF] 体积优化异常:', err_msg, flush=True)
        traceback.print_exc(file=sys.stdout)
        sys.stdout.flush()
        return jsonify({'error': err_msg}), 400


@app.route('/api/crack-and-unlock', methods=['POST'])
def api_crack_and_unlock():
    """
    暴力破解打开密码后解锁：登录或匿名，失败不扣次数，使用 SSE 推送进度。
    参考 pdfrip 项目的暴力破解方法。
    """
    user_id, anonymous_id = _quota_identity()
    if user_id is None and anonymous_id is None:
        return jsonify({'error': '请提供登录凭证或 X-Anonymous-Id'}), 401
    
    # 先检查配额是否足够，但不扣减（失败时不扣次数）
    if user_id is not None:
        quota = Quota.query.filter_by(user_id=user_id).first()
        if not quota or quota.unlock_remaining <= 0:
            return jsonify({'error': '解锁次数不足'}), 403
    else:
        anon = _get_or_create_anonymous_quota(anonymous_id)
        if anon.unlock_remaining <= 0:
            return jsonify({'error': '解锁次数不足'}), 403
    
    if 'file' not in request.files:
        return jsonify({'error': '未上传文件'}), 400
    f = request.files['file']
    if not f.filename or not f.filename.lower().endswith('.pdf'):
        return jsonify({'error': '请上传 PDF 文件'}), 400
    data = f.read()
    
    # 检查文件大小（防止内存耗尽）
    file_size_mb = len(data) / (1024 * 1024)
    if file_size_mb > config_module.MAX_FILE_SIZE_MB:
        return jsonify({'error': f'文件过大（{file_size_mb:.1f}MB），最大支持 {config_module.MAX_FILE_SIZE_MB}MB'}), 400
    
    stream = io.BytesIO(data)
    passwords = _password_list()  # 返回生成器，不转换为列表
    
    # 估算密码总数（用于进度显示，但不实际生成所有密码）
    # 常见密码 + 1-6位数字 + 日期 + 字母数字组合（限制）
    estimated_total = (
        len(COMMON_PASSWORDS) +  # 常见密码
        1111110 +  # 1-6位数字 (10 + 100 + 1000 + 10000 + 100000 + 1000000 - 1)
        7300 +  # 日期格式（10年 * 365天 * 2种格式）
        100000  # 字母数字组合（限制）
    )
    total = min(estimated_total, config_module.MAX_PASSWORD_ATTEMPTS)
    
    def generate():
        """SSE 流式生成器，推送进度和结果。"""
        last_err = None
        
        try:
            # 发送开始消息
            yield f"data: {json.dumps({'type': 'start', 'total': total, 'message': '开始暴力破解...'})}\n\n"
            
            idx = 0
            for pwd in passwords:
                # 限制最大尝试次数（防止内存耗尽）
                if idx >= config_module.MAX_PASSWORD_ATTEMPTS:
                    yield f"data: {json.dumps({'type': 'error', 'message': f'已达到最大尝试次数（{config_module.MAX_PASSWORD_ATTEMPTS}），请尝试其他方式获取密码'})}\n\n"
                    break
                
                # 每 1000 次尝试检查一次内存使用
                if idx > 0 and idx % 1000 == 0:
                    used_mb, limit_mb = _check_memory_usage()
                    if used_mb and limit_mb and used_mb > limit_mb:
                        yield f"data: {json.dumps({'type': 'error', 'message': f'内存使用过高（{used_mb:.1f}MB），已停止破解'})}\n\n"
                        break
                    # 定期清理内存
                    _cleanup_memory()
                
                stream.seek(0)
                try:
                    reader = PdfReader(stream)
                    if not reader.is_encrypted:
                        yield f"data: {json.dumps({'type': 'info', 'message': 'PDF 未加密，无需破解'})}\n\n"
                        break
                    
                    # 检查页数（防止超大文件）
                    try:
                        page_count = len(reader.pages)
                        if page_count > config_module.MAX_PAGES_LIMIT:
                            yield f"data: {json.dumps({'type': 'error', 'message': f'PDF 页数过多（{page_count}页），最大支持 {config_module.MAX_PAGES_LIMIT} 页'})}\n\n"
                            break
                    except Exception:
                        pass  # 如果无法读取页数，继续尝试
                    
                    # decrypt() 返回 True/False 表示是否成功，或 None（旧版本）
                    decrypt_result = reader.decrypt(pwd)
                    
                    # 每 10 个密码或前 5 个发送一次进度
                    if idx < 5 or idx % 10 == 0:
                        progress = min(99, int((idx + 1) * 100 / total))  # 最多显示 99%
                        yield f"data: {json.dumps({'type': 'progress', 'current': idx + 1, 'total': total, 'progress': progress, 'password': pwd if idx < 5 else None})}\n\n"
                    
                    idx += 1
                    
                    # 验证解密是否成功：检查返回值
                    if decrypt_result is False:
                        continue
                    
                    # 双重验证：尝试访问页面来验证解密是否真的成功
                    try:
                        # 尝试访问页面数量（这可能会抛出异常如果解密未成功）
                        page_count = len(reader.pages)
                        if page_count == 0:
                            continue
                        # 尝试访问第一页内容来验证解密是否真的成功
                        test_page = reader.pages[0]
                        # 如果能访问页面，说明解密成功
                        print('[FreeYourPDF] 暴力破解成功：密码 "%s"（尝试 %d/%d）' % (pwd, idx + 1, total), flush=True)
                        
                        # 生成解锁后的 PDF
                        writer = PdfWriter()
                        for page in reader.pages:
                            writer.add_page(page)
                        out = io.BytesIO()
                        writer.write(out)
                        out.seek(0)
                        result_pdf = out.getvalue()
                        result_filename = (f.filename or 'output.pdf').replace('.pdf', '_unlocked.pdf')
                        
                        # 清理内存
                        del reader, writer, out
                        _cleanup_memory()
                        
                        # 成功时扣减配额
                        if user_id is not None:
                            _consume_quota(user_id, 'unlock')
                        else:
                            _consume_anonymous_quota(anonymous_id, 'unlock')
                        _record_usage(user_id, anonymous_id, 'unlock', '/api/crack-and-unlock', 200)
                        
                        # 发送成功消息（包含 PDF 数据）
                        import base64
                        pdf_b64 = base64.b64encode(result_pdf).decode('utf-8')
                        yield f"data: {json.dumps({'type': 'success', 'password': pwd, 'attempts': idx + 1, 'total': total, 'pdf': pdf_b64, 'filename': result_filename})}\n\n"
                        return
                        
                    except Exception as page_err:
                        # 解密返回成功但访问页面失败，可能是密码错误或加密算法不支持
                        last_err = page_err
                        continue
                        
                except Exception as e:
                    last_err = e
                    continue
            
            # 所有密码都尝试完毕，未成功
            err_msg = '未能破解密码（已尝试 %d 个密码）' % idx
            print('[FreeYourPDF] 暴力破解失败：%s' % err_msg, flush=True)
            sys.stdout.flush()
            
            # 失败不扣次数，发送失败消息
            yield f"data: {json.dumps({'type': 'error', 'message': err_msg, 'attempts': idx})}\n\n"
            
        except Exception as e:
            err_msg = '暴力破解过程出错：' + str(e)
            print('[FreeYourPDF] 暴力破解失败：%s' % err_msg, flush=True)
            sys.stdout.flush()
            yield f"data: {json.dumps({'type': 'error', 'message': err_msg})}\n\n"
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-store, no-cache, must-revalidate, private',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Accel-Buffering': 'no',  # 禁用 nginx 缓冲
            'Connection': 'keep-alive',  # 保持连接（SSE 需要）
            'X-Content-Type-Options': 'nosniff',  # Cloudflare 兼容性
        }
    )


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.abspath(os.path.join(BASE_DIR, '..', 'frontend'))


# 启动时确认关键路由已注册（仅在实际对外服务的进程中打印，避免 reloader 双进程重复）
if os.environ.get('WERKZEUG_RUN_MAIN', 'true') != 'false':
    with app.app_context():
        _rules = [r.rule for r in app.url_map.iter_rules() if r.rule.startswith('/api/')]
        _key = [x for x in _rules if 'payment' in x or 'user' in x]
        print('[FreeYourPDF] 服务就绪，API 已加载（支付/用户等 %s 个路由）' % len(_key), flush=True)

# 收款码静态图（白名单，仅允许以下文件名）
PAYMENT_QR_FILENAMES = {'alipay-10-0.99.png', 'alipay-60-4.99.png', 'alipay-110-9.99.png'}


@app.route('/api/static/payment/<filename>', methods=['GET'])
def api_static_payment(filename):
    """提供充值收款码图片，供前端显示。"""
    if filename not in PAYMENT_QR_FILENAMES:
        return jsonify({'error': 'not found'}), 404
    static_dir = os.path.join(BASE_DIR, 'static', 'payment')
    path = os.path.join(static_dir, filename)
    if not os.path.isfile(path):
        return jsonify({'error': 'not found'}), 404
    return send_file(path, mimetype='image/png', max_age=86400)


@app.route('/api/health', methods=['GET'])
def api_health():
    """健康检查，确认服务与路由正常。"""
    return jsonify({'status': 'ok', 'service': 'freeyourpdf'})


@app.route('/', methods=['GET'])
def root_index():
    """根路径：返回前端首页或简单 JSON，避免 404。"""
    index_path = os.path.join(FRONTEND_DIR, 'index.html')
    if os.path.isfile(index_path):
        # 单页入口 HTML（与 2Vision main_prod 类似，将前端静态文件托管到同一服务）
        return send_from_directory(FRONTEND_DIR, 'index.html')
    # 如果前端目录不存在，返回一个友好的 JSON 提示
    return jsonify({
        'status': 'ok',
        'service': 'freeyourpdf-backend',
        'message': '前端静态文件未找到，请检查部署或通过 /api/* 调用接口。'
    })


@app.route('/admin', methods=['GET'])
def admin_index():
    """管理后台入口页面（如存在）。"""
    admin_dir = os.path.join(FRONTEND_DIR, 'admin')
    admin_index_path = os.path.join(admin_dir, 'index.html')
    if os.path.isfile(admin_index_path):
        return send_from_directory(admin_dir, 'index.html')
    return jsonify({'error': 'admin frontend not found'}), 404


@app.route('/assets/<path:filename>', methods=['GET'])
def frontend_assets(filename):
    """前端静态资源：图片、字体等。"""
    assets_dir = os.path.join(FRONTEND_DIR, 'assets')
    return send_from_directory(assets_dir, filename)


@app.route('/css/<path:filename>', methods=['GET'])
def frontend_css(filename):
    """前端样式文件。"""
    css_dir = os.path.join(FRONTEND_DIR, 'css')
    return send_from_directory(css_dir, filename)


@app.route('/js/<path:filename>', methods=['GET'])
def frontend_js(filename):
    """前端脚本文件。"""
    js_dir = os.path.join(FRONTEND_DIR, 'js')
    return send_from_directory(js_dir, filename)


@app.route('/.well-known/appspecific/com.chrome.devtools.json', methods=['GET'])
def api_chrome_devtools_probe():
    """
    Chrome DevTools 在本地调试时会定期请求该路径，默认会打出 404 日志。
    这里返回一个空 JSON，避免无意义的 404 噪音。
    """
    return jsonify({}), 200


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    # use_reloader=True：修改后端代码后自动重启
    app.run(host='0.0.0.0', port=port, debug=False, use_reloader=True)
