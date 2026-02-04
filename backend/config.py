# -*- coding: utf-8 -*-
"""从环境变量读取配置：SECRET_KEY、数据库、SMTP。支持从 backend/.env 加载。"""
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
    load_dotenv(Path(__file__).resolve().parent / '.env')
except ImportError:
    pass

SECRET_KEY = os.environ.get('SECRET_KEY') or os.environ.get('FLASK_SECRET_KEY')
if not SECRET_KEY:
    # HMAC-SHA256 要求 key 至少 32 字节，否则 PyJWT 报 InsecureKeyLengthWarning
    SECRET_KEY = 'dev-secret-change-in-production-32bytes'

# SQLite 路径
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, 'data')
SQLITE_PATH = os.environ.get('SQLITE_PATH') or os.environ.get('DATABASE_URL')
if not SQLITE_PATH:
    os.makedirs(DATA_DIR, exist_ok=True)
    SQLITE_PATH = os.path.join(DATA_DIR, 'freeyourpdf.db')
if SQLITE_PATH.startswith('sqlite:///'):
    pass
elif not SQLITE_PATH.startswith('sqlite:'):
    SQLITE_PATH = 'sqlite:///' + SQLITE_PATH

# Flask
MAX_CONTENT_LENGTH = 50 * 1024 * 1024  # 50MB

# JWT
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_DAYS = 7

# SMTP（发验证码）
SMTP_HOST = os.environ.get('SMTP_HOST')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_USER = os.environ.get('SMTP_USER')
SMTP_PASSWORD = os.environ.get('SMTP_PASSWORD')
SMTP_USE_TLS = os.environ.get('SMTP_USE_TLS', 'true').lower() in ('1', 'true', 'yes')

# 验证码
CODE_EXPIRE_MINUTES = 10
CODE_COOLDOWN_SECONDS = 60  # 同一邮箱 60 秒内不重复发

# 默认配额：登录用户 10 次，未登录（匿名）5 次
DEFAULT_QUOTA_ENCRYPT = 10
DEFAULT_QUOTA_UNLOCK = 10
DEFAULT_QUOTA_COMPRESS = 10
DEFAULT_QUOTA_ANONYMOUS_ENCRYPT = 5
DEFAULT_QUOTA_ANONYMOUS_UNLOCK = 5
DEFAULT_QUOTA_ANONYMOUS_COMPRESS = 5

# 用户名规则
USERNAME_MIN_LEN = 2
USERNAME_MAX_LEN = 32

# 初始管理员（首次启动时将该邮箱用户设为管理员，可选）
INITIAL_ADMIN_EMAIL = os.environ.get('INITIAL_ADMIN_EMAIL', '').strip()

# 支付：三档套餐，每档含 加密/解锁/体积优化 次数 + 价格(元)
PAYMENT_PACKS = [
    {'encrypt': 10, 'unlock': 10, 'compress': 10, 'amount': 0.99},
    {'encrypt': 60, 'unlock': 60, 'compress': 60, 'amount': 4.99},
    {'encrypt': 110, 'unlock': 110, 'compress': 110, 'amount': 9.99},
]
# 支付宝展示名称（支付说明用）
ALIPAY_ACCOUNT_NAME = os.environ.get('ALIPAY_ACCOUNT_NAME', '支付宝收款')

# 支付宝自动验证（用户点击「我已支付」时查询支付宝账单匹配到账）
# 不配置则保持原逻辑：点击即到账；配置后需在支付宝账单中匹配到对应金额+备注订单号才到账
ALIPAY_COOKIE = os.environ.get('ALIPAY_COOKIE', '').strip()
ALIPAY_CTOKEN = os.environ.get('ALIPAY_CTOKEN', '').strip()
ALIPAY_BILL_USER_ID = os.environ.get('ALIPAY_BILL_USER_ID', '').strip()

# 支付宝 Cookie 过期告警邮件（发到指定邮箱，不配置则使用下方默认邮箱）
ALIPAY_ALERT_EMAIL = os.environ.get('ALIPAY_ALERT_EMAIL', '651333734@qq.com').strip()
# 同一告警限流时间（小时），此时间内相同告警只发一封
ALERT_THROTTLE_HOURS = float(os.environ.get('ALERT_THROTTLE_HOURS', '24'))
