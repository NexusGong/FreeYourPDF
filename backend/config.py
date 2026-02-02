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
