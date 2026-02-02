# -*- coding: utf-8 -*-
"""用户、配额、验证码、支付模型。"""
from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    nickname = db.Column(db.String(50), nullable=True)
    avatar = db.Column(db.Text, nullable=True)  # Base64 头像
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, raw_password):
        self.password_hash = generate_password_hash(raw_password)

    def check_password(self, raw_password):
        return check_password_hash(self.password_hash, raw_password)


class Quota(db.Model):
    __tablename__ = 'quota'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), primary_key=True)
    encrypt_remaining = db.Column(db.Integer, nullable=False, default=10)
    unlock_remaining = db.Column(db.Integer, nullable=False, default=10)
    compress_remaining = db.Column(db.Integer, nullable=False, default=10)
    user = db.relationship('User', backref=db.backref('quota', uselist=False))


class AnonymousQuota(db.Model):
    """未登录用户配额（按设备 anonymous_id 区分，每项默认 5 次）。"""
    __tablename__ = 'anonymous_quota'
    anonymous_id = db.Column(db.String(64), primary_key=True)
    encrypt_remaining = db.Column(db.Integer, nullable=False, default=5)
    unlock_remaining = db.Column(db.Integer, nullable=False, default=5)
    compress_remaining = db.Column(db.Integer, nullable=False, default=5)


class VerificationCode(db.Model):
    __tablename__ = 'verification_code'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    code = db.Column(db.String(16), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Payment(db.Model):
    """支付记录（购买解锁/加密/体积优化次数）"""
    __tablename__ = 'payment'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='CASCADE'), nullable=False, index=True)
    pack_type = db.Column(db.String(20), nullable=False)  # unlock / encrypt / compress / combo
    amount = db.Column(db.Float, nullable=False)
    quantity = db.Column(db.Integer, nullable=False)  # 购买的次数
    status = db.Column(db.String(20), default='pending')  # pending / completed / failed
    payment_method = db.Column(db.String(20), default='alipay')
    transaction_id = db.Column(db.String(100), unique=True, index=True, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship('User', backref=db.backref('payments', lazy='dynamic'))


class PageVisit(db.Model):
    """页面访问记录（进入网站即计，用于区分仅访问与有使用）"""
    __tablename__ = 'page_visit'
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(100), nullable=True, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.String(500), nullable=True)
    device_type = db.Column(db.String(20), nullable=True, index=True)
    browser = db.Column(db.String(100), nullable=True)
    os = db.Column(db.String(100), nullable=True)
    country = db.Column(db.String(100), nullable=True, index=True)
    region = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    timezone = db.Column(db.String(50), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user = db.relationship('User', backref=db.backref('page_visits', lazy='dynamic'))


class UsageRecord(db.Model):
    """使用记录（加密/解锁/体积优化每次调用）"""
    __tablename__ = 'usage_record'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id', ondelete='SET NULL'), nullable=True, index=True)
    session_id = db.Column(db.String(100), nullable=True, index=True)
    usage_type = db.Column(db.String(20), nullable=False, index=True)  # encrypt / unlock / compress
    api_endpoint = db.Column(db.String(200), nullable=True, index=True)
    api_method = db.Column(db.String(10), nullable=True)
    response_status = db.Column(db.Integer, nullable=True, index=True)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    country = db.Column(db.String(100), nullable=True, index=True)
    region = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    timezone = db.Column(db.String(50), nullable=True)
    user_agent = db.Column(db.String(500), nullable=True)
    device_type = db.Column(db.String(20), nullable=True, index=True)
    browser = db.Column(db.String(100), nullable=True)
    os = db.Column(db.String(100), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    user = db.relationship('User', backref=db.backref('usage_records', lazy='dynamic'))
