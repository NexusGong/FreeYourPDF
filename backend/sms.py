# -*- coding: utf-8 -*-
"""短信验证码服务（与 2Vision 一致：内存存储，互亿无线 API 真实发送，不模拟）。"""
import re
import time
import random
from datetime import datetime, timedelta
from typing import Optional, Dict

import config as config_module

# 内存存储（生产可改为 Redis）
_sms_store: Dict[str, Dict] = {}


def _mask_phone(phone: str) -> str:
    if not phone or len(phone) < 7:
        return "****"
    return "%s***%s" % (phone[:3], phone[-4:])


def is_valid_phone(phone: str) -> bool:
    """中国大陆手机号：1 开头的 11 位数字。"""
    if not phone:
        return False
    phone = phone.strip().replace(" ", "").replace("-", "")
    return bool(re.match(r"^1\d{10}$", phone))


def _generate_code() -> str:
    return str(random.randint(100000, 999999))


def send_sms_code(phone: str) -> bool:
    """
    发送短信验证码。仅使用真实短信配置（与 2Vision 一致），不模拟。
    未配置 SMS_ENABLED/SMS_ACCOUNT/SMS_PASSWORD 时直接返回 False。
    Returns: True 表示发送成功并已存储；False 表示未配置或发送失败。
    """
    if not is_valid_phone(phone):
        return False
    if not (config_module.SMS_ENABLED and config_module.SMS_ACCOUNT and config_module.SMS_PASSWORD):
        print("[FreeYourPDF] 短信未配置（请设置 SMS_ENABLED、SMS_ACCOUNT、SMS_PASSWORD），不发送验证码", flush=True)
        return False
    existing = _sms_store.get(phone)
    if existing:
        last = existing.get("last_send_time", 0)
        if time.time() - last < config_module.SMS_SEND_INTERVAL_SECONDS:
            return False
    code = _generate_code()
    expire = datetime.utcnow() + timedelta(minutes=config_module.SMS_CODE_EXPIRE_MINUTES)
    try:
        import urllib.request
        import urllib.parse
        data = urllib.parse.urlencode({
            "account": config_module.SMS_ACCOUNT,
            "password": config_module.SMS_PASSWORD,
            "mobile": phone,
            "content": code,
            "templateid": config_module.SMS_TEMPLATE_ID or "1",
        }).encode()
        req = urllib.request.Request(
            config_module.SMS_API_URL or "https://api.ihuyi.com/sms/Submit.json",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
        # 互亿无线：code=2 表示提交成功
        try:
            import json
            r = json.loads(body)
            if r.get("code") != 2:
                print("[FreeYourPDF] SMS API 返回: code=%s msg=%s" % (r.get("code"), r.get("msg", "")), flush=True)
                return False
        except Exception:
            if "2" not in body or "提交成功" not in body:
                print("[FreeYourPDF] SMS API 返回异常: %s" % body[:200], flush=True)
                return False
    except Exception as e:
        print("[FreeYourPDF] SMS 发送异常 %s: %s" % (_mask_phone(phone), e), flush=True)
        return False
    _sms_store[phone] = {
        "code": code,
        "expire_time": expire,
        "last_send_time": time.time(),
        "verify_count": 0,
    }
    return True


def verify_sms_code(phone: str, code: str, consume: bool = True) -> bool:
    """校验短信验证码。consume=True 时通过后删除；consume=False 仅校验不删除（用于统一入口先判断是否已注册）。"""
    if not is_valid_phone(phone) or not code:
        return False
    info = _sms_store.get(phone)
    if not info:
        return False
    if datetime.utcnow() > info["expire_time"]:
        if consume:
            del _sms_store[phone]
        return False
    if info["code"] != code.strip():
        return False
    if consume:
        del _sms_store[phone]
    return True


def get_sms_remaining_seconds(phone: str) -> int:
    """距下次可发送的剩余秒数，0 表示可发送。"""
    info = _sms_store.get(phone)
    if not info:
        return 0
    last = info.get("last_send_time", 0)
    delta = config_module.SMS_SEND_INTERVAL_SECONDS - (time.time() - last)
    return max(0, int(delta))
