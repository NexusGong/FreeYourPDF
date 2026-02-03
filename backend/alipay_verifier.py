# -*- coding: utf-8 -*-
"""
支付宝收款验证服务（复刻自 2Vision，适配 FreeYourPDF）
用户点击「我已支付」时，通过支付宝商家账单接口查询是否有一笔匹配的收款（金额+备注订单号），
匹配成功才将订单置为已完成并增加配额；未配置 Cookie 时保持原逻辑（点击即到账）。
"""
import re
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from urllib.parse import quote

logger = logging.getLogger(__name__)

try:
    import requests
except ImportError:
    requests = None
    logger.warning("未安装 requests，支付宝验证功能不可用。请执行: pip install requests")


def _get_config():
    import config as config_module
    return config_module


class AlipayVerifier:
    """支付宝收款验证器"""

    def _key_log(self, msg):
        """仅关键信息输出到控制台（中文）"""
        import sys
        print('[FreeYourPDF] %s' % msg, flush=True)
        sys.stdout.flush()

    def __init__(self):
        cfg = _get_config()
        self.cookie = getattr(cfg, 'ALIPAY_COOKIE', '') or ''
        self.ctoken = getattr(cfg, 'ALIPAY_CTOKEN', '') or ''
        self.bill_user_id = getattr(cfg, 'ALIPAY_BILL_USER_ID', '') or ''
        self.matched_trade_nos: Set[str] = set()
        if not self.ctoken and self.cookie:
            self.ctoken = self._extract_ctoken_from_cookie(self.cookie) or ''
        if not self.bill_user_id and self.cookie:
            self.bill_user_id = self._extract_bill_user_id_from_cookie(self.cookie) or ''
        ok = bool(self.cookie and self.ctoken and self.bill_user_id and requests)
        if ok:
            self._key_log('支付宝验证：已就绪')
        elif self.cookie:
            logger.warning("支付宝配置不完整，缺少 ctoken 或 billUserId，请检查 .env")

    def _extract_ctoken_from_cookie(self, cookie: str) -> Optional[str]:
        m = re.search(r'(?:^|;\s*)ctoken=([^;]+)', cookie)
        if m:
            return m.group(1).strip()
        m = re.search(r'(?:^|;\s*)_CHIPS-ctoken=([^;]+)', cookie)
        if m:
            return m.group(1).strip()
        return None

    def _extract_bill_user_id_from_cookie(self, cookie: str) -> Optional[str]:
        m = re.search(r'(?:^|;\s*)__TRACERT_COOKIE_bucUserId=(\d+)', cookie)
        if m:
            return m.group(1).strip()
        m = re.search(r'(?:^|;\s*)CLUB_ALIPAY_COM=(\d+)', cookie)
        if m:
            return m.group(1).strip()
        return None

    def is_enabled(self) -> bool:
        """是否启用了支付宝验证（已配置 Cookie 等）"""
        return bool(self.cookie and self.ctoken and self.bill_user_id and requests)

    def is_cookie_valid(self) -> bool:
        """检查 Cookie 是否有效（能成功查一笔订单）"""
        if not self.is_enabled():
            return False
        try:
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            result, auth_denied = self.query_trade_list(start_time, end_time, page_num=1, page_size=1)
            if auth_denied or result is None:
                if result is None and not auth_denied:
                    try:
                        from alert_email import notify_alipay_cookie_invalid
                        notify_alipay_cookie_invalid('查询订单列表返回空，Cookie 可能已过期')
                    except Exception:
                        pass
                return False
            if isinstance(result, dict) and (result.get('errorCode') or result.get('error')):
                return False
            if isinstance(result, dict) and result.get('tradeList') is not None:
                return True
            if isinstance(result, dict) and 'result' in result:
                rd = result['result']
                if isinstance(rd, dict) and (rd.get('tradeList') or rd.get('list')):
                    return True
            return True
        except Exception as e:
            logger.warning("支付宝 Cookie 有效性检查异常: %s", e)
            return False

    def query_trade_list(
        self,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        page_num: int = 1,
        page_size: int = 20,
    ) -> tuple:
        """查询支付宝交易订单列表。返回 (result_or_none, auth_denied: bool)，auth_denied 表示认证被拒，调用方可直接 503 无需再请求。"""
        if not self.is_enabled():
            return None, False
        if not start_time:
            start_time = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        if not end_time:
            end_time = datetime.now()
        url = "https://mbillexprod.alipay.com/enterprise/tradeListQuery.json?ctoken=%s&_output_charset=utf-8" % (
            quote(self.ctoken, safe='')
        )
        data = {
            'billUserId': self.bill_user_id,
            'pageNum': page_num,
            'pageSize': page_size,
            'startTime': start_time.strftime('%Y-%m-%d %H:%M:%S'),
            'endTime': end_time.strftime('%Y-%m-%d %H:%M:%S'),
            'status': 'ALL',
            'queryEntrance': 1,
            'entityFilterType': 1,
            'sortTarget': 'gmtCreate',
            'activeTargetSearchItem': 'tradeNo',
            'tradeFrom': 'ALL',
            'sortType': 0,
            '_input_charset': 'gbk',
        }
        headers = {
            'referer': 'https://b.alipay.com/',
            'origin': 'https://b.alipay.com',
            'user-agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'accept': 'application/json',
            'content-type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'cookie': self.cookie,
        }
        try:
            resp = requests.post(url, data=data, headers=headers, timeout=15, allow_redirects=False)
            if resp.status_code != 200:
                logger.warning("支付宝订单查询 HTTP 状态 %s", resp.status_code)
                return None, False
            result = resp.json()
            if not isinstance(result, dict):
                return None, False
            if result.get('stat') == 'deny' or result.get('status') == 'deny':
                err = "支付宝订单查询认证被拒绝，请更新 ALIPAY_COOKIE"
                self._key_log('支付宝：认证被拒绝（Cookie 已过期），请按文档更新 .env')
                logger.warning("%s", err)
                try:
                    from alert_email import notify_alipay_cookie_invalid
                    notify_alipay_cookie_invalid(err)
                except Exception:
                    pass
                return None, True
            if result.get('errorCode') or result.get('error'):
                err = result.get('error') or result.get('errorMsg') or '未知错误'
                logger.warning("支付宝订单查询返回错误: %s", err)
                try:
                    from alert_email import notify_alipay_cookie_invalid
                    notify_alipay_cookie_invalid("支付宝订单查询返回错误: %s" % err)
                except Exception:
                    pass
                return None, False
            trade_list = self._get_trade_list(result)
            return result, False
        except Exception as e:
            logger.warning("支付宝订单查询异常: %s", e)
            try:
                from alert_email import notify_alipay_cookie_invalid
                notify_alipay_cookie_invalid("支付宝订单查询异常: %s" % e)
            except Exception:
                pass
            return None, False

    def _get_trade_list(self, result: Dict) -> List:
        trade_list = result.get('tradeList') or []
        if trade_list:
            return trade_list
        if 'result' in result:
            rd = result['result']
            if isinstance(rd, list):
                return rd
            if isinstance(rd, dict):
                trade_list = rd.get('tradeList') or rd.get('list') or rd.get('details') or []
                if trade_list:
                    return trade_list
                for k, v in rd.items():
                    if isinstance(v, list) and v and isinstance(v[0], dict):
                        s = v[0]
                        if any(f in s for f in ('tradeAmount', 'amount', 'gmtCreate', 'tradeNo', 'tradeTime')):
                            return v
        if isinstance(result.get('data'), list):
            return result['data']
        if isinstance(result.get('data'), dict):
            return result['data'].get('tradeList') or []
        target = result.get('target')
        if isinstance(target, list):
            return target
        if isinstance(target, dict):
            return target.get('tradeList') or target.get('list') or []
        return []

    def find_matching_order(
        self,
        amount: float,
        transaction_id: str,
        created_at: datetime,
        tolerance: float = 0.01,
    ) -> tuple:
        """
        查找匹配的支付宝收款订单。
        返回 (match_dict or None, api_reachable: bool, auth_denied: bool)。
        auth_denied 为 True 时表示本次请求已返回认证被拒，调用方可直接 503 无需再请求。
        """
        if not self.is_enabled():
            return None, False, False
        end_time = datetime.now()
        start_time = created_at - timedelta(minutes=5)
        if (end_time - start_time).total_seconds() > 86400:
            start_time = end_time - timedelta(hours=24)
        page_num = 1
        page_size = 50
        api_reachable = False
        auth_denied = False
        while True:
            result, auth_denied = self.query_trade_list(start_time, end_time, page_num, page_size)
            if auth_denied:
                break
            if not result:
                if page_num == 1:
                    logger.warning("查询支付宝订单失败，无法验证支付")
                break
            api_reachable = True
            trade_list = self._get_trade_list(result)
            if not trade_list:
                total_pages = result.get('totalPage') or result.get('totalPages') or 1
                if page_num >= total_pages:
                    break
                page_num += 1
                continue
            for trade in trade_list:
                if not isinstance(trade, dict):
                    continue
                trade_amount = 0
                for f in ('tradeAmount', 'amount', 'totalAmount', 'money', 'fee'):
                    if trade.get(f) is not None:
                        try:
                            trade_amount = float(trade[f])
                            break
                        except (ValueError, TypeError):
                            pass
                trade_time_str = ''
                for f in ('gmtCreate', 'gmtModified', 'createTime', 'payTime', 'tradeTime'):
                    if trade.get(f):
                        trade_time_str = str(trade[f])
                        break
                trade_memo = ''
                for f in ('buyerMemo', 'goodsMemo', 'memo', 'remark', 'note'):
                    if trade.get(f):
                        trade_memo = str(trade[f])
                        break
                if not trade_memo:
                    trade_memo = '; '.join(
                        str(trade[f]) for f in ('buyerMemo', 'goodsMemo', 'memo', 'remark') if trade.get(f)
                    )
                trade_no = ''
                for f in ('tradeNo', 'outTradeNo', 'trade_id', 'orderNo', 'orderId'):
                    if trade.get(f):
                        trade_no = str(trade[f])
                        break
                trade_status = str(trade.get('tradeStatus') or trade.get('status') or trade.get('payStatus') or '')
                if not trade_status and trade.get('tradeStatusExt'):
                    trade_status = str(trade['tradeStatusExt'])
                status_upper = trade_status.upper()
                is_success = (
                    not trade_status or
                    status_upper in ('SUCCESS', 'TRADE_SUCCESS', 'TRADE_FINISHED', 'FINISHED') or
                    trade_status in ('成功', '交易成功', '交易完成', '已完成', '完成')
                )
                if not is_success:
                    continue
                if trade_no and trade_no in self.matched_trade_nos:
                    continue
                trade_time = None
                try:
                    if trade_time_str and ' ' in trade_time_str:
                        trade_time = datetime.strptime(trade_time_str, '%Y-%m-%d %H:%M:%S')
                    elif trade_time_str:
                        trade_time = datetime.fromisoformat(trade_time_str.replace(' ', 'T'))
                except Exception:
                    continue
                if not trade_time:
                    continue
                amount_diff = abs(trade_amount - amount) if trade_amount > 0 else 999
                amount_match = amount_diff <= tolerance
                time_lower = created_at - timedelta(minutes=5)
                time_match = time_lower <= trade_time <= end_time
                tid_clean = (transaction_id or '').replace('TXN_', '').replace('txn_', '')
                memo_match = bool(
                    transaction_id and trade_memo and (
                        transaction_id in trade_memo or tid_clean in trade_memo or
                        transaction_id.upper() in trade_memo.upper() or tid_clean.upper() in trade_memo.upper() or
                        trade_memo.strip() in (transaction_id, tid_clean) or
                        trade_memo.strip() in (f"订单号：{transaction_id}", f"订单号:{transaction_id}")
                    )
                )
                # 有订单号时必须备注匹配，避免误匹配账上其他同金额流水（如重启后第一次点击误判成功）
                if transaction_id:
                    match_ok = memo_match and amount_match
                else:
                    match_ok = (memo_match and amount_match) or (amount_match and time_match)
                if not match_ok:
                    continue
                if trade_no:
                    self.matched_trade_nos.add(trade_no)
                self._key_log('支付宝：已匹配订单 金额 %.2f 元' % (trade_amount,))
                return ({
                    'trade_no': trade_no,
                    'amount': trade_amount,
                    'time': trade_time,
                    'memo': trade_memo,
                    'memo_match': memo_match,
                }, True, False)
            total_pages = result.get('totalPage') or result.get('totalPages') or 1
            if page_num >= total_pages:
                break
            page_num += 1
        logger.warning("未找到匹配的支付宝订单: 金额=%s, 订单号=%s", amount, transaction_id)
        return None, api_reachable, auth_denied


# 全局单例
_alipay_verifier = None


def get_alipay_verifier() -> AlipayVerifier:
    global _alipay_verifier
    if _alipay_verifier is None:
        _alipay_verifier = AlipayVerifier()
    return _alipay_verifier
