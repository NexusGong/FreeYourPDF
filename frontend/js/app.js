(function () {
  'use strict';

  var API_BASE = (typeof window.FREEYOURPDF_API_BASE !== 'undefined' && window.FREEYOURPDF_API_BASE) ? window.FREEYOURPDF_API_BASE : '';

  const STORAGE_KEY_TOKEN = 'freeyourpdf_token';
  const STORAGE_KEY_ANONYMOUS_ID = 'freeyourpdf_anonymous_id';
  const STORAGE_KEY_GLOW_LEVEL = 'freeyourpdf_glow_level';
  var currentUser = null;
  var stateQuota = null;

  function getGlowLevel() {
    var v = parseInt(localStorage.getItem(STORAGE_KEY_GLOW_LEVEL), 10);
    return (v === 1 || v === 2) ? v : 0;
  }
  function setGlowLevel(level) {
    level = level % 3;
    localStorage.setItem(STORAGE_KEY_GLOW_LEVEL, String(level));
    if (document.body) {
      if (level === 0) document.body.removeAttribute('data-glow-level');
      else document.body.setAttribute('data-glow-level', String(level));
    }
  }
  function cycleGlowLevel() {
    var next = (getGlowLevel() + 1) % 3;
    setGlowLevel(next);
  }

  function getToken() {
    return localStorage.getItem(STORAGE_KEY_TOKEN);
  }
  function setToken(token) {
    if (token) localStorage.setItem(STORAGE_KEY_TOKEN, token);
    else localStorage.removeItem(STORAGE_KEY_TOKEN);
  }
  function clearToken() {
    setToken(null);
    currentUser = null;
    stateQuota = null;
  }
  function setQuota(q) {
    stateQuota = q;
  }
  function getAnonymousId() {
    var id = localStorage.getItem(STORAGE_KEY_ANONYMOUS_ID);
    if (id) return id;
    var hex = '0123456789abcdef';
    var s = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
      var r = Math.random() * 16 | 0;
      var v = c === 'y' ? (r & 0x3 | 0x8) : r;
      return hex[v];
    });
    localStorage.setItem(STORAGE_KEY_ANONYMOUS_ID, s);
    return s;
  }

  /**
   * 将 ISO 时间字符串转换为用户本地时区的格式化时间
   * @param {string} isoString - ISO 格式时间字符串（如 "2024-01-01T12:00:00" 或 "2024-01-01T12:00:00Z"）
   * @param {boolean} includeSeconds - 是否包含秒数，默认 true
   * @returns {string} 格式化后的本地时间字符串（如 "2024-01-01 20:00:00"）
   */
  function formatLocalTime(isoString, includeSeconds) {
    if (!isoString || isoString === '-') return '-';
    if (includeSeconds === undefined) includeSeconds = true;
    
    try {
      // 处理 ISO 格式：如果末尾没有 Z，添加 Z 表示 UTC
      var dateStr = isoString;
      if (!dateStr.endsWith('Z') && !dateStr.includes('+') && !dateStr.includes('-', 10)) {
        // 如果没有时区信息，假设是 UTC
        if (dateStr.includes('T')) {
          dateStr = dateStr + 'Z';
        }
      }
      
      var date = new Date(dateStr);
      if (isNaN(date.getTime())) {
        return isoString; // 如果解析失败，返回原字符串
      }
      
      var year = date.getFullYear();
      var month = String(date.getMonth() + 1).padStart(2, '0');
      var day = String(date.getDate()).padStart(2, '0');
      var hours = String(date.getHours()).padStart(2, '0');
      var minutes = String(date.getMinutes()).padStart(2, '0');
      var seconds = String(date.getSeconds()).padStart(2, '0');
      
      if (includeSeconds) {
        return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes + ':' + seconds;
      } else {
        return year + '-' + month + '-' + day + ' ' + hours + ':' + minutes;
      }
    } catch (e) {
      console.error('时间格式化失败:', e, isoString);
      return isoString; // 出错时返回原字符串
    }
  }

  async function fetchWithAuth(url, opts) {
    var token = getToken();
    opts = opts || {};
    opts.headers = opts.headers || {};
    if (token) {
      opts.headers['Authorization'] = 'Bearer ' + token;
    } else {
      opts.headers['X-Anonymous-Id'] = getAnonymousId();
    }
    if (opts.body && typeof opts.body === 'object' && !(opts.body instanceof FormData) && !(opts.body instanceof Blob)) {
      if (!opts.headers['Content-Type']) opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    var res = await fetch(url, opts);
    if (res.status === 401) {
      clearToken();
      updateAuthUI();
      updateUsageUI();
      showGlobalHint('请先登录。', true);
      if (typeof window.applyAdminRoute === 'function') window.applyAdminRoute();
    }
    return res;
  }

  async function loadQuota() {
    try {
      var res = await fetchWithAuth(API_BASE + '/api/quota');
      if (res.ok) {
        var q = await res.json();
        setQuota(q);
        updateUsageUI();
      } else {
        setQuota(null);
        updateUsageUI();
      }
    } catch (e) {
      setQuota(null);
      updateUsageUI();
    }
  }

  function isTouchDevice() {
    return 'ontouchstart' in window || (navigator.maxTouchPoints && navigator.maxTouchPoints > 0);
  }

  function getFileInputPlaceholder() {
    return isTouchDevice() ? '点击选择多个 PDF' : '点击选择或拖入多个 PDF';
  }

  function updateUsageUI() {
    var q = stateQuota;
    var total = getToken() ? 20 : 10;
    var defaultRem = total;
    var remEncrypt = q && q.encrypt != null ? Math.max(0, q.encrypt) : defaultRem;
    var remUnlock = q && q.unlock != null ? Math.max(0, q.unlock) : defaultRem;
    var remCompress = q && q.compress != null ? Math.max(0, q.compress) : defaultRem;
    var elEncrypt = document.getElementById('usageValueEncrypt');
    var elUnlock = document.getElementById('usageValueUnlock');
    var elCompress = document.getElementById('usageValueCompress');
    var totalEncrypt = document.getElementById('usageTotalEncrypt');
    var totalUnlock = document.getElementById('usageTotalUnlock');
    var totalCompress = document.getElementById('usageTotalCompress');
    if (elEncrypt) elEncrypt.textContent = String(remEncrypt);
    if (elUnlock) elUnlock.textContent = String(remUnlock);
    if (elCompress) elCompress.textContent = String(remCompress);
    // 总数始终显示为固定的默认值（登录20次，匿名10次），而不是动态的剩余次数
    if (totalEncrypt) totalEncrypt.textContent = '/ ' + total;
    if (totalUnlock) totalUnlock.textContent = '/ ' + total;
    if (totalCompress) totalCompress.textContent = '/ ' + total;
    var extra = document.getElementById('extraSection');
    var anyExhausted = (remEncrypt <= 0 || remUnlock <= 0 || remCompress <= 0);
    if (extra) extra.setAttribute('aria-hidden', anyExhausted ? 'false' : 'true');
  }

  function getRemaining(type) {
    var q = stateQuota;
    var total = getToken() ? 20 : 10;
    if (type === 'encrypt') return (q && q.encrypt != null) ? Math.max(0, q.encrypt) : total;
    if (type === 'unlock') return (q && q.unlock != null) ? Math.max(0, q.unlock) : total;
    if (type === 'compress') return (q && q.compress != null) ? Math.max(0, q.compress) : total;
    return 0;
  }
  function canUseEncrypt() { return getRemaining('encrypt') > 0; }
  function canUseUnlock() { return getRemaining('unlock') > 0; }
  function canUseCompress() { return getRemaining('compress') > 0; }

  async function consumeQuotaApi(type) {
    var res = await fetchWithAuth(API_BASE + '/api/quota/consume', { method: 'POST', body: { type: type } });
    if (res.status === 401) return null;
    if (res.status === 403) return null;
    if (!res.ok) return null;
    var q = await res.json();
    setQuota(q);
    updateUsageUI();
    return q;
  }

  function updateAuthUI() {
    var wrap = document.getElementById('authUserWrap');
    var userEl = document.getElementById('authUser');
    var authBtn = document.getElementById('btnAuth');
    var rechargeLoginHint = document.getElementById('rechargeLoginHint');
    var rechargePacks = document.getElementById('rechargePacks');
    var avatarWrap = document.getElementById('authUserAvatarWrap');
    var avatarImg = document.getElementById('authUserAvatarImg');
    var avatarEmoji = document.getElementById('authUserAvatarEmoji');
    if (currentUser) {
      if (wrap) wrap.setAttribute('aria-hidden', 'false');
      if (userEl) userEl.textContent = (currentUser.nickname || currentUser.username) || '';
      if (authBtn) authBtn.setAttribute('aria-hidden', 'true');
      if (rechargeLoginHint) rechargeLoginHint.style.display = 'none';
      if (rechargePacks) { rechargePacks.style.display = 'block'; loadPaymentPacks(); }
      if (avatarWrap) {
        var av = currentUser.avatar;
        if (av && typeof av === 'string' && av.indexOf('data:image') === 0) {
          if (avatarImg) { avatarImg.src = av; avatarImg.style.display = 'block'; avatarImg.alt = '头像'; }
          if (avatarEmoji) { avatarEmoji.style.display = 'none'; avatarEmoji.textContent = ''; }
        } else if (av && typeof av === 'string') {
          if (avatarImg) avatarImg.style.display = 'none';
          if (avatarEmoji) { avatarEmoji.textContent = av; avatarEmoji.style.display = 'block'; }
        } else {
          if (avatarImg) avatarImg.style.display = 'none';
          if (avatarEmoji) { avatarEmoji.style.display = 'none'; avatarEmoji.textContent = ''; }
          avatarWrap.style.display = 'none';
          return;
        }
        avatarWrap.style.display = 'inline-flex';
      }
      closeUserDropdown();
    } else {
      if (wrap) wrap.setAttribute('aria-hidden', 'true');
      if (userEl) userEl.textContent = '';
      if (authBtn) authBtn.setAttribute('aria-hidden', 'false');
      if (rechargeLoginHint) rechargeLoginHint.style.display = 'block';
      if (rechargePacks) rechargePacks.style.display = 'none';
      if (avatarWrap) avatarWrap.style.display = 'none';
      if (avatarImg) avatarImg.style.display = 'none';
      if (avatarEmoji) avatarEmoji.style.display = 'none';
    }
  }

  function openUserDropdown() {
    var dd = document.getElementById('authUserDropdown');
    var trigger = document.getElementById('authUserTrigger');
    if (dd) { dd.setAttribute('aria-hidden', 'false'); }
    if (trigger) trigger.setAttribute('aria-expanded', 'true');
  }
  function closeUserDropdown() {
    var dd = document.getElementById('authUserDropdown');
    var trigger = document.getElementById('authUserTrigger');
    if (document.activeElement && dd && dd.contains(document.activeElement)) {
      if (trigger) trigger.focus();
    }
    if (dd) dd.setAttribute('aria-hidden', 'true');
    if (trigger) trigger.setAttribute('aria-expanded', 'false');
  }
  function toggleUserDropdown() {
    var dd = document.getElementById('authUserDropdown');
    var isOpen = dd && dd.getAttribute('aria-hidden') !== 'true';
    if (isOpen) closeUserDropdown();
    else openUserDropdown();
  }

  var currentOrderTransactionId = null;

  async function loadPaymentPacks() {
    try {
      var res = await fetch(API_BASE + '/api/payment/packs');
      if (!res.ok) return;
      var json = await res.json();
      var list = json.packs || [];
      var el = document.getElementById('packListCombo');
      if (!el) return;
      el.innerHTML = '';
      list.forEach(function (p) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.className = 'btn btn-secondary pack-btn';
        btn.textContent = p.encrypt + '次 ¥' + p.amount;
        btn.addEventListener('click', function () { createPaymentOrder(p.index); });
        el.appendChild(btn);
      });
    } catch (e) {}
  }

  async function createPaymentOrder(packIndex) {
    var res = await fetchWithAuth(API_BASE + '/api/payment/create', { method: 'POST', body: { pack_index: packIndex } });
    if (!res.ok) { var j = await res.json().catch(function () { return {}; }); showGlobalHint(j.error || '创建订单失败', true); return; }
    var json = await res.json();
    currentOrderTransactionId = json.transaction_id;
    document.getElementById('orderTransactionId').textContent = json.transaction_id;
    document.getElementById('orderAmount').textContent = json.amount;
    document.getElementById('rechargeOrder').style.display = 'block';
  }

  async function confirmPayment() {
    if (!currentOrderTransactionId) return;
    showPaymentConfirmLoading();
    try {
      var res = await fetchWithAuth(API_BASE + '/api/payment/confirm', { method: 'POST', body: { transaction_id: currentOrderTransactionId } });
      var json = await res.json().catch(function () { return {}; });
      if (res.ok && json.status === 'success') {
        currentOrderTransactionId = null;
        document.getElementById('rechargeOrder').style.display = 'none';
        showGlobalHint('支付确认成功，次数已到账。');
        await loadQuota();
      } else {
        var errMsg = json.error || json.detail || '确认失败，请稍后再试。';
        var alertTitle = (json.detail === 'no_matching_order') ? '未查询到订单' : (json.detail === 'alipay_auth_denied' ? 'Cookie 已过期' : '支付确认失败');
        showGlobalHint(errMsg, true);
        showPaymentConfirmAlert(errMsg, alertTitle);
      }
    } finally {
      closePaymentConfirmLoading();
    }
  }

  var _authPendingPhone = null;
  var _authPendingCode = null;

  function setAuthLoginMethod(method) {
    var formCode = document.getElementById('authFormCode');
    var formPwd = document.getElementById('authFormPassword');
    var subs = document.querySelectorAll('.auth-step[data-auth-step="verify"] .auth-subtab');
    if (method === 'password') {
      if (formCode) formCode.style.display = 'none';
      if (formPwd) formPwd.style.display = '';
      subs.forEach(function (s, i) { s.classList.toggle('is-active', (s.getAttribute('data-auth-login-method') === 'password')); });
    } else {
      if (formCode) formCode.style.display = '';
      if (formPwd) formPwd.style.display = 'none';
      subs.forEach(function (s, i) { s.classList.toggle('is-active', (s.getAttribute('data-auth-login-method') === 'code')); });
    }
    showAuthHint('');
  }

  function openAuthModal() {
    var modal = document.getElementById('authModal');
    if (modal) { modal.setAttribute('aria-hidden', 'false'); modal.classList.add('is-visible'); }
    _authPendingPhone = null;
    _authPendingCode = null;
    showAuthStep('verify');
    setAuthLoginMethod('code');
    showAuthHint('');
    var titleEl = document.getElementById('authModalTitle');
    if (titleEl) titleEl.textContent = '登录';
  }
  function closeAuthModal() {
    var modal = document.getElementById('authModal');
    if (modal) {
      if (document.activeElement && modal.contains(document.activeElement)) document.activeElement.blur();
      modal.setAttribute('aria-hidden', 'true'); modal.classList.remove('is-visible');
    }
    showAuthStep('verify');
  }
  function showAuthStep(step) {
    var verifyEl = document.getElementById('authStepVerify');
    var setProfileEl = document.getElementById('authStepSetProfile');
    if (step === 'verify') {
      if (verifyEl) verifyEl.style.display = '';
      if (setProfileEl) setProfileEl.style.display = 'none';
    } else {
      if (verifyEl) verifyEl.style.display = 'none';
      if (setProfileEl) setProfileEl.style.display = '';
    }
  }
  function showAuthHint(text, isError) {
    var el = document.getElementById('authModalHint');
    if (!el) return;
    el.textContent = text || '';
    el.setAttribute('aria-hidden', text ? 'false' : 'true');
    el.classList.toggle('modal-hint-error', !!isError);
    el.classList.toggle('modal-hint-ok', !isError && !!text);
  }

  function startSmsCountdown(btn, seconds) {
    var orig = btn.textContent;
    var left = seconds;
    btn.disabled = true;
    var t = setInterval(function () {
      left--;
      btn.textContent = left > 0 ? left + ' 秒后重发' : orig;
      if (left <= 0) { clearInterval(t); btn.disabled = false; }
    }, 1000);
  }

  async function authSendSmsCode(phone, hintOnFail, sendCodeBtn) {
    phone = (phone || '').trim().replace(/\s|-/g, '');
    var origText = (sendCodeBtn && sendCodeBtn.textContent) || '获取验证码';
    if (!/^1\d{10}$/.test(phone)) {
      showAuthHint('请输入以1开头的11位手机号', true);
      if (sendCodeBtn) { sendCodeBtn.disabled = false; sendCodeBtn.textContent = origText; }
      return false;
    }
    showAuthHint('正在发送验证码…', false);
    if (sendCodeBtn) { sendCodeBtn.disabled = true; sendCodeBtn.textContent = '发送中…'; }
    try {
      var res = await fetch(API_BASE + '/api/auth/sms/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone: phone }) });
      var json = await res.json().catch(function () { return {}; });
      if (res.ok) {
        showAuthHint('验证码已发送，请查收短信', false);
        showGlobalHint('验证码已发送。');
        if (sendCodeBtn) startSmsCountdown(sendCodeBtn, 60);
        return true;
      }
      showAuthHint(json.error || '发送失败', true);
      if (sendCodeBtn) { sendCodeBtn.disabled = false; sendCodeBtn.textContent = origText; }
      return false;
    } catch (e) {
      if (hintOnFail) showAuthHint('网络错误，请稍后重试', true);
      if (sendCodeBtn) { sendCodeBtn.disabled = false; sendCodeBtn.textContent = origText; }
      return false;
    } finally {
      if (sendCodeBtn && sendCodeBtn.disabled && sendCodeBtn.textContent === '发送中…') {
        sendCodeBtn.disabled = false;
        sendCodeBtn.textContent = origText;
      }
    }
  }

  async function onAuthSubmitCode() {
    var phone = (document.getElementById('authPhone') && document.getElementById('authPhone').value || '').trim().replace(/\s|-/g, '');
    var code = (document.getElementById('authCode') && document.getElementById('authCode').value || '').trim();
    if (!/^1\d{10}$/.test(phone)) { showAuthHint('请输入以1开头的11位手机号', true); return; }
    if (!code) { showAuthHint('请填写验证码', true); return; }
    try {
      var res = await fetch(API_BASE + '/api/auth/sms/submit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ phone: phone, code: code }) });
      var json = await res.json().catch(function () { return {}; });
      if (!res.ok) { showAuthHint(json.error || '验证失败', true); return; }
      if (json.access_token) {
        setToken(json.access_token);
        currentUser = json.user;
        closeAuthModal();
        updateAuthUI();
        showGlobalHint('登录成功。');
        await loadQuota();
        updateUsageUI();
        return;
      }
      if (json.need_register) {
        _authPendingPhone = phone;
        _authPendingCode = code;
        showAuthStep('set-profile');
        var titleEl = document.getElementById('authModalTitle');
        if (titleEl) titleEl.textContent = '设置用户名和密码';
        showAuthHint('请设置用户名和密码完成注册', false);
        return;
      }
      showAuthHint('请重试', true);
    } catch (e) {
      showAuthHint('网络错误，请稍后重试', true);
    }
  }

  async function onAuthPasswordLogin() {
    var username = (document.getElementById('authPasswordUsername') && document.getElementById('authPasswordUsername').value || '').trim();
    var password = document.getElementById('authPassword') && document.getElementById('authPassword').value || '';
    if (!username) { showAuthHint('请输入用户名', true); return; }
    if (!password) { showAuthHint('请填写密码', true); return; }
    try {
      var res = await fetch(API_BASE + '/api/auth/password/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: username, password: password }) });
      var json = await res.json().catch(function () { return {}; });
      if (!res.ok) { showAuthHint(json.error || '登录失败', true); return; }
      setToken(json.access_token);
      currentUser = json.user;
      closeAuthModal();
      updateAuthUI();
      showGlobalHint('登录成功。');
      await loadQuota();
      updateUsageUI();
    } catch (e) {
      showAuthHint('网络错误，请稍后重试', true);
    }
  }

  async function onAuthCompleteRegister() {
    if (!_authPendingPhone || !_authPendingCode) { showAuthHint('会话已过期，请关闭后重新获取验证码', true); return; }
    var username = (document.getElementById('authNewUsername') && document.getElementById('authNewUsername').value || '').trim();
    var password = document.getElementById('authNewPassword') && document.getElementById('authNewPassword').value || '';
    var passwordConfirm = document.getElementById('authNewPasswordConfirm') && document.getElementById('authNewPasswordConfirm').value || '';
    if (!username) { showAuthHint('请填写用户名', true); return; }
    if (!password) { showAuthHint('请设置密码', true); return; }
    if (password.length < 6) { showAuthHint('密码至少 6 位', true); return; }
    if (password !== passwordConfirm) { showAuthHint('两次输入的密码不一致', true); return; }
    try {
      var res = await fetch(API_BASE + '/api/auth/sms/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: username, phone: _authPendingPhone, code: _authPendingCode, password: password })
      });
      var json = await res.json().catch(function () { return {}; });
      if (!res.ok) { showAuthHint(json.error || '注册失败', true); return; }
      setToken(json.access_token);
      currentUser = json.user;
      closeAuthModal();
      updateAuthUI();
      showGlobalHint('注册成功，已自动登录。');
      await loadQuota();
      updateUsageUI();
    } catch (e) {
      showAuthHint('网络错误，请稍后重试', true);
    }
  }

  window.openAuthModal = openAuthModal;

  /** 每个功能 tab 单独保存提示信息，切换 tab 时只显示当前 tab 的提示 */
  var _currentTabForHint = 'encrypt';
  var _hintByTab = { encrypt: '', unlock: '', compress: '' };
  var _hintErrorByTab = { encrypt: false, unlock: false, compress: false };
  function setGlobalHintDOM(text, isError) {
    var el = document.getElementById('globalHint');
    if (!el) return;
    // 支持富文本高亮（如 <strong>），仅用于内部固定文案，安全可控
    el.innerHTML = text || '';
    el.classList.toggle('hint-error', !!isError);
    el.classList.toggle('hint-ok', !isError && !!text);
  }
  function showGlobalHint(text, isError) {
    if (_hintByTab[_currentTabForHint] !== undefined) {
      _hintByTab[_currentTabForHint] = text || '';
      _hintErrorByTab[_currentTabForHint] = !!isError;
    }
    setGlobalHintDOM(text || '', isError);
  }


  function showLoading(show, text) {
    const overlay = document.getElementById('loadingOverlay');
    const textEl = document.getElementById('loadingText');
    if (overlay) {
      overlay.setAttribute('aria-hidden', show ? 'false' : 'true');
      overlay.classList.toggle('is-visible', !!show);
    }
    if (textEl && text !== undefined) textEl.textContent = text || '处理中…';
  }

  function nameWithoutExt(name) {
    const i = name.lastIndexOf('.');
    return i > 0 ? name.slice(0, i) : name;
  }

  /**
   * 检测 PDF：优先请求后端 /api/detect，失败则用前端逻辑。
   * 返回 { encrypted: boolean, hasRestrictions: boolean } 或仅 encrypted（兼容旧逻辑）。
   */
  async function apiDetect(file) {
    try {
      var form = new FormData();
      form.append('file', file);
      var res = await fetch(API_BASE + '/api/detect', { method: 'POST', body: form });
      if (res.ok) {
        var json = await res.json();
        return { encrypted: json.encrypted, hasRestrictions: json.hasRestrictions };
      }
    } catch (e) {}
    return null;
  }

  async function detectEncryption(file) {
    var api = await apiDetect(file);
    if (api) return api.encrypted;
    // 后端不可用时，退回到简单的 /Encrypt 关键字检测（不再依赖前端 PDF 库）
    try {
      var bytes = new Uint8Array(await file.arrayBuffer());
      var text = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      return text.indexOf('/Encrypt') !== -1;
    } catch (e) {
      return false;
    }
  }

  async function detectHasRestrictions(file) {
    var api = await apiDetect(file);
    if (api) return api.hasRestrictions;
    try {
      var bytes = new Uint8Array(await file.arrayBuffer());
      var s = new TextDecoder('utf-8', { fatal: false }).decode(bytes);
      return s.indexOf('/Encrypt') !== -1;
    } catch (e) {
      return false;
    }
  }

  const fileListEl = document.getElementById('fileList');
  const pdfInput = document.getElementById('pdfInput');

  const state = {
    itemsByTab: { encrypt: [], unlock: [], compress: [] },
    currentTab: 'encrypt'
  };

  function getCurrentItems() {
    return state.itemsByTab[state.currentTab] || [];
  }

  function updateCardByTab() {
    var titleEl = document.getElementById('cardTitle');
    var descEl = document.getElementById('cardDesc');
    var t = state.currentTab;
    var titles = { encrypt: '选择 PDF 文件（加密）', unlock: '选择 PDF 文件（解锁）', compress: '选择 PDF 文件（优化）' };
    var intros = {
      encrypt: '支持多选，可对未加密的 PDF 进行加密。',
      unlock: '支持多选，可对需密码或有权限限制的 PDF 进行解锁（系统破解或解除限制）。',
      compress: '可对未加密的 PDF 进行体积优化。已加密的 PDF 请先解锁后再使用本功能。'
    };
    var strongNote = (t === 'encrypt')
      ? ' <strong>设置打开密码时由服务端加密，保证用您设置的密码可在 Adobe、预览等阅读器中正确打开。</strong>'
      : (t === 'compress')
      ? ' <strong>设备本地处理，文件不上传服务器，隐私与安全有保障。</strong>'
      : ' <strong>全部在您设备本地处理，文件不上传服务器，隐私与安全有保障。</strong>';
    if (titleEl) titleEl.textContent = titles[t] || titles.encrypt;
    if (descEl) descEl.innerHTML = (intros[t] || intros.encrypt) + strongNote;
  }

  function getCompressCompatibility() {
    var sel = document.getElementById('compressCompatibility');
    return sel ? sel.value : '1.7';
  }

  function getCompressMode() {
    // 统一走后端 /api/compress，由后端负责体积优化，不再在前端进行图片重采样
    return 'standard';
  }

  // 压缩质量由后端 Ghostscript 决定，前端不再管理滑块
  function getCompressRasterQuality() {
    return 0.5;
  }

  function setActiveTab(tab) {
    state.currentTab = tab;
    _currentTabForHint = tab;
    var tabEncrypt = document.getElementById('tabEncrypt');
    var tabUnlock = document.getElementById('tabUnlock');
    var tabCompress = document.getElementById('tabCompress');
    if (tabEncrypt) {
      tabEncrypt.classList.toggle('is-active', tab === 'encrypt');
      tabEncrypt.setAttribute('aria-selected', tab === 'encrypt' ? 'true' : 'false');
    }
    if (tabUnlock) {
      tabUnlock.classList.toggle('is-active', tab === 'unlock');
      tabUnlock.setAttribute('aria-selected', tab === 'unlock' ? 'true' : 'false');
    }
    if (tabCompress) {
      tabCompress.classList.toggle('is-active', tab === 'compress');
      tabCompress.setAttribute('aria-selected', tab === 'compress' ? 'true' : 'false');
    }
    updateCardByTab();
    syncCompressRasterQualityDisplay();
    renderFileList();
    setGlobalHintDOM(_hintByTab[tab] || '', _hintErrorByTab[tab]);
    var textEl = document.getElementById('pdfInputText');
    var n = getCurrentItems().length;
    if (textEl) textEl.textContent = n > 0 ? '已选 ' + n + ' 个文件，可继续添加' : getFileInputPlaceholder();
  }

  function syncCompressRasterQualityDisplay() {
    var input = document.getElementById('compressRasterQuality');
    var valueEl = document.getElementById('compressRasterQualityValue');
    if (valueEl && input) valueEl.textContent = input.value;
  }

  function renderRow(item, index) {
    const row = document.createElement('div');
    row.className = 'file-row';
    row.dataset.index = String(index);

    const hasProtectionResult = item.resultProtection && item.resultProtection.blob;
    const hasCompressResult = item.resultCompress && item.resultCompress.blob;

    var statusText = '检测中…';
    if (hasProtectionResult) {
      if (item.encrypted === true) statusText = '解密成功';
      else if (item.encrypted === false && item.hasRestrictions === true) statusText = '已解除限制';
      else statusText = '成功加密';
    } else if (item.encrypted === true) statusText = '需打开密码';
    else if (item.encrypted === false && item.hasRestrictions === true) statusText = '有权限限制';
    else if (item.encrypted === false && item.hasRestrictions === false) statusText = '无密码无限制';
    else if (item.encrypted === false && item.hasRestrictions === null) statusText = '检测中…';
    const canShowActions = item.encrypted !== null && (item.encrypted || item.hasRestrictions !== null);
    const tab = state.currentTab;
    var canShowEncrypt = !!item.file && item.encrypted === false && item.hasRestrictions === false;
    var canShowUnlock = !!item.file && (item.encrypted === true || item.hasRestrictions === true || hasProtectionResult);

    var encryptBlockInner = '';
    if (canShowEncrypt) {
      if (hasProtectionResult) {
        encryptBlockInner = '<button type="button" class="btn btn-download btn-download-protection" data-download-index="' + index + '" data-download-type="protection">下载</button>';
      } else {
        encryptBlockInner = '<button type="button" class="btn btn-primary btn-action btn-encrypt-open" data-action-index="' + index + '">加密</button>';
      }
    }
    var encryptBlock =
      '<div class="file-row-block file-row-block-protection">' +
        '<span class="file-row-block-label">' + (hasProtectionResult && item.encrypted === false && !item.hasRestrictions ? '结果' : '加密') + '</span>' +
        (canShowEncrypt ? '<div class="file-row-block-inner">' + encryptBlockInner + '</div>' : '') +
      '</div>';

    var unlockBlockInner = '';
    if (canShowUnlock) {
      if (hasProtectionResult) {
        unlockBlockInner = '<button type="button" class="btn btn-download btn-download-protection" data-download-index="' + index + '" data-download-type="protection">下载</button>';
      } else if (item.encrypted === true) {
        unlockBlockInner = '<button type="button" class="btn btn-primary btn-action" data-action-index="' + index + '">破解打开密码</button>';
      } else {
        unlockBlockInner = '<button type="button" class="btn btn-primary btn-unlock" data-unlock-index="' + index + '">解除权限限制</button>';
      }
    }
    var unlockLabel = hasProtectionResult ? '结果' : (item.encrypted === true ? '解密' : '解除限制');
    var unlockBlock =
      '<div class="file-row-block file-row-block-protection">' +
        '<span class="file-row-block-label">' + unlockLabel + '</span>' +
        (canShowUnlock ? '<div class="file-row-block-inner">' + unlockBlockInner + '</div>' : '') +
      '</div>';

    var compressBlock =
      '<div class="file-row-block file-row-block-compress">' +
        '<span class="file-row-block-label">优化</span>' +
        (canShowActions
          ? '<div class="file-row-block-inner">' +
              (!hasCompressResult
                ? '<button type="button" class="btn btn-primary btn-action-compress" data-compress-index="' + index + '">确认上传</button>'
                : '') +
              (hasCompressResult
                ? '<button type="button" class="btn btn-download btn-download-compress" data-download-index="' + index + '" data-download-type="compress">下载</button>'
                : '') +
            '</div>'
          : '') +
      '</div>';

    var blocksHtml = tab === 'encrypt' ? encryptBlock : (tab === 'unlock' ? unlockBlock : compressBlock);
    row.innerHTML =
      '<div class="file-row-head">' +
        '<span class="file-row-name" title="' + (item.name || '') + '">' + (item.name || '') + '</span>' +
        '<span class="file-row-head-right">' +
          '<span class="file-row-status status-' + (item.encrypted === null || (item.encrypted === false && item.hasRestrictions === null) ? 'detecting' : item.encrypted ? 'encrypted' : item.hasRestrictions ? 'restricted' : 'plain') + '">' + statusText + '</span>' +
          '<button type="button" class="btn btn-remove btn-remove-file" data-remove-index="' + index + '" title="从列表移除">删除</button>' +
        '</span>' +
      '</div>' +
      '<div class="file-row-blocks">' + blocksHtml + '</div>';

    return row;
  }

  function removeItemAtIndex(i) {
    var items = getCurrentItems();
    if (i < 0 || i >= items.length) return;
    items.splice(i, 1);
    if (pendingEncryptIndex === i) {
      pendingEncryptIndex = null;
      closeEncryptModal();
    } else if (pendingEncryptIndex > i) {
      pendingEncryptIndex--;
    }
    if (pendingCompressIndex === i) {
      pendingCompressIndex = null;
      closeCompressModal();
    } else if (pendingCompressIndex > i) {
      pendingCompressIndex--;
    }
    renderFileList();
    showGlobalHint('');
    var textEl = document.getElementById('pdfInputText');
    var n = getCurrentItems().length;
    if (textEl) textEl.textContent = n > 0 ? '已选 ' + n + ' 个文件，可继续添加' : getFileInputPlaceholder();
  }

  function renderFileList() {
    if (!fileListEl) return;
    fileListEl.innerHTML = '';
    getCurrentItems().forEach(function (item, index) {
      fileListEl.appendChild(renderRow(item, index));
    });

    fileListEl.querySelectorAll('.btn-action').forEach(function (btn) {
      btn.addEventListener('click', onActionClick);
    });
    fileListEl.querySelectorAll('.btn-action-compress').forEach(function (btn) {
      btn.addEventListener('click', onCompressClick);
    });
    fileListEl.querySelectorAll('.btn-download-protection, .btn-download-compress').forEach(function (btn) {
      btn.addEventListener('click', onDownloadClick);
    });
    fileListEl.querySelectorAll('.btn-remove-file').forEach(function (btn) {
      btn.addEventListener('click', function () {
        var i = parseInt(btn.getAttribute('data-remove-index'), 10);
        if (!isNaN(i)) removeItemAtIndex(i);
      });
    });
  }

  var pendingEncryptIndex = null;

  function openEncryptModal(index) {
    pendingEncryptIndex = index;
    var modal = document.getElementById('encryptModal');
    var requirePwdCb = document.getElementById('encRequirePassword');
    var pwdWrap = document.getElementById('encryptPasswordWrap');
    var pwdEl = document.getElementById('encryptPassword');
    var hintEl = document.getElementById('encryptModalHint');
    if (modal) { modal.setAttribute('aria-hidden', 'false'); modal.classList.add('is-visible'); }
    if (requirePwdCb) { requirePwdCb.checked = false; }
    if (pwdWrap) { pwdWrap.style.display = 'block'; }
    if (pwdEl) { pwdEl.value = ''; }
    if (hintEl) { hintEl.textContent = ''; hintEl.setAttribute('aria-hidden', 'true'); }
  }

  function toggleEncryptPasswordWrap() {
    /* 设置密码区域在打开加密弹窗时即显示，不再随「打开需要密码」勾选而显隐 */
  }

  function closeEncryptModal() {
    pendingEncryptIndex = null;
    var modal = document.getElementById('encryptModal');
    if (modal) {
      if (document.activeElement && modal.contains(document.activeElement)) {
        document.activeElement.blur();
      }
      modal.setAttribute('aria-hidden', 'true');
      modal.classList.remove('is-visible');
    }
  }

  function getEncryptPermissionsFromModal() {
    var requirePwd = document.getElementById('encRequirePassword') ? document.getElementById('encRequirePassword').checked : false;
    var pwdEl = document.getElementById('encryptPassword');
    var pwd = pwdEl ? pwdEl.value.trim() : '';
    return {
      requirePassword: requirePwd,
      userPassword: requirePwd ? pwd : '',
      /** 未勾选「打开需要密码」时，此密码作为「权限密码」，用于在阅读器中修改安全设置 */
      ownerPassword: !requirePwd ? pwd : '',
      modifying: document.getElementById('encPermModify') ? document.getElementById('encPermModify').checked : true,
      copying: document.getElementById('encPermCopy') ? document.getElementById('encPermCopy').checked : true,
      printing: document.getElementById('encPermPrint') ? document.getElementById('encPermPrint').checked : false,
      annotating: document.getElementById('encPermAnnotate') ? document.getElementById('encPermAnnotate').checked : true,
      fillingForms: document.getElementById('encPermFillingForms') ? document.getElementById('encPermFillingForms').checked : false,
      contentAccessibility: document.getElementById('encPermContentAccess') ? document.getElementById('encPermContentAccess').checked : false,
      documentAssembly: document.getElementById('encPermAssembly') ? document.getElementById('encPermAssembly').checked : true
    };
  }

  var pendingDecryptIndex = null;

  function openDecryptModal(index) {
    pendingDecryptIndex = index;
    var modal = document.getElementById('decryptModal');
    var hintEl = document.getElementById('decryptModalHint');
    if (modal) { modal.setAttribute('aria-hidden', 'false'); modal.classList.add('is-visible'); }
    if (hintEl) { hintEl.textContent = ''; hintEl.setAttribute('aria-hidden', 'true'); }
  }

  function closeDecryptModal() {
    pendingDecryptIndex = null;
    var modal = document.getElementById('decryptModal');
    if (modal) {
      if (document.activeElement && modal.contains(document.activeElement)) {
        document.activeElement.blur();
      }
      modal.setAttribute('aria-hidden', 'true');
      modal.classList.remove('is-visible');
    }
  }

  /** 只显示进度条与百分比，不显示文字 */
  function showDecryptProgress(show, percent) {
    var overlay = document.getElementById('decryptProgressOverlay');
    var bar = document.getElementById('decryptProgressBar');
    var percentEl = document.getElementById('decryptProgressPercent');
    var textEl = document.getElementById('decryptProgressText');
    if (overlay) {
      overlay.setAttribute('aria-hidden', show ? 'false' : 'true');
      overlay.classList.toggle('is-visible', !!show);
    }
    if (bar) bar.style.width = (percent == null ? 0 : percent) + '%';
    if (percentEl) percentEl.textContent = (percent == null ? 0 : Math.round(percent)) + '%';
    if (textEl && !show) {
      textEl.textContent = '暴力破解中...';
    }
  }

  function onActionClick(e) {
    const index = parseInt(e.target.getAttribute('data-action-index'), 10);
    const item = getCurrentItems()[index];
    if (!item || (item.resultProtection && item.resultProtection.blob)) return;
    if (item.encrypted) {
      if (!canUseUnlock()) {
        showGlobalHint('解锁次数不足。', true);
        return;
      }
      openDecryptModal(index);
    } else {
      if (!canUseEncrypt()) {
        showGlobalHint('加密次数不足。', true);
        return;
      }
      openEncryptModal(index);
    }
  }

  /**
   * 解除权限限制：统一请求后端 /api/unlock（需登录或匿名，后端扣配额），不再在前端本地解锁。
   */
  async function onUnlockClick(e) {
    var btn = e.target && e.target.closest ? e.target.closest('[data-unlock-index]') : e.target;
    var index = parseInt(btn ? btn.getAttribute('data-unlock-index') : (e.target && e.target.getAttribute('data-unlock-index')), 10);
    if (isNaN(index)) return;
    var item = getCurrentItems()[index];
    if (!item || !item.file || (item.resultProtection && item.resultProtection.blob)) return;
    if (item.encrypted === true) return;
    if (!canUseUnlock()) {
      showGlobalHint('解锁次数不足。', true);
      return;
    }
    showGlobalHint('正在处理…');
    showDecryptProgress(true, 0);
    try {
      var form = new FormData();
      form.append('file', item.file);
      var res = await fetchWithAuth(API_BASE + '/api/unlock', { method: 'POST', body: form });
      if (res.ok) {
        var blob = await res.blob();
        var name = (res.headers.get('Content-Disposition') || '').match(/filename="?([^";]+)"?/);
        var outName = (name && name[1]) ? decodeURIComponent(name[1]) : (nameWithoutExt(item.name) + '_unlocked.pdf');
        showDecryptProgress(false);
        item.resultProtection = { blob: blob, name: outName };
        await loadQuota();
        renderFileList();
        showGlobalHint('已解除权限限制，请点击「下载」保存。');
        return;
      }
      var errJson = await res.json().catch(function () { return {}; });
      var errMsg = errJson.error || res.statusText;
      showDecryptProgress(false);
      if (res.status === 403) {
        await loadQuota();
        showGlobalHint(errMsg || '解锁次数不足。', true);
        return;
      }
      showGlobalHint(errMsg || '解除失败。', true);
    } catch (err) {
      showDecryptProgress(false);
      console.error(err);
      showGlobalHint('解除失败：' + (err && err.message ? err.message : '网络或服务器错误'), true);
    }
  }

  // 保存当前破解任务的 reader，用于取消操作
  var currentCrackReader = null;
  var currentCrackCancelled = false;

  /**
   * 取消暴力破解
   */
  function cancelCrack() {
    if (currentCrackReader) {
      currentCrackCancelled = true;
      currentCrackReader.cancel().catch(function(err) {
        console.log('取消读取流:', err);
      });
      currentCrackReader = null;
    }
    showDecryptProgress(false);
    showGlobalHint('已取消暴力破解（失败不扣次数）', false);
  }

  /**
   * 解密：进入此弹窗时已是「需打开密码」，统一走后端 /api/crack-and-unlock（需登录或匿名，失败不扣次数），使用 SSE 推送进度。
   */
  async function onDecryptModalCrack() {
    var index = pendingDecryptIndex;
    if (index == null) return;
    var item = getCurrentItems()[index];
    if (!item || !item.file || !item.encrypted) { closeDecryptModal(); return; }
    if (!canUseUnlock()) {
      closeDecryptModal();
      showGlobalHint('解锁次数不足。', true);
      return;
    }
    closeDecryptModal();
    showGlobalHint('');
    showDecryptProgress(true, 0);
    currentCrackCancelled = false;
    currentCrackReader = null;
    
    // 更新进度文本
    var progressTextEl = document.getElementById('decryptProgressText');
    if (progressTextEl) progressTextEl.textContent = '暴力破解中...';
    
    try {
      var formCrack = new FormData();
      formCrack.append('file', item.file);
      
      // 使用 fetch + ReadableStream 接收 SSE 流（EventSource 不支持 POST）
      var response = await fetchWithAuth(API_BASE + '/api/crack-and-unlock', {
        method: 'POST',
        body: formCrack
      });
      
      if (!response.ok) {
        var errJson = await response.json().catch(function () { return {}; });
        showDecryptProgress(false);
        if (response.status === 403) {
          await loadQuota();
          showGlobalHint(errJson.error || '解锁次数不足。', true);
          return;
        }
        showGlobalHint(errJson.error || '请求失败。', true);
        return;
      }
      
      // 读取 SSE 流
      var reader = response.body.getReader();
      currentCrackReader = reader;
      var decoder = new TextDecoder();
      var buffer = '';
      var success = false;
      
      while (true) {
        // 检查是否已取消
        if (currentCrackCancelled) {
          reader.cancel().catch(function() {});
          break;
        }
        
        var { done, value } = await reader.read();
        if (done) break;
        
        buffer += decoder.decode(value, { stream: true });
        var lines = buffer.split('\n');
        buffer = lines.pop() || ''; // 保留最后不完整的行
        
        for (var line of lines) {
          // 再次检查是否已取消
          if (currentCrackCancelled) {
            break;
          }
          
          if (line.startsWith('data: ')) {
            try {
              var data = JSON.parse(line.substring(6));
              
              if (data.type === 'start') {
                if (progressTextEl) progressTextEl.textContent = '开始暴力破解...';
                showDecryptProgress(true, 0);
              } else if (data.type === 'progress') {
                var progress = data.progress || 0;
                var current = data.current || 0;
                var total = data.total || 0;
                var password = data.password;
                
                var text = '暴力破解中... (' + current + '/' + total + ')';
                if (password && current <= 5) {
                  text += ' 尝试密码: ' + password;
                }
                if (progressTextEl) progressTextEl.textContent = text;
                showDecryptProgress(true, progress);
              } else if (data.type === 'success') {
                success = true;
                var password = data.password || '';
                var attempts = data.attempts || 0;
                var pdfB64 = data.pdf;
                var filename = data.filename || (nameWithoutExt(item.name) + '_unlocked.pdf');
                
                if (progressTextEl) progressTextEl.textContent = '破解成功！密码: ' + password + ' (尝试 ' + attempts + ' 次)';
                showDecryptProgress(true, 100);
                
                // 将 base64 转换为 blob
                var binaryString = atob(pdfB64);
                var bytes = new Uint8Array(binaryString.length);
                for (var i = 0; i < binaryString.length; i++) {
                  bytes[i] = binaryString.charCodeAt(i);
                }
                var blobCrack = new Blob([bytes], { type: 'application/pdf' });
                
                showDecryptProgress(false);
                currentCrackReader = null;
                item.resultProtection = { blob: blobCrack, name: filename };
                await loadQuota();
                renderFileList();
                showGlobalHint('已破解并解密，密码为 "' + password + '"，请点击「下载」保存。');
                return;
              } else if (data.type === 'error') {
                showDecryptProgress(false);
                currentCrackReader = null;
                var errMsg = data.message || '未能破解密码';
                showGlobalHint(errMsg + '（失败不扣次数）', true);
                await loadQuota(); // 刷新配额显示
                return;
              } else if (data.type === 'info') {
                if (progressTextEl) progressTextEl.textContent = data.message || '处理中...';
              }
            } catch (e) {
              console.error('解析 SSE 数据失败:', e, line);
            }
          }
        }
      }
      
      // 清理 reader 引用
      currentCrackReader = null;
      
      if (currentCrackCancelled) {
        // 已取消，不显示错误消息
        return;
      }
      
      if (!success) {
        showDecryptProgress(false);
        showGlobalHint('未能破解密码（失败不扣次数）', true);
        await loadQuota();
      }
    } catch (err) {
      currentCrackReader = null;
      showDecryptProgress(false);
      if (!currentCrackCancelled) {
        console.error(err);
        showGlobalHint('暴力破解失败：' + (err && err.message ? err.message : '网络或服务器错误') + '（失败不扣次数）', true);
        await loadQuota();
      }
    }
  }

  function onEncryptModalConfirm() {
    var index = pendingEncryptIndex;
    if (index == null) return;
    var item = getCurrentItems()[index];
    if (!item || item.encrypted) { closeEncryptModal(); return; }

    var perms = getEncryptPermissionsFromModal();
    var hintEl = document.getElementById('encryptModalHint');
    if (perms.requirePassword && !perms.userPassword) {
      if (hintEl) { hintEl.textContent = '已勾选「打开需要密码」，请填写打开密码'; hintEl.setAttribute('aria-hidden', 'false'); }
      return;
    }
    closeEncryptModal();
    showGlobalHint('');
    runEncrypt(index, perms.userPassword, perms);
  }

  var pendingCompressIndex = null;

  function openCompressModal(index) {
    pendingCompressIndex = index;
    var modal = document.getElementById('compressModal');
    if (modal) {
      modal.setAttribute('aria-hidden', 'false');
      modal.classList.add('is-visible');
    }
    syncCompressRasterQualityDisplay();
  }

  function closeCompressModal() {
    pendingCompressIndex = null;
    var modal = document.getElementById('compressModal');
    if (modal) {
      if (document.activeElement && modal.contains(document.activeElement)) {
        document.activeElement.blur();
      }
      modal.setAttribute('aria-hidden', 'true');
      modal.classList.remove('is-visible');
    }
  }

  function onCompressClick(e) {
    const index = parseInt(e.target.getAttribute('data-compress-index'), 10);
    const item = getCurrentItems()[index];
    if (!item || (item.resultCompress && item.resultCompress.blob)) return;
    if (!canUseCompress()) {
      showGlobalHint('体积优化次数不足。', true);
      return;
    }
    if (item.encrypted) {
      showGlobalHint('体积优化为独立功能，仅支持未加密的 PDF。该文件已加密，请先解锁后再使用体积优化。', true);
      return;
    }

    openCompressModal(index);
  }

  function onCompressModalConfirm() {
    var index = pendingCompressIndex;
    if (index == null) return;
    closeCompressModal();
    showGlobalHint('');
    runCompress(index, null);
  }

  function onDownloadClick(e) {
    const index = parseInt(e.target.getAttribute('data-download-index'), 10);
    const type = e.target.getAttribute('data-download-type');
    const item = getCurrentItems()[index];
    if (!item || (type !== 'protection' && type !== 'compress')) return;
    const result = type === 'protection' ? item.resultProtection : item.resultCompress;
    if (!result || !result.blob) return;
    
    // 检测是否为移动设备（特别是iOS）
    const isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
    const isIOS = /iPhone|iPad|iPod/i.test(navigator.userAgent);
    const filename = result.name || 'output.pdf';
    
    if (isMobile) {
      // 移动端：使用更可靠的方式下载
      // iOS Safari 不支持 download 属性，需要特殊处理
      if (isIOS) {
        // iOS: 创建一个临时的 blob URL，然后通过新窗口打开
        // 注意：iOS Safari 会直接打开PDF而不是下载，所以需要提示用户
        const url = URL.createObjectURL(result.blob);
        
        // 尝试使用 a 标签打开，但设置 target="_blank" 让用户可以选择保存
        const a = document.createElement('a');
        a.href = url;
        a.target = '_blank';
        a.rel = 'noopener noreferrer';
        // 即使iOS不支持download，也设置它，某些情况下可能有用
        a.download = filename;
        // 设置样式使其不可见
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        
        // 延迟提示，让浏览器有时间处理
        setTimeout(function () {
          var passwordHint = '';
          if (type === 'protection' && item.resultProtection) {
            // 尝试从加密弹窗获取密码（如果还在内存中）
            var pwdEl = document.getElementById('encryptPassword');
            var requirePwdEl = document.getElementById('encRequirePassword');
            if (pwdEl && requirePwdEl && requirePwdEl.checked && pwdEl.value) {
              passwordHint = ' 密码：' + pwdEl.value;
            }
          }
          showGlobalHint('PDF已在新窗口打开。请点击右上角「分享」按钮，选择「存储到文件」或「保存到文件」来保存PDF。' + (type === 'protection' ? '（加密文件需要密码才能打开' + passwordHint + '）' : ''));
          URL.revokeObjectURL(url);
        }, 300);
      } else {
        // Android: 尝试使用 download 属性
        const url = URL.createObjectURL(result.blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = filename;
        a.style.display = 'none';
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () {
          URL.revokeObjectURL(url);
        }, 2000);
      }
    } else {
      // 桌面端：使用标准的 download 属性
      const url = URL.createObjectURL(result.blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
    }
  }

  function showEncryptProgress(show, percent, text) {
    var overlay = document.getElementById('encryptProgressOverlay');
    var bar = document.getElementById('encryptProgressBar');
    var percentEl = document.getElementById('encryptProgressPercent');
    var textEl = document.getElementById('encryptProgressText');
    if (overlay) {
      overlay.setAttribute('aria-hidden', show ? 'false' : 'true');
      overlay.classList.toggle('is-visible', !!show);
    }
    if (bar) bar.style.width = (percent == null ? 0 : percent) + '%';
    if (percentEl) percentEl.textContent = (percent == null ? 0 : Math.round(percent)) + '%';
    if (textEl && text !== undefined) textEl.textContent = text || '加密中…';
  }

  /** 规范打开密码：去除首尾空格。PDF 标准建议仅使用 ASCII/Latin-1 字符以保证各阅读器兼容。 */
  function toPdfLatin1Password(str) {
    return (typeof str === 'string' ? str : '').trim();
  }

  async function runEncrypt(index, pwd, permsFromModal) {
    const item = getCurrentItems()[index];
    if (!item || !item.file) return;

    showEncryptProgress(true, 0, '加密中…');
    var progressInterval = setInterval(function () {
      var bar = document.getElementById('encryptProgressBar');
      var percentEl = document.getElementById('encryptProgressPercent');
      var w = parseFloat(bar ? bar.style.width : '0') || 0;
      if (w < 75) {
        w = Math.min(75, w + 8);
        if (bar) bar.style.width = w + '%';
        if (percentEl) percentEl.textContent = Math.round(w) + '%';
      }
      clearProgressIntervalIfDone();
    }, 200);
    function clearProgressIntervalIfDone() {
      var bar = document.getElementById('encryptProgressBar');
      var w = parseFloat(bar ? bar.style.width : '0') || 0;
      if (w >= 100 && progressInterval) { clearInterval(progressInterval); progressInterval = null; }
    }

    try {
      var p = permsFromModal || {};
      var userPwd = toPdfLatin1Password(typeof p.userPassword === 'string' ? p.userPassword : (typeof pwd === 'string' ? pwd : ''));
      var ownerPwd = toPdfLatin1Password(typeof p.ownerPassword === 'string' ? p.ownerPassword : '');
      var form = new FormData();
      form.append('file', item.file);
      form.append('user_password', userPwd);
      form.append('owner_password', ownerPwd);
      form.append('permissions', JSON.stringify({
        modifying: p.modifying,
        copying: p.copying,
        annotating: p.annotating,
        documentAssembly: p.documentAssembly,
        fillingForms: p.fillingForms,
        contentAccessibility: p.contentAccessibility,
        printing: p.printing
      }));

      var res = await fetchWithAuth(API_BASE + '/api/encrypt', { method: 'POST', body: form });

      if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
      showEncryptProgress(true, 100, res.ok ? '加密完成' : '加密失败');

      if (!res.ok) {
        var errBody = await res.json().catch(function () { return {}; });
        var errMsg = (errBody && errBody.error) ? errBody.error : (res.status === 403 ? '加密次数不足或请先登录。' : '加密失败');
        showEncryptProgress(false);
        showGlobalHint(errMsg, true);
        return;
      }

      var blob = await res.blob();
      var disp = res.headers.get('Content-Disposition') || '';
      var nameMatch = disp.match(/filename\*?=(?:UTF-8'')?"?([^";\n]+)"?/i) || disp.match(/filename="?([^";]+)"?/);
      var outName = (nameMatch && nameMatch[1]) ? decodeURIComponent(nameMatch[1].trim()) : (nameWithoutExt(item.name) + '_encrypted.pdf');
      item.resultProtection = { blob: blob, name: outName };
      await loadQuota();
      renderFileList();

      setTimeout(function () {
        showEncryptProgress(false);
        var passwordHint = userPwd ? '（密码：' + userPwd + '）' : '';
        var isMobile = /iPhone|iPad|iPod|Android/i.test(navigator.userAgent);
        var downloadHint = isMobile 
          ? '加密完成！请点击「下载」按钮保存文件。' + (userPwd ? '保存后打开PDF时需要输入密码：' + userPwd : '')
          : '加密完成，请点击「下载」保存。用您设置的密码即可在各类 PDF 阅读器中打开。' + passwordHint;
        showGlobalHint(downloadHint);
      }, 500);
    } catch (e) {
      console.error(e);
      if (progressInterval) clearInterval(progressInterval);
      showEncryptProgress(false);
      showGlobalHint('加密失败：' + (e && e.message ? e.message : '未知错误'), true);
    }
  }

  /**
   * 解密并写入 resultProtection。内部使用 PDFDeSecure 式：复制页到新文档再保存，去除加密/权限。
   * @param {number} index - 文件索引
   * @param {string} [pwd] - 打开密码（可选；无密码时尝试直接打开）
   */
  async function runDecrypt(index, pwd) {
    const item = getCurrentItems()[index];
    if (!item || !item.file) return;

    showGlobalHint('');
    showLoading(true, '解密中…');

    try {
      var form = new FormData();
      form.append('file', item.file);
      form.append('password', (typeof pwd === 'string' ? pwd : '') || '');
      var res = await fetchWithAuth(API_BASE + '/api/unlock', { method: 'POST', body: form });

      if (res.ok) {
        var blob = await res.blob();
        var disp = res.headers.get('Content-Disposition') || '';
        var nameMatch = disp.match(/filename\*?=(?:UTF-8'')?"?([^";\n]+)"?/i) || disp.match(/filename="?([^";]+)"?/);
        var outName = (nameMatch && nameMatch[1]) ? decodeURIComponent(nameMatch[1].trim()) : (nameWithoutExt(item.name) + '_unlocked.pdf');
        item.resultProtection = { blob: blob, name: outName };
        await loadQuota();
        renderFileList();
        showLoading(false);
        showGlobalHint('解密成功，请点击「下载」保存。');
        return;
      }
      var errBody = await res.json().catch(function () { return {}; });
      var errMsg = (errBody && errBody.error) ? errBody.error : (res.status === 403 ? '解锁次数不足或请先登录。' : '解密失败，请检查密码是否正确。');
      showLoading(false);
      showGlobalHint(errMsg, true);
    } catch (e) {
      console.error(e);
      showLoading(false);
      showGlobalHint('解密失败：' + (e && e.message ? e.message : '网络或服务器错误'), true);
    }
  }

  function setPdfHeaderVersion(bytes, version) {
    var header = '%PDF-' + version + '\n';
    var enc = new TextEncoder();
    var headerBytes = enc.encode(header);
    for (var i = 0; i < headerBytes.length && i < bytes.length; i++) bytes[i] = headerBytes[i];
    return bytes;
  }

  async function runCompress(index, pwd) {
    const item = getCurrentItems()[index];
    if (!item || !item.file) return;

    showGlobalHint('');
    var mode = getCompressMode();
    var version = getCompressCompatibility();
    var useObjectStreams = version !== '1.4';

    if (mode !== 'raster') {
      try {
        showLoading(true, '正在体积优化…');
        var form = new FormData();
        form.append('file', item.file);
        var res = await fetchWithAuth(API_BASE + '/api/compress', { method: 'POST', body: form });
        showLoading(false);
        if (!res.ok) {
          var errBody = await res.json().catch(function () { return {}; });
          showGlobalHint((errBody && errBody.error) ? errBody.error : (res.status === 403 ? '体积优化次数不足或请先登录。' : '体积优化失败'), true);
          return;
        }
        var blob = await res.blob();
        // 从响应头读取压缩信息（如果后端提供了）
        var origBytes = parseInt(res.headers.get('X-Original-Size')) || item.file.size;
        var newBytes = parseInt(res.headers.get('X-Compressed-Size')) || blob.size;
        var compressionRatio = parseFloat(res.headers.get('X-Compression-Ratio')) || (newBytes / origBytes);
        var compressionMethod = res.headers.get('X-Compression-Method') || 'unknown';
        var smaller = newBytes < origBytes;
        var reductionPct = origBytes > 0 ? (100 - (newBytes / origBytes) * 100) : 0;
        var disp = res.headers.get('Content-Disposition') || '';
        var nameMatch = disp.match(/filename\*?=(?:UTF-8'')?"?([^";\n]+)"?/i) || disp.match(/filename="?([^";]+)"?/);
        var outName = (nameMatch && nameMatch[1]) ? decodeURIComponent(nameMatch[1].trim()) : (nameWithoutExt(item.name) + '_compressed.pdf');
        item.resultCompress = smaller ? { blob: blob, name: outName } : { blob: item.file, name: item.name };
        await loadQuota();
        renderFileList();
        var origKb = (origBytes / 1024).toFixed(1);
        var newKb = (newBytes / 1024).toFixed(1);
        var savedPct = reductionPct.toFixed(1);
        
        // 根据压缩效果给出不同的提示
        var hint = '';
        if (!smaller || reductionPct < 1) {
          // 压缩效果很差（减少<1%）或没有压缩
          hint = '文件体积优化完成，但效果有限。原大小约 <strong>' + origKb + ' KB</strong>，当前约 <strong>' + newKb + ' KB</strong>，较原文件减少约 <strong>' + savedPct + '%</strong>。';
          if (reductionPct < 0.5) {
            hint += '该PDF可能已经过优化，或包含大量文本/矢量图形，压缩空间有限。';
          }
        } else if (reductionPct < 5) {
          // 压缩效果一般（减少1-5%）
          hint = '体积已优化，请点击「下载」保存。原大小约 <strong>' + origKb + ' KB</strong>，当前约 <strong>' + newKb + ' KB</strong>，较原文件减少约 <strong>' + savedPct + '%</strong>。';
        } else {
          // 压缩效果良好（减少>5%）
          hint = '体积已优化，请点击「下载」保存。原大小约 <strong>' + origKb + ' KB</strong>，当前约 <strong>' + newKb + ' KB</strong>，较原文件减少约 <strong>' + savedPct + '%</strong>。';
        }
        showGlobalHint(hint);
      } catch (e) {
        console.error(e);
        showLoading(false);
        showGlobalHint('体积优化失败：' + (e && e.message ? e.message : '未知错误'), true);
      }
      return;
    }

    try {
      const bytes = new Uint8Array(await item.file.arrayBuffer());
      showLoading(true, '正在准备图片重采样…');
      var saved = await compressWithRaster(bytes, function (current, total, text) {
        showLoading(true, text);
      });
      var origBytes = item.file.size;
      var newBytes = saved.length;
      var smaller = newBytes < origBytes;
      if (smaller) {
        item.resultCompress = { blob: new Blob([saved], { type: 'application/pdf' }), name: nameWithoutExt(item.name) + '_compressed.pdf' };
      } else {
        item.resultCompress = { blob: item.file, name: item.name };
      }
      var consumed = await consumeQuotaApi('compress');
      if (!consumed) {
        showLoading(false);
        showGlobalHint('体积优化次数不足或请先登录。', true);
        return;
      }
      renderFileList();
      showLoading(false);
      var origKb = (origBytes / 1024).toFixed(1);
      var newKb = (newBytes / 1024).toFixed(1);
      var savedPct = origBytes > 0 ? (100 - (newBytes / origBytes) * 100).toFixed(1) : '0';
      var hint = smaller
        ? '体积已优化，请点击「下载」保存。原大小约 <strong>' + origKb + ' KB</strong>，当前约 <strong>' + newKb + ' KB</strong>，较原文件减少约 <strong>' + savedPct + '%</strong>。'
        : '文件体积已达最优。原大小约 <strong>' + origKb + ' KB</strong>，无需优化。';
      showGlobalHint(hint);
    } catch (e) {
      console.error(e);
      showLoading(false);
      showGlobalHint('体积优化失败：' + (e && e.message ? e.message : '未知错误') + (item.encrypted ? '，请检查密码。' : ''), true);
    }
  }

  function onFileSelect(files) {
    if (!files || !files.length) return;

    var newItems = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      if (!file || !file.name || !file.name.toLowerCase().endsWith('.pdf')) continue;

      const item = {
        file: file,
        name: file.name,
        encrypted: null,
        hasRestrictions: null,
        resultProtection: null,
        resultCompress: null
      };
      newItems.push(item);
    }
    var tabKey = state.currentTab;
    state.itemsByTab[tabKey] = newItems.concat(getCurrentItems());

    if (newItems.length === 0) {
      showGlobalHint('未选择有效的 PDF 文件，请选择 .pdf 文件。', true);
    } else {
      showGlobalHint('');
    }

    renderFileList();

    state.itemsByTab[tabKey].forEach(function (item, index) {
      if (item.encrypted !== null) return;
      (function (idx) {
        apiDetect(item.file).then(function (api) {
          if (api) {
            state.itemsByTab[tabKey][idx].encrypted = api.encrypted;
            state.itemsByTab[tabKey][idx].hasRestrictions = api.hasRestrictions;
            renderFileList();
          } else {
            detectEncryption(item.file).then(function (encrypted) {
              state.itemsByTab[tabKey][idx].encrypted = encrypted;
              if (encrypted) {
                renderFileList();
              } else {
                detectHasRestrictions(state.itemsByTab[tabKey][idx].file).then(function (hasRestrictions) {
                  state.itemsByTab[tabKey][idx].hasRestrictions = hasRestrictions;
                  renderFileList();
                });
              }
            }).catch(function (err) {
              console.error('[PDF检测]', item.name, err);
              renderFileList();
            });
            renderFileList();
          }
        }).catch(function (err) {
          console.error('[PDF检测]', item.name, err);
          detectEncryption(item.file).then(function (encrypted) {
            state.itemsByTab[tabKey][idx].encrypted = encrypted;
            if (encrypted) { renderFileList(); } else {
              detectHasRestrictions(state.itemsByTab[tabKey][idx].file).then(function (hasRestrictions) {
                state.itemsByTab[tabKey][idx].hasRestrictions = hasRestrictions;
                renderFileList();
              });
            }
          }).catch(function () { renderFileList(); });
          renderFileList();
        });
        renderFileList();
      })(index);
    });

    if (pdfInput) pdfInput.value = '';
    var textEl = document.getElementById('pdfInputText');
    if (textEl) textEl.textContent = '已选 ' + getCurrentItems().length + ' 个文件，可继续添加';
  }

  if (pdfInput) {
    pdfInput.addEventListener('change', function () {
      onFileSelect(this.files);
    });
  }

  var uploadCard = document.getElementById('uploadCard');
  function setupDrop(target) {
    if (!target) return;
    target.addEventListener('dragover', function (e) {
      e.preventDefault();
      e.stopPropagation();
      target.classList.add('is-dragover');
    });
    target.addEventListener('dragleave', function (e) {
      e.preventDefault();
      e.stopPropagation();
      target.classList.remove('is-dragover');
    });
    target.addEventListener('drop', function (e) {
      e.preventDefault();
      e.stopPropagation();
      target.classList.remove('is-dragover');
      onFileSelect(e.dataTransfer && e.dataTransfer.files);
    });
  }
  setupDrop(uploadCard);
  setupDrop(fileListEl);

  if (fileListEl) {
    fileListEl.addEventListener('click', function (e) {
      var btn = e.target && e.target.closest ? e.target.closest('button[data-unlock-index]') : null;
      if (!btn) return;
      e.preventDefault();
      e.stopPropagation();
      onUnlockClick({ target: btn });
    });
  }

  var tabEncrypt = document.getElementById('tabEncrypt');
  var tabUnlock = document.getElementById('tabUnlock');
  var tabCompress = document.getElementById('tabCompress');
  if (tabEncrypt) tabEncrypt.addEventListener('click', function () { setActiveTab('encrypt'); });
  if (tabUnlock) tabUnlock.addEventListener('click', function () { setActiveTab('unlock'); });
  if (tabCompress) tabCompress.addEventListener('click', function () { setActiveTab('compress'); });
  updateCardByTab();
  syncCompressRasterQualityDisplay();
  var compressRasterQualityEl = document.getElementById('compressRasterQuality');
  if (compressRasterQualityEl) compressRasterQualityEl.addEventListener('input', syncCompressRasterQualityDisplay);

  var encryptModalEl = document.getElementById('encryptModal');
  var encryptModalCancel = document.getElementById('encryptModalCancel');
  var encryptModalConfirm = document.getElementById('encryptModalConfirm');
  var encryptPasswordEl = document.getElementById('encryptPassword');
  var encRequirePasswordEl = document.getElementById('encRequirePassword');
  if (encryptModalCancel) encryptModalCancel.addEventListener('click', closeEncryptModal);
  if (encryptModalConfirm) encryptModalConfirm.addEventListener('click', onEncryptModalConfirm);
  if (encRequirePasswordEl) encRequirePasswordEl.addEventListener('change', toggleEncryptPasswordWrap);
  if (encryptModalEl) {
    encryptModalEl.addEventListener('click', function (e) {
      if (e.target === encryptModalEl) closeEncryptModal();
    });
  }
  if (encryptPasswordEl) {
    encryptPasswordEl.addEventListener('keydown', function (e) {
      if (e.key === 'Enter') onEncryptModalConfirm();
    });
  }

  var decryptModalEl = document.getElementById('decryptModal');
  var decryptModalCancel = document.getElementById('decryptModalCancel');
  var decryptModalCrack = document.getElementById('decryptModalCrack');
  var decryptProgressCancel = document.getElementById('decryptProgressCancel');
  if (decryptModalCancel) decryptModalCancel.addEventListener('click', closeDecryptModal);
  if (decryptModalCrack) decryptModalCrack.addEventListener('click', onDecryptModalCrack);
  if (decryptProgressCancel) decryptProgressCancel.addEventListener('click', cancelCrack);
  if (decryptModalEl) {
    decryptModalEl.addEventListener('click', function (e) {
      if (e.target === decryptModalEl) closeDecryptModal();
    });
  }

  var compressModalEl = document.getElementById('compressModal');
  var compressModalCancel = document.getElementById('compressModalCancel');
  var compressModalConfirm = document.getElementById('compressModalConfirm');
  if (compressModalCancel) compressModalCancel.addEventListener('click', closeCompressModal);
  if (compressModalConfirm) compressModalConfirm.addEventListener('click', onCompressModalConfirm);
  if (compressModalEl) {
    compressModalEl.addEventListener('click', function (e) {
      if (e.target === compressModalEl) closeCompressModal();
    });
  }

  updateUsageUI();
  updateAuthUI();

  function openProfileModal() {
    closeUserDropdown();
    var modal = document.getElementById('profileModal');
    if (modal) { modal.setAttribute('aria-hidden', 'false'); modal.classList.add('is-visible'); loadProfileForModal(); }
  }
  function closeProfileModal() {
    var modal = document.getElementById('profileModal');
    if (modal) { modal.setAttribute('aria-hidden', 'true'); modal.classList.remove('is-visible'); }
    var hint = document.getElementById('profileModalHint');
    if (hint) { hint.textContent = ''; hint.setAttribute('aria-hidden', 'true'); }
  }
  async function loadProfileForModal() {
    var set = function (id, v) { var el = document.getElementById(id); if (el) el.value = v != null ? v : ''; };
    var setText = function (id, v) { var el = document.getElementById(id); if (el) el.textContent = v != null ? v : '—'; };
    var json = null;
    var res = await fetchWithAuth(API_BASE + '/api/user/profile');
    if (res.ok) {
      json = await res.json();
    } else {
      if (res.status === 404 && currentUser) {
        json = {
          username: currentUser.username,
          email: currentUser.email || '',
          nickname: currentUser.nickname || currentUser.username,
          phone: currentUser.phone || null,
          password_set: currentUser.password_set || false,
          created_at: currentUser.created_at != null ? currentUser.created_at : null,
          avatar: currentUser.avatar || null,
          quota: stateQuota ? { encrypt: stateQuota.encrypt, unlock: stateQuota.unlock, compress: stateQuota.compress } : null
        };
      }
    }
    if (!json) return;
    set('profileUsername', json.username);
    set('profileEmail', json.email || '');
    setText('profilePhone', json.phone || '—');
    set('profileNickname', json.nickname || json.username);
    var avatarImg = document.getElementById('profileAvatarImg');
    var avatarEmoji = document.getElementById('profileAvatarEmoji');
    var avatarPlaceholder = document.getElementById('profileAvatarPlaceholder');
    profileSelectedAvatar = (json.avatar && typeof json.avatar === 'string') ? json.avatar : '';
    if (profileSelectedAvatar && profileSelectedAvatar.indexOf('data:image') === 0) {
      if (avatarImg) { avatarImg.src = profileSelectedAvatar; avatarImg.style.display = 'block'; avatarImg.alt = '头像'; }
      if (avatarEmoji) { avatarEmoji.textContent = ''; avatarEmoji.style.display = 'none'; }
      if (avatarPlaceholder) avatarPlaceholder.style.display = 'none';
    } else if (profileSelectedAvatar && AVATAR_LIBRARY.indexOf(profileSelectedAvatar) !== -1) {
      if (avatarImg) avatarImg.style.display = 'none';
      if (avatarEmoji) { avatarEmoji.textContent = profileSelectedAvatar; avatarEmoji.style.display = 'block'; }
      if (avatarPlaceholder) avatarPlaceholder.style.display = 'none';
    } else {
      profileSelectedAvatar = '';
      if (avatarImg) avatarImg.style.display = 'none';
      if (avatarEmoji) { avatarEmoji.style.display = 'none'; avatarEmoji.textContent = ''; }
      if (avatarPlaceholder) avatarPlaceholder.style.display = 'block';
    }
    var createdAtStr = formatLocalTime(json.created_at, false).split(' ')[0] || '';
    setText('profileCreatedAt', createdAtStr || '未知');
    var q = json.quota || {};
    var defaultTotal = getToken() ? 20 : 10;
    var enc = q.encrypt != null ? Math.max(0, q.encrypt) : defaultTotal;
    var unl = q.unlock != null ? Math.max(0, q.unlock) : defaultTotal;
    var com = q.compress != null ? Math.max(0, q.compress) : defaultTotal;
    setText('profileQuotaEncrypt', q.encrypt != null ? q.encrypt : '—');
    setText('profileQuotaEncryptTotal', q.encrypt != null ? '/ ' + Math.max(enc, defaultTotal) : '/ —');
    setText('profileQuotaUnlock', q.unlock != null ? q.unlock : '—');
    setText('profileQuotaUnlockTotal', q.unlock != null ? '/ ' + Math.max(unl, defaultTotal) : '/ —');
    setText('profileQuotaCompress', q.compress != null ? q.compress : '—');
    setText('profileQuotaCompressTotal', q.compress != null ? '/ ' + Math.max(com, defaultTotal) : '/ —');
    renderProfileAvatarLibrary();
    var wrap = document.getElementById('profileAvatarLibraryWrap');
    var btn = document.getElementById('profileAvatarToggleBtn');
    if (wrap) wrap.style.display = 'none';
    if (btn) btn.textContent = '选择头像';
  }

  var AVATAR_LIBRARY = ['😀','😎','🤓','😇','🙂','😊','🐶','🐱','🦊','🐼','🦉','🌸','🌻','🍀','🎨','⚡','🎭','🚀','📚','🎸','🏀','☕','🎯','🌟','💼','🔬','🎪','🌈','🦋','🐢'];
  var profileSelectedAvatar = '';

  function renderProfileAvatarLibrary() {
    var container = document.getElementById('profileAvatarLibrary');
    if (!container) return;
    container.innerHTML = '';
    AVATAR_LIBRARY.forEach(function (emoji) {
      var btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'profile-avatar-option' + (profileSelectedAvatar === emoji ? ' is-selected' : '');
      btn.textContent = emoji;
      btn.setAttribute('aria-label', '选择头像 ' + emoji);
      btn.addEventListener('click', function () {
        profileSelectedAvatar = emoji;
        var img = document.getElementById('profileAvatarImg');
        var emojiEl = document.getElementById('profileAvatarEmoji');
        var placeholder = document.getElementById('profileAvatarPlaceholder');
        if (img) img.style.display = 'none';
        if (emojiEl) { emojiEl.textContent = emoji; emojiEl.style.display = 'block'; }
        if (placeholder) placeholder.style.display = 'none';
        container.querySelectorAll('.profile-avatar-option').forEach(function (opt) {
          opt.classList.toggle('is-selected', opt.textContent === emoji);
        });
      });
      container.appendChild(btn);
    });
  }
  async function saveProfile() {
    var username = (document.getElementById('profileUsername') && document.getElementById('profileUsername').value || '').trim();
    var nickname = (document.getElementById('profileNickname') && document.getElementById('profileNickname').value || '').trim();
    var body = { username: username || undefined, nickname: nickname || null, avatar: profileSelectedAvatar || null };
    var res = await fetchWithAuth(API_BASE + '/api/user/profile', { method: 'PUT', body: body });
    var json = await res.json().catch(function () { return {}; });
    if (res.ok) { currentUser = currentUser || {}; currentUser.username = json.username; currentUser.nickname = json.nickname || json.username; currentUser.avatar = json.avatar; updateAuthUI(); closeProfileModal(); showGlobalHint('资料已保存'); } else { document.getElementById('profileModalHint').textContent = json.error || '保存失败'; document.getElementById('profileModalHint').setAttribute('aria-hidden', 'false'); }
  }
  function openChangePasswordModal() {
    closeUserDropdown();
    var modal = document.getElementById('changePasswordModal');
    if (modal) {
      modal.setAttribute('aria-hidden', 'false');
      modal.classList.add('is-visible');
      document.getElementById('changePasswordCurrent').value = '';
      document.getElementById('changePasswordNew').value = '';
      var hint = document.getElementById('changePasswordHint');
      if (hint) { hint.textContent = ''; hint.setAttribute('aria-hidden', 'true'); }
    }
  }
  function closeChangePasswordModal() {
    var modal = document.getElementById('changePasswordModal');
    if (modal) { modal.setAttribute('aria-hidden', 'true'); modal.classList.remove('is-visible'); }
  }
  async function changePasswordFromModal() {
    var current = (document.getElementById('changePasswordCurrent') && document.getElementById('changePasswordCurrent').value) || '';
    var newPwd = (document.getElementById('changePasswordNew') && document.getElementById('changePasswordNew').value) || '';
    var hint = document.getElementById('changePasswordHint');
    if (!hint) return;
    if (!current) { hint.textContent = '请填写当前密码'; hint.classList.add('modal-hint-error'); hint.setAttribute('aria-hidden', 'false'); return; }
    if (newPwd.length < 6) { hint.textContent = '新密码至少 6 位'; hint.classList.add('modal-hint-error'); hint.setAttribute('aria-hidden', 'false'); return; }
    var res = await fetchWithAuth(API_BASE + '/api/user/change-password', { method: 'POST', body: { current_password: current, new_password: newPwd } });
    var json = await res.json().catch(function () { return {}; });
    if (res.ok) {
      hint.textContent = '密码已修改';
      hint.classList.remove('modal-hint-error');
      hint.classList.add('modal-hint-ok');
      hint.setAttribute('aria-hidden', 'false');
      document.getElementById('changePasswordCurrent').value = '';
      document.getElementById('changePasswordNew').value = '';
      showGlobalHint('密码已修改');
      setTimeout(closeChangePasswordModal, 800);
    } else {
      hint.textContent = json.error || '修改失败';
      hint.classList.add('modal-hint-error');
      hint.classList.remove('modal-hint-ok');
      hint.setAttribute('aria-hidden', 'false');
    }
  }

  function applyAdminRoute() {
    var isAdmin = currentUser && currentUser.is_admin;
    var hash = (window.location.hash || '').replace(/^#/, '');
    var mainPage = document.getElementById('mainPage');
    var adminPage = document.getElementById('adminPage');
    var adminForbidden = document.getElementById('adminForbidden');
    if (hash === 'admin') {
      if (mainPage) mainPage.style.display = 'none';
      if (adminForbidden) adminForbidden.style.display = 'none';
      if (isAdmin && adminPage) {
        adminPage.style.display = 'block';
        loadAdminStats();
        switchAdminTab(document.querySelector('.admin-page-tab.is-active') ? document.querySelector('.admin-page-tab.is-active').getAttribute('data-admin-tab') : 'overview');
      } else {
        if (adminPage) adminPage.style.display = 'none';
        if (adminForbidden) adminForbidden.style.display = 'block';
      }
    } else {
      if (mainPage) mainPage.style.display = '';
      if (adminPage) adminPage.style.display = 'none';
      if (adminForbidden) adminForbidden.style.display = 'none';
      if (window._adminMonitorTimer) { clearInterval(window._adminMonitorTimer); window._adminMonitorTimer = null; }
    }
  }
  window.applyAdminRoute = applyAdminRoute;
  function switchAdminTab(tab) {
    document.querySelectorAll('.admin-page-tab').forEach(function (t) { t.classList.toggle('is-active', t.getAttribute('data-admin-tab') === tab); });
    document.querySelectorAll('.admin-page-main .admin-panel').forEach(function (p) { p.style.display = p.getAttribute('data-admin-panel') === tab ? '' : 'none'; });
    if (tab !== 'monitor' && window._adminMonitorTimer) { clearInterval(window._adminMonitorTimer); window._adminMonitorTimer = null; }
    if (tab === 'users') loadAdminUsers();
    if (tab === 'payments') loadAdminPayments();
    if (tab === 'access') loadAdminAccessLogs();
    if (tab === 'usage') loadAdminUsageLogs();
    if (tab === 'monitor') { loadAdminMonitor(); if (!window._adminMonitorTimer) window._adminMonitorTimer = setInterval(loadAdminMonitor, 5000); }
    if (tab === 'cost') loadAdminCost();
  }
  async function loadAdminStats() {
    var res = await fetchWithAuth(API_BASE + '/api/admin/stats');
    if (!res.ok) return;
    var json = await res.json();
    var d = json.data || {};
    var el;
    if (el = document.getElementById('adminStatUsers')) el.textContent = d.total_users != null ? d.total_users : 0;
    if (el = document.getElementById('adminStatPayments')) el.textContent = d.total_payments != null ? d.total_payments : 0;
    if (el = document.getElementById('adminStatRevenue')) el.textContent = d.total_revenue != null ? d.total_revenue : 0;
    if (el = document.getElementById('adminStatVisits')) el.textContent = d.total_visits != null ? d.total_visits : 0;
    if (el = document.getElementById('adminStatUsageCount')) el.textContent = d.total_usage_count != null ? d.total_usage_count : 0;
    var trend = d.usage_trend || [];
    var tbody = document.getElementById('adminUsageTrendBody');
    if (tbody) {
      tbody.innerHTML = '';
      trend.forEach(function (row) {
        var tr = document.createElement('tr');
        tr.innerHTML = '<td>' + (row.date || '') + '</td><td>' + (row.count != null ? row.count : 0) + '</td>';
        tbody.appendChild(tr);
      });
    }
    var visitTrend = d.visit_trend || [];
    var visitTbody = document.getElementById('adminVisitTrendBody');
    if (visitTbody) {
      visitTbody.innerHTML = '';
      visitTrend.forEach(function (row) {
        var tr = document.createElement('tr');
        tr.innerHTML = '<td>' + (row.date || '') + '</td><td>' + (row.count != null ? row.count : 0) + '</td>';
        visitTbody.appendChild(tr);
      });
    }
  }
  async function loadAdminMonitor() {
    var res = await fetchWithAuth(API_BASE + '/api/admin/monitor/realtime');
    if (!res.ok) return;
    var json = await res.json();
    var d = json.data || {};
    var el;
    if (el = document.getElementById('adminMonitorUsage1h')) el.textContent = d.recent_usage_1h != null ? d.recent_usage_1h : 0;
    if (el = document.getElementById('adminMonitorUsage24h')) el.textContent = d.recent_usage_24h != null ? d.recent_usage_24h : 0;
    if (el = document.getElementById('adminMonitorVisits1h')) el.textContent = d.recent_visits_1h != null ? d.recent_visits_1h : 0;
    if (el = document.getElementById('adminMonitorVisits24h')) el.textContent = d.recent_visits_24h != null ? d.recent_visits_24h : 0;
    var visitsBody = document.getElementById('adminMonitorRecentVisitsBody');
    if (visitsBody) {
      visitsBody.innerHTML = '';
      (d.recent_visits || []).forEach(function (r) {
        var tr = document.createElement('tr');
        tr.innerHTML = '<td>' + formatLocalTime(r.created_at) + '</td><td>' + (r.ip_address || '-') + '</td><td>' + (r.location || '-') + '</td><td>' + (r.device_type || '-') + '</td><td>' + (r.username || '-') + '</td><td>' + (r.phone || '-') + '</td>';
        visitsBody.appendChild(tr);
      });
    }
    var usageBody = document.getElementById('adminMonitorRecentUsageBody');
    if (usageBody) {
      usageBody.innerHTML = '';
      (d.recent_usage || []).forEach(function (r) {
        var tr = document.createElement('tr');
        tr.innerHTML = '<td>' + formatLocalTime(r.created_at) + '</td><td>' + (r.username || '-') + '</td><td>' + (r.phone || '-') + '</td><td>' + (r.type || '-') + '</td><td>' + (r.ip_address || '-') + '</td><td>' + (r.location || '-') + '</td>';
        usageBody.appendChild(tr);
      });
    }
  }
  async function loadAdminCost() {
    var res = await fetchWithAuth(API_BASE + '/api/admin/stats');
    if (!res.ok) return;
    var json = await res.json();
    var d = json.data || {};
    var revenue = d.total_revenue != null ? d.total_revenue : 0;
    var cost = d.total_cost != null ? d.total_cost : 0;
    var profit = revenue - cost;
    var el;
    if (el = document.getElementById('adminCostRevenue')) el.textContent = revenue;
    if (el = document.getElementById('adminCostCost')) el.textContent = cost;
    if (el = document.getElementById('adminCostProfit')) el.textContent = profit;
  }
  async function loadAdminAccessLogs() {
    var res = await fetchWithAuth(API_BASE + '/api/admin/access-logs?page=1&page_size=20');
    if (!res.ok) return;
    var json = await res.json();
    var tbody = document.getElementById('adminAccessBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (json.data || []).forEach(function (r) {
      var tr = document.createElement('tr');
      tr.innerHTML = '<td>' + formatLocalTime(r.created_at || r.time) + '</td><td>' + (r.ip_address || '-') + '</td><td>' + (r.location || '-') + '</td><td>' + (r.device_type || r.path || '-') + '</td><td>' + (r.username || r.user_id || '-') + '</td><td>' + (r.phone || '-') + '</td>';
      tbody.appendChild(tr);
    });
    var pager = document.getElementById('adminAccessPager');
    if (pager) pager.textContent = '共 ' + (json.total || 0) + ' 条';
  }
  async function loadAdminUsageLogs() {
    var res = await fetchWithAuth(API_BASE + '/api/admin/usage-logs?page=1&page_size=20');
    if (!res.ok) return;
    var json = await res.json();
    var tbody = document.getElementById('adminUsageBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (json.data || []).forEach(function (r) {
      var tr = document.createElement('tr');
      tr.innerHTML = '<td>' + formatLocalTime(r.created_at || r.time) + '</td><td>' + (r.username || r.user_id || '-') + '</td><td>' + (r.phone || '-') + '</td><td>' + (r.type || '-') + '</td><td>' + (r.ip_address || '-') + '</td><td>' + (r.location || '-') + '</td>';
      tbody.appendChild(tr);
    });
    var pager = document.getElementById('adminUsagePager');
    if (pager) pager.textContent = '共 ' + (json.total || 0) + ' 条';
  }

  var rechargePacksData = [];
  var rechargeSelectedPackIndex = null;
  var RECHARGE_FALLBACK_PACKS = [
    { index: 0, encrypt: 10, unlock: 10, compress: 10, amount: 0.99 },
    { index: 1, encrypt: 60, unlock: 60, compress: 60, amount: 4.99 },
    { index: 2, encrypt: 110, unlock: 110, compress: 110, amount: 9.99 },
  ];
  function openRechargeModal() {
    closeUserDropdown();
    var modal = document.getElementById('rechargeModal');
    if (!modal) return;
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-visible');
    document.getElementById('rechargeOrderPanel').style.display = 'none';
    document.getElementById('rechargeConfirmWrap').style.display = 'none';
    var qrImg = document.getElementById('rechargeQrImg');
    if (qrImg) { qrImg.src = ''; qrImg.classList.remove('is-visible'); }
    var cardsEl = document.getElementById('rechargeCards');
    if (cardsEl) cardsEl.style.display = '';
    rechargeSelectedPackIndex = null;
    if (rechargePacksData.length) {
      renderRechargeCards(rechargePacksData);
    } else {
      renderRechargeCards(RECHARGE_FALLBACK_PACKS);
      loadRechargePacksForModal();
    }
  }
  function closeRechargeModal() {
    var modal = document.getElementById('rechargeModal');
    if (modal) { modal.setAttribute('aria-hidden', 'true'); modal.classList.remove('is-visible'); }
  }
  async function loadRechargePacksForModal() {
    try {
      var res = await fetch(API_BASE + '/api/payment/packs');
      if (res.ok) {
        var json = await res.json();
        var packs = json.packs || [];
        if (packs.length) {
          rechargePacksData = packs;
          renderRechargeCards(rechargePacksData);
        }
      }
    } catch (e) {}
  }
  function renderRechargeCards(list) {
    var el = document.getElementById('rechargeCards');
    if (!el) return;
    el.className = 'pay-plan-list';
    el.innerHTML = '';
    var items = list && list.length ? list : RECHARGE_FALLBACK_PACKS;
    items.forEach(function (p) {
      var card = document.createElement('button');
      card.type = 'button';
      card.className = 'pay-plan-card';
      card.setAttribute('data-pack-index', p.index);
      card.innerHTML = '<div class="pay-plan-main">' +
        '<span class="pay-plan-count-wrap"><span class="pay-plan-count">' + p.encrypt + '</span><span class="pay-plan-unit"> 次</span></span>' +
        '<span class="pay-plan-features">加密 ' + p.encrypt + ' 次 · 解锁 ' + p.unlock + ' 次 · 体积优化 ' + p.compress + ' 次</span>' +
        '</div><div class="pay-plan-price">¥' + p.amount + '</div>';
      card.addEventListener('click', function () { selectRechargePack(p.index); });
      el.appendChild(card);
    });
  }
  function selectRechargePack(packIndex) {
    rechargeSelectedPackIndex = packIndex;
    document.querySelectorAll('.pay-plan-card').forEach(function (c) { c.classList.toggle('is-selected', parseInt(c.getAttribute('data-pack-index'), 10) === packIndex); });
    var list = rechargePacksData.length ? rechargePacksData : RECHARGE_FALLBACK_PACKS;
    var pack = list.find(function (p) { return p.index === packIndex; });
    var label = pack ? '加密' + pack.encrypt + '次 / 解锁' + pack.unlock + '次 / 体积优化' + pack.compress + '次 — ¥' + pack.amount : '';
    document.getElementById('rechargeSelectedLabel').textContent = label;
    document.getElementById('rechargeConfirmWrap').style.display = 'block';
  }
  async function confirmRechargeSelect() {
    if (rechargeSelectedPackIndex == null) return;
    await createPaymentOrderFromModal(rechargeSelectedPackIndex);
  }
  var RECHARGE_QR_IMAGES = ['alipay-10-0.99.png', 'alipay-60-4.99.png', 'alipay-110-9.99.png'];
  async function createPaymentOrderFromModal(packIndex) {
    var res = await fetchWithAuth(API_BASE + '/api/payment/create', { method: 'POST', body: { pack_index: packIndex } });
    if (!res.ok) { var j = await res.json().catch(function () { return {}; }); showGlobalHint(j.error || '创建订单失败', true); return; }
    var json = await res.json();
    currentOrderTransactionId = json.transaction_id;
    document.getElementById('rechargeModalTransactionId').textContent = json.transaction_id;
    var accountName = (json.payment_info && json.payment_info.account_name) ? json.payment_info.account_name : '支付宝收款';
    document.getElementById('rechargeQrAccount').textContent = accountName + ' · 金额 ' + json.amount + ' 元';
    var qrImg = document.getElementById('rechargeQrImg');
    var baseUrl = (typeof API_BASE === 'string' && API_BASE) ? API_BASE.replace(/\/$/, '') : (window.location.protocol + '//' + window.location.hostname + ':5001');
    if (qrImg && RECHARGE_QR_IMAGES[packIndex]) {
      qrImg.src = baseUrl + '/api/static/payment/' + encodeURIComponent(RECHARGE_QR_IMAGES[packIndex]);
      qrImg.alt = '支付宝收款码 · ¥' + json.amount;
      qrImg.classList.add('is-visible');
    } else if (qrImg) {
      qrImg.src = '';
      qrImg.classList.remove('is-visible');
    }
    document.getElementById('rechargeCards').style.display = 'none';
    document.getElementById('rechargeConfirmWrap').style.display = 'none';
    document.getElementById('rechargeOrderPanel').style.display = 'block';
  }
  function showPaymentConfirmLoading() {
    var modal = document.getElementById('paymentConfirmLoadingModal');
    if (modal) { modal.setAttribute('aria-hidden', 'false'); modal.classList.add('is-visible'); }
  }
  function closePaymentConfirmLoading() {
    var modal = document.getElementById('paymentConfirmLoadingModal');
    if (modal) { modal.setAttribute('aria-hidden', 'true'); modal.classList.remove('is-visible'); }
  }
  function showPaymentConfirmAlert(message, title) {
    var modal = document.getElementById('paymentConfirmAlertModal');
    var titleEl = document.getElementById('paymentConfirmAlertTitle');
    var msgEl = document.getElementById('paymentConfirmAlertMessage');
    if (!modal || !msgEl) return;
    if (titleEl) titleEl.textContent = title != null ? title : '支付确认失败';
    msgEl.textContent = message || '确认失败，请稍后再试。';
    modal.setAttribute('aria-hidden', 'false');
    modal.classList.add('is-visible');
  }
  function closePaymentConfirmAlert() {
    var modal = document.getElementById('paymentConfirmAlertModal');
    if (modal) { modal.setAttribute('aria-hidden', 'true'); modal.classList.remove('is-visible'); }
  }
  async function confirmPaymentFromModal() {
    if (!currentOrderTransactionId) {
      showPaymentConfirmAlert('请先完成下单并获取订单号后再点击「我已支付」。', '缺少订单号');
      return;
    }
    showPaymentConfirmLoading();
    try {
      var res = await fetchWithAuth(API_BASE + '/api/payment/confirm', { method: 'POST', body: { transaction_id: currentOrderTransactionId } });
      var json = await res.json().catch(function () { return {}; });
      if (res.ok && json.status === 'success') {
        currentOrderTransactionId = null;
        document.getElementById('rechargeOrderPanel').style.display = 'none';
        showGlobalHint('支付确认成功，次数已到账。');
        closeRechargeModal();
        await loadQuota();
        updateUsageUI();
        await loadProfileForModal();
      } else {
        var errMsg = json.error || json.detail || '确认失败，请稍后再试。';
        var alertTitle = (json.detail === 'no_matching_order') ? '未查询到订单' : (json.detail === 'alipay_auth_denied' ? 'Cookie 已过期' : '支付确认失败');
        showGlobalHint(errMsg, true);
        showPaymentConfirmAlert(errMsg, alertTitle);
      }
    } finally {
      closePaymentConfirmLoading();
    }
  }
  var pendingAdminUserEditId = null;

  function openAdminUserEditModal(userId) {
    pendingAdminUserEditId = userId;
    var modal = document.getElementById('adminUserEditModal');
    var hintEl = document.getElementById('adminUserEditHint');
    if (hintEl) { hintEl.textContent = ''; hintEl.setAttribute('aria-hidden', 'true'); }
    if (modal) {
      modal.setAttribute('aria-hidden', 'false');
      modal.classList.add('is-visible');
    }
    loadAdminUserDetail(userId);
  }

  function closeAdminUserEditModal() {
    pendingAdminUserEditId = null;
    var modal = document.getElementById('adminUserEditModal');
    if (modal) {
      if (document.activeElement && modal.contains(document.activeElement)) {
        document.activeElement.blur();
      }
      modal.setAttribute('aria-hidden', 'true');
      modal.classList.remove('is-visible');
    }
  }

  async function loadAdminUserDetail(userId) {
    var res = await fetchWithAuth(API_BASE + '/api/admin/users/' + userId);
    if (!res.ok) {
      showGlobalHint('加载用户信息失败', true);
      closeAdminUserEditModal();
      return;
    }
    var json = await res.json();
    var user = json.data.user || {};
    var quota = json.data.quota || {};
    
    var usernameEl = document.getElementById('adminUserEditUsername');
    var emailEl = document.getElementById('adminUserEditEmail');
    var nicknameEl = document.getElementById('adminUserEditNickname');
    var phoneEl = document.getElementById('adminUserEditPhone');
    var passwordEl = document.getElementById('adminUserEditPassword');
    var isAdminEl = document.getElementById('adminUserEditIsAdmin');
    var encryptEl = document.getElementById('adminUserEditEncrypt');
    var unlockEl = document.getElementById('adminUserEditUnlock');
    var compressEl = document.getElementById('adminUserEditCompress');
    
    if (usernameEl) usernameEl.value = user.username || '';
    if (emailEl) emailEl.value = user.email || '';
    if (nicknameEl) nicknameEl.value = user.nickname || '';
    if (phoneEl) phoneEl.value = user.phone || '';
    if (passwordEl) passwordEl.value = '';
    if (isAdminEl) isAdminEl.checked = user.is_admin || false;
    if (encryptEl) encryptEl.value = quota.encrypt != null ? quota.encrypt : '';
    if (unlockEl) unlockEl.value = quota.unlock != null ? quota.unlock : '';
    if (compressEl) compressEl.value = quota.compress != null ? quota.compress : '';
  }

  async function submitAdminUserEdit() {
    var userId = pendingAdminUserEditId;
    if (!userId) return;
    
    var usernameEl = document.getElementById('adminUserEditUsername');
    var emailEl = document.getElementById('adminUserEditEmail');
    var nicknameEl = document.getElementById('adminUserEditNickname');
    var phoneEl = document.getElementById('adminUserEditPhone');
    var passwordEl = document.getElementById('adminUserEditPassword');
    var isAdminEl = document.getElementById('adminUserEditIsAdmin');
    var encryptEl = document.getElementById('adminUserEditEncrypt');
    var unlockEl = document.getElementById('adminUserEditUnlock');
    var compressEl = document.getElementById('adminUserEditCompress');
    var hintEl = document.getElementById('adminUserEditHint');
    
    var data = {};
    if (usernameEl && usernameEl.value.trim()) data.username = usernameEl.value.trim();
    if (emailEl && emailEl.value.trim()) data.email = emailEl.value.trim();
    if (nicknameEl) data.nickname = nicknameEl.value.trim() || null;
    if (phoneEl) data.phone = phoneEl.value.trim() || null;
    if (passwordEl && passwordEl.value.trim()) data.password = passwordEl.value.trim();
    if (isAdminEl) data.is_admin = isAdminEl.checked;
    if (encryptEl && encryptEl.value !== '') data.encrypt_remaining = parseInt(encryptEl.value, 10);
    if (unlockEl && unlockEl.value !== '') data.unlock_remaining = parseInt(unlockEl.value, 10);
    if (compressEl && compressEl.value !== '') data.compress_remaining = parseInt(compressEl.value, 10);
    
    try {
      var res = await fetchWithAuth(API_BASE + '/api/admin/users/' + userId, {
        method: 'PUT',
        body: data
      });
      var json = await res.json();
      if (res.ok) {
        closeAdminUserEditModal();
        loadAdminUsers();
        showGlobalHint('用户信息已更新');
      } else {
        if (hintEl) {
          hintEl.textContent = json.error || '更新失败';
          hintEl.setAttribute('aria-hidden', 'false');
        }
      }
    } catch (err) {
      if (hintEl) {
        hintEl.textContent = '更新失败：' + (err.message || '网络错误');
        hintEl.setAttribute('aria-hidden', 'false');
      }
    }
  }

  async function loadAdminUsers() {
    var search = (document.getElementById('adminUserSearch') && document.getElementById('adminUserSearch').value || '').trim();
    var url = API_BASE + '/api/admin/users?page=1&page_size=20';
    if (search) url += '&search=' + encodeURIComponent(search);
    var res = await fetchWithAuth(url);
    if (!res.ok) return;
    var json = await res.json();
    var tbody = document.getElementById('adminUsersBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (json.data || []).forEach(function (u) {
      var q = u.quota || {};
      var tr = document.createElement('tr');
      var editBtn = '<button type="button" class="btn btn-secondary btn-sm" onclick="window.openAdminUserEdit(' + u.id + ')">编辑</button>';
      tr.innerHTML = '<td>' + u.id + '</td><td>' + (u.nickname || u.username) + '</td><td>' + (u.email || '-') + '</td><td>' + (u.phone || '-') + '</td><td>' + (u.password_set ? '是' : '否') + '</td><td>' + (q.encrypt != null ? q.encrypt : '-') + '</td><td>' + (q.unlock != null ? q.unlock : '-') + '</td><td>' + (q.compress != null ? q.compress : '-') + '</td><td>' + formatLocalTime(u.created_at) + '</td><td>' + editBtn + '</td>';
      tbody.appendChild(tr);
    });
    var pager = document.getElementById('adminUsersPager');
    if (pager) pager.textContent = '共 ' + (json.total || 0) + ' 条';
  }
  
  // 暴露给全局，供 onclick 调用
  window.openAdminUserEdit = openAdminUserEditModal;
  async function loadAdminPayments() {
    var res = await fetchWithAuth(API_BASE + '/api/admin/payments?page=1&page_size=50');
    if (!res.ok) return;
    var json = await res.json();
    var tbody = document.getElementById('adminPaymentsBody');
    if (!tbody) return;
    tbody.innerHTML = '';
    (json.data || []).forEach(function (p) {
      var tr = document.createElement('tr');
      tr.innerHTML = '<td>' + p.id + '</td><td>' + (p.username || p.user_id) + '</td><td>' + (p.phone || '-') + '</td><td>' + (p.pack_type || '') + '</td><td>' + p.quantity + '</td><td>' + p.amount + '</td><td>' + p.status + '</td><td>' + formatLocalTime(p.created_at) + '</td>';
      tbody.appendChild(tr);
    });
    var pager = document.getElementById('adminPaymentsPager');
    if (pager) pager.textContent = '共 ' + (json.total || 0) + ' 条';
  }

  var btnAuth = document.getElementById('btnAuth');
  if (btnAuth) btnAuth.addEventListener('click', openAuthModal);

  var authUserTrigger = document.getElementById('authUserTrigger');
  if (authUserTrigger) authUserTrigger.addEventListener('click', function (e) { e.stopPropagation(); toggleUserDropdown(); });
  document.addEventListener('click', function (e) {
    var dropdown = document.getElementById('authUserDropdown');
    var wrap = document.getElementById('authUserWrap');
    if (dropdown && wrap && !wrap.contains(e.target)) {
      closeUserDropdown();
    }
  });
  var authUserWrap = document.getElementById('authUserWrap');
  if (authUserWrap) authUserWrap.addEventListener('click', function (e) { e.stopPropagation(); });
  var authUserDropdown = document.getElementById('authUserDropdown');
  if (authUserDropdown) authUserDropdown.addEventListener('click', function (e) { e.stopPropagation(); });

  var dropdownProfile = document.getElementById('dropdownProfile');
  var dropdownRecharge = document.getElementById('dropdownRecharge');
  var dropdownChangePassword = document.getElementById('dropdownChangePassword');
  var dropdownLogout = document.getElementById('dropdownLogout');
  if (dropdownProfile) dropdownProfile.addEventListener('click', function (e) { e.stopPropagation(); openProfileModal(); });
  if (dropdownRecharge) dropdownRecharge.addEventListener('click', function (e) { e.stopPropagation(); openRechargeModal(); });
  if (dropdownChangePassword) dropdownChangePassword.addEventListener('click', function (e) { e.stopPropagation(); openChangePasswordModal(); });
  if (dropdownLogout) dropdownLogout.addEventListener('click', function (e) {
    e.stopPropagation();
    closeUserDropdown();
    clearToken();
    updateAuthUI();
    updateUsageUI();
    showGlobalHint('已退出登录。');
    applyAdminRoute();
  });

  var rechargeLoginBtn = document.getElementById('rechargeLoginBtn');
  if (rechargeLoginBtn) rechargeLoginBtn.addEventListener('click', openAuthModal);
  var btnConfirmPaid = document.getElementById('btnConfirmPaid');
  if (btnConfirmPaid) btnConfirmPaid.addEventListener('click', confirmPayment);
  var rechargeConfirmSelectBtn = document.getElementById('rechargeConfirmSelectBtn');
  if (rechargeConfirmSelectBtn) rechargeConfirmSelectBtn.addEventListener('click', confirmRechargeSelect);

  var rechargeModalClose = document.getElementById('rechargeModalClose');
  if (rechargeModalClose) rechargeModalClose.addEventListener('click', closeRechargeModal);
  var rechargeModalConfirmPaid = document.getElementById('rechargeModalConfirmPaid');
  if (rechargeModalConfirmPaid) rechargeModalConfirmPaid.addEventListener('click', confirmPaymentFromModal);
  var rechargeCopyOrderId = document.getElementById('rechargeCopyOrderId');
  if (rechargeCopyOrderId) rechargeCopyOrderId.addEventListener('click', function () {
    var el = document.getElementById('rechargeModalTransactionId');
    var text = el ? el.textContent : '';
    if (!text) return;
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(function () { showGlobalHint('订单号已复制'); }).catch(function () { showGlobalHint('复制失败', true); });
    } else {
      var input = document.createElement('input'); input.value = text; input.readOnly = true; input.style.position = 'absolute'; input.style.left = '-9999px'; document.body.appendChild(input); input.select(); try { document.execCommand('copy'); showGlobalHint('订单号已复制'); } catch (e) { showGlobalHint('复制失败', true); } document.body.removeChild(input);
    }
  });
  var rechargeModalEl = document.getElementById('rechargeModal');
  if (rechargeModalEl) rechargeModalEl.addEventListener('click', function (e) { if (e.target === rechargeModalEl) closeRechargeModal(); });
  var paymentConfirmAlertClose = document.getElementById('paymentConfirmAlertClose');
  if (paymentConfirmAlertClose) paymentConfirmAlertClose.addEventListener('click', closePaymentConfirmAlert);
  var paymentConfirmAlertModal = document.getElementById('paymentConfirmAlertModal');
  if (paymentConfirmAlertModal) paymentConfirmAlertModal.addEventListener('click', function (e) { if (e.target === paymentConfirmAlertModal) closePaymentConfirmAlert(); });

  var profileModalEl = document.getElementById('profileModal');
  var profileModalCancel = document.getElementById('profileModalCancel');
  var profileModalSave = document.getElementById('profileModalSave');
  var profileAvatarToggleBtn = document.getElementById('profileAvatarToggleBtn');
  if (profileAvatarToggleBtn) {
    profileAvatarToggleBtn.addEventListener('click', function () {
      var wrap = document.getElementById('profileAvatarLibraryWrap');
      if (!wrap) return;
      var isHidden = wrap.style.display === 'none';
      wrap.style.display = isHidden ? '' : 'none';
      profileAvatarToggleBtn.textContent = isHidden ? '收起' : '选择头像';
    });
  }
  if (profileModalCancel) profileModalCancel.addEventListener('click', closeProfileModal);
  if (profileModalSave) profileModalSave.addEventListener('click', saveProfile);
  if (profileModalEl) profileModalEl.addEventListener('click', function (e) { if (e.target === profileModalEl) closeProfileModal(); });

  var changePasswordModalEl = document.getElementById('changePasswordModal');
  var changePasswordModalCancel = document.getElementById('changePasswordModalCancel');
  var changePasswordModalSubmit = document.getElementById('changePasswordModalSubmit');
  if (changePasswordModalCancel) changePasswordModalCancel.addEventListener('click', closeChangePasswordModal);
  if (changePasswordModalSubmit) changePasswordModalSubmit.addEventListener('click', changePasswordFromModal);
  if (changePasswordModalEl) changePasswordModalEl.addEventListener('click', function (e) { if (e.target === changePasswordModalEl) closeChangePasswordModal(); });

  document.querySelectorAll('.admin-page-tab').forEach(function (t) {
    t.addEventListener('click', function () { switchAdminTab(t.getAttribute('data-admin-tab')); });
  });
  var adminPageBack = document.getElementById('adminPageBack');
  if (adminPageBack) adminPageBack.addEventListener('click', function (e) { e.preventDefault(); location.hash = ''; applyAdminRoute(); });
  var adminForbiddenEl = document.getElementById('adminForbidden');
  if (adminForbiddenEl) {
    var adminForbiddenLink = adminForbiddenEl.querySelector('a');
    if (adminForbiddenLink) adminForbiddenLink.addEventListener('click', function (e) { e.preventDefault(); location.hash = ''; applyAdminRoute(); });
  }
  var adminPaymentTestBtn = document.getElementById('adminPaymentTestBtn');
  if (adminPaymentTestBtn) adminPaymentTestBtn.addEventListener('click', async function () {
    var resultEl = document.getElementById('adminPaymentTestResult');
    if (resultEl) resultEl.textContent = '处理中…';
    var res = await fetchWithAuth(API_BASE + '/api/admin/payment-test', { method: 'POST', body: {} });
    var json = await res.json().catch(function () { return {}; });
    if (resultEl) resultEl.textContent = res.ok ? (json.message || '测试到账成功') : (json.error || '请求失败');
  });
  var adminUserSearchBtn = document.getElementById('adminUserSearchBtn');
  if (adminUserSearchBtn) adminUserSearchBtn.addEventListener('click', function () { loadAdminUsers(); });
  
  var adminUserEditModal = document.getElementById('adminUserEditModal');
  var adminUserEditCancel = document.getElementById('adminUserEditCancel');
  var adminUserEditSubmit = document.getElementById('adminUserEditSubmit');
  if (adminUserEditCancel) adminUserEditCancel.addEventListener('click', closeAdminUserEditModal);
  if (adminUserEditSubmit) adminUserEditSubmit.addEventListener('click', submitAdminUserEdit);
  if (adminUserEditModal) {
    adminUserEditModal.addEventListener('click', function (e) {
      if (e.target === adminUserEditModal) closeAdminUserEditModal();
    });
  }
  
  window.addEventListener('hashchange', applyAdminRoute);

  var authModalEl = document.getElementById('authModal');
  var authModalCancel = document.getElementById('authModalCancel');
  if (authModalCancel) authModalCancel.addEventListener('click', closeAuthModal);
  if (authModalEl) authModalEl.addEventListener('click', function (e) { if (e.target === authModalEl) closeAuthModal(); });

  var authLoginMethodSubs = document.querySelectorAll('.auth-step[data-auth-step="verify"] .auth-subtab');
  authLoginMethodSubs.forEach(function (btn) {
    btn.addEventListener('click', function () { setAuthLoginMethod(btn.getAttribute('data-auth-login-method') || 'code'); });
  });

  var authSendCodeBtn = document.getElementById('authSendCode');
  if (authSendCodeBtn) authSendCodeBtn.addEventListener('click', function () {
    var phone = (document.getElementById('authPhone') && document.getElementById('authPhone').value || '').trim().replace(/\s|-/g, '');
    authSendSmsCode(phone, true, authSendCodeBtn);
  });

  var authSubmitCodeBtn = document.getElementById('authSubmitCode');
  if (authSubmitCodeBtn) authSubmitCodeBtn.addEventListener('click', onAuthSubmitCode);

  var authSubmitPasswordBtn = document.getElementById('authSubmitPassword');
  if (authSubmitPasswordBtn) authSubmitPasswordBtn.addEventListener('click', onAuthPasswordLogin);

  var authCompleteRegisterBtn = document.getElementById('authCompleteRegister');
  if (authCompleteRegisterBtn) authCompleteRegisterBtn.addEventListener('click', onAuthCompleteRegister);

  setGlowLevel(getGlowLevel());
  var glowLevelBtn = document.getElementById('glowLevelBtn');
  if (glowLevelBtn) glowLevelBtn.addEventListener('click', cycleGlowLevel);

  async function initAuth() {
    if (getToken()) {
      try {
        var res = await fetchWithAuth(API_BASE + '/api/me');
        if (res.ok) {
          var json = await res.json();
          if (json.user) currentUser = json.user;
        } else {
          clearToken();
        }
      } catch (e) {
        clearToken();
      }
    }
    updateAuthUI();
    await loadQuota();
    applyAdminRoute();
  }
  initAuth();

  function recordVisit() {
    if (!API_BASE) return;
    fetchWithAuth(API_BASE + '/api/visit', {
      method: 'POST',
      body: { session_id: getAnonymousId() }
    }).catch(function () {});
  }
  recordVisit();

  var initialTextEl = document.getElementById('pdfInputText');
  if (initialTextEl) initialTextEl.textContent = getFileInputPlaceholder();
})();
