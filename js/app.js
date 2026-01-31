(function () {
  'use strict';

  var API_BASE = (typeof window.FREEYOURPDF_API_BASE !== 'undefined' && window.FREEYOURPDF_API_BASE) ? window.FREEYOURPDF_API_BASE : '';

  if (!window.PDFLib || !window.PDFLib.PDFDocument) {
    document.body.innerHTML = '<div class="page" style="padding:2rem;text-align:center;color:#a1a1aa;">PDF 库加载失败，请检查网络或刷新页面。</div>';
    return;
  }

  if (typeof window.pdfjsLib !== 'undefined' && window.pdfjsLib.GlobalWorkerOptions) {
    window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/3.11.174/pdf.worker.min.js';
  }

  const STORAGE_KEY_ENCRYPT = 'freeyourpdf_used_encrypt';
  const STORAGE_KEY_UNLOCK = 'freeyourpdf_used_unlock';
  const STORAGE_KEY_COMPRESS = 'freeyourpdf_used_compress';
  const FREE_LIMIT = 10;

  const PDFDocument = window.PDFLib.PDFDocument;

  function getUsedCountEncrypt() {
    const v = localStorage.getItem(STORAGE_KEY_ENCRYPT);
    return v === null ? 0 : Math.max(0, parseInt(v, 10));
  }
  function setUsedCountEncrypt(n) {
    localStorage.setItem(STORAGE_KEY_ENCRYPT, String(Math.max(0, n)));
  }
  function getUsedCountUnlock() {
    const v = localStorage.getItem(STORAGE_KEY_UNLOCK);
    return v === null ? 0 : Math.max(0, parseInt(v, 10));
  }
  function setUsedCountUnlock(n) {
    localStorage.setItem(STORAGE_KEY_UNLOCK, String(Math.max(0, n)));
  }
  function getUsedCountCompress() {
    const v = localStorage.getItem(STORAGE_KEY_COMPRESS);
    return v === null ? 0 : Math.max(0, parseInt(v, 10));
  }
  function setUsedCountCompress(n) {
    localStorage.setItem(STORAGE_KEY_COMPRESS, String(Math.max(0, n)));
  }

  function consumeEncrypt() {
    const used = getUsedCountEncrypt();
    if (used >= FREE_LIMIT) return false;
    setUsedCountEncrypt(used + 1);
    return true;
  }
  function consumeUnlock() {
    const used = getUsedCountUnlock();
    if (used >= FREE_LIMIT) return false;
    setUsedCountUnlock(used + 1);
    return true;
  }
  function consumeCompress() {
    const used = getUsedCountCompress();
    if (used >= FREE_LIMIT) return false;
    setUsedCountCompress(used + 1);
    return true;
  }

  function updateUsageUI() {
    const remEncrypt = Math.max(0, FREE_LIMIT - getUsedCountEncrypt());
    const remUnlock = Math.max(0, FREE_LIMIT - getUsedCountUnlock());
    const remCompress = Math.max(0, FREE_LIMIT - getUsedCountCompress());
    const elEncrypt = document.getElementById('usageValueEncrypt');
    const elUnlock = document.getElementById('usageValueUnlock');
    const elCompress = document.getElementById('usageValueCompress');
    if (elEncrypt) elEncrypt.textContent = remEncrypt;
    if (elUnlock) elUnlock.textContent = remUnlock;
    if (elCompress) elCompress.textContent = remCompress;
    const extra = document.getElementById('extraSection');
    const anyExhausted = remEncrypt <= 0 || remUnlock <= 0 || remCompress <= 0;
    if (extra) extra.setAttribute('aria-hidden', anyExhausted ? 'false' : 'true');
  }

  function canUseEncrypt() { return getUsedCountEncrypt() < FREE_LIMIT; }
  function canUseUnlock() { return getUsedCountUnlock() < FREE_LIMIT; }
  function canUseCompress() { return getUsedCountCompress() < FREE_LIMIT; }

  function showGlobalHint(text, isError) {
    const el = document.getElementById('globalHint');
    if (!el) return;
    el.textContent = text || '';
    el.classList.toggle('hint-error', !!isError);
    el.classList.toggle('hint-ok', !isError && !!text);
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
    var bytes = new Uint8Array(await file.arrayBuffer());
    var hasEncrypt = new TextDecoder('utf-8', { fatal: false }).decode(bytes).indexOf('/Encrypt') !== -1;
    if (hasEncrypt) {
      try {
        await PDFDocument.load(bytes, { password: '' });
        return false;
      } catch (e) {}
      try {
        await PDFDocument.load(bytes);
        return false;
      } catch (e2) {
        return true;
      }
    }
    try {
      await PDFDocument.load(bytes);
      return false;
    } catch (e) {
      try {
        await PDFDocument.load(bytes, { password: '' });
        return false;
      } catch (e2) {
        return true;
      }
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

  /** 尝试用指定密码打开 PDF，成功返回 true；空字符串显式传 password: '' 以支持空密码 PDF */
  async function tryPassword(bytes, pwd) {
    try {
      var loadOpts = pwd === undefined ? {} : { password: pwd };
      await PDFDocument.load(bytes, loadOpts);
      return true;
    } catch (e) {
      return false;
    }
  }

  /**
   * 解锁：将 PDF 每页复制到新文档再保存，移除加密/权限（参考 PDFDeSecure）
   * @param {Uint8Array} bytes - 原 PDF 字节
   * @param {string} [password] - 若需密码打开则传入
   * @returns {Promise<Uint8Array|null>} 解锁后的 PDF 字节，失败返回 null
   */
  async function unlockPdfToBytes(bytes, password) {
    try {
      var loadOpts = password === undefined ? {} : { password: password };
      var doc = await PDFDocument.load(bytes, loadOpts);
      var newDoc = await PDFDocument.create();
      var indices = doc.getPageIndices();
      if (!indices || indices.length === 0) return null;
      var copiedPages = await newDoc.copyPages(doc, indices);
      for (var i = 0; i < copiedPages.length; i++) newDoc.addPage(copiedPages[i]);
      return await newDoc.save({ useObjectStreams: false });
    } catch (e) {
      console.error('unlockPdfToBytes failed', e);
      return null;
    }
  }

  /** 常见密码 + 1～4 位数字 + 日期 DDMMYYYY(2000～2030)，用于需要打开密码时暴力破解 */
  var COMMON_PASSWORDS = [
    '', '123456', 'password', '12345678', '1234', '12345', 'qwerty', '123456789',
    '1234567', '111111', '000000', '123123', 'abc123', 'password1', 'admin', 'root',
    'pdf', 'PDF', 'Pdf', 'pass', 'Pass', 'open', 'Open', 'secret', 'changeme'
  ];
  function pad2(n) { return n < 10 ? '0' + n : String(n); }
  function daysInMonth(m, y) {
    if (m === 2) return (y % 4 === 0 && (y % 100 !== 0 || y % 400 === 0)) ? 29 : 28;
    if (m === 4 || m === 6 || m === 9 || m === 11) return 30;
    return 31;
  }
  function buildPasswordList() {
    var seen = {};
    var list = [];
    function add(p) { if (seen[p]) return; seen[p] = true; list.push(p); }
    COMMON_PASSWORDS.forEach(add);
    for (var len = 1; len <= 4; len++) {
      var max = Math.pow(10, len);
      for (var n = 0; n < max; n++) {
        var s = String(n);
        while (s.length < len) s = '0' + s;
        add(s);
      }
    }
    for (var y = 2000; y <= 2030; y++) {
      for (var m = 1; m <= 12; m++) {
        for (var d = 1; d <= daysInMonth(m, y); d++) add(pad2(d) + pad2(m) + String(y));
      }
    }
    return list;
  }
  var CRACK_PASSWORD_LIST = null;
  function getCrackPasswordList() {
    if (!CRACK_PASSWORD_LIST) CRACK_PASSWORD_LIST = buildPasswordList();
    return CRACK_PASSWORD_LIST;
  }
  async function crackPdfPassword(bytes, onProgress) {
    var list = getCrackPasswordList();
    var total = list.length;
    for (var i = 0; i < list.length; i++) {
      var pwd = list[i];
      if (onProgress) onProgress(i + 1, total, pwd === '' ? '（空密码）' : pwd);
      if (await tryPassword(bytes, pwd)) return pwd;
    }
    return null;
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
    var titles = { encrypt: '选择 PDF 文件（加密）', unlock: '选择 PDF 文件（解锁）', compress: '选择 PDF 文件（体积优化）' };
    var intros = {
      encrypt: '支持多选，可对未加密的 PDF 进行加密。',
      unlock: '支持多选，可对需密码或有权限限制的 PDF 进行解锁（系统破解或解除限制）。',
      compress: '支持多选，可对未加密的 PDF 进行体积优化。已加密的 PDF 请先解锁后再使用本功能。'
    };
    if (titleEl) titleEl.textContent = titles[t] || titles.encrypt;
    if (descEl) descEl.innerHTML = (intros[t] || intros.encrypt) + ' <strong>全部在您设备本地处理，文件不上传服务器，隐私与安全有保障。</strong>';
  }

  function getCompressCompatibility() {
    var sel = document.getElementById('compressCompatibility');
    return sel ? sel.value : '1.7';
  }

  function getCompressMode() {
    var sel = document.getElementById('compressMode');
    return sel ? sel.value : 'standard';
  }

  function getCompressRasterQuality() {
    var el = document.getElementById('compressRasterQuality');
    if (!el) return 0.5;
    var v = parseFloat(el.value, 10);
    return isNaN(v) ? 0.5 : Math.max(0.4, Math.min(0.95, v));
  }

  function setActiveTab(tab) {
    state.currentTab = tab;
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
    var textEl = document.getElementById('pdfInputText');
    var n = getCurrentItems().length;
    if (textEl) textEl.textContent = n > 0 ? '已选 ' + n + ' 个文件，可继续添加' : '点击选择或拖入多个 PDF';
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
        '<span class="file-row-block-label">体积优化</span>' +
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
    if (textEl) textEl.textContent = n > 0 ? '已选 ' + n + ' 个文件，可继续添加' : '点击选择或拖入多个 PDF';
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
    if (overlay) {
      overlay.setAttribute('aria-hidden', show ? 'false' : 'true');
      overlay.classList.toggle('is-visible', !!show);
    }
    if (bar) bar.style.width = (percent == null ? 0 : percent) + '%';
    if (percentEl) percentEl.textContent = (percent == null ? 0 : Math.round(percent)) + '%';
  }

  function onActionClick(e) {
    const index = parseInt(e.target.getAttribute('data-action-index'), 10);
    const item = getCurrentItems()[index];
    if (!item || (item.resultProtection && item.resultProtection.blob)) return;

    if (item.encrypted) {
      if (!canUseUnlock()) {
        showGlobalHint('解锁免费次数已用完。', true);
        return;
      }
      openDecryptModal(index);
    } else {
      if (!canUseEncrypt()) {
        showGlobalHint('加密免费次数已用完。', true);
        return;
      }
      openEncryptModal(index);
    }
  }

  /**
   * 解除权限限制：优先请求后端 /api/unlock（无密码），失败则用前端 unlockPdfToBytes。
   */
  async function onUnlockClick(e) {
    var btn = e.target && e.target.closest ? e.target.closest('[data-unlock-index]') : e.target;
    var index = parseInt(btn ? btn.getAttribute('data-unlock-index') : (e.target && e.target.getAttribute('data-unlock-index')), 10);
    if (isNaN(index)) return;
    var item = getCurrentItems()[index];
    if (!item || !item.file || (item.resultProtection && item.resultProtection.blob)) return;
    if (item.encrypted === true) return;
    if (!canUseUnlock()) {
      showGlobalHint('解锁免费次数已用完。', true);
      return;
    }
    showGlobalHint('正在处理…');
    showDecryptProgress(true, 0);
    try {
      var form = new FormData();
      form.append('file', item.file);
      var res = await fetch(API_BASE + '/api/unlock', { method: 'POST', body: form });
      if (res.ok) {
        var blob = await res.blob();
        var name = (res.headers.get('Content-Disposition') || '').match(/filename="?([^";]+)"?/);
        var outName = (name && name[1]) ? decodeURIComponent(name[1]) : (nameWithoutExt(item.name) + '_unlocked.pdf');
        showDecryptProgress(false);
        item.resultProtection = { blob: blob, name: outName };
        if (!consumeUnlock()) {
          showGlobalHint('解锁免费次数已用完。', true);
          return;
        }
        updateUsageUI();
        renderFileList();
        showGlobalHint('已解除权限限制，请点击「下载」保存。');
        return;
      }
      var errJson = await res.json().catch(function () { return {}; });
      var errMsg = errJson.error || res.statusText;
      showDecryptProgress(false);
      showGlobalHint(errMsg || '解除失败。', true);
    } catch (err) {
      showDecryptProgress(false);
      try {
        var bytes = new Uint8Array(await item.file.arrayBuffer());
        var saved = await unlockPdfToBytes(bytes);
        if (saved != null && saved.length > 0) {
          item.resultProtection = { blob: new Blob([saved], { type: 'application/pdf' }), name: nameWithoutExt(item.name) + '_unlocked.pdf' };
          if (!consumeUnlock()) {
            showGlobalHint('解锁免费次数已用完。', true);
            return;
          }
          updateUsageUI();
          renderFileList();
          showGlobalHint('已解除权限限制，请点击「下载」保存。');
        } else {
          showGlobalHint('解除失败或该 PDF 无需解除。', true);
        }
      } catch (e2) {
        console.error(e2);
        showGlobalHint('解除失败：' + (err && err.message ? err.message : '未知错误'), true);
      }
    }
  }

  /**
   * 解密：进入此弹窗时已是「需打开密码」，直接走后端 /api/crack-and-unlock（不再先请求 /api/unlock，避免无谓 400）；后端不可用时用前端暴力破解。
   */
  async function onDecryptModalCrack() {
    var index = pendingDecryptIndex;
    if (index == null) return;
    var item = getCurrentItems()[index];
    if (!item || !item.file || !item.encrypted) { closeDecryptModal(); return; }
    if (!canUseUnlock()) {
      closeDecryptModal();
      showGlobalHint('解锁免费次数已用完。', true);
      return;
    }
    closeDecryptModal();
    showGlobalHint('');
    showDecryptProgress(true, 30);
    try {
      var formCrack = new FormData();
      formCrack.append('file', item.file);
      var resCrack = await fetch(API_BASE + '/api/crack-and-unlock', { method: 'POST', body: formCrack });
      if (resCrack.ok) {
        var blobCrack = await resCrack.blob();
        var nameCrack = (resCrack.headers.get('Content-Disposition') || '').match(/filename="?([^";]+)"?/);
        var outNameCrack = (nameCrack && nameCrack[1]) ? decodeURIComponent(nameCrack[1]) : (nameWithoutExt(item.name) + '_unlocked.pdf');
        showDecryptProgress(false);
        item.resultProtection = { blob: blobCrack, name: outNameCrack };
        if (!consumeUnlock()) {
          showGlobalHint('解锁免费次数已用完。', true);
          return;
        }
        updateUsageUI();
        renderFileList();
        showGlobalHint('已破解并解密，请点击「下载」保存。');
        return;
      }
      var errJson = await resCrack.json().catch(function () { return {}; });
      showDecryptProgress(false);
      showGlobalHint(errJson.error || '未能破解密码。', true);
    } catch (err) {
      showDecryptProgress(false);
      var bytes = new Uint8Array(await item.file.arrayBuffer());
      var saved = await unlockPdfToBytes(bytes);
      if (saved != null && saved.length > 0) {
        item.resultProtection = { blob: new Blob([saved], { type: 'application/pdf' }), name: nameWithoutExt(item.name) + '_unlocked.pdf' };
        if (!consumeUnlock()) {
          showGlobalHint('解锁免费次数已用完。', true);
          return;
        }
        updateUsageUI();
        renderFileList();
        showGlobalHint('已解除限制（无需密码），请点击「下载」保存。');
        return;
      }
      showDecryptProgress(true, 10);
      var total = getCrackPasswordList().length;
      var found = await crackPdfPassword(bytes, function (tried, tot) {
        var pct = 10 + (total ? (tried / total) * 85 : 0);
        showDecryptProgress(true, pct);
      });
      if (found !== null) {
        showDecryptProgress(false);
        await runDecrypt(index, found);
      } else {
        showDecryptProgress(false);
        showGlobalHint('未能破解密码。', true);
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
      showGlobalHint('体积优化免费次数已用完。', true);
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
    const url = URL.createObjectURL(result.blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = result.name || 'output.pdf';
    a.click();
    setTimeout(function () { URL.revokeObjectURL(url); }, 2000);
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
      const bytes = new Uint8Array(await item.file.arrayBuffer());
      const doc = await PDFDocument.load(bytes);
      var ownerPwd = (typeof crypto !== 'undefined' && crypto.getRandomValues)
        ? Array.from(crypto.getRandomValues(new Uint8Array(24)))
            .map(function (c) { return ('0' + c.toString(16)).slice(-2); })
            .join('')
        : pwd + '_' + Date.now() + '_owner';
      var p = permsFromModal || {};
      var userPwd = (typeof pwd === 'string' ? pwd : '') || '';
      var securityOpt = {
        userPassword: userPwd,
        ownerPassword: ownerPwd,
        permissions: {
          modifying: !p.modifying,
          copying: !p.copying,
          annotating: !p.annotating,
          documentAssembly: !p.documentAssembly,
          fillingForms: !p.fillingForms,
          contentAccessibility: !p.contentAccessibility,
          printing: p.printing ? false : 'highResolution'
        }
      };
      if (typeof doc.encrypt === 'function') {
        doc.encrypt(securityOpt);
      } else if (typeof doc.setProtection === 'function') {
        doc.setProtection(securityOpt);
      }
      var saved = await doc.save({ useObjectStreams: false });

      if (progressInterval) { clearInterval(progressInterval); progressInterval = null; }
      showEncryptProgress(true, 100, '加密完成');

      item.resultProtection = { blob: new Blob([saved], { type: 'application/pdf' }), name: nameWithoutExt(item.name) + '_encrypted.pdf' };
      if (!consumeEncrypt()) {
        showEncryptProgress(false);
        showGlobalHint('加密免费次数已用完。', true);
        return;
      }
      updateUsageUI();
      renderFileList();

      setTimeout(function () {
        showEncryptProgress(false);
        showGlobalHint('加密完成，请点击「下载」保存。');
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
      const bytes = new Uint8Array(await item.file.arrayBuffer());
      var saved = await unlockPdfToBytes(bytes, pwd);

      if (saved == null || saved.length === 0) {
        showLoading(false);
        showGlobalHint('解密失败，请检查密码是否正确。', true);
        return;
      }

      item.resultProtection = { blob: new Blob([saved], { type: 'application/pdf' }), name: nameWithoutExt(item.name) + '_unlocked.pdf' };
      if (!consumeUnlock()) {
        showLoading(false);
        showGlobalHint('解锁免费次数已用完。', true);
        return;
      }
      updateUsageUI();
      renderFileList();
      showLoading(false);
      showGlobalHint('解密成功，请点击「下载」保存。');
    } catch (e) {
      console.error(e);
      showLoading(false);
      showGlobalHint('解密失败：' + (e && e.message ? e.message : '未知错误'), true);
    }
  }

  function setPdfHeaderVersion(bytes, version) {
    var header = '%PDF-' + version + '\n';
    var enc = new TextEncoder();
    var headerBytes = enc.encode(header);
    for (var i = 0; i < headerBytes.length && i < bytes.length; i++) bytes[i] = headerBytes[i];
    return bytes;
  }

  /**
   * 将 Canvas 转为 JPEG 的 Uint8Array（供 pdf-lib embedJpg 使用）
   * @param {HTMLCanvasElement} canvas
   * @param {number} quality 0–1
   * @returns {Promise<Uint8Array>}
   */
  function canvasToJpegBytes(canvas, quality) {
    return new Promise(function (resolve, reject) {
      try {
        canvas.toBlob(function (blob) {
          if (!blob) { reject(new Error('Canvas toBlob failed')); return; }
          var reader = new FileReader();
          reader.onloadend = function () { resolve(new Uint8Array(reader.result)); };
          reader.onerror = reject;
          reader.readAsArrayBuffer(blob);
        }, 'image/jpeg', quality);
      } catch (e) { reject(e); }
    });
  }

  /**
   * 图片重采样压缩：用 pdf.js 将每页渲染为 Canvas，导出为 JPEG 后由 pdf-lib 打包成新 PDF，显著减小体积。
   * @param {Uint8Array} bytes 原 PDF
   * @param {function(number, number, string)?} onProgress (currentPage, totalPages, text)
   * @returns {Promise<Uint8Array>}
   */
  async function compressWithRaster(bytes, onProgress) {
    var pdfjsLib = window.pdfjsLib;
    if (!pdfjsLib || !pdfjsLib.getDocument) {
      throw new Error('图片重采样需要 PDF.js，请刷新页面后重试。');
    }
    var scale = 2;
    var jpegQuality = getCompressRasterQuality();
    var loadingTask = pdfjsLib.getDocument({ data: bytes });
    var pdfDoc = await loadingTask.promise;
    var numPages = pdfDoc.numPages;
    var canvas = document.createElement('canvas');
    var ctx = canvas.getContext('2d');
    var pageImages = [];

    for (var p = 1; p <= numPages; p++) {
      if (onProgress) onProgress(p, numPages, '正在渲染第 ' + p + '/' + numPages + ' 页…');
      var page = await pdfDoc.getPage(p);
      var viewport = page.getViewport({ scale: scale });
      canvas.width = viewport.width;
      canvas.height = viewport.height;
      await page.render({ canvasContext: ctx, viewport: viewport }).promise;
      var jpegBytes = await canvasToJpegBytes(canvas, jpegQuality);
      pageImages.push({ bytes: jpegBytes, width: viewport.width, height: viewport.height });
    }

    if (onProgress) onProgress(numPages, numPages, '正在生成新 PDF…');
    var newDoc = await PDFDocument.create();
    for (var i = 0; i < pageImages.length; i++) {
      var img = pageImages[i];
      var page = newDoc.addPage([img.width, img.height]);
      var embedded = await newDoc.embedJpg(img.bytes);
      page.drawImage(embedded, { x: 0, y: 0, width: img.width, height: img.height });
    }
    var version = getCompressCompatibility();
    var useObjectStreams = version !== '1.4';
    var saved = await newDoc.save({ useObjectStreams: useObjectStreams });
    if (version === '1.7') saved = setPdfHeaderVersion(saved, '1.7');
    return saved;
  }

  async function runCompress(index, pwd) {
    const item = getCurrentItems()[index];
    if (!item || !item.file) return;

    showGlobalHint('');
    var mode = getCompressMode();
    var version = getCompressCompatibility();
    var useObjectStreams = version !== '1.4';

    try {
      const bytes = new Uint8Array(await item.file.arrayBuffer());
      var saved;

      if (mode === 'raster') {
        showLoading(true, '正在准备图片重采样…');
        saved = await compressWithRaster(bytes, function (current, total, text) {
          showLoading(true, text);
        });
      } else {
        showLoading(true, '正在体积优化…');
        const loadOpts = item.encrypted ? { password: pwd || undefined } : {};
        const doc = await PDFDocument.load(bytes, loadOpts);
        saved = await doc.save({ useObjectStreams: useObjectStreams });
        if (version === '1.7') saved = setPdfHeaderVersion(saved, '1.7');
      }

      var origBytes = item.file.size;
      var newBytes = saved.length;
      var smaller = newBytes < origBytes;
      if (smaller) {
        item.resultCompress = { blob: new Blob([saved], { type: 'application/pdf' }), name: nameWithoutExt(item.name) + '_compressed.pdf' };
      } else {
        item.resultCompress = { blob: item.file, name: item.name };
      }
      if (!consumeCompress()) {
        showLoading(false);
        showGlobalHint('体积优化免费次数已用完。', true);
        return;
      }
      updateUsageUI();
      renderFileList();
      showLoading(false);
      var origKb = (origBytes / 1024).toFixed(1);
      var newKb = (newBytes / 1024).toFixed(1);
      var ratioPct = origBytes > 0 ? ((newBytes / origBytes) * 100).toFixed(1) : '0';
      var hint = smaller
        ? '体积已优化，请点击「下载」保存。原大小约 ' + origKb + ' KB，当前约 ' + newKb + ' KB，当前为原体积的 ' + ratioPct + '%。'
        : '文件体积已达最优。原大小约 ' + origKb + ' KB，无需优化。';
      if (smaller && parseFloat(ratioPct) >= 90 && mode !== 'raster') {
        hint += ' 该文件可能已经过压缩，可尝试「图片重采样」模式进一步缩小。';
      }
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
  if (decryptModalCancel) decryptModalCancel.addEventListener('click', closeDecryptModal);
  if (decryptModalCrack) decryptModalCrack.addEventListener('click', onDecryptModalCrack);
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
})();
