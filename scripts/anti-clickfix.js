/**
 * Anti-ClickFix v2 — 检测 + 定位 + 拦截 ClickFix 劫持攻击。
 * 在拦截的同时将完整取证信息输出到 console 和 localStorage，
 * 方便部署后定位真正的注入源。
 */
(function () {
  'use strict';

  // ==================== 取证存储 ====================
  var FORENSIC_KEY = '__acf_forensic__';
  var forensicLogs = [];

  function loadLogs() {
    try {
      var raw = localStorage.getItem(FORENSIC_KEY);
      return raw ? JSON.parse(raw) : [];
    } catch (e) { return []; }
  }

  function saveLog(entry) {
    forensicLogs.push(entry);
    if (forensicLogs.length > 50) forensicLogs = forensicLogs.slice(-50);
    try {
      localStorage.setItem(FORENSIC_KEY, JSON.stringify(forensicLogs));
    } catch (e) {}
    // Also expose globally for easy inspection
    window.__ACF_FORENSIC__ = forensicLogs;
  }

  forensicLogs = loadLogs();
  window.__ACF_FORENSIC__ = forensicLogs;

  // ==================== 源码追踪 ====================
  var loadedScripts = [];
  var scriptObserver = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var m = mutations[i];
      for (var j = 0; j < m.addedNodes.length; j++) {
        var node = m.addedNodes[j];
        if (node.nodeName === 'SCRIPT') {
          loadedScripts.push({
            src: node.src || '(inline)',
            time: Date.now(),
            text: node.src ? '' : (node.textContent || '').slice(0, 500)
          });
        }
      }
    }
  });
  scriptObserver.observe(document.documentElement, { childList: true, subtree: true });

  function getRecentScripts(withinMs) {
    var cutoff = Date.now() - (withinMs || 3000);
    return loadedScripts.filter(function (s) { return s.time >= cutoff; });
  }

  // ==================== 检测关键词 ====================
  var MALICIOUS_CMD_KEYWORDS = [
    'powershell', 'cmd.exe', 'rundll32', 'mshta', 'wscript',
    'cscript', 'regsvr32', 'certutil', 'bitsadmin',
    'irm ', 'iex ', 'iwr ', 'Invoke-Expression', 'Invoke-WebRequest',
    'DownloadString', 'DownloadFile', 'FromBase64String',
    'start-process', 'New-Object Net.WebClient',
    'shell:protocol', 'ms-settings:', 'search-ms:'
  ];

  var CAPTCHA_KEYWORDS = [
    'press windows', 'press win', 'windows + r', 'win + r', 'win+r',
    'ctrl + v', 'ctrl+v', 'paste the', 'run dialog',
    'verify you are human', 'not a robot', 'complete the check',
    'click allow', 'press allow', 'to continue',
    'ddos protection', 'security check', 'unusual traffic',
    'suspicious activity', 'confirm you are human',
    'i am not a robot', 'bot detected', 'human verification',
    'cloudflare', 'captcha', 'please verify'
  ];

  // ==================== DOM 操作 Hook ====================
  var domMutationStack = [];

  function hookMethod(obj, method, fn) {
    var original = obj[method];
    obj[method] = function () {
      try { fn.apply(this, arguments); } catch (e) {}
      return original.apply(this, arguments);
    };
  }

  // Hook innerHTML / outerHTML setters on HTMLElement prototype
  var innerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML') ||
                            Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'innerHTML');
  if (innerHTMLDescriptor && innerHTMLDescriptor.set) {
    var _setInnerHTML = innerHTMLDescriptor.set;
    Object.defineProperty(Element.prototype, 'innerHTML', {
      set: function (value) {
        if (typeof value === 'string' && value.length > 200) {
          var lower = value.toLowerCase();
          var hit = false;
          for (var i = 0; i < CAPTCHA_KEYWORDS.length; i++) {
            if (lower.indexOf(CAPTCHA_KEYWORDS[i]) !== -1) { hit = true; break; }
          }
          if (hit) {
            domMutationStack.push({
              method: 'innerHTML',
              target: this.tagName + (this.id ? '#' + this.id : '') + (this.className ? '.' + this.className.split(' ')[0] : ''),
              html: value.slice(0, 3000),
              stack: new Error().stack,
              time: Date.now()
            });
          }
        }
        return _setInnerHTML.call(this, value);
      },
      get: innerHTMLDescriptor.get,
      configurable: true
    });
  }

  // Hook appendChild
  hookMethod(Node.prototype, 'appendChild', function (child) {
    if (child && child.nodeType === 1 && isSuspiciousElement(child)) {
      domMutationStack.push({
        method: 'appendChild',
        target: describeElement(child),
        html: child.outerHTML ? child.outerHTML.slice(0, 3000) : '',
        stack: new Error().stack,
        time: Date.now()
      });
    }
  });

  // Hook insertBefore
  hookMethod(Node.prototype, 'insertBefore', function (child) {
    if (child && child.nodeType === 1 && isSuspiciousElement(child)) {
      domMutationStack.push({
        method: 'insertBefore',
        target: describeElement(child),
        html: child.outerHTML ? child.outerHTML.slice(0, 3000) : '',
        stack: new Error().stack,
        time: Date.now()
      });
    }
  });

  function describeElement(el) {
    try {
      return el.tagName + (el.id ? '#' + el.id : '') + (el.className && typeof el.className === 'string' ? '.' + el.className.split(' ')[0] : '');
    } catch (e) { return '(unknown)'; }
  }

  function isSuspiciousElement(el) {
    try {
      if (el.nodeType !== 1) return false;
      if (!el.textContent) return false;
      var text = el.textContent.toLowerCase();
      var hits = 0;
      for (var i = 0; i < CAPTCHA_KEYWORDS.length; i++) {
        if (text.indexOf(CAPTCHA_KEYWORDS[i]) !== -1) hits++;
        if (hits >= 2) return true;
      }
      return false;
    } catch (e) { return false; }
  }

  // ==================== 覆盖层检测 ====================
  function isFullPageOverlay(el) {
    if (!el || el.nodeType !== 1) return false;
    var style = window.getComputedStyle(el);
    if (style.position !== 'fixed' && style.position !== 'absolute') return false;
    if (style.display === 'none' || style.visibility === 'hidden') return false;
    if (parseFloat(style.opacity) === 0) return false;
    var zIndex = parseInt(style.zIndex, 10);
    if (isNaN(zIndex) || zIndex < 1000) return false;
    var rect = el.getBoundingClientRect();
    var vw = window.innerWidth;
    var vh = window.innerHeight;
    return rect.width >= vw * 0.8 && rect.height >= vh * 0.8;
  }

  function countCaptchaHits(text) {
    var hits = 0;
    var matched = [];
    for (var j = 0; j < CAPTCHA_KEYWORDS.length; j++) {
      if (text.indexOf(CAPTCHA_KEYWORDS[j]) !== -1) {
        hits++;
        matched.push(CAPTCHA_KEYWORDS[j]);
      }
    }
    return { hits: hits, matched: matched };
  }

  function countMaliciousCmdHits(text) {
    var hits = 0;
    var matched = [];
    for (var j = 0; j < MALICIOUS_CMD_KEYWORDS.length; j++) {
      if (text.indexOf(MALICIOUS_CMD_KEYWORDS[j]) !== -1) {
        hits++;
        matched.push(MALICIOUS_CMD_KEYWORDS[j]);
      }
    }
    return { hits: hits, matched: matched };
  }

  // ==================== 绘图取证面板 ====================
  var reportPanel = null;

  function showReportPanel(report) {
    // Remove existing panel
    if (reportPanel) reportPanel.remove();

    var panel = document.createElement('div');
    panel.id = '__acf_report__';
    panel.style.cssText =
      'position:fixed;bottom:10px;right:10px;z-index:2147483647;' +
      'max-width:480px;max-height:70vh;overflow-y:auto;' +
      'background:#1a1a2e;color:#e0e0e0;border:2px solid #e74c3c;' +
      'border-radius:8px;padding:14px;font:12px/1.5 monospace;' +
      'box-shadow:0 0 20px rgba(231,76,60,0.5);';

    var title = document.createElement('div');
    title.style.cssText = 'color:#e74c3c;font-weight:bold;font-size:14px;margin-bottom:8px;';
    title.textContent = 'ClickFix DETECTED & BLOCKED';

    var close = document.createElement('button');
    close.textContent = 'X';
    close.style.cssText =
      'position:absolute;top:6px;right:10px;background:none;border:none;' +
      'color:#e74c3c;font-size:16px;cursor:pointer;';
    close.onclick = function () { panel.remove(); reportPanel = null; };

    var content = document.createElement('pre');
    content.style.cssText = 'white-space:pre-wrap;word-break:break-all;margin:0;font:inherit;';
    content.textContent = formatReport(report);

    panel.appendChild(title);
    panel.appendChild(close);
    panel.appendChild(content);
    document.body.appendChild(panel);
    reportPanel = panel;
  }

  function formatReport(report) {
    var lines = [];
    lines.push('Time:        ' + new Date(report.time).toISOString());
    lines.push('Page:        ' + report.pageUrl);
    lines.push('User-Agent:  ' + report.userAgent);
    lines.push('Detector:    ' + report.detector);
    lines.push('');
    lines.push('--- CAPTCHA Keywords Matched ---');
    report.captchaMatched.forEach(function (kw) { lines.push('  * "' + kw + '"'); });
    lines.push('');
    if (report.maliciousMatched && report.maliciousMatched.length > 0) {
      lines.push('--- Malicious CMD Keywords ---');
      report.maliciousMatched.forEach(function (kw) { lines.push('  * "' + kw + '"'); });
      lines.push('');
    }
    if (report.recentScripts && report.recentScripts.length > 0) {
      lines.push('--- Recently Loaded Scripts (possible source) ---');
      report.recentScripts.forEach(function (s) {
        lines.push('  ' + s.src + ' (' + new Date(s.time).toISOString() + ')');
      });
      lines.push('');
    }
    if (report.domStack && report.domStack.length > 0) {
      lines.push('--- DOM Mutation Trace ---');
      report.domStack.forEach(function (m) {
        lines.push('  Method:  ' + m.method);
        lines.push('  Target:  ' + m.target);
        lines.push('  Time:    ' + new Date(m.time).toISOString());
        lines.push('  Stack:   ' + (m.stack || '(none)').split('\n').slice(0, 5).join('\n           '));
        lines.push('  ---');
      });
      lines.push('');
    }
    lines.push('--- Overlay HTML (first 2000 chars) ---');
    lines.push(report.overlayHtml.slice(0, 2000));
    lines.push('');
    lines.push('--- Full Text Content (first 2000 chars) ---');
    lines.push(report.fullText.slice(0, 2000));
    lines.push('');
    lines.push('>>> All forensic data saved to localStorage key: ' + FORENSIC_KEY);
    lines.push('>>> Access via: window.__ACF_FORENSIC__');
    return lines.join('\n');
  }

  // ==================== 核心检测逻辑 ====================
  function buildForensicReport(el, detector) {
    var text = (el.textContent || '').toLowerCase();
    var captchaResult = countCaptchaHits(text);
    var cmdResult = countMaliciousCmdHits(text);
    var overlayHtml = '';
    try { overlayHtml = el.outerHTML || el.innerHTML || ''; } catch (e) {}

    return {
      time: Date.now(),
      pageUrl: window.location.href,
      userAgent: navigator.userAgent,
      detector: detector,
      captchaMatched: captchaResult.matched,
      captchaHitCount: captchaResult.hits,
      maliciousMatched: cmdResult.matched,
      maliciousHitCount: cmdResult.hits,
      recentScripts: getRecentScripts(5000),
      domStack: domMutationStack.slice(-10),
      overlayHtml: overlayHtml,
      fullText: el.textContent || '',
      elementTag: el.tagName,
      elementId: el.id || '',
      elementClass: (el.className && typeof el.className === 'string') ? el.className : '',
      computedZIndex: (function () {
        try { return window.getComputedStyle(el).zIndex; } catch (e) { return 'N/A'; }
      })()
    };
  }

  function handleDetection(el, detector) {
    // Build forensic report BEFORE removing
    var report = buildForensicReport(el, detector);

    // Log to console in a highly visible way
    console.group('%c[Anti-ClickFix] CLICKFIX ATTACK DETECTED & BLOCKED',
      'color:red;font-size:16px;font-weight:bold;');
    console.log('%cDetection: %c' + detector,
      'color:#e74c3c;font-weight:bold;', 'color:#e0e0e0;');
    console.log('%cCaptcha keywords matched: %c' + report.captchaMatched.join(', '),
      'color:#e74c3c;', 'color:#f39c12;');
    if (report.maliciousMatched.length > 0) {
      console.log('%cMalicious CMD keywords: %c' + report.maliciousMatched.join(', '),
        'color:#e74c3c;', 'color:#e74c3c;');
    }
    console.log('%cRecent scripts (possible source):',
      'color:#e74c3c;font-weight:bold;');
    report.recentScripts.forEach(function (s) {
      console.log('  %c' + s.src + ' %c@ ' + new Date(s.time).toISOString(),
        'color:#f39c12;', 'color:#888;');
    });
    if (report.domStack.length > 0) {
      console.log('%cDOM mutation call stack:', 'color:#e74c3c;font-weight:bold;');
      report.domStack.forEach(function (m) {
        console.log('  %c' + m.method + ' %c-> ' + m.target,
          'color:#f39c12;', 'color:#888;');
        if (m.stack) console.log('  %c' + m.stack.split('\n').slice(1, 6).join('\n  '),
          'color:#666;');
      });
    }
    console.log('%cSuspicious HTML (check for CDN/injection source URLs):',
      'color:#e74c3c;font-weight:bold;');
    console.log(report.overlayHtml);
    console.log('%cFull forensic report saved. Access via:',
      'color:#f39c12;');
    console.log('  localStorage.getItem("' + FORENSIC_KEY + '")');
    console.log('  window.__ACF_FORENSIC__');
    console.groupEnd();

    // Save to persistent storage
    saveLog(report);

    // Show visible report panel
    try { showReportPanel(report); } catch (e) {}

    // Remove the malicious element
    try { el.remove(); } catch (e) {}

    return report;
  }

  // ==================== 扫描检测 ====================
  function scanForSuspiciousElements() {
    var all = document.querySelectorAll('*');
    for (var i = 0; i < all.length; i++) {
      var el = all[i];
      if (!isFullPageOverlay(el)) continue;
      var text = (el.textContent || '').toLowerCase();
      var result = countCaptchaHits(text);
      if (result.hits >= 2) {
        handleDetection(el, 'delayed-scan');
      }
    }
  }

  // ==================== MutationObserver ====================
  var observer = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var m = mutations[i];
      for (var j = 0; j < m.addedNodes.length; j++) {
        var node = m.addedNodes[j];
        if (node.nodeType !== 1) continue;

        // Direct overlay injection
        if (isFullPageOverlay(node)) {
          var text = (node.textContent || '').toLowerCase();
          var result = countCaptchaHits(text);
          if (result.hits >= 1) {
            handleDetection(node, 'mutation-direct-overlay');
            return;
          }
        }

        // Overlay inside added container
        var candidates = node.querySelectorAll ?
          node.querySelectorAll('div, section, article, aside, main, dialog, form') : [];
        for (var k = 0; k < candidates.length; k++) {
          if (isFullPageOverlay(candidates[k])) {
            var t = (candidates[k].textContent || '').toLowerCase();
            var r = countCaptchaHits(t);
            if (r.hits >= 1) {
              handleDetection(candidates[k], 'mutation-child-overlay');
              return;
            }
          }
        }

        // Broad scan for any injected element with captcha text
        if (node.querySelectorAll) {
          var allInside = node.querySelectorAll('*');
          for (var l = 0; l < Math.min(allInside.length, 500); l++) {
            var inner = allInside[l];
            var innerText = (inner.textContent || '').toLowerCase();
            var innerResult = countCaptchaHits(innerText);
            if (innerResult.hits >= 2) {
              // Check if it's large enough to be an overlay
              try {
                var rect = inner.getBoundingClientRect();
                if (rect.width > window.innerWidth * 0.5 && rect.height > window.innerHeight * 0.5) {
                  handleDetection(inner, 'mutation-broad-scan');
                  return;
                }
              } catch (e) {}
            }
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['style', 'class']
  });

  // ==================== 定时扫描 ====================
  function scheduleScans() {
    setTimeout(function () { scanForSuspiciousElements(); }, 100);
    setTimeout(function () { scanForSuspiciousElements(); }, 500);
    setTimeout(function () { scanForSuspiciousElements(); }, 1500);
    setTimeout(function () { scanForSuspiciousElements(); }, 3000);
    setTimeout(function () { scanForSuspiciousElements(); }, 5000);
    // Continue periodic scanning
    setInterval(function () { scanForSuspiciousElements(); }, 8000);
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', scheduleScans);
  } else {
    scheduleScans();
  }

  // ==================== 剪贴板保护（带取证） ====================
  var _writeText = navigator.clipboard && navigator.clipboard.writeText;
  if (_writeText) {
    navigator.clipboard.writeText = function () {
      var args = arguments;
      if (args[0] && typeof args[0] === 'string') {
        var cmdResult = countMaliciousCmdHits(args[0].toLowerCase());
        if (cmdResult.hits > 0) {
          var clipReport = {
            time: Date.now(),
            pageUrl: window.location.href,
            userAgent: navigator.userAgent,
            detector: 'clipboard-writeText',
            captchaMatched: [],
            maliciousMatched: cmdResult.matched,
            maliciousHitCount: cmdResult.hits,
            recentScripts: getRecentScripts(5000),
            domStack: domMutationStack.slice(-10),
            overlayHtml: '',
            fullText: 'CLIPBOARD CONTENT: ' + args[0],
            clipboardContent: args[0]
          };
          console.group('%c[Anti-ClickFix] MALICIOUS CLIPBOARD WRITE BLOCKED',
            'color:red;font-size:16px;font-weight:bold;');
          console.log('%cBlocked content:', 'color:#e74c3c;');
          console.log(args[0]);
          console.log('%cRecent scripts:', 'color:#e74c3c;');
          getRecentScripts(5000).forEach(function (s) {
            console.log('  ' + s.src);
          });
          console.groupEnd();
          saveLog(clipReport);
          try { showReportPanel(clipReport); } catch (e) {}
          return Promise.resolve();
        }
      }
      return _writeText.apply(navigator.clipboard, args);
    };
  }

  // ==================== 暴露 API ====================
  window.__ACF__ = {
    getLogs: function () { return forensicLogs; },
    getRecentScripts: getRecentScripts,
    scanNow: scanForSuspiciousElements,
    clearLogs: function () {
      forensicLogs = [];
      try { localStorage.removeItem(FORENSIC_KEY); } catch (e) {}
    },
    dumpReport: function () {
      if (forensicLogs.length === 0) { console.log('[ACF] No incidents recorded.'); return; }
      forensicLogs.forEach(function (r, i) {
        console.group('[ACF] Incident #' + (i + 1) + ' at ' + new Date(r.time).toISOString());
        console.log(formatReport(r));
        console.groupEnd();
      });
    }
  };

  console.log('%c[Anti-ClickFix v2] Active. Detection + forensic logging enabled.%c\n' +
    'Commands: __ACF__.dumpReport() | __ACF__.getLogs() | __ACF__.clearLogs()',
    'color:#27ae60;font-weight:bold;', 'color:#888;');

})();
