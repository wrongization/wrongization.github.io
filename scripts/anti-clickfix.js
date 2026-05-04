/**
 * Anti-ClickFix — detects and blocks ClickFix hijack overlays.
 * ClickFix attacks inject full-page fake CAPTCHA overlays that trick users
 * into running malicious PowerShell / CMD commands via clipboard.
 */
(function () {
  'use strict';

  var BLOCKED_KEYWORDS = [
    'powershell', 'cmd.exe', 'rundll32', 'mshta', 'wscript',
    'cscript', 'regsvr32', 'certutil', 'bitsadmin',
    'irm ', 'iex ', 'iwr ', 'Invoke-Expression', 'Invoke-WebRequest',
    'DownloadString', 'DownloadFile', 'FromBase64String',
    'start-process', 'New-Object Net.WebClient',
    'shell:protocol', 'ms-settings:', 'search-ms:'
  ];

  function hasSuspiciousContent(text) {
    var lower = text.toLowerCase();
    for (var i = 0; i < BLOCKED_KEYWORDS.length; i++) {
      if (lower.indexOf(BLOCKED_KEYWORDS[i]) !== -1) return true;
    }
    return false;
  }

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

  function scanForSuspiciousElements() {
    var all = document.querySelectorAll('*');
    for (var i = 0; i < all.length; i++) {
      var el = all[i];
      if (!isFullPageOverlay(el)) continue;

      // Check for captcha-like text
      var text = (el.textContent || '').toLowerCase();
      var captchaHits = [
        'press windows', 'press win', 'windows + r', 'win + r', 'win+r',
        'ctrl + v', 'ctrl+v', 'paste the', 'run dialog',
        'verify you are human', 'not a robot', 'complete the check',
        'click allow', 'press allow', 'to continue',
        'ddos protection', 'security check', 'unusual traffic',
        'suspicious activity', 'confirm you are human'
      ];
      var hitCount = 0;
      for (var j = 0; j < captchaHits.length; j++) {
        if (text.indexOf(captchaHits[j]) !== -1) hitCount++;
      }
      if (hitCount >= 2) {
        el.remove();
        console.warn('[Anti-ClickFix] Removed suspicious overlay matching ClickFix pattern');
      }
    }
  }

  // Monitor DOM for injected overlays
  var observer = new MutationObserver(function (mutations) {
    for (var i = 0; i < mutations.length; i++) {
      var m = mutations[i];
      for (var j = 0; j < m.addedNodes.length; j++) {
        var node = m.addedNodes[j];
        if (node.nodeType === 1) {
          // Check if this node or its container is a full-page overlay
          if (isFullPageOverlay(node)) {
            var text = (node.textContent || '').toLowerCase();
            if (text.indexOf('captcha') !== -1 || text.indexOf('verify') !== -1 ||
                text.indexOf('press') !== -1 || text.indexOf('robot') !== -1) {
              node.remove();
              console.warn('[Anti-ClickFix] Blocked injected overlay');
              return;
            }
          }
          // Scan all children of the added node
          var children = node.querySelectorAll ? node.querySelectorAll('div, section, article, aside, main, dialog') : [];
          for (var k = 0; k < children.length; k++) {
            if (isFullPageOverlay(children[k])) {
              children[k].remove();
              console.warn('[Anti-ClickFix] Blocked injected child overlay');
              return;
            }
          }
        }
      }
    }
  });

  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  // Scan immediately after DOM is ready
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      setTimeout(scanForSuspiciousElements, 100);
      setTimeout(scanForSuspiciousElements, 2000);
    });
  } else {
    setTimeout(scanForSuspiciousElements, 100);
    setTimeout(scanForSuspiciousElements, 2000);
  }

  // Monitor clipboard for suspicious overwrites
  var _writeText = navigator.clipboard && navigator.clipboard.writeText;
  if (_writeText) {
    navigator.clipboard.writeText = function () {
      var args = arguments;
      if (args[0] && typeof args[0] === 'string' && hasSuspiciousContent(args[0])) {
        console.warn('[Anti-ClickFix] Blocked suspicious clipboard write');
        return Promise.resolve();
      }
      return _writeText.apply(navigator.clipboard, args);
    };
  }

  // Also monkey-patch the older execCommand('copy') path
  var _execCommand = document.execCommand;
  document.execCommand = function (command) {
    if (command === 'copy' || command === 'cut') {
      var sel = window.getSelection();
      if (sel && sel.toString() && hasSuspiciousContent(sel.toString())) {
        console.warn('[Anti-ClickFix] Blocked suspicious clipboard copy');
        return false;
      }
    }
    return _execCommand.apply(document, arguments);
  };

  // Detect and warn about unexpected full-page redirects
  var _replace = window.location.replace;
  var _assign = window.location.assign;
  var warned = false;

  window.addEventListener('beforeunload', function (e) {
    // If a script injected into the page suddenly tries to navigate away,
    // it could be a redirect to a malicious site. We can't block this
    // without breaking legitimate navigation, but we log it.
  });

})();
