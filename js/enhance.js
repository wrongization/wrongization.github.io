/* 前端增强与性能细节脚本 */
(() => {
  const doc = document;
  /* 1. 渐显动画 IntersectionObserver */
  const observer = 'IntersectionObserver' in window ? new IntersectionObserver(entries => {
    entries.forEach(e => { if (e.isIntersecting) { e.target.classList.add('appear'); observer.unobserve(e.target); } });
  }, { rootMargin: '0px 0px -10% 0px', threshold: .15 }) : null;

  const markFadeSeq = () => {
    doc.querySelectorAll('.recent-post-item, .card-widget, article, .post-item').forEach(el => { el.classList.add('fade-seq'); observer && observer.observe(el); });
  };
  document.addEventListener('DOMContentLoaded', markFadeSeq);
  /* pjax 场景简单兼容 */
  doc.addEventListener('pjax:complete', markFadeSeq);

  /* 2. 顶部滚动进度条 */
  const scrollHandler = () => {
    const h = doc.documentElement; const max = h.scrollHeight - h.clientHeight; const p = max > 0 ? (h.scrollTop / max) * 100 : 0; h.style.setProperty('--scroll-progress', p.toFixed(2) + '%'); };
  window.addEventListener('scroll', scrollHandler, { passive: true });
  scrollHandler();

  /* 3. 背景渐变容器注入 */
  const webBg = doc.getElementById('web_bg');
  if (webBg && !webBg.querySelector('.animated-bg')) { const div = doc.createElement('div'); div.className = 'animated-bg'; webBg.appendChild(div); }

  /* 4. 图片懒加载增强：为未声明 loading 的图片添加 lazy 并添加 skeleton */
  const enhanceLazyImg = () => {
    doc.querySelectorAll('img:not([loading])').forEach(img => { img.setAttribute('loading','lazy'); });
    doc.querySelectorAll('.post-cover img').forEach(img => {
      if (img.complete) return; // 已加载
      const skel = doc.createElement('div'); skel.className='img-skel'; img.before(skel); img.dataset.loading = 'true';
      img.addEventListener('load', () => { img.dataset.loaded='true'; skel.remove(); });
      img.addEventListener('error', () => skel.remove());
    });
  };
  document.addEventListener('DOMContentLoaded', enhanceLazyImg);
  doc.addEventListener('pjax:complete', enhanceLazyImg);

  /* 5. 动态降低重型背景脚本在移动端的性能消耗 */
  const reduceHeavyEffects = () => {
    if (window.innerWidth < 900) {
      // 隐藏可能的 canvas_nest 画布
      doc.querySelectorAll('canvas').forEach(c => { if (c.style && /-1/.test(c.style.zIndex)) { c.style.opacity = .35; } });
    }
  };
  window.addEventListener('resize', reduceHeavyEffects);
  reduceHeavyEffects();

  /* 6. 预加载关键字体以减少 FOUT（可根据实际字体文件补充） */
  const preloadFonts = () => {
    const head = doc.head; if (!head) return; const existing = head.querySelector('link[data-auto-preload-font]'); if (existing) return;
    ['https://fonts.googleapis.com','https://fonts.gstatic.com'].forEach(href => { const l = doc.createElement('link'); l.rel='preconnect'; l.href=href; l.setAttribute('crossorigin',''); head.appendChild(l); });
  };
  preloadFonts();

  /* 7. 如果启用 pjax，监听页面切换恢复滚动条进度 */
  doc.addEventListener('pjax:send', () => { doc.documentElement.style.setProperty('--scroll-progress','0%'); });
  doc.addEventListener('pjax:complete', scrollHandler);
})();
