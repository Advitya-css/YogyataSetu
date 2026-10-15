/* YogyataSetu — small progressive enhancements. Pages work without JavaScript; this adds save, share, listen and comfort. */
(function () {
  var YS = window.YS || { t: {} };
  var KEY = 'ys_saved';

  function store(k, v) { try { if (v === undefined) return localStorage.getItem(k); localStorage.setItem(k, v); } catch (e) { return null; } }
  function getJSON(k, d) { try { return JSON.parse(store(k) || '') || d; } catch (e) { return d; } }
  function getSaved() { return getJSON(KEY, []); }
  function setSaved(a) { store(KEY, JSON.stringify(a)); }

  var toastEl = document.querySelector('[data-toast]'), toastTimer;
  function toast(msg) {
    if (!toastEl) return;
    toastEl.textContent = msg; toastEl.classList.add('show');
    clearTimeout(toastTimer); toastTimer = setTimeout(function () { toastEl.classList.remove('show'); }, 2000);
  }

  /* ---------- language & theme ---------- */
  var pick = document.querySelector('[data-lang-pick]');
  if (pick) pick.addEventListener('change', function () { location.href = pick.value; });
  var themeBtn = document.querySelector('[data-theme-toggle]');
  if (themeBtn) themeBtn.addEventListener('click', function () {
    var root = document.documentElement;
    var cur = root.getAttribute('data-theme') || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    var next = cur === 'dark' ? 'light' : 'dark';
    root.setAttribute('data-theme', next); store('ys_theme', next);
  });
  var back = document.querySelector('[data-back]');
  if (back && history.length > 1 && document.referrer && document.referrer.indexOf(location.host) > -1) {
    back.addEventListener('click', function (e) { e.preventDefault(); history.back(); });
  }

  /* ---------- save ---------- */
  function paintSaved() {
    var saved = getSaved();
    document.querySelectorAll('[data-save]').forEach(function (b) {
      var on = saved.indexOf(b.getAttribute('data-save')) > -1;
      b.setAttribute('aria-pressed', on ? 'true' : 'false');
      var label = b.querySelector('span'); if (label) label.textContent = on ? YS.t.saved : YS.t.save;
    });
    document.querySelectorAll('[data-saved-count]').forEach(function (c) { c.textContent = saved.length ? saved.length : ''; });
  }

  /* ---------- listen (text to speech in the page language) ---------- */
  var speaking = null;
  function stopSpeaking() {
    if (window.speechSynthesis) speechSynthesis.cancel();
    if (speaking) { var s = speaking.querySelector('span'); if (s) s.textContent = YS.t.listen; speaking = null; }
  }
  function pickVoice(lang) {
    var voices = speechSynthesis.getVoices(), base = lang.split('-')[0];
    return voices.filter(function (v) { return v.lang && v.lang.replace('_', '-').toLowerCase() === lang.toLowerCase(); })[0] ||
           voices.filter(function (v) { return v.lang && v.lang.toLowerCase().indexOf(base) === 0; })[0] || null;
  }
  function speak(btn) {
    if (speaking === btn) { stopSpeaking(); return; }
    stopSpeaking();
    var u = new SpeechSynthesisUtterance(btn.getAttribute('data-say'));
    u.lang = YS.speech || 'en-IN';
    var v = pickVoice(u.lang); if (v) u.voice = v;
    u.rate = 0.95; u.onend = stopSpeaking;
    speaking = btn; var s = btn.querySelector('span'); if (s) s.textContent = YS.t.stop;
    speechSynthesis.speak(u);
  }
  if (!('speechSynthesis' in window)) document.documentElement.classList.add('no-tts');

  /* ---------- share ---------- */
  function closeShares(except) {
    document.querySelectorAll('.share-pop.open').forEach(function (p) {
      if (p !== except) { p.classList.remove('open'); p.previousElementSibling.setAttribute('aria-expanded', 'false'); }
    });
  }
  function openShare(btn) {
    var url = new URL(btn.getAttribute('data-url'), location.href).href;
    var text = btn.getAttribute('data-text');
    if (navigator.share && matchMedia('(pointer: coarse)').matches) {
      navigator.share({ title: btn.getAttribute('data-title'), text: text, url: url }).catch(function () {});
      return;
    }
    var pop = btn.nextElementSibling, msg = text + '\n' + url;
    pop.querySelector('[data-wa]').href = 'https://wa.me/?text=' + encodeURIComponent(msg);
    pop.querySelector('[data-sms]').href = 'sms:?&body=' + encodeURIComponent(msg);
    pop.querySelector('[data-copy]').setAttribute('data-copy', url);
    var open = !pop.classList.contains('open');
    closeShares(pop); pop.classList.toggle('open', open); btn.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  document.addEventListener('click', function (e) {
    var b;
    if ((b = e.target.closest('[data-save]'))) {
      var id = b.getAttribute('data-save'), saved = getSaved(), i = saved.indexOf(id);
      if (i > -1) saved.splice(i, 1); else saved.unshift(id);
      setSaved(saved); paintSaved();
      if (i === -1) toast(YS.t.saved);
      return;
    }
    if ((b = e.target.closest('[data-share]'))) { openShare(b); return; }
    if ((b = e.target.closest('[data-copy]'))) {
      var link = b.getAttribute('data-copy');
      (navigator.clipboard ? navigator.clipboard.writeText(link) : Promise.reject()).then(function () { toast(YS.t.copied); }, function () { prompt('', link); });
      closeShares(); return;
    }
    if ((b = e.target.closest('[data-listen]'))) { speak(b); return; }
    if ((b = e.target.closest('[data-level-filter]'))) {
      document.querySelectorAll('[data-level-filter]').forEach(function (x) { x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); });
      applyFilters(); return;
    }
    if (!e.target.closest('.share-menu')) closeShares();
  });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeShares(); stopSpeaking(); } });

  /* ---------- results filters (type + need) ---------- */
  function applyFilters() {
    var lvBtn = document.querySelector('[data-level-filter][aria-pressed="true"]');
    var lv = lvBtn ? lvBtn.getAttribute('data-level-filter') : '';
    var catSel = document.querySelector('[data-cat-filter]'), cat = catSel ? catSel.value : '';
    document.querySelectorAll('[data-filterable] .row').forEach(function (li) {
      var okL = !lv || li.getAttribute('data-level') === lv;
      var okC = !cat || (' ' + li.getAttribute('data-cats') + ' ').indexOf(' ' + cat + ' ') > -1;
      li.hidden = !(okL && okC);
    });
    document.querySelectorAll('[data-filterable]').forEach(function (ul) {
      var any = ul.querySelector('.row:not([hidden])');
      ul.hidden = !any;
      var h = ul.previousElementSibling; if (h && h.classList.contains('group-sub')) { h.hidden = !any; h = h.previousElementSibling; }
      if (h) h.hidden = !any;
    });
  }
  var catSel = document.querySelector('[data-cat-filter]');
  if (catSel) catSel.addEventListener('change', applyFilters);

  /* ---------- browse filters submit on change ---------- */
  var auto = document.querySelector('[data-autosubmit]');
  if (auto) auto.querySelectorAll('select').forEach(function (s) { s.addEventListener('change', function () { auto.submit(); }); });

  /* ---------- sentence form ---------- */
  document.querySelectorAll('[data-sentence-form]').forEach(function (f) {
    var more = f.querySelector('[data-more]'), flag = f.querySelector('[data-more-flag]'), gender = f.querySelector('[name=gender]');
    function syncMore() { if (more && flag) flag.value = more.open ? '1' : ''; }
    function syncGender() {
      f.querySelectorAll('[data-female-only]').forEach(function (l) {
        var show = gender.value === 'female'; l.hidden = !show;
        if (!show) l.querySelector('input').checked = false;
      });
    }
    if (more) more.addEventListener('toggle', syncMore);
    if (gender) { gender.addEventListener('change', syncGender); syncGender(); }
    f.addEventListener('submit', function (e) {
      syncMore();
      var bad = Array.prototype.filter.call(f.querySelectorAll('[required]'), function (el) { return !el.value; });
      var age = f.querySelector('[name=age]');
      if (age.value && (age.value < 0 || age.value > 120)) bad.push(age);
      if (bad.length) { e.preventDefault(); bad[0].focus(); bad.forEach(function (el) { el.parentNode.classList.add('miss'); }); }
    });
    f.querySelectorAll('.blank select, .blank input').forEach(function (el) {
      el.addEventListener('input', function () { el.parentNode.classList.remove('miss'); });
    });
  });

  /* size each blank to its chosen answer (browsers without CSS field-sizing) */
  if (!(window.CSS && CSS.supports && CSS.supports('field-sizing', 'content'))) {
    var cv = document.createElement('canvas').getContext('2d');
    var fit = function (sel) {
      var cs = getComputedStyle(sel), opt = sel.options[sel.selectedIndex];
      cv.font = cs.fontWeight + ' ' + cs.fontSize + ' ' + cs.fontFamily;
      sel.style.width = Math.ceil(cv.measureText(opt ? opt.text : '').width + parseFloat(cs.fontSize) * 1.5) + 'px';
    };
    document.querySelectorAll('.blank select').forEach(function (sel) {
      fit(sel); sel.addEventListener('change', function () { fit(sel); });
      if (document.fonts) document.fonts.ready.then(function () { fit(sel); });
    });
  }

  /* ---------- document checklist remembers ticks ---------- */
  document.querySelectorAll('[data-docs]').forEach(function (ul) {
    var k = 'ys_docs_' + ul.getAttribute('data-docs'), done = getJSON(k, []);
    ul.querySelectorAll('input').forEach(function (c) {
      c.checked = done.indexOf(c.value) > -1;
      c.addEventListener('change', function () {
        var now = Array.prototype.filter.call(ul.querySelectorAll('input'), function (x) { return x.checked; }).map(function (x) { return x.value; });
        store(k, JSON.stringify(now));
      });
    });
  });

  /* ---------- saved page ---------- */
  var list = document.querySelector('[data-saved-list]');
  if (list) {
    var ids = getSaved(), empty = list.querySelector('[data-saved-empty]');
    if (!ids.length) { empty.hidden = false; }
    else {
      fetch(list.getAttribute('data-src') + '?ids=' + encodeURIComponent(ids.join(',')))
        .then(function (r) { return r.text(); })
        .then(function (html) { list.insertAdjacentHTML('beforeend', html); paintSaved(); if (!list.querySelector('.row')) empty.hidden = false; });
      list.addEventListener('click', function (e) {
        var b = e.target.closest('[data-save]');
        if (b && b.getAttribute('aria-pressed') === 'true') {
          var li = b.closest('.row'); if (li) li.remove();
          if (!list.querySelector('.row')) { var ul = list.querySelector('.rows'); if (ul) ul.remove(); empty.hidden = false; }
        }
      });
    }
  }

  paintSaved();

  /* ---------- switch to the bottom bar when the top menu does not fit (long language labels) ---------- */
  (function () {
    var root = document.documentElement, row = document.querySelector('.head-row');
    if (!row) return;
    function fit() {
      root.classList.remove('nav-compact');
      if (row.scrollWidth > row.clientWidth + 1) root.classList.add('nav-compact');
    }
    fit();
    window.addEventListener('resize', fit);
    if (document.fonts && document.fonts.ready) document.fonts.ready.then(fit);
  })();
  /* ---------- scheme checker: paste button, focus the answer ---------- */
  (function () {
    var box = document.getElementById('q'), paste = document.querySelector('[data-paste]');
    if (box && paste && navigator.clipboard && navigator.clipboard.readText) {
      paste.hidden = false;
      paste.addEventListener('click', function () {
        navigator.clipboard.readText().then(function (txt) {
          if (txt) { box.value = txt.slice(0, 4000); box.focus(); toast(YS.t.pasted); }
        }, function () { box.focus(); });
      });
    }
    if (box) box.addEventListener('keydown', function (e) {
      if (e.key === 'Enter' && (e.ctrlKey || e.metaKey) && box.form) box.form.requestSubmit ? box.form.requestSubmit() : box.form.submit();
    });
    var res = document.querySelector('.verdict');
    if (res && location.hash === '#result') res.focus({ preventScroll: true });
  })();
})();
