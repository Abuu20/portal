'use strict';
/* PORTAL front end, part 4/4: opening windows, running a search, status bar, toasts, drag-and-drop and start-up. */
    let lastQuery = '';
    function reportText() {
      const ws = [...wins.values()].filter(w => w.res && !w.res.error && w.id !== 'ai' && w.id !== 'diff').sort((a, b) => a.seq - b.seq);
      const L = ['PORTAL REPORT', `Generated: ${new Date().toISOString()}`, `Target: ${lastQuery || '(file)'}`, ''];
      for (const w of ws) L.push('='.repeat(60), resText(w), '');
      return L.join('\n');
    }

    function downloadReport() {
      if (![...wins.values()].some(w => w.res)) return toast('Run a scan first');
      const slug = (lastQuery || 'file').replace(/[^a-z0-9]+/gi, '-').replace(/^-|-$/g, '').slice(0, 40) || 'scan';
      const url = URL.createObjectURL(new Blob([reportText()], { type: 'text/plain' }));
      const a = el('a', { href: url, download: `portal-report-${slug}.txt` });
      document.body.append(a); a.click(); a.remove();
      sfx.click();
      setTimeout(() => URL.revokeObjectURL(url), 2000);
    }

    /* =====================================================================
     L oading, pi*vots, root window, status
     ===================================================================== */
    async function load(w) {
      w.el.classList.add('loading'); w.el.classList.remove('error');
      const run = ++w.run, sess = w.session;
      const res = await (w.spec.loader ? w.spec.loader()
      : api(`/api/run?module=${encodeURIComponent(w.spec.module)}&q=${encodeURIComponent(w.spec.q)}`));
      if (sess !== session || !wins.has(w.id) || run !== w.run) return;
      renderBody(w, res);
      fitHeight(w);
      updateRoot();
      relayout();
      if (!res.error) autoPivots(w, res);
    }

    function autoPivots(w, res) {
      if (snapshotMode || w.depth >= MAX_DEPTH) return;
      for (const p of res.pivots || []) {
        if (!p.auto || autoCount >= MAX_AUTO) continue;
        autoCount++;
        openWindow({ module: p.module, q: p.q, title: MODULE_TITLES[p.module] || p.module, depth: w.depth + 1, parent: w.id });
      }
    }

    function openWindow(spec) {
      const id = spec.id || `${spec.module}|${spec.q}`;
      const existing = wins.get(id);
      if (existing) {
        if (spec.parent && !edges.some(e => e.a === spec.parent && e.b === id)) edges.push({ a: spec.parent, b: id });
        if (existing.min) restore(existing); else flash(existing);
        dirty();
        return existing;
      }
      const w = createWindow({ ...spec, id, sub: spec.sub ?? (spec.module === 'file' ? '' : spec.q) });
      if (spec.parent) edges.push({ a: spec.parent, b: id });
      relayout();
      load(w);
      return w;
    }

    function makeRoot(plan) {
      const w = createWindow({ id: 'root', title: 'TARGET', icon: '◉', depth: 0, parent: null, sub: plan.label });
      w.el.classList.remove('loading');
      w.res = { highlights: [], sections: [{ title: plan.label, rows: [['Query', plan.value]] }] };
      w.body.replaceChildren(el('div', { class: 'chips', id: 'rootchips' }),
                             el('div', { class: 'sec' }, el('h4', { text: plan.label }),
                                el('table', {}, el('tr', {}, el('td', { text: 'Query' }), el('td', { text: plan.value, class: 'tone-info' })))));
      updateRoot();
      relayout();
    }

    let wasPending = false, doneTimer = null;
    function updateStatus() {
      let bad = 0, warn = 0, ok = 0, pending = 0, n = 0;
      for (const x of wins.values()) {
        if (x.id === 'root') continue;
        n++;
        if (x.el.classList.contains('loading')) pending++;
        else if (x.sev === 'bad') bad++;
        else if (x.sev === 'warn') warn++;
        else if (x.sev === 'ok') ok++;
      }
      $('#st-win').textContent = String(n);
      $('#st-bad').textContent = String(bad); $('#st-bad').parentElement.classList.toggle('on', bad > 0);
      $('#st-warn').textContent = String(warn); $('#st-warn').parentElement.classList.toggle('on', warn > 0);
      $('#st-ok').textContent = String(ok); $('#st-ok').parentElement.classList.toggle('on', ok > 0);
      $('#st-run').textContent = String(pending); $('#st-run').parentElement.classList.toggle('on', pending > 0);
      $('#progress').classList.toggle('on', pending > 0);
      return { bad, warn, ok, pending };
    }

    function updateRoot() {
      const { bad, warn, ok, pending } = updateStatus();
      clearTimeout(doneTimer);
      if (pending > 0) wasPending = true;
      else if (wasPending) {
        doneTimer = setTimeout(() => { if (updateStatus().pending === 0) { wasPending = false; sfx.done(bad > 0); hooks.done(); } }, 700);
      }
      const w = wins.get('root');
      if (!w) return;
      const c = $('#rootchips', w.body);
      if (!c) return;
      c.replaceChildren(...[
        chipEl({ label: 'critical', value: bad, tone: bad ? 'bad' : 'info' }),
                        chipEl({ label: 'warnings', value: warn, tone: warn ? 'warn' : 'info' }),
                        chipEl({ label: 'clean', value: ok, tone: ok ? 'ok' : 'info' }),
                        pending ? chipEl({ label: 'running', value: pending, tone: 'info' }) : null,
      ].filter(Boolean));
      setSev(w, bad ? 'bad' : warn ? 'warn' : pending ? 'info' : 'ok');
    }

    /* =====================================================================
     A ctions    *
     ===================================================================== */
    function reset() {
      session++; autoCount = 0; seq = 0; hoverId = null; hoverHead = null; wasPending = false;
      snapshotMode = false; hooks.reset();
      clearTimeout(doneTimer);
      wins.forEach(w => w.el.remove());
      wins.clear(); edges = [];
      wires.replaceChildren();
      empty.classList.remove('gone');
      renderDock(); updateStatus();
      relayout();
    }

    async function search(q) {
      q = q.trim();
      if (!q) return;
      reset();
      sfx.scan();
      const plan = await api('/api/plan?q=' + encodeURIComponent(q));
      if (plan.error) { sfx.error(); return toast(plan.error); }
      empty.classList.add('gone');
      lastQuery = plan.value; scanType = plan.type;
      makeRoot(plan);
      for (const m of plan.modules) openWindow({ module: m.module, q: m.q, title: m.title, depth: 1, parent: 'root' });
      try { history.replaceState(null, '', '#' + encodeURIComponent(q)); } catch { /* ignore */ }
    }

    function uploadFile(file) {
      if (!file) return;
      reset();
      sfx.scan();
      lastQuery = file.name; scanType = 'file';
      makeRoot({ label: 'Uploaded file', value: `${file.name} (${file.size.toLocaleString()} bytes)` });
      const fd = new FormData();
      fd.append('file', file, file.name);
      openWindow({ id: `file|${Date.now()}`, module: 'file', title: 'File analysis', sub: file.name, depth: 1, parent: 'root',
                 loader: () => api('/api/file', { method: 'POST', body: fd }) });
      $('#q').value = '';
    }

    let toastTimer;
    function toast(msg, good) {
      const t = $('#toast');
      t.textContent = msg; t.classList.toggle('good', !!good); t.classList.add('on');
      clearTimeout(toastTimer); toastTimer = setTimeout(() => t.classList.remove('on'), 3500);
    }

    function setLayout(mode) {
      layoutMode = mode;
      store.set('portal.layout', mode);
      sfx.click();
      applyLayoutMode();
    }
    function toggleLines() {
      if (layoutMode === 'tiles') { linesTiles = !linesTiles; store.set('portal.linesTiles', linesTiles ? '1' : '0'); }
      else { linesFlow = !linesFlow; store.set('portal.linesFlow', linesFlow ? '1' : '0'); }
      sfx.click(); dirty();
    }
    function syncSoundBtn() {
      const b = $('#sound');
      b.textContent = sfx.on ? '🔊' : '🔇';
      b.classList.toggle('off', !sfx.on);
      b.title = sfx.on ? 'Sound on (M to mute)' : 'Sound off (M to unmute)';
    }

    /* ---------- wiring ---------- */
    const input = $('#q');
    $('#go').addEventListener('click', () => search(input.value));
    input.addEventListener('keydown', e => { if (e.key === 'Enter') search(input.value); });
    $('#pick').addEventListener('click', () => { sfx.click(); $('#file').click(); });
    $('#file').addEventListener('change', e => { uploadFile(e.target.files[0]); e.target.value = ''; });
    $('#layout').addEventListener('click', () => setLayout(layoutMode === 'tiles' ? 'flow' : 'tiles'));
    $('#report').addEventListener('click', downloadReport);
    $('#shareAll').addEventListener('click', e => {
      if (![...wins.values()].some(w => w.res)) return toast('Run a scan first');
      openMenu(e.currentTarget, shareItems(reportText(), 'Portal report'));
    });
    $('#clear').addEventListener('click', () => { sfx.close(); reset(); input.value = ''; history.replaceState(null, '', location.pathname); });
    $('#sound').addEventListener('click', () => { sfx.set(!sfx.on); syncSoundBtn(); });

    document.addEventListener('keydown', e => {
      const typing = /^(INPUT|TEXTAREA)$/.test(document.activeElement?.tagName || '');
      if (e.key === '/' && !typing) { e.preventDefault(); input.focus(); input.select(); }
      else if (e.key === 'Escape') { const m = $('.win.max'); if (m) { m.classList.remove('max'); dirty(); } closeMenu(); }
      else if (!typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
        if (e.key === 'l' || e.key === 'L') setLayout(layoutMode === 'tiles' ? 'flow' : 'tiles');
        else if (e.key === 'm' || e.key === 'M') { sfx.set(!sfx.on); syncSoundBtn(); }
      }
    });

    let dragDepth = 0;
    addEventListener('dragenter', e => { if (e.dataTransfer?.types.includes('Files')) { dragDepth++; $('#drop').classList.add('on'); } });
    addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('#drop').classList.remove('on'); } });
    addEventListener('dragover', e => e.preventDefault());
    addEventListener('drop', e => {
      e.preventDefault(); dragDepth = 0; $('#drop').classList.remove('on');
      const f = e.dataTransfer?.files?.[0];
      if (f) uploadFile(f);
    });
      addEventListener('paste', e => {
        const f = e.clipboardData?.files?.[0];
        if (f) { e.preventDefault(); uploadFile(f); }
      });
      let resizeTimer;
      addEventListener('resize', () => { clearTimeout(resizeTimer); resizeTimer = setTimeout(() => relayout(), 60); });
      stage.addEventListener('scroll', () => dirty());

      for (const x of ['8.8.8.8', 'example.com', 'admin@example.com', 'https://example.com', '-6.8160, 39.2803',
        'Dar es Salaam', 'CVE-2024-3094', '5449000000996', 'solar energy tanzania', '@torvalds']) {
        $('#examples').append(el('span', { class: 'ex', text: x, onclick: () => { input.value = x; search(x); } }));
        }

        syncSoundBtn();
      applyLayoutMode();
      if (location.hash.length > 1) {
        try { const q = decodeURIComponent(location.hash.slice(1)); input.value = q; search(q); } catch { /* ignore */ }
      }
      input.focus();
