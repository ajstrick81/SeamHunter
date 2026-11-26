'use strict';
/* SeamHunter desktop GUI — vanilla JS, no dependencies, talks only to 127.0.0.1. */

const TOKEN = document.querySelector('meta[name="seam-token"]').content;
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'}[c]));
const enc = encodeURIComponent;

async function api(path, body) {
  const opt = {headers: {'X-Seam-Token': TOKEN}};
  if (body !== undefined) {
    opt.method = 'POST';
    opt.headers['Content-Type'] = 'application/json';
    opt.body = JSON.stringify(body);
  }
  const r = await fetch(path, opt);
  if (r.status === 403 && !sessionStorage.getItem('seam-reloaded')) {
    // the server was restarted (new session token): reload once to pick it up
    const txt = await r.clone().text();
    if (txt === 'bad token') {
      try { sessionStorage.setItem('seam-reloaded', '1'); } catch { /* private mode */ }
      location.reload();
      return new Promise(() => {});
    }
  }
  try { sessionStorage.removeItem('seam-reloaded'); } catch { /* ignore */ }
  let j;
  try { j = await r.json(); } catch { throw new Error(`HTTP ${r.status}`); }
  if (j && j.error) throw new Error(j.error);
  return j;
}
const fileUrl = (dir, f) => `/files?dir=${enc(dir)}&f=${enc(f)}&t=${enc(TOKEN)}`;

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 2600);
}

const I = {
  scan: '<svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="7.5"/><circle cx="12" cy="12" r="2.2"/><path d="M12 1.8v4M12 18.2v4M1.8 12h4M18.2 12h4"/></svg>',
  copy: '<svg viewBox="0 0 24 24"><rect x="8" y="8" width="12" height="12" rx="3"/><path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/></svg>',
  folder: '<svg viewBox="0 0 24 24"><path d="M3.5 7.5a2 2 0 0 1 2-2h4l2 2.2h7a2 2 0 0 1 2 2v7.8a2 2 0 0 1-2 2h-13a2 2 0 0 1-2-2z"/></svg>',
  code: '<svg viewBox="0 0 24 24"><path d="M8.5 7 3.5 12l5 5M15.5 7l5 5-5 5"/></svg>',
  compare: '<svg viewBox="0 0 24 24"><path d="M4 8h13M13.5 4.5 17 8l-3.5 3.5M20 16H7M10.5 12.5 7 16l3.5 3.5"/></svg>',
  trash: '<svg viewBox="0 0 24 24"><path d="M4.5 7h15M9.5 7V4.5h5V7M6.5 7l1 12.5h9l1-12.5"/></svg>',
  plus: '<svg viewBox="0 0 24 24"><path d="M12 5v14M5 12h14"/></svg>',
  search: '<svg viewBox="0 0 24 24"><circle cx="10.5" cy="10.5" r="6"/><path d="m15 15 5 5"/></svg>',
  upload: '<svg viewBox="0 0 24 24"><path d="M12 16V4M7 9l5-5 5 5M4 19.5h16"/></svg>',
  back: '<svg viewBox="0 0 24 24"><path d="M15 5 8 12l7 7"/></svg>',
  stop: '<svg viewBox="0 0 24 24"><rect x="6" y="6" width="12" height="12" rx="2.5"/></svg>',
  open: '<svg viewBox="0 0 24 24"><path d="M14 4.5h5.5V10M19.5 4.5 11 13M10 5.5H6a2 2 0 0 0-2 2V18a2 2 0 0 0 2 2h10.5a2 2 0 0 0 2-2v-4"/></svg>',
};

/* ------------------------------------------------------------------ formatting */
const fmtSize = n => n == null ? '' : n > 1e9 ? (n / 1e9).toFixed(1) + ' GB' : n > 1e6 ? (n / 1e6).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1e3)) + ' KB';
const fmtAgo = ts => {
  if (!ts) return '';
  const s = Date.now() / 1000 - ts;
  if (s < 90) return 'just now';
  if (s < 3600) return Math.round(s / 60) + ' min ago';
  if (s < 86400) return Math.round(s / 3600) + ' h ago';
  if (s < 86400 * 30) return Math.round(s / 86400) + ' d ago';
  return new Date(ts * 1000).toLocaleDateString();
};
const fmtDur = s => s == null ? '' : s < 60 ? s.toFixed(s < 10 ? 1 : 0) + ' s' : Math.floor(s / 60) + ' m ' + Math.round(s % 60) + ' s';
// "com.x_1.2-345_2arch_1dpi_24lang_<hash>_apkmirror.com.apkm" -> "com.x 1.2 · apkm"
const prettyFile = n => {
  const m = String(n || '').match(/^(.*?)_(\d[\w.+-]*?)-\d+_(?:\d+arch|minAPI|nodpi).*\.(apkm|apk|xapk|apks)$/i);
  return m ? `${m[1]} ${m[2]} · ${m[3]}` : String(n || '');
};
const hue = s => { let h = 0; for (const c of String(s)) h = (h * 31 + c.charCodeAt(0)) >>> 0; return h % 360; };
const shortEngine = e => e ? e.replace(/\s*\(.*$/, '').replace(/\s+—.*$/, '').replace(/^Google IMA \/ DAI client SDK/, 'IMA / DAI client').replace(/^Server-side stitching \(SSAI\)/, 'SSAI') : '';
const SIG_RE = /(L[\w/$-]+;-&gt;(?:[\w$-]|&lt;|&gt;)+\([^)\s]*\)(?:\[*L[\w/$-]+;|\[*[VZBSCIJFD]))/g;
const inline = s => {
  // backtick code first (kept verbatim), then bare smali method refs in prose get the code look too
  const parts = esc(s).split(/`([^`]+)`/);
  return parts.map((p, i) => i % 2 ? `<code>${p}</code>` : p.replace(SIG_RE, '<code>$1</code>')).join('')
    .replace(/\*\*([^*]+)\*\*/g, '<b>$1</b>');
};
const verNum = s => (s.code != null ? Number(s.code) : 0);

function md(text) {
  const out = [];
  let list = false;
  let inPre = false;
  const pre = [];
  for (const raw of String(text || '').split('\n')) {
    if (raw.startsWith('```')) {
      if (inPre) { out.push(`<pre>${esc(pre.join('\n'))}</pre>`); pre.length = 0; inPre = false; }
      else { if (list) { out.push('</ul>'); list = false; } inPre = true; }
      continue;
    }
    if (inPre) { pre.push(raw); continue; }
    const h = raw.match(/^(#{1,4})\s+(.*)/);
    if (h) { if (list) { out.push('</ul>'); list = false; } out.push(`<h${h[1].length + 1}>${inline(h[2])}</h${h[1].length + 1}>`); continue; }
    const li = raw.match(/^\s*[-*]\s+(.*)/);
    if (li) { if (!list) { out.push('<ul>'); list = true; } out.push(`<li>${inline(li[1])}</li>`); continue; }
    if (list) { out.push('</ul>'); list = false; }
    if (raw.trim()) out.push(`<p>${inline(raw)}</p>`);
  }
  if (list) out.push('</ul>');
  if (inPre) out.push(`<pre>${esc(pre.join('\n'))}</pre>`);
  return `<div class="md">${out.join('')}</div>`;
}

/* ------------------------------------------------------------------ app art */
function art(s, {count, big} = {}) {
  const name = displayName(s);
  const h = hue(s.package);
  let inner;
  if (s.art && s.art.banner) {
    inner = `<img class="banner" src="${fileUrl(s.dir, s.art.banner)}" alt="" loading="lazy">`;
  } else if (s.art && s.art.icon) {
    const u = fileUrl(s.dir, s.art.icon);
    inner = `<div class="blur" style="background-image:url('${u}')"></div><img class="icon" src="${u}" alt="" loading="lazy">`;
  } else {
    inner = `<div class="blur" style="background:radial-gradient(circle at 30% 30%,hsl(${h} 80% 45%),hsl(${(h + 60) % 360} 70% 18%))"></div>
      <div class="mono-avatar" style="background:linear-gradient(135deg,hsl(${h} 75% 52%),hsl(${(h + 40) % 360} 70% 36%))">${esc(name.slice(0, 1).toUpperCase())}</div>`;
  }
  return `<div class="art">${inner}<div class="scan-lines"></div>${count ? `<span class="count">${count} build${count > 1 ? 's' : ''}</span>` : ''}</div>`;
}
function lead(s) {
  if (s && s.art && s.art.icon) return `<div class="lead"><img src="${fileUrl(s.dir, s.art.icon)}" alt="" loading="lazy"></div>`;
  const h = hue(s ? s.package : '?');
  return `<div class="lead" style="background:linear-gradient(135deg,hsl(${h} 70% 48%),hsl(${(h + 40) % 360} 65% 32%))">${esc(displayName(s).slice(0, 1).toUpperCase())}</div>`;
}
const NAME_CACHE = {};
function displayName(s) {
  if (!s) return '?';
  return s.name || NAME_CACHE[s.package] || prettyPkg(s.package);
}
function prettyPkg(p, label) {
  // Prefer the app's own manifest label when the scan captured one; otherwise prettify the package id.
  // SeamHunter ships no curated catalog of commercial apps.
  if (label) return label;
  const last = String(p || '?').split('.').filter(x => !['com', 'tv', 'android', 'app', 'mobile', 'org', 'net'].includes(x)).pop() || p;
  return last.charAt(0).toUpperCase() + last.slice(1);
}
function driftChip(s) {
  if (!s.known) return '<span class="chip cyan"><i class="dot"></i>New app</span>';
  const d = s.drift || {};
  if (d.lineage) return '<span class="chip bad"><i class="dot"></i>New lineage</span>';
  if (!d.bad) return `<span class="chip ok"><i class="dot"></i>Known · ${d.ok}/${d.total} OK</span>`;
  return `<span class="chip ${d.hard ? 'bad' : 'warn'}"><i class="dot"></i>Drift · ${d.bad}${d.fixes ? ' · fix ready' : ''}</span>`;
}

/* ------------------------------------------------------------------ data */
const store = {scans: null, state: null, jobs: []};
async function loadScans(force) {
  if (!store.scans || force) {
    const r = await api('/api/scans');
    store.scans = r.scans;
    store.roots = r.roots;
    store.artPending = r.art_pending;
    for (const s of store.scans) if (s.name) NAME_CACHE[s.package] = s.name;
  }
  return store.scans;
}
async function loadState(force) {
  if (!store.state || force) store.state = await api('/api/state');
  return store.state;
}
function groups(scans) {
  const by = {};
  for (const s of scans) (by[s.package] ||= []).push(s);
  return Object.entries(by).map(([pkg, list]) => {
    list.sort((a, b) => verNum(b) - verNum(a) || b.scanned - a.scanned);
    // "latest" = newest STORE build: patched builds carry a bumped versionCode (Disable auto-updates)
    // and config splits have no code at all
    const real = list.filter(x => x.classes > 0);
    const store = real.filter(x => ['apkm', 'xapk', 'apks'].includes(x.kind));
    const latest = (store.length ? store : real.length ? real : list)[0];
    const withArt = list.find(x => x.art && x.art.banner) || list.find(x => x.art && x.art.icon) || list[0];
    return {pkg, list, latest, art: withArt, name: displayName(list.find(x => x.name) || list[0])};
  }).sort((a, b) => a.name.localeCompare(b.name));
}

/* ------------------------------------------------------------------ router */
let pollers = [];
const every = (fn, ms) => { const id = setInterval(fn, ms); pollers.push(id); return id; };
function route() {
  const h = location.hash.replace(/^#\/?/, '') || 'apps';
  const [path, q] = h.split('?');
  const parts = path.split('/');
  return {name: parts[0], arg: decodeURIComponent(parts.slice(1).join('/')), q: new URLSearchParams(q || '')};
}
async function render() {
  pollers.forEach(clearInterval);
  pollers = [];
  const r = route();
  const navKey = {app: 'apps', report: 'apps', job: 'scan'}[r.name] || r.name;
  $$('#nav a').forEach(a => a.classList.toggle('on', a.dataset.nav === navKey));
  const main = $('#main');
  const view = VIEWS[r.name] || VIEWS.apps;
  main.innerHTML = '<div class="page"><div class="skeleton"></div></div>';
  try {
    await view(main, r);
  } catch (e) {
    main.innerHTML = `<div class="page"><div class="note bad"><b>Something went wrong.</b> ${esc(e.message)}</div></div>`;
  }
  main.scrollTop = 0;
}
window.addEventListener('hashchange', render);

/* ------------------------------------------------------------------ views */
const VIEWS = {};

VIEWS.apps = async (main, r) => {
  const scans = await loadScans(true);
  const gs = groups(scans);
  const filter = r.q.get('f') || 'all';
  const known = gs.filter(g => g.latest.known).length;
  const attention = gs.filter(g => g.latest.known && g.latest.drift && g.latest.drift.bad).length;
  if (!scans.length) {
    main.innerHTML = `<div class="page fadein"><div class="empty">
      <img src="/static/banner.webp" alt="SeamHunter">
      <h1>Find the seam. Clip the ad.</h1>
      <p class="sub">Scan an Android TV app to map where its ads enter — nothing leaves this PC.</p>
      <div class="row" style="justify-content:center"><a class="btn primary" href="#/scan">${I.scan} Scan your first app</a>
      <a class="btn" href="#/settings">Choose folders</a></div>
      <p class="muted mono" style="font-size:12px">Results folder: ${esc((store.roots || [])[0] || '')}</p></div></div>`;
    return;
  }
  main.innerHTML = `<div class="page fadein">
    <div class="hero"><div class="tv" aria-hidden="true"></div>
      <div class="txt"><div><div class="wm"><span class="w1">Seam</span><span class="w2">Hunter</span></div><div class="rule"></div>
        <div class="tag">Find the seam · clip the ad</div></div>
        <div class="stats">
          <div class="stat"><b>${gs.length}</b><span>apps</span></div>
          <div class="stat"><b>${scans.length}</b><span>builds</span></div>
          <div class="stat"><b>${known}</b><span>known</span></div>
          <div class="stat"><b style="color:${attention ? 'var(--amber)' : 'var(--ok)'}">${attention}</b><span>need a look</span></div>
        </div></div></div>
    <div class="head"><div class="grow"><div class="eyebrow">Your apps</div><h1>Apps</h1></div>
      <div class="search">${I.search}<input class="input" id="q" placeholder="Search apps or packages" autocomplete="off"></div></div>
    <div class="chips" style="margin:-6px 0 20px">
      ${[['all', 'All'], ['known', 'Known apps'], ['new', 'New apps'], ['attention', 'Needs a look']].map(([k, l]) =>
        `<button class="chip f ${filter === k ? 'on' : ''}" data-f="${k}">${l}</button>`).join('')}</div>
    <div class="grid" id="grid"></div></div>
    <a class="btn primary fab" href="#/scan">${I.scan} Scan an app</a>`;
  const draw = () => {
    const q = $('#q').value.trim().toLowerCase();
    const list = gs.filter(g => {
      if (q && !(g.name.toLowerCase().includes(q) || g.pkg.includes(q))) return false;
      const l = g.latest;
      if (filter === 'known') return !!l.known;
      if (filter === 'new') return !l.known;
      if (filter === 'attention') return l.known && l.drift && l.drift.bad;
      return true;
    });
    $('#grid').innerHTML = list.map(g => {
      const l = g.latest;
      return `<a class="card app" href="#/app/${enc(g.pkg)}">${art(g.art, {count: g.list.length})}
        <div class="body"><div class="name">${esc(g.name)}</div><div class="pkg">${esc(g.pkg)} · v${esc(l.version)}</div>
        <div class="meta">${driftChip(l)}${l.trackers != null ? `<span class="chip ${l.trackers >= 10 ? 'warn' : ''}">${l.trackers} tracker${l.trackers === 1 ? '' : 's'}</span>` : ''}${l.target ? '<span class="chip">target</span>' : ''}${l.engine ? `<span class="chip">${esc(shortEngine(l.engine))}</span>` : ''}</div></div></a>`;
    }).join('') || '<p class="muted">No apps match.</p>';
  };
  draw();
  $('#q').addEventListener('input', draw);
  if (store.artPending) {
    // app art is being extracted in the background: refresh the cards as it lands
    every(async () => {
      await loadScans(true);
      const fresh = groups(store.scans);
      gs.splice(0, gs.length, ...fresh);
      draw();
      if (!store.artPending) pollers.forEach(clearInterval);
    }, 3000);
  }
  $$('[data-f]').forEach(b => b.onclick = () => { location.hash = `#/apps?f=${b.dataset.f}`; });
};

VIEWS.app = async (main, r) => {
  const scans = await loadScans();
  const g = groups(scans).find(x => x.pkg === r.arg);
  if (!g) { location.hash = '#/apps'; return; }
  const l = g.latest;
  let ka = null;
  if (l.known) {
    try { ka = (await api('/api/report?dir=' + enc(l.dir))).report.known_app; } catch { /* optional */ }
  }
  const sel = new Set();
  main.innerHTML = `<div class="page fadein">
    <a class="btn ghost small" href="#/apps">${I.back} Apps</a>
    <div class="card rhead" style="margin-top:14px">${art(g.art)}
      <div class="info"><div class="eyebrow">${l.known ? 'Known app · ' + esc(l.known) : 'New app'}</div>
        <h1 style="margin:0">${esc(g.name)}</h1><div class="mono muted" style="font-size:13px">${esc(g.pkg)}</div>
        <div class="chips">${driftChip(l)}${l.engine ? `<span class="chip">${esc(shortEngine(l.engine))}</span>` : ''}<span class="chip">${g.list.length} build${g.list.length > 1 ? 's' : ''}</span></div>
      </div></div>
    ${ka ? `<div class="card pad" style="margin-top:18px"><h2>What we know</h2><dl class="kv">
      ${[['Delivery', ka.delivery], ['Seam', ka.seam], ['Action', ka.action], ['Drift notes', ka.drift], ['Targets', (ka.targets || []).join(', ')]]
        .filter(x => x[1]).map(([k, v]) => `<dt>${k}</dt><dd>${inline(v)}</dd>`).join('')}</dl></div>` : ''}
    <div class="head" style="margin:26px 0 12px"><div class="grow"><h2 style="margin:0">Builds</h2>
      <p class="sub">Tick two builds to compare them.</p></div></div>
    <div class="card list" id="builds">${g.list.map((s, i) => `
      <div class="item" data-i="${i}"><div class="check" data-check="${i}" title="Select to compare"></div>${lead(s)}
        <div class="t"><b>v${esc(s.version)} <span class="muted mono" style="font-weight:400;font-size:12px">· ${esc(s.code ?? '')}</span></b>
          <span>${esc(s.kind || '')} · ${fmtSize(s.size)} · scanned ${fmtAgo(s.scanned)} · ${esc(s.input || '')}</span></div>
        <div class="chips">${driftChip(s)}${s.target ? '<span class="chip">target</span>' : ''}</div></div>`).join('')}</div></div>
    <button class="btn primary fab" id="cmp" hidden>${I.compare} Compare 2 builds</button>`;
  const upd = () => {
    $$('#builds .item').forEach(el => el.classList.toggle('sel', sel.has(+el.dataset.i)));
    $('#cmp').hidden = sel.size !== 2;
  };
  $$('#builds .item').forEach(el => el.addEventListener('click', ev => {
    const i = +el.dataset.i;
    if (ev.target.closest('[data-check]')) {
      if (sel.has(i)) sel.delete(i); else { if (sel.size >= 2) sel.delete([...sel][0]); sel.add(i); }
      upd();
    } else {
      location.hash = '#/report?dir=' + enc(g.list[i].dir);
    }
  }));
  $('#cmp').onclick = () => {
    const [a, b] = [...sel].map(i => g.list[i]).sort((x, y) => verNum(x) - verNum(y));
    location.hash = `#/compare?a=${enc(a.dir)}&b=${enc(b.dir)}`;
  };
};

VIEWS.report = async (main, r) => {
  const dir = r.q.get('dir');
  const R = await api('/api/report?dir=' + enc(dir));
  const f = R.report, s = R.summary;
  const m = f.manifest || {}, code = f.code || {}, ka = f.known_app, seams = f.seams || {};
  const name = displayName(s);
  const tabs = [
    ['plan', 'Investigation points', (f.plan || []).length],
    ka ? ['drift', 'Drift', (ka.results || []).length] : null,
    ['seams', 'Seams', (seams.candidates || []).length],
    ['integration', 'Integration', (seams.integration_points || []).length],
    ['privacy', 'Privacy', f.trackers ? f.trackers.count : null],
    ['stack', 'Stack', (f.sdks || []).length],
    ['drafts', 'Drafts', Object.keys(R.drafts || {}).length],
    ['manifest', 'Manifest', null],
    ['full', 'Full report', null],
  ].filter(Boolean);
  const tab = r.q.get('tab') || 'plan';
  main.innerHTML = `<div class="page fadein">
    <a class="btn ghost small" href="#/app/${enc(s.package)}">${I.back} ${esc(name)}</a>
    <div class="card rhead" style="margin-top:14px">${art(s)}
      <div class="info"><div class="eyebrow">Report <span class="dot">·</span> ${esc(f.tool || '')}</div>
        <h1 style="margin:0">${esc(name)} <span class="muted" style="font-weight:500">v${esc(m.versionName)}</span></h1>
        <div class="mono muted" style="font-size:12.5px">${esc(m.package)} · ${esc(m.versionCode)} · ${esc(f.input || '')}</div>
        <div class="chips">${driftChip(s)}${s.target ? '<span class="chip">declared target</span>' : ''}
          ${(f.engine_guess || []).map(e => `<span class="chip">${esc(shortEngine(e))}</span>`).join('')}
          <span class="chip">${(code.classes || 0).toLocaleString()} classes</span>
          ${code.obfuscation ? `<span class="chip">${esc(String(code.obfuscation.verdict || '').split(' (')[0])}</span>` : ''}
          <span class="chip">${fmtDur(f.elapsed_seconds)} scan</span></div>
        <div class="row" style="margin-top:4px">
          <button class="btn primary" id="copyClaude">${I.copy} Copy for Claude</button>
          <a class="btn" href="#/explorer?dir=${enc(dir)}">${I.code} Explorer</a>
          <a class="btn" href="#/compare?b=${enc(dir)}">${I.compare} Compare</a>
          <button class="btn" id="openDir">${I.folder} Folder</button>
          <span class="spacer"></span>
          <button class="btn ghost danger small" id="del">${I.trash} Delete scan</button></div>
      </div></div>
    ${(f.warnings || []).length ? `<div class="note" style="margin-top:16px">${(f.warnings || []).map(inline).join('<br>')}</div>` : ''}
    <div class="tabs" role="tablist">${tabs.map(([k, l, n]) => `<button class="${k === tab ? 'on' : ''}" data-tab="${k}">${l}${n != null ? `<span class="n">${n}</span>` : ''}</button>`).join('')}</div>
    <div id="tab"></div></div>`;
  $$('[data-tab]').forEach(b => b.onclick = () => { history.replaceState(null, '', `#/report?dir=${enc(dir)}&tab=${b.dataset.tab}`); render(); });
  $('#copyClaude').onclick = async () => {
    const head = `SeamHunter report — ${name} ${m.versionName} (${m.package})\nScan folder: ${dir}\n` +
      `Query it locally: autopsy show|xref|strings|fp|class "${dir}" <ref>\n\n`;
    try { await navigator.clipboard.writeText(head + R.md); toast(`Copied report.md (${Math.round(R.md.length / 1024)} KB) — paste it into Claude`); }
    catch { toast('Clipboard blocked — use Folder › report.md'); }
  };
  $('#openDir').onclick = () => api('/api/open', {path: dir}).catch(e => toast(e.message));
  $('#del').onclick = async () => {
    if (!confirm(`Delete this scan folder?\n\n${dir}\n\nThe APK itself is not touched.`)) return;
    await api('/api/delete', {dir});
    store.scans = null;
    toast('Scan deleted');
    location.hash = '#/app/' + enc(s.package);
  };
  TABS[tab]($('#tab'), {R, f, s, dir, ka, seams});
};

const statusChip = st => {
  const cls = {OK: 'ok', FOUND_BY_STRINGS: 'ok', UNVERIFIABLE: '', AMBIGUOUS: 'warn', CLASS_MISSING: 'bad', METHOD_MISSING: 'bad'}[st] ?? 'warn';
  return `<span class="chip ${cls}">${esc(st)}</span>`;
};

const TABS = {
  plan(el, {f}) {
    const items = f.plan || [];
    el.innerHTML = `<ol class="plan" style="padding:0;margin:0">${items.map(p => {
      const alert = /^(DIFFERENT LINEAGE|NO DEX)|PATCH ABORTS/.test(p);
      const hot = /^(FIX READY|SEAM)/.test(p);
      return `<li class="${alert ? 'alert' : hot ? 'hot' : ''}"><div>${inline(p)}</div></li>`;
    }).join('')}</ol>`;
  },
  drift(el, {ka}) {
    const res = ka.results || [];
    el.innerHTML = `<div class="two">
      <div class="card pad"><h2>${esc(ka.key)} <span class="muted" style="font-weight:400">· targets ${esc((ka.targets || []).join(', '))}</span></h2>
        <dl class="kv">${[['This build', ka.version_is_target ? 'a declared target' : 'NOT a declared target'], ['Engine', ka.engine], ['Delivery', ka.delivery],
          ['Seam', ka.seam], ['Action', ka.action], ['Patch evidence', ka.patch_evidence], ['Drift notes', ka.drift]]
          .filter(x => x[1]).map(([k, v]) => `<dt>${k}</dt><dd>${inline(v)}</dd>`).join('')}</dl></div>
      <div class="card pad"><h2>Summary</h2><div class="chips">${Object.entries(ka.summary || {}).map(([k, v]) => `${statusChip(k)}<span class="chip mono">${v}</span>`).join('')}</div>
        <p class="sub" style="margin-top:14px">“PATCH ABORTS” = the patch uses <code>.method</code> for that fingerprint, so one miss stops the whole patch.
        a “soft” match (<code>methodOrNull</code> / try-catch) is one a consumer can tolerate missing.</p></div></div>
      <div class="card" style="margin-top:18px;overflow:hidden"><table><thead><tr><th>Fingerprint</th><th>Status</th><th>Where / next step</th></tr></thead><tbody>
      ${res.map((x, i) => `<tr><td><b>${esc(x.id)}</b><div class="muted" style="font-size:12px">${esc((x.usedBy || []).join(', '))}</div></td>
        <td>${statusChip(x.status)}${x.impact ? `<div style="margin-top:6px;font-size:12px" class="${x.hard ? '' : 'muted'}">${esc(x.impact)}</div>` : ''}${x.partial ? '<div class="muted" style="font-size:12px">partially verified</div>' : ''}</td>
        <td class="sig">${esc(x.where || '')}${(x.issues || []).map(t => `<div class="muted" style="font-family:var(--sans);font-size:12px">${inline(t)}</div>`).join('')}
          ${(x.candidates || []).length && x.status !== 'OK' ? `<div class="muted" style="margin-top:6px">candidates:</div>${x.candidates.slice(0, 3).map(c => `<div>${esc(c)}</div>`).join('')}` : ''}
          ${x.fix ? `<div class="note cyan" style="margin-top:10px;font-family:var(--sans)"><b>Fix ready</b> → ${esc(x.fix.target)}</div>
            <pre style="margin-top:8px">${esc(JSON.stringify(x.fix.descriptor, null, 2))}</pre><button class="btn small" data-copyfix="${i}" style="margin-top:8px">${I.copy} Copy descriptor</button>` : ''}</td></tr>`).join('')}
      </tbody></table></div>`;
    $$('[data-copyfix]', el).forEach(b => b.onclick = () => navigator.clipboard.writeText(JSON.stringify(res[+b.dataset.copyfix].fix.descriptor, null, 2)).then(() => toast('Descriptor copied')));
  },
  seams(el, {seams, dir}) {
    const c = seams.candidates || [];
    const max = Math.max(1, ...c.map(x => x.score));
    let shown = 40;
    const draw = () => {
      el.innerHTML = `<div class="card" style="overflow:hidden"><table><thead><tr><th style="width:46px">#</th><th style="width:120px">Score</th><th>Method · why</th><th style="width:30%">Strategy</th></tr></thead><tbody>
        ${c.slice(0, shown).map((x, i) => `<tr class="click" data-id="${x.id}"><td class="mono muted">${i + 1}</td>
          <td><div class="score">${x.score}<div class="bar"><i style="width:${Math.round(100 * x.score / max)}%"></i></div></div>
            <div class="muted" style="font-size:11.5px;margin-top:4px">${esc(x.vendor || 'app')}</div></td>
          <td class="sig">${esc(x.sig)}<div class="why">${(x.why || []).map(w => `<span class="chip">${esc(w)}</span>`).join('')}</div></td>
          <td style="font-size:12.5px;color:var(--ink2)">${inline(x.strategy || '')}</td></tr>`).join('')}
        </tbody></table></div>
        ${shown < c.length ? `<div class="row" style="justify-content:center;margin-top:14px"><button class="btn" id="more">Show all ${c.length}</button></div>` : ''}`;
      $$('tr[data-id]', el).forEach(tr => tr.onclick = () => { location.hash = `#/explorer?dir=${enc(dir)}&id=${tr.dataset.id}`; });
      const more = $('#more', el);
      if (more) more.onclick = () => { shown = c.length; draw(); };
    };
    draw();
  },
  integration(el, {seams}) {
    const ips = seams.integration_points || [], imps = seams.implementers || [];
    el.innerHTML = `<h3 style="margin-top:0">Integration points — app code calling known seam APIs</h3>
      ${ips.length ? ips.map(p => `<div class="card pad" style="margin-bottom:14px"><div class="row"><span class="chip cyan mono">${esc(p.id)}</span><span class="chip">${esc(p.engine)}</span>
        <span class="chip mono">${p.count} site${p.count === 1 ? '' : 's'}</span></div>
        <p style="margin:12px 0 6px"><b>${inline(p.what)}</b></p>
        <dl class="kv"><dt>Role</dt><dd>${inline(p.strategy)}</dd><dt>Risk</dt><dd>${inline(p.risk)}</dd></dl>
        ${(p.sites || []).length ? `<pre style="margin-top:12px;max-height:200px">${(p.sites || []).slice(0, 25).map(x => esc(typeof x === 'string' ? x : (x.sig || JSON.stringify(x)))).join('\n')}</pre>` : ''}</div>`).join('')
        : '<p class="muted">No app code calls a catalogued seam API.</p>'}
      <h3>Implementers — found by interface, immune to R8 renames</h3>
      ${imps.length ? imps.map(p => `<div class="card pad" style="margin-bottom:14px"><div class="row"><b>${esc(p.label)}</b><span class="chip mono">${p.count}</span></div>
        <p class="sub" style="margin:8px 0">${inline(p.strategy || '')}</p>
        <pre style="max-height:180px">${(p.classes || []).slice(0, 30).map(c => esc(typeof c === 'string' ? c : (c.class || c.name || JSON.stringify(c)))).join('\n')}</pre></div>`).join('')
        : '<p class="muted">None.</p>'}`;
  },
  privacy(el, {f}) {
    const t = f.trackers;
    if (!t) { el.innerHTML = '<div class="note cyan">This scan predates the tracker audit — Rescan it to see trackers, vendor controls and a blocklist.</div>'; return; }
    const catChip = c => `<span class="chip ${['acr', 'fingerprint', 'replay'].includes(c) ? 'bad' : ['attribution', 'measurement', 'social'].includes(c) ? 'warn' : ''}">${esc(c)}</span>`;
    const blk = {safe: 'ok', caution: 'warn', never: 'bad'};
    const rules = kinds => kinds.flatMap(k => t.blocklist[k].map(h => `||${h}^`)).join('\n');
    el.innerHTML = `<div class="stats card pad" style="margin-top:0">
        <div class="stat"><b>${t.count}</b><span>trackers</span></div>
        ${Object.entries(t.by_category).map(([k, v]) => `<div class="stat"><b>${v}</b><span>${esc(k)}</span></div>`).join('')}
        <div class="stat"><b style="color:${t.permissions.length ? 'var(--amber)' : 'var(--ok)'}">${t.permissions.length}</b><span>sensitive perms</span></div></div>
      ${t.permissions.length ? `<div class="note" style="margin-top:16px"><b>Sensitive permissions:</b> ${t.permissions.map(p => `<code>${esc(p.permission.split('.').pop())}</code> ${esc(p.what)}`).join(' · ')}</div>` : ''}
      <div class="card" style="margin-top:18px;overflow:hidden"><table><thead><tr><th>Tracker</th><th>Category</th><th>Evidence</th><th>Hosts</th><th>Started from</th></tr></thead><tbody>
      ${t.items.map(i => { const e = i.evidence; return `<tr><td><b>${esc(i.name)}</b>${i.note ? `<div class="muted" style="font-size:12px">${esc(i.note)}</div>` : ''}</td>
        <td>${catChip(i.category)}<div class="muted" style="font-size:11.5px;margin-top:4px">${esc(i.category_label)}</div></td>
        <td style="font-size:12.5px">${e.classes ? `${e.classes} classes` : ''}${e.components.length ? `<div>${e.components.length} manifest component(s)</div>` : ''}${!e.classes && !e.components.length ? esc(i.confidence) + (e.markers.length ? ': ' + e.markers.map(esc).join(', ') : '') : ''}</td>
        <td>${i.hosts.map(h => `<div class="mono" style="font-size:11.5px"><span class="dot" style="color:var(--${blk[h.block] === 'ok' ? 'ok' : blk[h.block] === 'warn' ? 'amber' : 'bad'})"></span> ${esc(h.host)}</div>`).join('') || '<span class="muted">—</span>'}</td>
        <td class="sig" style="font-size:11.5px">${i.init_sites.slice(0, 2).map(x => `<div>${esc(x.caller)}</div>`).join('') || '<span class="muted" style="font-family:var(--sans)">not called from app code</span>'}</td></tr>`; }).join('') ||
        '<tr><td class="muted">No known tracker SDKs, components or hosts found.</td></tr>'}</tbody></table></div>
      ${t.kill_switches.length ? `<h3>Vendor control flags</h3><div class="card pad"><p class="sub" style="margin:0 0 12px">Vendor-documented <code>&lt;meta-data&gt;</code> flags that influence tracking / personalization.</p>
        <table><tbody>${t.kill_switches.map(k => `<tr><td><b>${esc(k.tracker)}</b></td><td class="mono" style="font-size:12px">${esc(k.key)} = ${esc(k.value)}</td>
          <td style="font-size:12.5px">${esc(k.effect)}</td><td style="font-size:12.5px">${k.current == null ? '<span class="chip warn">not set · on</span>' :
          `<span class="chip ${String(k.current) === String(k.value) ? 'ok' : 'warn'}">now ${esc(k.current)}</span>${k.via ? `<div class="muted mono" style="font-size:11px">${esc(k.via)}</div>` : ''}`}</td></tr>`).join('')}</tbody></table></div>` : ''}
      <h3>Blocklist (AdGuard / DNS)</h3><div class="two">
        <div class="card pad"><div class="row"><span class="chip ok">safe · ${t.blocklist.safe.length}</span><span class="spacer"></span><button class="btn small" id="cpSafe">Copy rules</button></div>
          <p class="sub" style="margin:8px 0">Reporting-only endpoints — blocking never touches playback or UI.</p><pre style="max-height:220px">${esc(rules(['safe'])) || '—'}</pre></div>
        <div class="card pad"><div class="row"><span class="chip warn">caution · ${t.blocklist.caution.length}</span><span class="chip bad">never · ${t.blocklist.never.length}</span><span class="spacer"></span><button class="btn small" id="cpCaution">Copy caution rules</button></div>
          <p class="sub" style="margin:8px 0">Caution hosts also carry app features (deep links, in-app messages) — test before blocking. <b>Never</b> hosts drive config / consent: blocking breaks the app.</p>
          <pre style="max-height:220px">${esc(rules(['caution'])) || '—'}${t.blocklist.never.length ? '\n\n# do NOT block\n' + esc(t.blocklist.never.map(h => '# ' + h).join('\n')) : ''}</pre></div></div>
      ${t.other_hosts.length ? `<p class="sub" style="margin-top:14px">Other analytics/measurement hosts seen in code (no SDK match): ${t.other_hosts.map(h => `<code>${esc(h)}</code>`).join(' ')}</p>` : ''}`;
    $('#cpSafe', el).onclick = () => navigator.clipboard.writeText(rules(['safe'])).then(() => toast(`Copied ${t.blocklist.safe.length} AdGuard rules`));
    $('#cpCaution', el).onclick = () => navigator.clipboard.writeText(rules(['caution'])).then(() => toast('Copied caution rules — test before using'));
  },
  stack(el, {f}) {
    const sev = s => ({high: 'bad', medium: 'warn', low: ''}[s] ?? '');
    const libs = (f.native || {}).libs || [];
    el.innerHTML = `<div class="two"><div class="card" style="overflow:hidden"><table><thead><tr><th>SDK</th><th>Category</th><th>Evidence</th></tr></thead><tbody>
      ${(f.sdks || []).map(x => `<tr><td><b>${esc(x.sdk)}</b><div class="muted" style="font-size:12px">${esc(x.note || '')}</div></td>
        <td><span class="chip ${x.category === 'ads' || x.category === 'ssai' ? 'warn' : ''}">${esc(x.category)}</span></td>
        <td class="mono" style="font-size:12px">${x.classes ? x.classes + ' classes' : esc(x.by)}</td></tr>`).join('')}</tbody></table></div>
      <div><div class="card pad"><h2>Protections &amp; hazards</h2>${(f.protections || []).map(p => `<div style="padding:10px 0;border-bottom:1px solid var(--line)">
          <div class="row"><span class="chip ${sev(p.severity)}">${esc(p.severity)}</span><b>${esc(p.label)}</b><span class="chip mono">${(p.hits || []).length} hits</span></div>
          <div class="muted" style="font-size:12.5px;margin-top:6px">${inline(p.note || '')}</div></div>`).join('') || '<p class="muted">None detected.</p>'}</div>
        <div class="card pad" style="margin-top:18px"><h2>Native libraries</h2>${libs.length ? `<table><tbody>${libs.map(x => `<tr><td class="mono" style="font-size:12px">${esc(x.lib)}</td>
          <td class="muted" style="font-size:12px">${esc(x.abi || '')}</td><td class="mono" style="font-size:12px">${fmtSize(x.size)}</td>
          <td>${(x.engines || []).map(e => `<span class="chip">${esc(e.engine || e)}</span>`).join('')}</td></tr>`).join('')}</tbody></table>` : '<p class="muted">No native code.</p>'}</div></div></div>
      <div class="card" style="margin-top:18px;overflow:hidden"><table><thead><tr><th>Host</th><th>Category</th><th>Used by</th></tr></thead><tbody>
      ${(f.hosts || []).filter(h => h.category).slice(0, 80).map(h => `<tr><td class="mono" style="font-size:12.5px">${esc(h.host)}<div class="muted" style="font-family:var(--sans);font-size:12px">${esc(h.note || '')}</div></td>
        <td><span class="chip ${['ads', 'ssai'].includes(h.category) ? 'warn' : ''}">${esc(h.category)}</span></td>
        <td class="sig" style="font-size:11.5px">${(h.used_by || []).slice(0, 2).map(esc).join('<br>')}</td></tr>`).join('') || '<tr><td class="muted">No classified hosts.</td></tr>'}
      </tbody></table></div>`;
  },
  drafts(el, {R}) {
    const names = Object.keys(R.drafts || {});
    if (!names.length) { el.innerHTML = '<p class="muted">No drafts for this build.</p>'; return; }
    let cur = names.find(n => n.endsWith('Fingerprints.kt')) || names[0];
    const draw = () => {
      el.innerHTML = `<div class="split"><div class="card pad files">${names.map(n => `<button class="${n === cur ? 'on' : ''}" data-f="${esc(n)}">${esc(n)}</button>`).join('')}
        <p class="sub" style="margin-top:12px;font-size:12.5px">Scoping notes (SCOPING.md / VERIFY.md): evidence-backed candidate seams only — verify before acting.</p></div>
        <div class="card pad"><div class="row" style="margin-bottom:12px"><b class="mono">${esc(cur)}</b><span class="spacer"></span><button class="btn small" id="cp">${I.copy} Copy</button></div>
        <pre style="max-height:calc(100vh - 330px)">${esc(R.drafts[cur])}</pre></div></div>`;
      $$('[data-f]', el).forEach(b => b.onclick = () => { cur = b.dataset.f; draw(); });
      $('#cp', el).onclick = () => navigator.clipboard.writeText(R.drafts[cur]).then(() => toast('Copied ' + cur));
    };
    draw();
  },
  manifest(el, {f}) {
    const m = f.manifest || {}, b = f.bundle || {}, a = m.application || {}, code = f.code || {};
    el.innerHTML = `<div class="two"><div class="card pad"><h2>Manifest</h2><dl class="kv">
      ${[['Package', m.package], ['Version', `${m.versionName} (${m.versionCode})`], ['SDK', `min ${m.minSdk} · target ${m.targetSdk}`], ['TV / leanback', m.tv ? 'yes' : 'no'],
        ['Launchers', (m.launchers || []).join(', ')], ['extractNativeLibs', String(a.extractNativeLibs)], ['Cleartext', String(a.usesCleartextTraffic)],
        ['Network config', a.networkSecurityConfig], ['Components', Object.entries(m.components || {}).map(([k, v]) => `${v} ${k}`).join(' · ')]]
        .filter(x => x[1] != null && x[1] !== 'undefined').map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <h3>Ad permissions</h3><div class="chips">${(m.ad_permissions || []).map(p => `<span class="chip warn mono">${esc(p)}</span>`).join('') || '<span class="muted">none</span>'}</div>
      <h3>Permissions</h3><div class="chips">${(m.permissions || []).map(p => `<span class="chip mono">${esc(p.replace('android.permission.', ''))}</span>`).join('')}</div></div>
      <div class="card pad"><h2>Bundle &amp; code</h2><dl class="kv">
      ${[['Kind', `${b.kind} · ${(b.splits || []).length} split(s) · ${fmtSize(b.size)}`], ['Dex', `${(code.dex_files || []).length} files · ${(code.classes || 0).toLocaleString()} classes · ${(code.methods || 0).toLocaleString()} methods`],
        ['Obfuscation', code.obfuscation && code.obfuscation.verdict], ['Kotlin', code.kotlin ? 'yes' : 'no'], ['Compiler', (code.compiler_markers || []).slice(0, 2).join(' · ')]]
        .filter(x => x[1]).map(([k, v]) => `<dt>${k}</dt><dd>${esc(v)}</dd>`).join('')}</dl>
      <h3>Splits</h3><pre style="max-height:260px">${(b.splits || []).map(x => `${x.name.padEnd(42)} ${fmtSize(x.size)}`).map(esc).join('\n')}</pre></div></div>`;
  },
  full(el, {dir}) {
    el.innerHTML = `<iframe class="full" sandbox="allow-scripts" src="${fileUrl(dir, 'report.html')}" title="Full report"></iframe>`;
  },
};

/* ------------------------------------------------------------------ scan */
VIEWS.scan = async main => {
  const [st, lib, jobs] = await Promise.all([loadState(true), api('/api/library'), api('/api/jobs')]);
  const opts = st.settings.scan;
  const tools = st.tools || {};
  const toggles = [
    ['fast', 'Fast scan', 'Skip native-library string scanning. Large .so files take a while.', true],
    ['java', 'Java excerpts', tools.jadx ? 'Decompile the top classes with jadx and embed them next to the smali.' : 'Needs jadx — run `autopsy tools install` (off until then).', !!tools.jadx],
    ['apktool', 'apktool smali tree', tools.apktool ? "Also write a full smali tree for the repo's check.mjs." : 'Needs apktool on PATH.', !!tools.apktool],
  ];
  main.innerHTML = `<div class="page fadein">
    <div class="head"><div class="grow"><div class="eyebrow">Step 1 <span class="dot">·</span> select an app</div><h1>Scan</h1>
      <p class="sub">Static analysis only — SeamHunter never patches, and nothing leaves this PC.</p></div></div>
    <div class="two">
      <div><div class="drop" id="pick">${I.upload.replace('<svg', '<svg style="width:46px;height:46px"')}<b>Drop an app here, or click to browse</b>
        <span class="muted mono" style="font-size:12px">.apkm · .apk · .xapk · .apks</span></div>
        <h3>Options</h3><div class="card" id="opts">${toggles.map(([k, t, d, en]) => `
          <div class="toggle ${opts[k] && en ? 'on' : ''}" data-k="${k}" ${en ? '' : 'style="opacity:.5;cursor:default"'}><div class="t"><b>${t}</b><span>${inline(d)}</span></div><div class="switch"></div></div>`).join('')}</div></div>
      <div><h3 style="margin-top:0">Queue</h3><div class="card list" id="jobs">${jobs.jobs.length ? jobs.jobs.slice(0, 8).map(j => jobItem(j)).join('') :
        '<div class="item" style="cursor:default"><div class="t"><span>No scans yet this session.</span></div></div>'}</div></div></div>
    <div class="head" style="margin:30px 0 12px"><div class="grow"><div class="eyebrow">Your APK library</div><h2 style="margin:6px 0 0">Library</h2></div>
      <div class="search">${I.search}<input class="input" id="lq" placeholder="Filter files" autocomplete="off"></div>
      <button class="btn" id="addLib">${I.plus} Add folder</button></div>
    <div id="lib"></div></div>`;
  $('#pick').onclick = async () => {
    const r = await api('/api/pick', {kind: 'file'});
    if (r.path) startScan(r.path);
  };
  $$('#opts .toggle').forEach(t => t.onclick = async () => {
    const k = t.dataset.k;
    if (!toggles.find(x => x[0] === k)[3]) return;
    const scan = {...store.state.settings.scan, [k]: !t.classList.contains('on')};
    const r = await api('/api/settings', {settings: {scan}});
    store.state.settings = r.settings;
    t.classList.toggle('on', r.settings.scan[k]);
  });
  $$('#jobs [data-job]').forEach(el => el.onclick = () => { location.hash = '#/job/' + el.dataset.job; });
  $('#addLib').onclick = async () => {
    const r = await api('/api/pick', {kind: 'folder'});
    if (!r.path) return;
    await api('/api/settings', {settings: {library_dirs: [...store.state.settings.library_dirs, r.path]}});
    store.state = null;
    render();
  };
  const scansByDir = Object.fromEntries((await loadScans(true)).map(s => [s.dir, s]));
  const drawLib = () => {
    const q = $('#lq').value.trim().toLowerCase();
    if (!lib.dirs.length) {
      $('#lib').innerHTML = `<div class="note cyan">Add the folder where you keep your APKs (for example <code>C:\\apks</code>) and every build shows up here with its scan status.</div>`;
      return;
    }
    $('#lib').innerHTML = lib.dirs.map(d => {
      const files = d.files.filter(f => !q || f.rel.toLowerCase().includes(q));
      return `<div class="row" style="margin:6px 0 10px"><span class="mono muted" style="font-size:12.5px">${esc(d.dir)}</span><span class="chip mono">${d.files.length}</span>
        <button class="btn ghost small" data-open="${esc(d.dir)}">${I.folder} Open</button><button class="btn ghost small danger" data-rm="${esc(d.dir)}">Remove</button></div>
        <div class="card list" style="margin-bottom:22px">${files.slice(0, 400).map(f => {
          const sc = f.scans.map(x => scansByDir[x]).filter(Boolean)[0];
          return `<div class="item" data-path="${esc(f.path)}">${sc ? lead(sc) : `<div class="lead mono" style="font-size:12px;color:var(--mute)">${esc(f.name.split('.').pop())}</div>`}
            <div class="t"><b>${esc(f.name)}</b><span>${esc(f.rel)} · ${fmtSize(f.size)} · ${fmtAgo(f.mtime)}</span></div>
            ${sc ? `<span class="chip ok" data-report="${esc(sc.dir)}"><i class="dot"></i>Scanned · ${esc(sc.tool || '')}</span>` : ''}
            <button class="btn small ${sc ? '' : 'primary'}" data-scan="${esc(f.path)}" data-replace="${sc ? esc(sc.dir) : ''}">${I.scan} ${sc ? 'Rescan' : 'Scan'}</button></div>`;
        }).join('') || '<div class="item" style="cursor:default"><div class="t"><span>No app files here.</span></div></div>'}</div>`;
    }).join('');
    $$('[data-scan]').forEach(b => b.onclick = ev => { ev.stopPropagation(); startScan(b.dataset.scan, b.dataset.replace); });
    $$('[data-report]').forEach(b => b.onclick = ev => { ev.stopPropagation(); location.hash = '#/report?dir=' + enc(b.dataset.report); });
    $$('#lib .item[data-path]').forEach(el => el.onclick = () => {
      const r = el.querySelector('[data-report]');
      if (r) location.hash = '#/report?dir=' + enc(r.dataset.report);
    });
    $$('[data-open]').forEach(b => b.onclick = () => api('/api/open', {path: b.dataset.open}).catch(e => toast(e.message)));
    $$('[data-rm]').forEach(b => b.onclick = async () => {
      await api('/api/settings', {settings: {library_dirs: store.state.settings.library_dirs.filter(x => x !== b.dataset.rm)}});
      store.state = null;
      render();
    });
  };
  drawLib();
  $('#lq').addEventListener('input', drawLib);
};

function jobItem(j) {
  const chip = {queued: '<span class="chip">Queued</span>', running: `<span class="chip cyan"><i class="dot"></i>${j.step}/${j.steps}</span>`,
    done: '<span class="chip ok">Done</span>', failed: '<span class="chip bad">Failed</span>', cancelled: '<span class="chip">Cancelled</span>'}[j.status];
  return `<div class="item" data-job="${j.id}"><div class="lead">${I.scan.replace('<svg', '<svg style="width:22px;height:22px;fill:none;stroke:var(--cyan);stroke-width:1.7"')}</div>
    <div class="t"><b>${esc(prettyFile(j.display))}</b><span>${j.status === 'running' ? 'scanning…' : fmtAgo(j.ended || j.created)}</span></div>${chip}</div>`;
}

async function startScan(path, replace) {
  try {
    const r = await api('/api/scan', replace ? {path, replace} : {path});
    toast('Scan queued');
    location.hash = '#/job/' + r.job.id;
  } catch (e) { toast(e.message); }
}

VIEWS.job = async (main, r) => {
  const id = r.arg;
  let since = 0;
  let job = await api(`/api/job?id=${enc(id)}`);
  main.innerHTML = `<div class="page fadein">
    <a class="btn ghost small" href="#/scan">${I.back} Scan</a>
    <div class="head" style="margin-top:14px"><div class="grow"><div class="eyebrow" id="jEyebrow">Scanning</div>
      <h1 style="word-break:break-all">${esc(prettyFile(job.display))}</h1><p class="sub mono" style="font-size:12px">${esc(job.input)}</p></div>
      <div class="row" id="jActs"></div></div>
    <div class="bar" style="margin:-6px 0 24px;height:8px"><i id="jBar" style="width:0"></i></div>
    <div class="two"><div class="card pad"><div class="stepper" id="steps"></div></div>
      <div><h3 style="margin-top:0">Log</h3><div class="log" id="log"></div><div id="jNote" style="margin-top:14px"></div></div></div></div>`;
  const log = $('#log');
  const draw = j => {
    job = j;
    const t0 = j.started;
    $('#steps').innerHTML = j.step_names.map((n, i) => {
      const k = i + 1;
      let cls = 'wait';
      if (j.status === 'done' || k < j.step) cls = 'done';
      else if (k === j.step) cls = j.status === 'failed' ? 'fail' : j.status === 'running' ? 'run' : 'done';
      const st = j.step_times[i], en = j.step_times[i + 1] || (cls === 'done' && j.ended) || null;
      const dur = st && en ? fmtDur(en - st) : (cls === 'run' && st ? fmtDur(Date.now() / 1000 - st) : '');
      return `<div class="step ${cls}"><div class="ico"></div><div class="lbl"><b>${esc(n)}</b><span>${dur}</span></div></div>`;
    }).join('');
    const pct = j.status === 'done' ? 100 : Math.max(2, Math.round(100 * Math.max(0, j.step - 0.5) / j.steps));
    $('#jBar').style.width = pct + '%';
    const el = t0 ? fmtDur((j.ended || Date.now() / 1000) - t0) : '';
    $('#jEyebrow').innerHTML = {queued: 'Queued — waiting for the scan ahead', running: `Scanning <span class="dot">·</span> ${el}`,
      done: `Done <span class="dot">·</span> ${el}`, failed: 'Failed', cancelled: 'Cancelled'}[j.status];
    if (j.log && j.log.length) {
      const atBottom = log.scrollHeight - log.scrollTop - log.clientHeight < 40;
      log.insertAdjacentHTML('beforeend', j.log.map(l => /^\[\d+\/\d+\]/.test(l) ? `<span class="s">${esc(l)}</span>` : esc(l)).join('\n') + '\n');
      since = j.log_total;
      if (atBottom) log.scrollTop = log.scrollHeight;
    }
    const acts = $('#jActs');
    if (j.status === 'running' || j.status === 'queued') {
      if (!$('#cancel')) acts.innerHTML = `<button class="btn danger" id="cancel">${I.stop} Cancel</button>`;
      $('#cancel').onclick = () => api('/api/cancel', {id}).then(() => toast('Cancelling…'));
    } else if (j.status === 'done') {
      acts.innerHTML = `<a class="btn primary" href="#/report?dir=${enc(j.out)}">${I.open} Open report</a>`;
      $('#jNote').innerHTML = `<div class="note cyan">Saved to <code>${esc(j.out)}</code></div>`;
      store.scans = null;
    } else if (j.status === 'failed') {
      acts.innerHTML = `<button class="btn" id="retry">${I.scan} Try again</button>`;
      $('#retry').onclick = () => startScan(j.input);
      $('#jNote').innerHTML = `<div class="note bad"><b>The scan failed.</b> ${esc(j.error || '')}</div>`;
    } else {
      acts.innerHTML = '';
    }
  };
  draw(job);
  every(async () => {
    if (!['running', 'queued'].includes(job.status)) return;
    try { draw(await api(`/api/job?id=${enc(id)}&since=${since}`)); } catch { /* next tick */ }
  }, 700);
};

/* ------------------------------------------------------------------ explorer */
VIEWS.explorer = async (main, r) => {
  const scans = (await loadScans()).slice().sort((a, b) => displayName(a).localeCompare(displayName(b)) || verNum(b) - verNum(a));
  let dir = r.q.get('dir') || (scans[0] && scans[0].dir);
  if (!dir) { main.innerHTML = '<div class="page"><div class="note cyan">Scan an app first — the explorer browses a scan\'s code index.</div></div>'; return; }
  main.innerHTML = `<div class="page fadein" style="max-width:none">
    <div class="head"><div class="grow"><div class="eyebrow">Code index <span class="dot">·</span> smali, callers, strings</div><h1>Explorer</h1></div>
      <select class="input" id="xdir" style="min-width:320px">${scans.map(s => `<option value="${esc(s.dir)}" ${s.dir === dir ? 'selected' : ''}>${esc(displayName(s))} · v${esc(s.version)}${s.kind !== 'apkm' ? ' — ' + esc(prettyFile(s.input)) : ''}</option>`).join('')}</select></div>
    <div class="row" style="margin-bottom:16px">
      <select class="input" id="xkind" style="min-width:170px"><option value="seam">Seam candidates</option><option value="method">Methods</option>
        <option value="class">Classes</option><option value="string">Strings</option><option value="ref">Callers of ref</option></select>
      <div class="search" style="flex:1">${I.search}<input class="input" id="xq" style="width:100%" placeholder="AdBreak, getAdCuePoints, /ads/, Playing media without ads…" autocomplete="off"></div>
      <button class="btn primary" id="xgo">Search</button></div>
    <div class="split"><div class="card panel list" id="xlist"></div><div class="card pad panel" id="xdet"><p class="muted">Pick a result. Every invoke target and caller in the smali is clickable.</p></div></div></div>`;
  const X = (ep, qs) => api(`/api/x/${ep}?dir=${enc(dir)}&${qs}`);
  const search = async () => {
    $('#xlist').innerHTML = '<div class="item"><div class="t"><span>Searching…</span></div></div>';
    const d = await X('search', `kind=${$('#xkind').value}&q=${enc($('#xq').value.trim())}`);
    $('#xlist').innerHTML = d.items.map((it, i) => `<div class="item" data-i="${i}" style="padding:9px 14px"><div class="t">
      <b class="mono" style="font-size:12px;white-space:normal;word-break:break-all;font-weight:500">${esc(it.label)}</b><span>${esc(it.k)}</span></div></div>`).join('') ||
      '<div class="item"><div class="t"><span>No results.</span></div></div>';
    $$('#xlist [data-i]').forEach(el => el.onclick = () => {
      $$('#xlist .item').forEach(x => x.classList.remove('sel'));
      el.classList.add('sel');
      const it = d.items[+el.dataset.i];
      if (it.id) showMethod(it.id); else showClass(it.cls);
    });
  };
  const linkify = sm => esc(sm)
    .replace(/(L[\w/$\-]+;-&gt;[\w$&lt;&gt;\-]+\([^)]*\)[\w/$[;]+)/g, m => `<a class="ref" data-sig="${m}">${m}</a>`)
    .replace(/(&quot;.*?&quot;)/g, '<span class="s">$1</span>')
    .replace(/^(\s+)(invoke-[\w/-]+|const-string[\w/]*|return[\w-]*|if-\w+|goto[\w/]*|[is]get[\w-]*|[is]put[\w-]*|new-instance|throw)/gm, '$1<span class="op">$2</span>')
    .replace(/^(\s*)(\.method|\.end method|\.registers|\.locals)/gm, '$1<span class="kw">$2</span>');
  const unesc = s => { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; };
  const wire = el => {
    $$('a.ref[data-sig]', el).forEach(a => a.onclick = async () => {
      const d = await X('resolve', 'sig=' + enc(unesc(a.dataset.sig)));
      if (d.id) showMethod(d.id); else { $('#xkind').value = 'ref'; $('#xq').value = unesc(a.dataset.sig); search(); }
    });
    $$('[data-mid]', el).forEach(a => a.onclick = () => showMethod(a.dataset.mid));
    $$('[data-cls]', el).forEach(a => a.onclick = () => showClass(a.dataset.cls));
  };
  const showMethod = async id => {
    const d = await X('method', 'id=' + id);
    const D = $('#xdet');
    D.innerHTML = `<div class="mono" style="font-size:13px;word-break:break-all;font-weight:600">${esc(d.sig)}</div>
      <div class="chips" style="margin:10px 0"><span class="chip mono">#${d.id}</span><span class="chip">${esc(d.owner)}</span>${d.source ? `<span class="chip mono">${esc(d.source)}</span>` : ''}
      <button class="chip f" data-cls="${esc(d.cls)}">Class outline</button><button class="chip f" id="fpb">Draft fingerprint</button></div>
      <div id="fp"></div><h3>Smali</h3><pre>${linkify(d.smali)}</pre>
      <h3>Callers · ${d.callers.length}</h3>${d.callers.map(c => `<div><a class="ref mono" style="font-size:12px;cursor:pointer;word-break:break-all" data-mid="${c.id}">${esc(c.sig)}</a></div>`).join('') || '<p class="muted">None in the index.</p>'}
      <h3>Strings</h3>${d.strings.map(s => `<div class="mono" style="font-size:12px;color:#7CF7EA;word-break:break-all">"${esc(s)}"</div>`).join('') || '<p class="muted">None.</p>'}`;
    wire(D);
    $('#fpb').onclick = async () => {
      const f = await X('fp', 'id=' + id);
      $('#fp').innerHTML = `<h3>Fingerprint · matches ${f.matches}${f.unique ? ' (unique)' : ''}</h3>${(f.notes || []).map(n => `<div class="muted" style="font-size:12.5px">${inline(n)}</div>`).join('')}
        <pre style="margin-top:8px">${esc(JSON.stringify(f.descriptor, null, 2))}</pre><button class="btn small" id="cpf" style="margin-top:8px">${I.copy} Copy</button>`;
      $('#cpf').onclick = () => navigator.clipboard.writeText(JSON.stringify(f.descriptor, null, 2)).then(() => toast('Descriptor copied'));
    };
    D.scrollTop = 0;
  };
  const showClass = async cls => {
    const d = await X('class', 'name=' + enc(cls));
    const D = $('#xdet');
    if (!d.name) { D.innerHTML = `<p class="muted">${esc(cls)} is not in the index (framework/SDK class).</p>`; return; }
    D.innerHTML = `<div class="mono" style="font-size:13px;word-break:break-all;font-weight:600">${esc(d.name)}</div>
      <p class="muted" style="font-size:12.5px">extends <a class="ref mono" style="cursor:pointer" data-cls="${esc(d.super)}">${esc(d.super)}</a>${d.interfaces ? ' · implements ' + esc(d.interfaces) : ''}</p>
      <div class="chips"><span class="chip">${esc(d.owner)}</span>${d.source ? `<span class="chip mono">${esc(d.source)}</span>` : ''}</div>
      <h3>Fields</h3><pre>${d.fields.map(esc).join('\n') || '—'}</pre>
      <h3>Methods · ${d.methods.length}</h3>${d.methods.map(x => `<div><a class="ref mono" style="font-size:12px;cursor:pointer;word-break:break-all" data-mid="${x.id}">${esc(x.label)}</a></div>`).join('')}`;
    wire(D);
  };
  $('#xgo').onclick = search;
  $('#xq').addEventListener('keydown', e => { if (e.key === 'Enter') search(); });
  $('#xdir').onchange = () => { location.hash = '#/explorer?dir=' + enc($('#xdir').value); };
  await search();
  if (r.q.get('id')) showMethod(r.q.get('id'));
};

/* ------------------------------------------------------------------ compare */
VIEWS.compare = async (main, r) => {
  const scans = (await loadScans()).slice().sort((a, b) => displayName(a).localeCompare(displayName(b)) || verNum(a) - verNum(b));
  let b = r.q.get('b') || '', a = r.q.get('a') || '';
  const bs = scans.find(s => s.dir === b);
  if (bs && !a) {
    const older = scans.filter(s => s.package === bs.package && s.dir !== bs.dir && verNum(s) <= verNum(bs)).pop();
    a = older ? older.dir : '';
  }
  const opt = sel => scans.map(s => `<option value="${esc(s.dir)}" ${s.dir === sel ? 'selected' : ''}>${esc(displayName(s))} · v${esc(s.version)}${s.code ? ' · ' + esc(s.code) : ''}${s.kind !== 'apkm' ? ' — ' + esc(prettyFile(s.input)) : ''}</option>`).join('');
  main.innerHTML = `<div class="page fadein">
    <div class="head"><div class="grow"><div class="eyebrow">Old build → new build</div><h1>Compare</h1>
      <p class="sub">R8 renames, where each seam went, drifted fingerprints, new ad strings and hosts. Same build twice (stock vs patched) shows every changed method body.</p></div></div>
    <div class="card pad"><div class="row">
      <select class="input" id="ca" style="flex:1"><option value="">Old build…</option>${opt(a)}</select>
      <span style="color:var(--cyan)">${I.compare.replace('<svg', '<svg style="width:22px;height:22px;fill:none;stroke:currentColor;stroke-width:1.8"')}</span>
      <select class="input" id="cb" style="flex:1"><option value="">New build…</option>${opt(b)}</select>
      <button class="btn primary" id="go">Compare</button></div></div>
    <div id="out" style="margin-top:20px"></div></div>`;
  const go = async () => {
    const A = $('#ca').value, B = $('#cb').value;
    if (!A || !B) { toast('Pick two builds'); return; }
    history.replaceState(null, '', `#/compare?a=${enc(A)}&b=${enc(B)}`);
    $('#out').innerHTML = '<div class="card pad"><div class="row"><div class="step run" style="padding:0"><div class="ico"></div></div><b>Comparing…</b><span class="muted">class shapes, renames and seams — 20–40 s on big apps</span></div></div>';
    try {
      const d = await api(`/api/diff?a=${enc(A)}&b=${enc(B)}`);
      const x = d.diff, c = x.classes || {};
      const fps = (x.fingerprints || []);
      $('#out').innerHTML = `<div class="stats card pad" style="margin-top:0">
          <div class="stat"><b>${(c.renamed_matched || 0).toLocaleString()}</b><span>renames matched</span></div>
          <div class="stat"><b>${(c.added || 0).toLocaleString()}</b><span>classes added</span></div>
          <div class="stat"><b>${(c.removed || 0).toLocaleString()}</b><span>removed</span></div>
          <div class="stat"><b>${(x.seam_moves || []).filter(m => m.status !== 'same').length}</b><span>seams moved</span></div>
          ${x.body_changes ? `<div class="stat"><b style="color:var(--amber)">${x.body_changes.count}</b><span>bodies changed</span></div>` : ''}
          <div class="stat"><b style="color:${fps.some(f => f.new !== 'OK') ? 'var(--amber)' : 'var(--ok)'}">${fps.filter(f => f.new !== 'OK').length}</b><span>fingerprints off</span></div></div>
        <div class="card pad" style="margin-top:18px">${md(d.md)}</div>`;
    } catch (e) {
      $('#out').innerHTML = `<div class="note bad">${esc(e.message)}</div>`;
    }
  };
  $('#go').onclick = go;
  if (a && b) go();
};

/* ------------------------------------------------------------------ settings */
VIEWS.settings = async main => {
  const st = await loadState(true);
  const s = st.settings, t = st.tools || {};
  const folderList = (key, title, help) => `<div class="card pad" style="margin-bottom:18px"><div class="row"><h2 style="margin:0">${title}</h2><span class="spacer"></span>
      <button class="btn small" data-add="${key}">${I.plus} Add folder</button></div><p class="sub" style="margin:6px 0 12px">${help}</p>
      <div class="list">${(s[key] || []).map((p, i) => `<div class="item" style="cursor:default;padding:10px 0"><div class="t"><b class="mono" style="font-size:13px;font-weight:500">${esc(p)}</b>
        ${i === 0 && key === 'results_dirs' ? '<span>New scans are saved here</span>' : ''}</div>
        <button class="btn ghost small" data-open="${esc(p)}">${I.folder}</button>
        ${(key !== 'results_dirs' || s[key].length > 1) ? `<button class="btn ghost small danger" data-del="${key}" data-i="${i}">Remove</button>` : ''}</div>`).join('') || '<p class="muted">None yet.</p>'}</div></div>`;
  main.innerHTML = `<div class="page fadein"><div class="head"><div class="grow"><div class="eyebrow">Preferences</div><h1>Settings</h1></div></div>
    ${folderList('results_dirs', 'Results folders', 'Where scans are saved and looked for. Each scan is a folder with report.md (the Claude handoff), report.html, report.json and the code index.')}
    ${folderList('library_dirs', 'APK library folders', 'Folders SeamHunter lists on the Scan page, with each file’s scan status.')}
    <div class="two"><div class="card pad"><h2>Optional tools</h2><dl class="kv">
      <dt>Java</dt><dd>${t.java ? `<span class="chip ok">found</span> <span class="mono muted" style="font-size:12px">${esc(t.java)}</span>` : '<span class="chip">not found</span>'}</dd>
      <dt>jadx</dt><dd>${t.jadx ? `<span class="chip ok">found</span> <span class="mono muted" style="font-size:12px">${esc(t.jadx)}</span>` : '<span class="chip">not installed</span> <span class="muted">— <code>autopsy tools install</code> for Java excerpts</span>'}</dd>
      <dt>apktool</dt><dd>${t.apktool ? `<span class="chip ok">found</span> <span class="mono muted" style="font-size:12px">${esc(t.apktool)}</span>` : '<span class="chip">not found</span>'}</dd></dl></div>
    <div class="card pad"><h2>About</h2><img src="/static/banner.webp" alt="SeamHunter" style="width:100%;border-radius:12px;border:1px solid var(--line)">
      <dl class="kv" style="margin-top:14px"><dt>Version</dt><dd class="mono">${esc(st.version)}</dd><dt>Installed at</dt><dd class="mono" style="font-size:12px">${esc(st.app_root)}</dd>
      <dt>Settings file</dt><dd class="mono" style="font-size:12px">${esc(st.conf)}</dd>
      <dt>Privacy</dt><dd>Runs on 127.0.0.1 only. No telemetry, no network — static analysis, never patching.</dd></dl></div></div></div>`;
  $$('[data-add]').forEach(b => b.onclick = async () => {
    const r = await api('/api/pick', {kind: 'folder'});
    if (!r.path) return;
    const k = b.dataset.add;
    const next = k === 'results_dirs' ? [...s[k], r.path] : [...s[k], r.path];
    await api('/api/settings', {settings: {[k]: next}});
    store.state = null; store.scans = null;
    render();
  });
  $$('[data-del]').forEach(b => b.onclick = async () => {
    const k = b.dataset.del;
    await api('/api/settings', {settings: {[k]: s[k].filter((_, i) => i !== +b.dataset.i)}});
    store.state = null; store.scans = null;
    render();
  });
  $$('[data-open]').forEach(b => b.onclick = () => api('/api/open', {path: b.dataset.open}).catch(e => toast(e.message)));
};

/* ------------------------------------------------------------------ global: jobs badge, heartbeat, drag & drop */
async function tickJobs() {
  try {
    const {jobs} = await api('/api/jobs');
    store.jobs = jobs;
    const active = jobs.filter(j => j.status === 'running' || j.status === 'queued');
    const badge = $('#scanBadge');
    badge.hidden = !active.length;
    badge.textContent = active.length;
    const mj = $('#miniJob');
    const run = jobs.find(j => j.status === 'running');
    mj.hidden = !run;
    if (run) {
      mj.innerHTML = `<b>${esc(prettyFile(run.display))}</b><span class="muted">step ${run.step}/${run.steps}</span><div class="bar"><i style="width:${Math.round(100 * Math.max(0.5, run.step - 0.5) / run.steps)}%"></i></div>`;
      mj.onclick = () => { location.hash = '#/job/' + run.id; };
    }
  } catch { /* server going away */ }
}
setInterval(tickJobs, 2500);
setInterval(() => api('/api/ping').catch(() => {}), 10000);

let dragDepth = 0;
const hasFiles = e => e.dataTransfer && [...e.dataTransfer.types].includes('Files');
window.addEventListener('dragenter', e => { if (!hasFiles(e)) return; e.preventDefault(); dragDepth++; $('#dropVeil').hidden = false; });
window.addEventListener('dragover', e => { if (hasFiles(e)) e.preventDefault(); });
window.addEventListener('dragleave', () => { if (--dragDepth <= 0) { dragDepth = 0; $('#dropVeil').hidden = true; } });
window.addEventListener('drop', e => {
  if (!hasFiles(e)) return;
  e.preventDefault();
  dragDepth = 0;
  $('#dropVeil').hidden = true;
  const f = e.dataTransfer.files[0];
  if (!f) return;
  if (!/\.(apk|apkm|xapk|apks)$/i.test(f.name)) { toast('Drop an .apk, .apkm, .xapk or .apks'); return; }
  const xhr = new XMLHttpRequest();
  xhr.open('POST', '/api/upload?name=' + enc(f.name));
  xhr.setRequestHeader('X-Seam-Token', TOKEN);
  xhr.upload.onprogress = ev => { if (ev.lengthComputable) toast(`Copying ${f.name} — ${Math.round(100 * ev.loaded / ev.total)}%`); };
  xhr.onload = () => {
    try {
      const r = JSON.parse(xhr.responseText);
      if (r.error) throw new Error(r.error);
      location.hash = '#/job/' + r.job.id;
    } catch (err) { toast(err.message); }
  };
  xhr.onerror = () => toast('Upload failed');
  xhr.send(f);
});

/* ------------------------------------------------------------------ code rain */
(function rain() {
  const c = $('#rain');
  const ctx = c.getContext('2d');
  const glyphs = '0123456789ABCDEF;->()[]{}/$Lv#invokeconst';
  const fs = 15;
  let cols = [], w = 0, h = 0;
  const size = () => {
    w = c.width = innerWidth; h = c.height = innerHeight;
    cols = Array.from({length: Math.ceil(w / fs)}, () => Math.random() * -h / fs);
    ctx.fillStyle = '#060A14'; ctx.fillRect(0, 0, w, h);
  };
  size();
  addEventListener('resize', size);
  const reduce = matchMedia('(prefers-reduced-motion: reduce)').matches;
  let last = 0;
  const frame = t => {
    if (!document.hidden && t - last > 70) {
      last = t;
      ctx.fillStyle = 'rgba(6,10,20,0.14)';
      ctx.fillRect(0, 0, w, h);
      ctx.font = `${fs}px "JetBrains Mono", monospace`;
      cols.forEach((y, i) => {
        ctx.fillStyle = Math.random() < 0.04 ? '#CFFFE0' : '#27E36B';
        ctx.fillText(glyphs[(Math.random() * glyphs.length) | 0], i * fs, y * fs);
        cols[i] = y * fs > h && Math.random() > 0.975 ? 0 : y + 1;
      });
    }
    if (!reduce) requestAnimationFrame(frame);
  };
  requestAnimationFrame(frame);
})();

/* ------------------------------------------------------------------ boot */
loadState().then(s => { $('#ver').textContent = `v${s.version} · local · private`; }).catch(() => {});
tickJobs();
render();
