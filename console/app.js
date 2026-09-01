/* AIRLOCK console.
 *
 * Read-only. Nothing in here writes: the only POST is /api/replay, which is a
 * what-if the server runs with persist=False.
 *
 * Everything from the database goes through esc() before it reaches innerHTML.
 * That is not boilerplate here -- the taint inventory's whole purpose is to
 * display prompt-injection payloads, so this page renders hostile strings by
 * design and must never interpret them.
 */

const esc = (v) => String(v ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const fmt = (n) => (n === null || n === undefined) ? '&mdash;' : Number(n).toLocaleString();
const num = (n, d = 2) => (n === null || n === undefined) ? '&mdash;' : Number(n).toFixed(d);

// A negative TAINT_MAX is the gateway's sentinel for a scan that applied but
// could not be taken. Showing it as -1.00 would read as a very clean result
// set, which is the opposite of what it means.
const taint = (n) => (n === null || n === undefined) ? '&mdash;'
  : (Number(n) < 0 ? '<span title="the result set could not be scanned">not scanned</span>'
                   : num(n));
const $ = (s) => document.querySelector(s);

async function api(path, opts) {
  const r = await fetch(path, opts);
  const body = await r.json().catch(() => ({ detail: r.statusText }));
  if (!r.ok) throw new Error(body.detail || `HTTP ${r.status}`);
  return body;
}

function fail(el, e) {
  el.innerHTML = `<div class="err">${esc(e.message)}</div>`;
}

/* ---------------- overview ---------------- */

async function loadOverview() {
  const o = await api('/api/overview');

  $('#dsn').textContent = o.dsn;

  const chain = $('#chain');
  chain.className = 'pill ' + (o.chain_intact ? 'ok' : 'bad');
  chain.innerHTML = `<span class="dot live"></span> ${o.chain_intact
    ? 'hash chain intact'
    : `chain broken at #${esc(o.chain_breaks.map((b) => b.SEQ).join(', '))}`}`;

  const vitals = [
    ['decisions recorded', fmt(o.total), ''],
    ['allowed', fmt(o.allow), 'allow'],
    ['denied', fmt(o.deny), 'deny'],
    ['held for approval', fmt(o.require_approval), 'hold'],
    ['group sizes measured', fmt(o.groups_measured), ''],
    ['result sets scanned', fmt(o.taint_scanned), ''],
    ['withheld on taint', fmt(o.taint_withheld), 'deny'],
    ['mean decision', num(o.avg_latency_ms, 1) + ' ms', ''],
  ];
  $('#vitals').innerHTML = vitals.map(([k, n, cls]) =>
    `<div class="vital"><div class="n ${cls}">${n}</div><div class="k">${k}</div></div>`).join('');

  const total = Math.max(o.total, 1);
  const bar = $('#bar');
  bar.querySelector('.a').style.width = (o.allow / total * 100) + '%';
  bar.querySelector('.h').style.width = (o.require_approval / total * 100) + '%';
  bar.querySelector('.d').style.width = (o.deny / total * 100) + '%';

  $('#legend').innerHTML = [
    ['allow', o.allow, 'allowed through'],
    ['hold', o.require_approval, 'held for a human'],
    ['deny', o.deny, 'refused'],
  ].map(([c, n, label]) =>
    `<span><i class="key" style="background:var(--${c})"></i>${label} <b>${fmt(n)}</b></span>`
  ).join('') + `<span style="color:var(--dim)">${fmt(o.taint_rows)} tainted rows across `
             + `${fmt(o.taint_columns)} columns, worst ${num(o.taint_worst)}</span>`;
}

/* ---------------- ledger ---------------- */

let selectedSeq = null;

async function loadLedger() {
  const p = new URLSearchParams({
    limit: $('#f-limit').value,
    decision: $('#f-decision').value,
    kind: $('#f-kind').value,
    q: $('#f-q').value.trim(),
  });
  for (const [k, v] of [...p]) if (!v) p.delete(k);

  const body = $('#ledger-body');
  try {
    const d = await api('/api/ledger?' + p);
    $('#ledger-count').innerHTML = `${fmt(d.rows.length)} of ${fmt(d.total)} matching`;
    if (!d.rows.length) {
      body.innerHTML = '<tr><td colspan="9"><div class="empty">nothing matches</div></td></tr>';
      return;
    }
    body.innerHTML = d.rows.map((r) => `
      <tr data-seq="${r.SEQ}" class="${r.SEQ === selectedSeq ? 'sel' : ''}">
        <td class="num">${r.SEQ}</td>
        <td class="num">${esc((r.TS || '').slice(11, 23))}</td>
        <td><span class="kind">${esc(r.STMT_KIND)}</span></td>
        <td class="sql">${esc(r.STMT_TEXT)}</td>
        <td><span class="tag ${esc(r.DECISION)}">${esc(r.DECISION)}</span></td>
        <td class="num">${fmt(r.EST_ROWS)}</td>
        <td class="num">${fmt(r.MIN_GROUP)}</td>
        <td class="num">${taint(r.TAINT_MAX)}</td>
        <td class="num">${num(r.LATENCY_MS, 1)}</td>
      </tr>`).join('');
    body.querySelectorAll('tr').forEach((tr) =>
      tr.onclick = () => openEntry(Number(tr.dataset.seq)));
  } catch (e) { fail(body.parentElement.parentElement, e); }
}

async function openEntry(seq) {
  selectedSeq = seq;
  document.querySelectorAll('#ledger-body tr').forEach((tr) =>
    tr.classList.toggle('sel', Number(tr.dataset.seq) === seq));

  const drawer = $('#drawer');
  drawer.classList.add('on');
  const out = $('#drawer-body');
  out.innerHTML = '<div class="empty">loading&hellip;</div>';

  try {
    const e = await api('/api/ledger/' + seq);
    const measured = [
      ['rows affected', fmt(e.EST_ROWS)],
      ['smallest group', fmt(e.MIN_GROUP)],
      ['worst taint', taint(e.TAINT_MAX)],
      ['decided in', num(e.LATENCY_MS, 1) + ' ms'],
    ];
    let features = e.FEATURES;
    try { features = JSON.stringify(JSON.parse(e.FEATURES), null, 2); } catch { /* raw */ }

    out.innerHTML = `
      <h3>Decision #${e.SEQ} &nbsp;<span class="tag ${esc(e.DECISION)}">${esc(e.DECISION)}</span></h3>
      <div class="hint">${esc(e.TS)} &middot; ${esc(e.PRINCIPAL)} &middot; session ${esc(String(e.SESSION_ID).slice(0, 12))}</div>

      <div class="field"><div class="k">statement</div><pre>${esc(e.STMT_TEXT)}</pre></div>
      <div class="field"><div class="k">why</div><pre>${esc(e.REASON)}</pre></div>
      <div class="field"><div class="k">measured before deciding</div>
        <div class="mgrid">${measured.map(([k, v]) =>
          `<div><div class="n">${v}</div><div class="k">${k}</div></div>`).join('')}</div></div>
      ${e.POLICIES.length ? `<div class="field"><div class="k">rules that fired</div><pre>${
        e.POLICIES.map((p) => `#${p.POLICY_ID}  ${p.NAME}  [${p.RULE_KIND} -> ${p.EFFECT}${
          p.THRESHOLD === null ? '' : ', threshold ' + p.THRESHOLD}]`).map(esc).join('\n')
      }</pre></div>` : ''}
      ${e.ROLLBACK_SQL ? `<div class="field"><div class="k">compensating statement</div><pre>${esc(e.ROLLBACK_SQL)}</pre></div>` : ''}
      <div class="field"><div class="k">statement features</div><pre>${esc(features)}</pre></div>
      <div class="field"><div class="k">chain</div>
        <pre class="hash">prev  ${esc(e.PREV_HASH)}\nentry ${esc(e.ENTRY_HASH)}</pre></div>`;
  } catch (e) { fail(out, e); }
}

/* ---------------- taint ---------------- */

async function loadTaint() {
  try {
    const d = await api('/api/taint?limit=50');
    $('#taint-cols').innerHTML = d.by_column.map((c) => `
      <tr><td class="sql">${esc(c.TABLE_NAME)}.${esc(c.COLUMN_NAME)}</td>
      <td class="num">${fmt(c.N)}</td>
      <td>${scoreBar(c.WORST)}</td></tr>`).join('');

    $('#taint-body').innerHTML = d.rows.map((r) => `
      <tr>
        <td>${scoreBar(r.SCORE)}</td>
        <td class="sql">${esc(r.TABLE_NAME)}.${esc(r.COLUMN_NAME)}</td>
        <td class="pat">${esc(r.PATTERNS)}</td>
        <td class="sample">${esc(String(r.SAMPLE).slice(0, 220))}</td>
      </tr>`).join('') || '<tr><td colspan="4"><div class="empty">'
        + 'no tainted rows &mdash; run sql/30_taint_seed.sql then python -m airlock.taint'
        + '</div></td></tr>';
  } catch (e) { fail($('#taint-body').parentElement.parentElement, e); }
}

const scoreBar = (s) => `<span class="score"><b>${num(s)}</b>
  <span class="track"><span class="fill" style="width:${Math.round(Number(s) * 100)}%"></span></span></span>`;

/* ---------------- policies + replay controls ---------------- */

let policyCache = [];

async function loadPolicies() {
  try {
    policyCache = await api('/api/policies');
    $('#policy-body').innerHTML = policyCache.map((p) => `
      <tr>
        <td class="num">${p.POLICY_ID}</td>
        <td class="ident"><span class="kind">${esc(p.NAME)}</span></td>
        <td class="kind">${esc(p.RULE_KIND)}</td>
        <td><span class="tag ${esc(p.EFFECT)}">${esc(p.EFFECT)}</span></td>
        <td class="sql">${esc([p.TARGET_SCHEMA, p.TARGET_TABLE, p.TARGET_COLUMN]
            .filter(Boolean).join('.')) || '<span style="color:var(--dim)">any</span>'}</td>
        <td class="num">${p.THRESHOLD === null ? '&mdash;' : p.THRESHOLD}</td>
        <td class="note">${esc(p.NOTE)}</td>
      </tr>`).join('');
    renderReplayRules();
  } catch (e) { fail($('#policy-body').parentElement.parentElement, e); }
}

function renderReplayRules() {
  $('#replay-rules').innerHTML = policyCache.map((p) => `
    <div class="rule" data-name="${esc(p.NAME)}">
      <div class="top">
        <input type="checkbox" class="on-off" checked title="include this rule">
        <span class="nm">${esc(p.NAME)}</span>
        ${p.THRESHOLD === null ? '<span class="hint">no threshold</span>'
          : `<input type="number" class="thr" step="any" value="${p.THRESHOLD}"
                    data-original="${p.THRESHOLD}">`}
      </div>
      <div class="meta">${esc(p.RULE_KIND)} &rarr; ${esc(p.EFFECT)}</div>
    </div>`).join('');

  $('#replay-rules').querySelectorAll('.rule').forEach((row) => {
    const box = row.querySelector('.on-off');
    box.onchange = () => row.classList.toggle('off', !box.checked);
  });
}

async function runReplay() {
  const sets = {}, disable = [];
  $('#replay-rules').querySelectorAll('.rule').forEach((row) => {
    const name = row.dataset.name;
    if (!row.querySelector('.on-off').checked) { disable.push(name); return; }
    const thr = row.querySelector('.thr');
    if (thr && Number(thr.value) !== Number(thr.dataset.original)) {
      sets[name] = Number(thr.value);
    }
  });

  const out = $('#replay-out');
  const btn = $('#run-replay');
  if (!Object.keys(sets).length && !disable.length) {
    out.innerHTML = '<div class="empty">Change a threshold or switch a rule off first '
                  + '&mdash; replaying the rules as they stand only proves the engine '
                  + 'still agrees with itself.</div>';
    return;
  }

  btn.disabled = true;
  out.innerHTML = '<div class="empty">re-deciding the whole ledger&hellip;</div>';
  try {
    const d = await api('/api/replay', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ sets, disable }),
    });
    out.innerHTML = `
      <div class="diffbig">
        <div><div class="n deny" style="color:var(--deny)">${fmt(d.newly_blocked)}</div>
             <div class="k">would now be stopped</div></div>
        <div><div class="n" style="color:var(--allow)">${fmt(d.newly_allowed)}</div>
             <div class="k">would now be allowed</div></div>
      </div>
      <div class="card">
        <h4>${fmt(d.changed)} of ${fmt(d.total)} recorded decisions change</h4>
        <div class="sub">${d.amendments.map((a) => esc(a.name) + ': '
          + (a.to === null ? 'disabled' : `${a.from} &rarr; ${a.to}`)).join(' &middot; ')}
          &nbsp;&mdash;&nbsp; nothing was written to AIRLOCK.POLICY</div>
        ${d.examples.map((x) => `
          <div class="ex">
            <div class="h">#${x.seq} <span class="tag ${esc(x.old)}">${esc(x.old)}</span>
              <span class="arrow">&rarr;</span>
              <span class="tag ${esc(x.new)}">${esc(x.new)}</span></div>
            <div class="r">${esc(x.reason)}</div>
          </div>`).join('') || '<div class="empty">no worked examples</div>'}
      </div>`;
  } catch (e) { fail(out, e); }
  btn.disabled = false;
}

/* ---------------- sessions ---------------- */

async function loadSessions() {
  try {
    const rows = await api('/api/sessions');
    $('#session-body').innerHTML = rows.map((s) => `
      <tr>
        <td class="kind">${esc(String(s.SESSION_ID).slice(0, 16))}</td>
        <td>${esc(s.PRINCIPAL)}</td>
        <td class="num">${esc(s.STARTED_AT)}</td>
        <td class="num">${fmt(s.STATEMENTS)}</td>
        <td class="num" style="color:var(--allow)">${fmt(s.ALLOWED)}</td>
        <td class="num" style="color:var(--deny)">${fmt(s.STOPPED)}</td>
      </tr>`).join('');
  } catch (e) { fail($('#session-body').parentElement.parentElement, e); }
}

/* ---------------- wiring ---------------- */

const loaders = {
  ledger: loadLedger, taint: loadTaint, replay: loadPolicies,
  policies: loadPolicies, sessions: loadSessions,
};
let activeTab = 'ledger';

// The breadcrumb names the page, so it needs a label per destination rather
// than the button's text: once the rail collapses to icons there is no text to
// read off it.
const LABELS = {
  ledger: 'Ledger', taint: 'Taint inventory',
  replay: 'Policy replay', policies: 'Rule set', sessions: 'Sessions',
};

function setTab(tab) {
  activeTab = tab;
  document.querySelectorAll('nav button').forEach((x) =>
    x.classList.toggle('on', x.dataset.tab === tab));
  document.querySelectorAll('.panel').forEach((p) =>
    p.classList.toggle('on', p.id === 'tab-' + tab));
  $('#crumb').textContent = LABELS[tab] || tab;
  loaders[tab]();
}

document.querySelectorAll('nav button').forEach((b) => {
  b.onclick = () => setTab(b.dataset.tab);
});

$('#refresh').onclick = () => { loadOverview(); loaders[activeTab](); };
$('#drawer-close').onclick = () => $('#drawer').classList.remove('on');
document.onkeydown = (e) => { if (e.key === 'Escape') $('#drawer').classList.remove('on'); };
$('#run-replay').onclick = runReplay;
$('#reset-replay').onclick = () => {
  renderReplayRules();
  $('#replay-out').innerHTML = '<div class="empty">Move a threshold, then run the '
    + 'what-if to see what the change would have done to every decision already '
    + 'on record.</div>';
};

['#f-decision', '#f-kind', '#f-limit'].forEach((s) => $(s).onchange = loadLedger);
let typing;
$('#f-q').oninput = () => { clearTimeout(typing); typing = setTimeout(loadLedger, 260); };

$('#crumb').textContent = LABELS[activeTab];
loadOverview();
loadLedger();
loadPolicies();

// The ledger is append-only and the console is a live view of it. Refreshing the
// list while a decision is open in the drawer would pull it out from under the
// reader, so the feed holds still until the drawer is closed.
setInterval(() => {
  loadOverview();
  if (activeTab === 'ledger' && !$('#drawer').classList.contains('on')) loadLedger();
}, 5000);
