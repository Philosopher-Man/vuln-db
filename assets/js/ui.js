/* ════════════════════════════════════════════════════════════════════
   ui.js — Interfaz: renderizado de tarjetas, buscador/filtros, motor de
   copiado, toasts y calculadora (drawer). El bootstrap vive en app.js.
   Secciones:
     1. Referencias DOM + estado + persistencia (localStorage)
     2. Utilidades de render (escape, normalización, resaltado)
     3. Filtrado, búsqueda y orden
     4. Renderizado de tarjetas (anillo + botones CVSS + Copiar nombre)
     5. Motor de copiado (formatos estrictos) + toasts con barra de progreso
     6. Calculadora CVSS 4.0 (drawer + scroll-lock robusto)
     7. Atajos de teclado + accesibilidad
     8. Eventos de filtros/buscador
     9. Init + API para app.js (onLibReady / onLibFailed)
   v2.0: el botón Custom es un LANZADOR puro de la calculadora vinculada
   (sin estado persistente por hallazgo) y cada tarjeta incorpora un
   botón "Copiar nombre" con el formato de informe [<CÓDIGO>] <Título>.
   ════════════════════════════════════════════════════════════════════ */

import {
  VULNS, CAT_NAMES, GROUPS, SEV, TIER_KEYS, TIER_SORT,
  METRIC_OPTS, METRIC_GROUPS,
} from './data.js';
import {
  r1, sevOf, sevLabelOf, formatCVSS, formatReportName, scoreOf, libIsReady,
  parseVector, buildVector, DEFAULT_VECTOR,
} from './cvss.js';

/* ── 1. REFERENCIAS DOM + ESTADO ───────────────────────────────────── */
const $ = (sel) => document.querySelector(sel);
const gridEl = $('#vulnGrid');
const emptyEl = $('#empty');
const countEl = $('#count');
const footCountEl = $('#footCount');
const qInput = $('#q');
const btnClear = $('#btnClear');
const btnClearFilters = $('#btnClearFilters');
const sortEl = $('#sort');
const searchbarEl = $('#searchbar');
const toastsEl = $('#toasts');
const drawerEl = $('#drawer');
const scrimEl = $('#scrim');
const vecInput = $('#vecInput');
const vecMsg = $('#vecMsg');
const drawerLinkEl = $('#drawerLink');
const scoreNumEl = $('#scoreNum');
const sevPillEl = $('#sevPill');
const scoreRingEl = $('#scoreRing');
const srValEl = $('#srVal');
const scoreCenterEl = $('#scoreCenter');
const copyPreviewEl = $('#copyPreview');
const btnCalcCopy = $('#btnCalcCopy');
const metricsEl = $('#metrics');
const libStatusEl = $('#libStatus');

/* Claves de localStorage. v2.0: solo persisten los filtros y el último
   vector editado en la calculadora libre; el estado Custom por hallazgo
   dejó de existir (la clave heredada de la v1.0 se limpia en initUI). */
const LS_FILTERS = 'appsec-filters-v2';
const LS_LASTVEC = 'appsec-last-vector-v2';
const LS_CUSTOMS_LEGACY = 'appsec-vuln-customs-v2'; // obsoleta: solo se elimina

const state = {
  q: '',
  group: 'all',
  sev: 'all',
  sort: 'az',
};

/* ── Persistencia: filtros (q, group, sev, sort) ───────────────────── */
function loadFilters() {
  try {
    const raw = localStorage.getItem(LS_FILTERS);
    if (!raw) return;
    const o = JSON.parse(raw);
    if (typeof o.q === 'string') state.q = o.q;
    if (o.group && (o.group === 'all' || GROUPS[o.group])) state.group = o.group;
    if (o.sev && (o.sev === 'all' || SEV[o.sev])) state.sev = o.sev;
    if (['az', 'id', 'sev'].includes(o.sort)) state.sort = o.sort;
  } catch (e) { /* almacenamiento no disponible: continuar con valores por defecto */ }
}
let filterTimer = null;
function persistFilters() {
  clearTimeout(filterTimer);
  filterTimer = setTimeout(() => {
    try {
      localStorage.setItem(LS_FILTERS, JSON.stringify({
        q: state.q, group: state.group, sev: state.sev, sort: state.sort,
      }));
    } catch (e) { /* modo privado: ignorar */ }
  }, 150);
}

/* ── Persistencia: último vector de la calculadora libre ──────────── */
function setLastVector(v) {
  try { localStorage.setItem(LS_LASTVEC, v); } catch (e) { /* ignorar */ }
}
function getLastVector() {
  try { return localStorage.getItem(LS_LASTVEC) || null; } catch (e) { return null; }
}

/* ── 2. UTILIDADES DE RENDER ───────────────────────────────────────── */
/* Escapa texto para inserción segura en HTML: todo texto dinámico pasa
   por aquí antes de entrar al DOM. */
function esc(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/* Normaliza para búsqueda: minúsculas y sin tildes (NFD + strip diacríticos) */
function norm(s) {
  return String(s == null ? '' : s).normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

/* Mapa de índices normalizados → originales, para resaltar coincidencias */
function normIndexMap(str) {
  const map = [];
  let out = '';
  for (let i = 0; i < str.length; i++) {
    const d = str[i].normalize('NFD');
    for (const ch of d) {
      if (/[\u0300-\u036f]/.test(ch)) continue;
      out += ch.toLowerCase();
      map.push(i);
    }
  }
  return { n: out, map };
}

/* Resalta TODAS las coincidencias (insensibles a tildes/mayúsculas) con <mark>. */
function highlight(text, qNorm) {
  if (!qNorm) return esc(text);
  const { n, map } = normIndexMap(text);
  const ranges = [];
  let idx = 0;
  while (idx <= n.length - qNorm.length) {
    const at = n.indexOf(qNorm, idx);
    if (at === -1) break;
    const a = map[at];
    const b = map[at + qNorm.length - 1] + 1;
    if (ranges.length && a <= ranges[ranges.length - 1][1]) {
      ranges[ranges.length - 1][1] = Math.max(ranges[ranges.length - 1][1], b);
    } else {
      ranges.push([a, b]);
    }
    idx = at + qNorm.length;
  }
  if (!ranges.length) return esc(text);
  let html = '';
  let pos = 0;
  for (const [a, b] of ranges) {
    html += esc(text.slice(pos, a)) + '<mark>' + esc(text.slice(a, b)) + '</mark>';
    pos = b;
  }
  return html + esc(text.slice(pos));
}

/* ── Índice por id + haystack de búsqueda precalculado ─────────────── */
const BY_ID = new Map();
for (const v of VULNS) {
  v.hay = norm([
    v.t, v.d, v.code, CAT_NAMES[v.code] || '', (v.cwe || []).join(' '),
    (v.tags || []).join(' '), GROUPS[v.g] ? GROUPS[v.g].label : '', '#' + v.id, String(v.id),
  ].join(' | '));
  BY_ID.set(v.id, v);
}

function tierScore(v, tier) { return r1(v.tiers[tier].s); }

/* ── 3. FILTRADO, BÚSQUEDA Y ORDEN ─────────────────────────────────── */
function getFiltered() {
  const q = norm(state.q.trim());
  const list = VULNS.filter((v) => {
    if (state.group !== 'all' && v.g !== state.group) return false;
    if (state.sev !== 'all' && v.def !== state.sev) return false;
    if (q && !v.hay.includes(q)) return false;
    return true;
  });
  const byTitle = (a, b) => a.t.localeCompare(b.t, 'es', { sensitivity: 'base', numeric: true }) || (a.id - b.id);
  if (state.sort === 'id') {
    list.sort((a, b) => a.id - b.id);
  } else if (state.sort === 'sev') {
    list.sort((a, b) =>
      (TIER_SORT[a.def] - TIER_SORT[b.def]) ||
      (tierScore(b, b.def) - tierScore(a, a.def)) ||
      byTitle(a, b));
  } else {
    list.sort(byTitle); // A–Z por título (orden por defecto)
  }
  return list;
}

/* ── 4. RENDERIZADO DE TARJETAS ────────────────────────────────────── */
const ICON_CHECK = '<svg class="ic-check" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
/* Portapapeles (botón "Copiar nombre") y calculadora (lanzador Custom) */
const ICON_CLIP = '<svg class="ic-clip" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>';
const ICON_CALC = '<svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="4" y="2" width="16" height="20" rx="2"/><path d="M8 6.5h8"/><path d="M8 11h.01M12 11h.01M16 11h.01"/><path d="M8 15h.01M12 15h.01M16 15v.01"/><path d="M8 18.5h8"/></svg>';

/* Circunferencia del anillo de las tarjetas (r = 18 en viewBox 44) */
const RING_C_CARD = 2 * Math.PI * 18;
/* Circunferencia del anillo de la calculadora (r = 52 en viewBox 120) */
const RING_C_CALC = 2 * Math.PI * 52;

function scoreBadgeHTML(v) {
  const def = v.def;
  const s = tierScore(v, def);
  const lbl = SEV[def].label;
  const off = (RING_C_CARD * (1 - s / 10)).toFixed(1);
  return `<div class="card-score" data-sev="${def}" role="img" aria-label="Severidad por defecto: ${esc(lbl)} ${s.toFixed(1)} de 10">
    <span class="ring-wrap">
      <svg class="ring" viewBox="0 0 44 44" aria-hidden="true">
        <circle class="ring-track" cx="22" cy="22" r="18"/>
        <circle class="ring-val" cx="22" cy="22" r="18" stroke-dasharray="${RING_C_CARD.toFixed(1)}" stroke-dashoffset="${off}"/>
      </svg>
      <span class="cs-num">${s.toFixed(1)}</span>
    </span>
    <span class="cs-lbl">${esc(lbl)}</span>
  </div>`;
}

function tierBtnHTML(v, tier) {
  const s = tierScore(v, tier);
  const lbl = SEV[tier].label;
  const full = formatCVSS(v.tiers[tier].v, s, lbl); // formato estricto completo
  return `<button type="button" class="btn-tier t-${tier}" data-action="tier" data-id="${v.id}" data-tier="${tier}"
    title="Copiar: ${esc(full)}"
    aria-label="${esc('Copiar CVSS nivel ' + lbl + ' — ' + full)}">
    <span class="lbl">${ICON_CHECK}${lbl}</span><span class="val">${s.toFixed(1)}</span>
  </button>`;
}

/* Botón Custom (v2.0): lanzador PURO de la calculadora vinculada. Siempre
   abre el drawer arrancando del vector por defecto del hallazgo; nunca
   copia un vector ni persiste estado (la tarjeta conserva su nivel). */
function customBtnHTML(v) {
  return `<button type="button" class="btn-tier t-custom" data-action="custom" data-id="${v.id}"
    title="Abrir la calculadora CVSS 4.0 vinculada a este hallazgo (parte de su vector por defecto)"
    aria-label="${esc('Abrir la calculadora CVSS 4.0 para ' + v.t)}">
    <span class="lbl">${ICON_CALC}Custom</span><span class="val">—</span>
  </button>`;
}

/* Botón "Copiar nombre" (v2.0): copia el nombre de informe exacto con el
   formato [<CÓDIGO>] <Título> — única fuente de verdad: formatReportName(). */
function copyNameBtnHTML(v) {
  const full = formatReportName(v);
  return `<button type="button" class="copy-name-btn" data-action="name" data-id="${v.id}"
    title="Copiar: ${esc(full)}"
    aria-label="${esc('Copiar nombre de informe — ' + full)}">
    ${ICON_CLIP}${ICON_CHECK}<span>Copiar nombre</span>
  </button>`;
}

function cardHTML(v) {
  const defLbl = SEV[v.def].label;
  const defScore = tierScore(v, v.def);
  const catName = CAT_NAMES[v.code] || '';
  const grpLabel = GROUPS[v.g] ? GROUPS[v.g].label : v.g;
  const q = state.q.trim() ? norm(state.q.trim()) : '';
  const tiersRows = TIER_KEYS.map((k) =>
    `<div class="vec-row"><span class="vl ${k}">${SEV[k].label} · ${tierScore(v, k).toFixed(1)}</span><span class="vv">${esc(v.tiers[k].v)}</span></div>`
  ).join('');
  return `<article class="card sev-${v.def}" data-id="${v.id}" aria-label="${esc('Hallazgo ' + v.id + ': ' + v.t)}">
  <div class="card-top">
    <div class="card-badges">
      <span class="badge id" title="Número interno del hallazgo">#${v.id}</span>
      <span class="badge cat" title="${esc(catName)}">${esc(v.code)}</span>
      <span class="badge grp" title="Grupo del catálogo">${esc(grpLabel)}</span>
    </div>
    ${scoreBadgeHTML(v)}
  </div>
  <h3 class="card-title">${highlight(v.t, q)}</h3>
  <p class="card-desc" title="${esc(v.d)}">${highlight(v.d, q)}</p>
  <div class="card-tags">${(v.cwe || []).map((c) => `<span class="tag" title="Weakness CWE asociada">${esc(c)}</span>`).join('')}${(v.tags || []).map((t) => `<span class="tag">${highlight(t, q)}</span>`).join('')}</div>
  <code class="card-vector" title="Vector CVSS 4.0 por defecto (nivel ${esc(defLbl)})"><span class="lbl">CVSS ${defScore.toFixed(1)} ▸ </span>${esc(v.tiers[v.def].v)}</code>
  <details class="card-vectors">
    <summary>Vectores por nivel</summary>
    <div>${tiersRows}</div>
  </details>
  <div class="card-actions">
    ${TIER_KEYS.map((k) => tierBtnHTML(v, k)).join('')}
    ${customBtnHTML(v)}
  </div>
  ${copyNameBtnHTML(v)}
</article>`;
}

function renderCards() {
  const list = getFiltered();
  gridEl.innerHTML = list.map(cardHTML).join('');
  emptyEl.hidden = list.length !== 0;
  updateCount(list.length);
  setCustomOfflineWarn(!libIsReady()); // aviso accesible si el CDN no está listo
}

function updateCount(n) {
  const total = VULNS.length;
  const shown = typeof n === 'number' ? n : getFiltered().length;
  countEl.textContent = shown === total ? `${total} hallazgos` : `${shown} de ${total} hallazgos`;
}

/* "Limpiar filtros" solo es visible cuando hay filtros activos */
function updateClearFiltersVisibility() {
  const active = state.q.trim() !== '' || state.group !== 'all' || state.sev !== 'all';
  btnClearFilters.hidden = !active;
}

/* Aviso accesible (aria-describedby) en los lanzadores Custom mientras la
   librería CVSS no está disponible. v2.0: ya no hay estado que refrescar. */
function setCustomOfflineWarn(on) {
  for (const b of gridEl.querySelectorAll('[data-action="custom"]')) {
    if (on) b.setAttribute('aria-describedby', 'cvssOfflineNote');
    else b.removeAttribute('aria-describedby');
  }
}

/* ── 5. MOTOR DE COPIADO + TOASTS ────────────────────────────────────
   Toda copia usa navigator.clipboard.writeText (API moderna) con
   respaldo execCommand para contextos sin permiso. El texto SIEMPRE
   proviene de formatCVSS() / formatReportName() (formatos estrictos). */
async function copyText(text) {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch (e) { /* caer al respaldo */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.top = '-1000px';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch (e) { return false; }
}

/* Toast con barra de progreso de auto-cierre (pausable al pasar el puntero) */
function toast(text, ok) {
  const DURATION = ok ? 3400 : 4800;
  const el = document.createElement('div');
  el.className = 'toast' + (ok ? '' : ' err');
  el.innerHTML = ok
    ? `<svg class="t-ic" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>
       <div class="t-body"><strong>Copiado al portapapeles</strong><code>${esc(text)}</code></div>
       <span class="t-bar" style="animation-duration:${DURATION}ms"></span>`
    : `<svg class="t-ic" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>
       <div class="t-body"><strong>No se pudo copiar</strong><code>Copia manual: ${esc(text)}</code></div>
       <span class="t-bar" style="animation-duration:${DURATION}ms"></span>`;
  toastsEl.appendChild(el);
  while (toastsEl.children.length > 3) toastsEl.firstElementChild.remove();

  let remain = DURATION;
  let start = performance.now();
  let timer = null;
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    el.classList.add('out');
    setTimeout(() => el.remove(), 330);
  };
  const arm = () => { start = performance.now(); timer = setTimeout(close, remain); };
  arm();
  /* Pausa (barra + temporizador) mientras el puntero está sobre el toast */
  el.addEventListener('mouseenter', () => {
    clearTimeout(timer);
    remain = Math.max(0, remain - (performance.now() - start));
    el.classList.add('paused');
  });
  el.addEventListener('mouseleave', () => { el.classList.remove('paused'); arm(); });
}

/* Feedback en el botón: check verde durante 1.5 s */
const flashTimers = new WeakMap();
function flashBtn(btn) {
  btn.classList.add('copied');
  clearTimeout(flashTimers.get(btn));
  flashTimers.set(btn, setTimeout(() => btn.classList.remove('copied'), 1500));
}

/* Copia el texto con formato estricto y muestra el feedback completo */
async function doCopy(btn, vector, score, sevLabel) {
  if (score == null || !sevLabel) return;
  doCopyRaw(btn, formatCVSS(vector, score, sevLabel)); // única fuente de verdad
}

/* Copia texto libre (nombre de informe, resultado del drawer) con el
   mismo feedback: toast con el string COMPLETO + flash del botón. */
async function doCopyRaw(btn, text) {
  const ok = await copyText(text);
  toast(text, ok);
  if (ok && btn) flashBtn(btn);
}

/* Delegación de eventos: un solo listener para toda la grilla */
gridEl.addEventListener('click', (ev) => {
  const btn = ev.target.closest('[data-action]');
  if (!btn) return;
  const id = parseInt(btn.dataset.id, 10);
  const v = BY_ID.get(id);
  if (!v) return;
  if (btn.dataset.action === 'tier') {
    const tier = btn.dataset.tier;
    doCopy(btn, v.tiers[tier].v, tierScore(v, tier), SEV[tier].label);
  } else if (btn.dataset.action === 'name') {
    /* v2.0: nombre de informe [<CÓDIGO>] <Título> */
    doCopyRaw(btn, formatReportName(v));
  } else if (btn.dataset.action === 'custom') {
    /* v2.0: lanzador puro — SIEMPRE abre la calculadora vinculada,
       arrancando del vector por defecto del hallazgo. Nunca copia. */
    openCalc(v.id, btn);
  }
});

/* ── 6. CALCULADORA CVSS 4.0 (drawer lateral) ────────────────────────
   Modos:
     · Libre     — desde la cabecera: edita cualquier vector; recuerda el
       último editado en localStorage (lastVector).
     · Vinculada — desde una tarjeta (botón Custom): SIEMPRE arranca del
       vector por defecto del hallazgo y NO persiste nada en la tarjeta. */
const calcState = { open: false, linkedId: null, m: {}, extras: [], returnFocus: null };

/* Scroll-lock robusto: fija el body (evita el salto en iOS), compensa el
   ancho del scrollbar y restaura scrollY exacto al cerrar. */
const scrollLock = { on: false, y: 0, prev: null };
function lockScroll() {
  if (scrollLock.on) return;
  scrollLock.on = true;
  scrollLock.y = window.scrollY;
  const gap = window.innerWidth - document.documentElement.clientWidth;
  const b = document.body;
  scrollLock.prev = {
    position: b.style.position, top: b.style.top, left: b.style.left,
    right: b.style.right, width: b.style.width, paddingRight: b.style.paddingRight,
  };
  b.classList.add('scroll-locked');
  if (gap > 0) b.style.paddingRight = gap + 'px'; // evita el salto de layout en escritorio
  Object.assign(b.style, { position: 'fixed', top: `-${scrollLock.y}px`, left: '0', right: '0', width: '100%' });
}
function unlockScroll() {
  if (!scrollLock.on) return;
  scrollLock.on = false;
  const b = document.body;
  Object.assign(b.style, scrollLock.prev);
  b.classList.remove('scroll-locked');
  window.scrollTo(0, scrollLock.y); // restauración sin salto
}

/* Construye los selects de métricas una sola vez */
function buildMetricsUI() {
  metricsEl.innerHTML = METRIC_GROUPS.map((g) => `
    <fieldset>
      <legend>${esc(g.title)}</legend>
      <div class="metrics-grid">
        ${g.keys.map((k) => `
          <div class="metric">
            <label for="sel-${k}"><span class="mk">${k}</span> ${esc(METRIC_OPTS[k].name)}</label>
            <select id="sel-${k}" data-metric="${k}" aria-label="${esc(k + ' — ' + METRIC_OPTS[k].name)}">
              ${METRIC_OPTS[k].opts.map((o) => `<option value="${o[0]}">${esc(o[1])}</option>`).join('')}
            </select>
          </div>`).join('')}
      </div>
    </fieldset>`).join('');
  metricsEl.addEventListener('change', (ev) => {
    const sel = ev.target.closest('select[data-metric]');
    if (!sel) return;
    calcState.m[sel.dataset.metric] = sel.value;
    applyVectorToUI(buildVector(calcState.m, calcState.extras), false);
    recomputeCalc();
  });
}

function syncSelects() {
  for (const sel of metricsEl.querySelectorAll('select[data-metric]')) {
    sel.value = calcState.m[sel.dataset.metric] || '';
  }
}

/* Aplica un vector al input (y opcionalmente al estado ya validado) */
function applyVectorToUI(vec, updateState) {
  if (updateState) {
    const p = parseVector(vec);
    if (!p) return false;
    calcState.m = p.m;
    calcState.extras = p.extras;
    vec = buildVector(p.m, p.extras);
  }
  vecInput.value = vec;
  syncSelects();
  return true;
}

/* Micro-animación "pop" al recalcular (reinicia la clase .pop) */
function popScore() {
  scoreCenterEl.classList.remove('pop');
  void scoreCenterEl.offsetWidth; // fuerza reflow para reiniciar la animación
  scoreCenterEl.classList.add('pop');
}

/* Recalcula el puntaje en vivo: anillo, número, píldora y vista previa
   del texto copiable. (v2.0: sin custom vinculado; solo lastVector). */
function recomputeCalc() {
  const vec = buildVector(calcState.m, calcState.extras);
  const s = scoreOf(vec);
  if (s != null) {
    const score = r1(s);
    const sev = sevOf(score);
    const text = formatCVSS(vec, score, sevLabelOf(sev)); // formato estricto completo
    scoreRingEl.dataset.sev = sev;
    srValEl.style.strokeDasharray = RING_C_CALC.toFixed(1);
    srValEl.style.strokeDashoffset = (RING_C_CALC * (1 - score / 10)).toFixed(1);
    scoreNumEl.textContent = score.toFixed(1);
    scoreNumEl.classList.remove('no-score');
    sevPillEl.hidden = false;
    sevPillEl.dataset.sev = sev;
    sevPillEl.textContent = sevLabelOf(sev);
    copyPreviewEl.textContent = text;
    btnCalcCopy.disabled = false;
    btnCalcCopy.dataset.text = text;
    popScore();
  } else {
    scoreNumEl.textContent = libIsReady() ? '—' : 'CDN no disponible';
    scoreNumEl.classList.add('no-score');
    sevPillEl.hidden = true;
    copyPreviewEl.textContent = '—';
    btnCalcCopy.disabled = true;
    delete btnCalcCopy.dataset.text;
  }
  setLastVector(vec);
}

function setLinkedUI() {
  if (calcState.linkedId != null) {
    const v = BY_ID.get(calcState.linkedId);
    drawerLinkEl.innerHTML = `<div class="linked">
      <span>Vinculado a:</span>
      <span class="badge id">#${v.id}</span><strong>${esc(v.t)}</strong>
      <span class="badge cat">${esc(v.code)}</span>
    </div>
    <div class="linked" style="margin-top:6px">Personaliza el vector y copia el resultado desde la calculadora; la tarjeta conserva su nivel por defecto.</div>`;
  } else {
    drawerLinkEl.innerHTML = '<div class="free-hint">Modo libre: edita el vector y copia el resultado. Desde una tarjeta, la calculadora se vincula al hallazgo.</div>';
  }
}

function openCalc(vulnId, openerBtn) {
  calcState.open = true;
  calcState.linkedId = vulnId != null ? vulnId : null;
  calcState.returnFocus = openerBtn || document.activeElement;
  let vec;
  if (vulnId != null) {
    /* v2.0: el modo vinculado SIEMPRE parte del vector por defecto del
       hallazgo (no recuerda ediciones previas por hallazgo). */
    const v = BY_ID.get(vulnId);
    vec = v.tiers[v.def].v;
  } else {
    vec = getLastVector() || DEFAULT_VECTOR;
  }
  applyVectorToUI(vec, true);
  setLinkedUI();
  vecMsg.textContent = '';
  vecMsg.className = 'vec-msg';
  vecInput.classList.remove('invalid');
  drawerEl.classList.add('is-open');
  drawerEl.setAttribute('aria-hidden', 'false');
  scrimEl.classList.add('is-open');
  lockScroll();
  recomputeCalc();
  setTimeout(() => vecInput.focus(), 180);
}

function closeCalc() {
  if (!calcState.open) return;
  calcState.open = false;
  drawerEl.classList.remove('is-open');
  drawerEl.setAttribute('aria-hidden', 'true');
  scrimEl.classList.remove('is-open');
  unlockScroll();
  /* Devuelve el foco al botón que abrió el drawer SIN desplazar el viewport:
     la posición de scroll ya fue restaurada exactamente por unlockScroll(). */
  if (calcState.returnFocus && calcState.returnFocus.isConnected) {
    calcState.returnFocus.focus({ preventScroll: true });
  }
}

/* Validación en vivo del vector manual */
vecInput.addEventListener('input', () => {
  const p = parseVector(vecInput.value);
  if (p) {
    calcState.m = p.m;
    calcState.extras = p.extras;
    vecInput.classList.remove('invalid');
    vecMsg.textContent = 'Válido — puntaje recalculado en tiempo real';
    vecMsg.className = 'vec-msg ok';
    syncSelects();
    recomputeCalc();
  } else {
    vecInput.classList.add('invalid');
    vecMsg.textContent = 'Vector incompleto o inválido: se requiere el prefijo CVSS:4.0 y las 11 métricas base (AV, AC, AT, PR, UI, VC, VI, VA, SC, SI, SA)';
    vecMsg.className = 'vec-msg err';
  }
});

btnCalcCopy.addEventListener('click', () => {
  const text = btnCalcCopy.dataset.text;
  if (text) doCopyRaw(btnCalcCopy, text);
});

$('#drawerClose').addEventListener('click', closeCalc);
scrimEl.addEventListener('click', closeCalc);
$('#btnFreeCalc').addEventListener('click', () => openCalc(null));

/* ── 7. ATAJOS DE TECLADO + ACCESIBILIDAD ──────────────────────────── */
function isTyping(el) {
  return el instanceof Element &&
    (el.matches('input, textarea, select') || el.isContentEditable);
}

document.addEventListener('keydown', (ev) => {
  /* Esc: cierra la calculadora; si está cerrada, limpia el buscador */
  if (ev.key === 'Escape') {
    if (calcState.open) { closeCalc(); return; }
    if (qInput.value) {
      qInput.value = '';
      state.q = '';
      btnClear.hidden = true;
      updateClearFiltersVisibility();
      persistFilters();
      renderCards();
    }
    return;
  }
  /* "/" enfoca el buscador (si no se está escribiendo) */
  if (ev.key === '/' && !isTyping(ev.target)) {
    ev.preventDefault();
    qInput.focus();
    qInput.select();
    return;
  }
  /* Ctrl/Cmd+K: equivalente a "/" */
  if ((ev.ctrlKey || ev.metaKey) && ev.key.toLowerCase() === 'k') {
    ev.preventDefault();
    qInput.focus();
    qInput.select();
    return;
  }
  /* Trampa de foco dentro del drawer abierto */
  if (ev.key === 'Tab' && calcState.open) {
    const focusables = drawerEl.querySelectorAll('button, input, select, summary, [href]');
    if (!focusables.length) return;
    const first = focusables[0];
    const last = focusables[focusables.length - 1];
    if (ev.shiftKey && document.activeElement === first) { ev.preventDefault(); last.focus(); }
    else if (!ev.shiftKey && document.activeElement === last) { ev.preventDefault(); first.focus(); }
  }
});

/* ── 8. EVENTOS: BÚSQUEDA, FILTROS Y ORDEN ─────────────────────────── */
qInput.addEventListener('input', () => {
  state.q = qInput.value;
  btnClear.hidden = !qInput.value;
  updateClearFiltersVisibility();
  persistFilters();
  renderCards();
});
btnClear.addEventListener('click', () => {
  qInput.value = '';
  state.q = '';
  btnClear.hidden = true;
  updateClearFiltersVisibility();
  persistFilters();
  renderCards();
  qInput.focus();
});

for (const chip of document.querySelectorAll('.chip[data-group]')) {
  chip.addEventListener('click', () => {
    state.group = chip.dataset.group;
    for (const c of document.querySelectorAll('.chip[data-group]')) c.setAttribute('aria-pressed', String(c === chip));
    updateClearFiltersVisibility();
    persistFilters();
    renderCards();
  });
}
for (const chip of document.querySelectorAll('.chip[data-sev]')) {
  chip.addEventListener('click', () => {
    state.sev = chip.dataset.sev;
    for (const c of document.querySelectorAll('.chip[data-sev]')) c.setAttribute('aria-pressed', String(c === chip));
    updateClearFiltersVisibility();
    persistFilters();
    renderCards();
  });
}
sortEl.addEventListener('change', () => { state.sort = sortEl.value; persistFilters(); renderCards(); });

function clearAllFilters() {
  state.q = '';
  state.group = 'all';
  state.sev = 'all';
  qInput.value = '';
  btnClear.hidden = true;
  for (const c of document.querySelectorAll('.chip[data-group]')) c.setAttribute('aria-pressed', String(c.dataset.group === 'all'));
  for (const c of document.querySelectorAll('.chip[data-sev]')) c.setAttribute('aria-pressed', String(c.dataset.sev === 'all'));
  updateClearFiltersVisibility();
  persistFilters();
  renderCards();
  qInput.focus();
}
btnClearFilters.addEventListener('click', clearAllFilters);
$('#btnEmptyReset').addEventListener('click', clearAllFilters);

/* Sombra del buscador sticky SOLO al hacer scroll (IntersectionObserver
   sobre el centinela situado justo encima del buscador). */
function initStuckObserver() {
  const sentinel = document.getElementById('stickSentinel');
  if (!sentinel || !('IntersectionObserver' in window)) return;
  new IntersectionObserver((entries) => {
    searchbarEl.classList.toggle('is-stuck', !entries[0].isIntersecting);
  }).observe(sentinel);
}

/* ── 9. INIT + API PARA app.js ─────────────────────────────────────── */
export function initUI() {
  loadFilters();
  /* v2.0: el estado Custom por hallazgo dejó de existir — limpieza única
     de la clave heredada de la v1.0 para no dejar datos huérfanos. */
  try { localStorage.removeItem(LS_CUSTOMS_LEGACY); } catch (e) { /* ignorar */ }
  /* Aplica el estado persistido a los controles */
  qInput.value = state.q;
  btnClear.hidden = !state.q;
  sortEl.value = state.sort;
  for (const c of document.querySelectorAll('.chip[data-group]')) c.setAttribute('aria-pressed', String(c.dataset.group === state.group));
  for (const c of document.querySelectorAll('.chip[data-sev]')) c.setAttribute('aria-pressed', String(c.dataset.sev === state.sev));
  updateClearFiltersVisibility();

  buildMetricsUI();
  renderCards();
  initStuckObserver();
  const by = (g) => VULNS.filter((v) => v.g === g).length;
  footCountEl.textContent = `${VULNS.length} hallazgos · Web ${by('web')} / API ${by('api')} / Móvil ${by('movil')} / LLM ${by('llm')}`;
}

/* La librería CVSS se cargó: recálculo en vivo de todos los puntajes
   embebidos y del drawer si estaba abierto esperando la librería. */
export function onLibReady() {
  /* Indicador de estado de la librería (cabecera) */
  libStatusEl.classList.remove('loading', 'offline');
  libStatusEl.classList.add('ready');
  libStatusEl.querySelector('.txt').textContent = 'CVSS 4.0 · Lista';
  let corrected = 0;
  let changed = false;
  for (const v of VULNS) {
    for (const k of TIER_KEYS) {
      const s = scoreOf(v.tiers[k].v);
      if (s != null && r1(s) !== r1(v.tiers[k].s)) { v.tiers[k].s = r1(s); changed = true; corrected++; }
    }
  }
  if (corrected) console.info('[AppSec] ' + corrected + ' puntajes embebidos corregidos en vivo (los vectores eran correctos; servían de respaldo sin conexión).');
  if (changed) renderCards();
  setCustomOfflineWarn(false); // la calculadora ya está disponible
  if (calcState.open) recomputeCalc(); // drawer abierto: recalcular ahora
}

/* Ambos CDN fallaron: NO se dispara el recálculo. Los puntajes embebidos
   (validados en build-time) siguen operativos; los lanzadores Custom
   muestran el aviso accesible (aria-describedby → #cvssOfflineNote). */
export function onLibFailed() {
  document.body.classList.add('lib-off');
  libStatusEl.classList.remove('loading', 'ready');
  libStatusEl.classList.add('offline');
  libStatusEl.querySelector('.txt').textContent = 'CVSS offline · puntajes embebidos';
  const note = document.getElementById('calcLibNote');
  if (note) note.hidden = false;
  setCustomOfflineWarn(true); // aplica aria-describedby del aviso
  console.warn('[AppSec] No se pudo cargar ae-cvss-calculator desde jsDelivr ni unpkg. La calculadora queda deshabilitada; los puntajes por defecto siguen operativos.');
}
