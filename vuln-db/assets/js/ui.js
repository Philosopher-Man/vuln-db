/* ════════════════════════════════════════════════════════════════════
   ui.js — Interfaz: renderizado de tarjetas, buscador/filtros, motor de
   copiado, toasts y calculadora (drawer). El bootstrap vive en app.js.
   Secciones:
     1. Referencias DOM + estado + persistencia (localStorage)
     2. Utilidades de render (escape, normalización, resaltado)
     3. Filtrado, búsqueda y orden
     4. Renderizado de tarjetas (anillo de puntaje + barra de acciones)
     5. Botón Custom: actualización IN SITU (sin reemplazar nodos)
     6. Motor de copiado (formato estricto) + toasts con barra de progreso
     7. Calculadora CVSS 4.0 (drawer + scroll-lock robusto)
     8. Atajos de teclado + accesibilidad
     9. Eventos de filtros/buscador
    10. Init + API para app.js (onLibReady / onLibFailed)
   ════════════════════════════════════════════════════════════════════ */

import {
  VULNS, CAT_NAMES, GROUPS, SEV, SEV_LABELS, TIER_KEYS, TIER_SORT,
  METRIC_BASE_ORDER, METRIC_OPTS, METRIC_GROUPS,
} from './data.js';
import {
  r1, sevOf, sevLabelOf, formatCVSS, scoreOf, libIsReady,
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
const btnResetVuln = $('#btnResetVuln');
const metricsEl = $('#metrics');
const libStatusEl = $('#libStatus');

/* Claves de localStorage (v2: los IDs se renumeraron 1..59 en la limpieza
   de datos, por lo que NO se heredan los customs guardados contra la
   numeración anterior). */
const LS_FILTERS = 'appsec-filters-v2';
const LS_CUSTOMS = 'appsec-vuln-customs-v2';
const LS_LASTVEC = 'appsec-last-vector-v2';

const state = {
  q: '',
  group: 'all',
  sev: 'all',
  sort: 'az',
  customs: new Map(), // id → { v: vector, s: score }
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

/* ── Persistencia: vectores Custom por hallazgo ────────────────────── */
function loadCustoms() {
  try {
    const raw = localStorage.getItem(LS_CUSTOMS);
    if (!raw) return;
    const obj = JSON.parse(raw);
    for (const k of Object.keys(obj)) {
      const id = parseInt(k, 10);
      const c = obj[k];
      if (Number.isInteger(id) && BY_ID.has(id) && c && typeof c.v === 'string') {
        state.customs.set(id, { v: c.v, s: typeof c.s === 'number' ? c.s : null });
      }
    }
  } catch (e) { /* almacenamiento no disponible o corrupto: continuar sin customs */ }
}
let persistTimer = null;
function persistCustoms() {
  clearTimeout(persistTimer);
  persistTimer = setTimeout(() => {
    try {
      const obj = {};
      for (const [id, c] of state.customs) obj[id] = c;
      localStorage.setItem(LS_CUSTOMS, JSON.stringify(obj));
    } catch (e) { /* modo privado: ignorar */ }
  }, 250);
}

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
function customOf(v) { return state.customs.get(v.id) || null; }

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

/* Esqueleto del botón Custom: SIEMPRE habilitado. Su contenido/estado se
   completa con updateCustomButton() (actualización in situ, sin innerHTML). */
function customBtnSkeletonHTML(v) {
  return `<button type="button" class="btn-tier t-custom" data-action="custom" data-id="${v.id}">
    <span class="lbl"><span class="dot" aria-hidden="true"></span>${ICON_CHECK}Custom</span><span class="val">—</span>
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
    ${customBtnSkeletonHTML(v)}
  </div>
</article>`;
}

function renderCards() {
  const list = getFiltered();
  gridEl.innerHTML = list.map(cardHTML).join('');
  emptyEl.hidden = list.length !== 0;
  updateCount(list.length);
  refreshCustomButtons(); // completa el estado inicial de los botones Custom
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

/* ── 5. BOTÓN CUSTOM (actualización in situ) ─────────────────────────
   Refactor clave: en lugar de reemplazar el nodo (innerHTML), se
   actualizan SOLO clases, atributos y textos del botón existente.
   Así se preservan el foco, las transiciones CSS y los listeners. */
function updateCustomButton(btn, v) {
  const c = customOf(v);
  const valEl = btn.querySelector('.val');
  btn.classList.toggle('is-set', !!c);
  if (c && c.s != null) {
    const sev = sevOf(c.s);
    valEl.textContent = r1(c.s).toFixed(1);
    btn.dataset.sev = sev || '';
    const full = formatCVSS(c.v, c.s, sevLabelOf(sev) || '—'); // formato estricto completo
    btn.title = 'Copiar Custom: ' + full;
    btn.setAttribute('aria-label', 'Copiar CVSS Custom de ' + v.t + ' — ' + full);
  } else {
    valEl.textContent = '—';
    delete btn.dataset.sev;
    const msg = 'Sin vector Custom: haz clic para abrir la calculadora, ajustar el vector de este hallazgo y copiar el puntaje recalculado';
    btn.title = msg;
    btn.setAttribute('aria-label', 'Configurar CVSS Custom de ' + v.t);
  }
  /* Aviso accesible si la librería CVSS no está disponible (CDN caído) */
  if (libIsReady()) btn.removeAttribute('aria-describedby');
  else btn.setAttribute('aria-describedby', 'cvssOfflineNote');
}

function refreshCustomButtons() {
  for (const btn of gridEl.querySelectorAll('[data-action="custom"]')) {
    const v = BY_ID.get(parseInt(btn.dataset.id, 10));
    if (v) updateCustomButton(btn, v);
  }
}

/* ── 6. MOTOR DE COPIADO + TOASTS ────────────────────────────────────
   Toda copia usa navigator.clipboard.writeText (API moderna) con
   respaldo execCommand para contextos sin permiso. El texto SIEMPRE
   proviene de formatCVSS() (vector + Score + puntaje/severidad). */
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
  const text = formatCVSS(vector, score, sevLabel); // única fuente de verdad
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
  } else if (btn.dataset.action === 'custom') {
    /* Custom siempre habilitado: copia si hay vector; si no, abre la
       calculadora del hallazgo para definirlo. */
    const c = customOf(v);
    if (c && c.s != null) doCopy(btn, c.v, c.s, sevLabelOf(sevOf(c.s)));
    else openCalc(v.id, btn);
  }
});

/* ── 7. CALCULADORA CVSS 4.0 (drawer lateral) ────────────────────────
   Modos:
     · Libre     — desde la cabecera: edita cualquier vector.
     · Vinculada — desde una tarjeta (botón Custom): precarga el vector
       del hallazgo y guarda los cambios como su vector Custom. */
const calcState = { open: false, linkedId: null, m: {}, extras: [], returnFocus: null, suppressSave: false };

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

/* Recalcula el puntaje en vivo: anillo, número, píldora, vista previa
   del texto copiable y custom vinculado. */
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
  /* Modo vinculado: guardar como Custom SOLO si el vector difiere del nivel
     por defecto del hallazgo (abrir la calculadora sin cambios no activa el
     indicador Custom). Si el analista vuelve al vector por defecto editando,
     el custom se elimina. suppressSave evita que el ciclo de restauración
     vuelva a crear el custom. */
  if (calcState.linkedId != null) {
    const v = BY_ID.get(calcState.linkedId);
    if (v) {
      if (s != null && !calcState.suppressSave) {
        const defVec = v.tiers[v.def].v;
        if (vec !== defVec) {
          state.customs.set(v.id, { v: vec, s: r1(s) });
          persistCustoms();
        } else if (state.customs.has(v.id)) {
          state.customs.delete(v.id);
          persistCustoms();
        }
      }
      calcState.suppressSave = false;
      refreshCustomButtons();
    }
  }
}

function setLinkedUI() {
  if (calcState.linkedId != null) {
    const v = BY_ID.get(calcState.linkedId);
    drawerLinkEl.innerHTML = `<div class="linked">
      <span>Vinculado a:</span>
      <span class="badge id">#${v.id}</span><strong>${esc(v.t)}</strong>
      <span class="badge cat">${esc(v.code)}</span>
    </div>
    <div class="linked" style="margin-top:6px">Los ajustes se guardan como puntaje <strong>Custom</strong> de este hallazgo.</div>`;
    btnResetVuln.hidden = false;
  } else {
    drawerLinkEl.innerHTML = '<div class="free-hint">Modo libre: edita el vector y copia el resultado. Desde una tarjeta, la calculadora se vincula al hallazgo.</div>';
    btnResetVuln.hidden = true;
  }
}

function openCalc(vulnId, openerBtn) {
  calcState.open = true;
  calcState.linkedId = vulnId != null ? vulnId : null;
  calcState.returnFocus = openerBtn || document.activeElement;
  let vec;
  if (vulnId != null) {
    const v = BY_ID.get(vulnId);
    const c = customOf(v);
    vec = c ? c.v : v.tiers[v.def].v;
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
  if (!text) return;
  copyText(text).then((ok) => { toast(text, ok); if (ok) flashBtn(btnCalcCopy); });
});

/* Restaura el vector por defecto del hallazgo vinculado (y borra su custom) */
btnResetVuln.addEventListener('click', () => {
  if (calcState.linkedId == null) return;
  const v = BY_ID.get(calcState.linkedId);
  state.customs.delete(v.id);
  persistCustoms();
  calcState.suppressSave = true; // que recomputeCalc no lo vuelva a guardar
  applyVectorToUI(v.tiers[v.def].v, true);
  setLinkedUI();
  recomputeCalc();
});

$('#drawerClose').addEventListener('click', closeCalc);
scrimEl.addEventListener('click', closeCalc);
$('#btnFreeCalc').addEventListener('click', () => openCalc(null));

/* ── 8. ATAJOS DE TECLADO + ACCESIBILIDAD ──────────────────────────── */
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

/* ── 9. EVENTOS: BÚSQUEDA, FILTROS Y ORDEN ─────────────────────────── */
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

/* ── 10. INIT + API PARA app.js ────────────────────────────────────── */
export function initUI() {
  loadFilters();
  loadCustoms();
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

/* La librería CVSS se cargó: recálculo en vivo de todos los puntajes.
   (Antes existía aquí una rama vacía "else if (calcState.open…) { nada }":
   ahora se implementa de verdad — si el drawer está abierto esperando
   la librería, se recalcula su puntaje en el momento.) */
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
  let customsChanged = false;
  for (const c of state.customs.values()) {
    const s = scoreOf(c.v);
    if (s != null && r1(s) !== r1(c.s)) { c.s = r1(s); customsChanged = true; }
  }
  if (customsChanged) persistCustoms();
  if (corrected) console.info('[AppSec] ' + corrected + ' puntajes embebidos corregidos en vivo (los vectores eran correctos; servían de respaldo sin conexión).');
  if (changed || customsChanged) renderCards();
  else refreshCustomButtons();
  if (calcState.open) recomputeCalc(); // drawer abierto: recalcular ahora
}

/* Ambos CDN fallaron: NO se dispara el recálculo. Los puntajes embebidos
   (validados en build-time) siguen operativos y los botones Custom
   muestran el aviso accesible (aria-describedby → #cvssOfflineNote). */
export function onLibFailed() {
  document.body.classList.add('lib-off');
  libStatusEl.classList.remove('loading', 'ready');
  libStatusEl.classList.add('offline');
  libStatusEl.querySelector('.txt').textContent = 'CVSS offline · puntajes embebidos';
  const note = document.getElementById('calcLibNote');
  if (note) note.hidden = false;
  refreshCustomButtons(); // aplica aria-describedby del aviso
  console.warn('[AppSec] No se pudo cargar ae-cvss-calculator desde jsDelivr ni unpkg. La calculadora queda deshabilitada; los puntajes por defecto siguen operativos.');
}
