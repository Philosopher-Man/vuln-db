/* ════════════════════════════════════════════════════════════════════
   cvss.js — Motor CVSS 4.0 de la app.
   · Carga de la librería ae-cvss-calculator@1.0.13 vía CDN, con espejo
     (jsDelivr → unpkg) y validación con vector centinela.
   · Parseo/normalización estricta de vectores (prefijo + 11 métricas base).
   · formatCVSS(): ÚNICA fuente de verdad del formato de salida.
   ════════════════════════════════════════════════════════════════════ */

import { SEV, SEV_LABELS, TIER_KEYS, METRIC_BASE_ORDER, METRIC_OPTS } from './data.js';

/* Librería de cálculo: CDN principal + espejo de respaldo (versión fijada) */
export const LIB_URLS = [
  'https://cdn.jsdelivr.net/npm/ae-cvss-calculator@1.0.13/dist/ae-cvss-calculator.min.js',
  'https://unpkg.com/ae-cvss-calculator@1.0.13/dist/ae-cvss-calculator.min.js',
];

/* Vector por defecto de la calculadora y centinela de validación:
   el peor caso canónico debe puntuar exactamente 10.0. */
export const DEFAULT_VECTOR = 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H';

/* ── Redondeo a 1 decimal (evita residuos de coma flotante) ────────── */
export function r1(x) { return Math.round(x * 10) / 10; }

/* ── Estado de la librería ─────────────────────────────────────────── */
const LIB = { ready: false, api: null };
export function libIsReady() { return LIB.ready; }

/* Adaptador: aísla la API de ae-cvss-calculator. En el navegador expone
   el global UMD "CvssCalculator" con la clase Cvss4P0 (calculateScores().base),
   validada contra la implementación oficial de FIRST. */
function detectLibAPI() {
  const G = window.CvssCalculator || window.aeCvssCalculator;
  if (G && typeof G.Cvss4P0 === 'function') {
    return {
      score: (vec) => {
        try {
          const s = new G.Cvss4P0(vec).calculateScores();
          const b = s && s.base;
          return typeof b === 'number' && isFinite(b) ? b : null;
        } catch (e) { return null; }
      },
    };
  }
  return null;
}

function loadScript(src) {
  return new Promise((resolve, reject) => {
    const s = document.createElement('script');
    s.src = src;
    s.async = true;
    s.onload = () => resolve(src);
    s.onerror = () => reject(new Error('fallo al cargar ' + src));
    document.head.appendChild(s);
  });
}

/* Carga secuencial con fallback: jsDelivr → unpkg → rechazo.
   Resuelve cuando alguna URL entrega una librería funcional. */
export function loadCVSSLib() {
  return new Promise((resolve, reject) => {
    (async () => {
      for (const url of LIB_URLS) {
        try {
          await loadScript(url);
          const api = detectLibAPI();
          if (!api) continue;                       // cargó pero sin la API esperada
          if (r1(api.score(DEFAULT_VECTOR)) !== 10) continue; // centinela inválido → espejo
          LIB.ready = true;
          LIB.api = api;
          console.info('[AppSec] Librería CVSS 4.0 lista (' + url + ')');
          resolve(api);
          return;
        } catch (e) { /* probar el siguiente CDN */ }
      }
      reject(new Error('No se pudo cargar la librería CVSS desde ningún CDN'));
    })();
  });
}

/* Puntaje de un vector (null si la librería no está lista o el vector falla) */
export function scoreOf(vec) {
  if (!LIB.ready) return null;
  return LIB.api.score(vec);
}

/* ── Severidad (clave de SEV) a partir del puntaje redondeado ──────── */
export function sevOf(score) {
  if (score == null || !isFinite(score)) return null;
  const x = r1(score);
  if (x <= 0) return 'ninguna';
  for (const k of TIER_KEYS) {
    if (x >= SEV[k].min && x <= SEV[k].max) return k;
  }
  return null;
}

/* Etiqueta lista para mostrar (Bajo / Moderado / Alta / Extrema / Ninguna) */
export function sevLabelOf(sevKey) { return SEV_LABELS[sevKey] || null; }

/* ★ FORMATO DE SALIDA ESTRICTO — única fuente de verdad de toda la app.
   Estructura: <VECTOR_CVSS_4.0> Score <PUNTAJE>/<SEVERIDAD>
   Ej.: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N Score 6.9/Moderado
   Reglas: vector primero (prefijo CVSS:4.0/ + 11 métricas base), la palabra
   "Score" con S mayúscula, puntaje con 1 decimal, barra SIN espacios y
   severidad con inicial mayúscula. No debe variarse. */
export function formatCVSS(vector, score, sevLabel) {
  return String(vector) + ' Score ' + r1(score).toFixed(1) + '/' + sevLabel;
}

/* ── Parseo estricto del vector ──────────────────────────────────────
   Requiere prefijo CVSS:4.0 (o CVSS:4) y las 11 métricas base completas.
   Las métricas adicionales (E:, CR:, MAV:…) se preservan como "extras". */
export function parseVector(str) {
  const parts = String(str || '').trim().split('/').map((s) => s.trim()).filter(Boolean);
  if (!parts.length) return null;
  const head = parts[0].toUpperCase().replace(/^#/, '');
  if (head !== 'CVSS:4.0' && head !== 'CVSS:4') return null;
  const m = {};
  const extras = [];
  for (let i = 1; i < parts.length; i++) {
    const seg = parts[i].split(':');
    if (seg.length !== 2 || !seg[0] || !seg[1]) return null;
    const K = seg[0].toUpperCase();
    const V = seg[1].toUpperCase();
    const conf = METRIC_OPTS[K];
    if (conf) {
      if (!conf.opts.some((o) => o[0] === V)) return null;
      if (m[K]) return null;
      m[K] = V;
    } else {
      if (!/^[A-Z]{1,4}$/.test(K) || !/^[A-Z0-9]$/.test(V)) return null;
      if (extras.includes(K + ':' + V)) return null;
      extras.push(K + ':' + V);
    }
  }
  for (const k of METRIC_BASE_ORDER) if (!m[k]) return null; // base completa obligatoria
  return { m, extras };
}

/* Reconstruye el vector canónico: prefijo + 11 métricas base en orden + extras */
export function buildVector(m, extras) {
  return 'CVSS:4.0/' + METRIC_BASE_ORDER.map((k) => k + ':' + m[k]).join('/') +
    (extras && extras.length ? '/' + extras.join('/') : '');
}
