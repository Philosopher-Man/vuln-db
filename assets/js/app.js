/* ════════════════════════════════════════════════════════════════════
   app.js — Bootstrap de la SPA.
   Orden de dependencias (módulos ES, sin bundler):
       data.js  (solo datos)  ←  cvss.js  (motor)  ←  ui.js  (interfaz)  ←  app.js
   1. initUI(): pinta el catálogo con los puntajes embebidos (validados
      en build-time) y restaura filtros/customs desde localStorage.
   2. loadCVSSLib(): carga ae-cvss-calculator@1.0.13 (jsDelivr → unpkg).
      · Éxito  → onLibReady(): recálculo en vivo de todos los puntajes.
      · Fallo  → onLibFailed(): sin recálculo; aviso accesible en los
                 botones Custom (la calculadora requiere conexión).
   ════════════════════════════════════════════════════════════════════ */

import { initUI, onLibReady, onLibFailed } from './ui.js';
import { loadCVSSLib } from './cvss.js';

initUI();
loadCVSSLib().then(onLibReady, onLibFailed);
