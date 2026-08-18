"use strict";

/* ---------- состояние ---------- */

const TOKEN_KEY = "lacert_admin_token";
let token = localStorage.getItem(TOKEN_KEY) || "";
let pollTimer = null;
let openEventsDeviceID = null;
let currentView = "devices";
let devicesByID = {};
// null — режим неизвестен: шлюз сообщает его только авторизованному запросу.
let gatewayLogSessionKeys = null;

// deviceIDs — множество выбранных устройств на вкладке «Мониторинг».
// Пустое множество означает «все устройства»: так вкладка ведёт себя при первом
// открытии и после кнопки «сбросить». Раньше здесь было одиночное поле
// deviceID, из-за чего выбор ограничивался вариантами «одно» или «все».
const monState = { range: "1h", deviceIDs: new Set(), customSince: null, customUntil: null };

// Устройства, известные на момент последнего обновления списка. Нужны, чтобы
// кнопка «выбрать все» отмечала именно существующие.
let monKnownDevices = [];

const RANGE_MS = { "30m": 30 * 60000, "1h": 3600000, "6h": 6 * 3600000, "12h": 12 * 3600000, "24h": 24 * 3600000 };

/* ---------- утилиты ---------- */

function el(id) { return document.getElementById(id); }

function showToast(message, kind) {
  const t = el("toast");
  t.textContent = message;
  t.className = "toast" + (kind ? " toast-" + kind : "");
  t.classList.remove("hidden");
  clearTimeout(showToast._timer);
  showToast._timer = setTimeout(() => t.classList.add("hidden"), 3500);
}

function fmtTime(iso) {
  if (!iso) return "—";
  const d = new Date(iso);
  // Неразборчивую отметку показываем как есть — так виден сам испорченный
  // текст, а не безликий прочерк. Но результат fmtTime подставляется в
  // разметку без внешнего экранирования, поэтому экранируем здесь: сейчас все
  // отметки времени приходят с сервера и безопасны, однако полагаться на это
  // свойство вызывающего кода не стоит. Обычный вывод toLocaleString
  // спецсимволов не содержит, так что на него это не влияет.
  if (isNaN(d.getTime())) return escapeHTML(iso);
  return d.toLocaleString("ru-RU", { hour12: false });
}

function shortHex(hex, n) {
  if (!hex) return "—";
  n = n || 10;
  return hex.length > n ? hex.slice(0, n) + "…" : hex;
}

function escapeHTML(s) {
  return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[c]));
}

async function safeJSON(resp) {
  try { return await resp.json(); } catch (e) { return null; }
}

/* ---------- API ---------- */

async function api(path, options) {
  options = options || {};
  const headers = Object.assign({}, options.headers || {});
  if (token) headers["Authorization"] = "Bearer " + token;
  if (options.body) headers["Content-Type"] = "application/json";

  const resp = await fetch(path, Object.assign({}, options, { headers }));
  return resp;
}

/* ---------- gateway info ---------- */

async function loadGatewayInfo() {
  try {
    // Через api(), а не голый fetch: сам публичный ключ шлюз отдаёт всем, но
    // служебное поле log_session_keys — только по токену.
    const resp = await api("/api/v1/gateway");
    if (!resp.ok) throw new Error("status " + resp.status);
    const data = await resp.json();
    el("gw-fingerprint").textContent = "gw: " + shortHex(data.kem_pub_hex, 16);
    gatewayLogSessionKeys =
      "log_session_keys" in data ? !!data.log_session_keys : null;
    setConn(true);
  } catch (e) {
    el("gw-fingerprint").textContent = "gw: недоступен";
    setConn(false);
  }
}

function setConn(ok) {
  const ind = el("conn-indicator");
  ind.classList.remove("conn-ok", "conn-bad", "conn-unknown");
  ind.classList.add(ok ? "conn-ok" : "conn-bad");
}

/* ---------- навигация между видами ---------- */

function switchView(name) {
  currentView = name;
  document.querySelectorAll(".view").forEach((v) => v.classList.add("hidden"));
  el("view-" + name).classList.remove("hidden");
  document.querySelectorAll(".nav-btn").forEach((b) => b.classList.toggle("active", b.getAttribute("data-view") === name));

  if (name === "monitoring") loadMonitoring();
  if (name === "rotations") loadRotations();
  if (name === "firmware") loadFirmwareChecks();
  if (name === "metrics") loadMetrics();
}

/* ---------- устройства ---------- */

async function loadDevices() {
  let resp;
  try {
    resp = await api("/api/v1/devices");
  } catch (e) {
    setConn(false);
    return;
  }
  setConn(true);

  if (resp.status === 401) {
    el("auth-banner").classList.remove("hidden");
    el("device-table").classList.add("hidden");
    el("empty-state").classList.add("hidden");
    el("device-count").textContent = "";
    return;
  }
  el("auth-banner").classList.add("hidden");

  if (!resp.ok) {
    showToast("Не удалось получить список устройств (status " + resp.status + ")", "error");
    return;
  }

  const devices = await resp.json();
  renderDevices(devices || []);
}

function renderDevices(devices) {
  devicesByID = {};
  devices.forEach((d) => { devicesByID[d.device_id] = d; });
  populateDeviceSelects(devices);

  const tbody = el("device-rows");
  const table = el("device-table");
  const empty = el("empty-state");

  el("device-count").textContent = devices.length
    ? devices.length + (devices.length === 1 ? " устройство" : " устройств")
    : "";

  if (devices.length === 0) {
    table.classList.add("hidden");
    empty.classList.remove("hidden");
    tbody.innerHTML = "";
    return;
  }
  empty.classList.add("hidden");
  table.classList.remove("hidden");

  devices.sort((a, b) => a.device_id.localeCompare(b.device_id));

  tbody.innerHTML = devices.map(rowHTML).join("");

  tbody.querySelectorAll("tr[data-device-id]").forEach((tr) => {
    tr.addEventListener("click", (ev) => {
      if (ev.target.closest("button")) return;
      openEventsDrawer(tr.getAttribute("data-device-id"));
    });
  });
  tbody.querySelectorAll("button[data-revoke]").forEach((btn) => {
    btn.addEventListener("click", (ev) => {
      ev.stopPropagation();
      revokeDevice(btn.getAttribute("data-revoke"));
    });
  });
}

function populateDeviceSelects(devices) {
  const ids = devices.map((d) => d.device_id).sort();
  monKnownDevices = ids;
  [["rot-device-select", "все устройства"],
   ["fw-device-select", "все устройства"]].forEach((pair) => {
    const sel = el(pair[0]);
    const prevValue = sel.value;
    sel.innerHTML = '<option value="">' + pair[1] + "</option>" +
      ids.map((id) => '<option value="' + escapeHTML(id) + '">' + escapeHTML(id) + "</option>").join("");
    if (ids.indexOf(prevValue) !== -1) sel.value = prevValue;
  });
  renderDeviceChecks(ids);
}

// Флажки выбора устройств на вкладке «Мониторинг».
//
// Список перестраивается при каждом обновлении реестра, поэтому отметки
// приходится восстанавливать. Устройства, исчезнувшие из реестра, из выборки
// удаляются: иначе выбор ссылался бы на несуществующее, и графики оставались бы
// пустыми без видимой причины.
function renderDeviceChecks(ids) {
  const box = el("mon-device-checks");
  if (!box) return;
  if (ids.length === 0) {
    box.innerHTML = '<span class="dev-pick-empty">устройств пока нет</span>';
    updateDeviceSummary();
    return;
  }
  Array.from(monState.deviceIDs).forEach((id) => {
    if (ids.indexOf(id) === -1) monState.deviceIDs.delete(id);
  });
  box.innerHTML = ids.map((id) => {
    const on = monState.deviceIDs.has(id);
    return '<label class="dev-chip' + (on ? " checked" : "") + '">' +
      '<input type="checkbox" value="' + escapeHTML(id) + '"' + (on ? " checked" : "") + ">" +
      '<span class="dev-chip-box"></span>' +
      "<span>" + escapeHTML(id) + "</span></label>";
  }).join("");
  updateDeviceSummary();
}

function updateDeviceSummary() {
  const sum = el("mon-device-summary");
  if (!sum) return;
  const n = monState.deviceIDs.size;
  if (n === 0) sum.textContent = "все устройства";
  else if (n === 1) sum.textContent = Array.from(monState.deviceIDs)[0];
  else sum.textContent = "выбрано устройств: " + n;
}

function telemetrySummaryShort(lt) {
  if (!lt) return "—";
  const entries = Object.entries(lt.parsed || {});
  if (entries.length === 0) return shortHex(lt.raw_payload, 28);
  return entries.slice(0, 3).map((e) => e[0] + "=" + e[1]).join("; ");
}

function rowHTML(d) {
  let statusClass, statusLabel;
  if (d.revoked) {
    statusClass = "status-revoked";
    statusLabel = "отозвано";
  } else if (d.online) {
    statusClass = "status-online";
    statusLabel = "online";
  } else {
    statusClass = "status-offline";
    statusLabel = "offline";
  }

  const lastSeen = d.last_seen ? fmtTime(d.last_seen) : "—";
  const revokeDisabled = d.revoked ? "disabled" : "";

  return (
    '<tr data-device-id="' + escapeHTML(d.device_id) + '">' +
      '<td class="col-status"><span class="status-dot ' + statusClass + '">●</span></td>' +
      '<td class="device-id-cell mono">' + escapeHTML(d.device_id) + "</td>" +
      '<td><span class="badge">' + escapeHTML(d.sig_algorithm) + "</span></td>" +
      '<td class="' + statusClass + '">' + statusLabel + (d.revoked && d.revoked_reason ? ' <span class="dim-cell">(' + escapeHTML(d.revoked_reason) + ")</span>" : "") + "</td>" +
      '<td class="dim-cell mono">' + escapeHTML(telemetrySummaryShort(d.last_telemetry)) + "</td>" +
      '<td class="dim-cell">' + lastSeen + "</td>" +
      '<td class="col-actions"><button class="row-revoke-btn" data-revoke="' + escapeHTML(d.device_id) + '" ' + revokeDisabled + ">отозвать</button></td>" +
    "</tr>"
  );
}

async function revokeDevice(deviceID) {
  if (!confirm('Отозвать устройство "' + deviceID + '"? Оно будет немедленно исключено из доверенной сети.')) {
    return;
  }
  try {
    const resp = await api("/api/v1/devices/" + encodeURIComponent(deviceID) + "/revoke", {
      method: "POST",
      body: JSON.stringify({ reason: "отозвано вручную через веб-интерфейс" }),
    });
    if (!resp.ok && resp.status !== 204) {
      const body = await safeJSON(resp);
      throw new Error((body && body.error) || "status " + resp.status);
    }
    showToast("Устройство отозвано", "ok");
    loadDevices();
  } catch (e) {
    showToast("Не удалось отозвать устройство: " + e.message, "error");
  }
}

/* ---------- карточка устройства: последние данные + журнал событий ---------- */

async function openEventsDrawer(deviceID) {
  openEventsDeviceID = deviceID;
  el("events-device-id").textContent = deviceID;
  renderLastTelemetryBox(devicesByID[deviceID] && devicesByID[deviceID].last_telemetry);
  el("events-list").innerHTML = '<li class="events-empty">Загрузка…</li>';
  openDrawer("events");

  try {
    const resp = await api("/api/v1/devices/" + encodeURIComponent(deviceID) + "/events");
    if (!resp.ok) throw new Error("status " + resp.status);
    const events = (await resp.json()) || [];
    renderEvents(events);
  } catch (e) {
    el("events-list").innerHTML = '<li class="events-empty">Не удалось загрузить журнал: ' + escapeHTML(e.message) + "</li>";
  }
}

function renderLastTelemetryBox(lt) {
  const box = el("events-last-telemetry");
  if (!lt) {
    box.innerHTML = '<div class="muted">данных пока нет</div>';
    return;
  }
  const entries = Object.entries(lt.parsed || {});
  const chips = entries.map((e) =>
    '<span class="telemetry-chip">' + escapeHTML(e[0]) + "=<b>" + escapeHTML(String(e[1])) + "</b></span>"
  ).join("");
  box.innerHTML =
    '<div class="telemetry-raw">' + escapeHTML(lt.raw_payload) + "</div>" +
    '<div class="telemetry-chips">' + (chips || '<span class="muted">числовых полей нет</span>') + "</div>" +
    '<div class="telemetry-time">' + fmtTime(lt.received_at) + "</div>";
}


/* Значимость события: по ней журнал раскрашивается, чтобы важное не терялось
   среди рядовых записей.

   Тревожные — то, что означает отказ или потерю доверия. Заметные — то, что
   само по себе не поломка, но требует внимания: например, устройство
   переподключается из-за задержек сети, а ключи при этом уже разошлись и
   обмен не работал. Раньше такая запись выглядела так же, как рядовое
   рукопожатие, и терялась. */
function eventSeverity(type) {
  switch (type) {
    case "revoked":
    case "handshake_rejected":
    case "data_rejected":
    case "firmware_check_rejected":
      return "evt-bad";
    case "rotation_timeout":
    case "reregistered":
      return "evt-warn";
    default:
      return "";
  }
}

function renderEvents(events) {
  const list = el("events-list");
  if (events.length === 0) {
    list.innerHTML = '<li class="events-empty">Событий пока нет.</li>';
    return;
  }
  list.innerHTML = events.map((e) =>
    "<li>" +
      '<span class="evt-type ' + eventSeverity(e.event_type) + '">' +
        escapeHTML(e.event_type) + "</span>" +
      escapeHTML(e.detail || "") +
      '<span class="evt-time">' + fmtTime(e.created_at) + "</span>" +
    "</li>"
  ).join("");
}

/* ---------- регистрация устройства ---------- */

function parseSerialLine(line) {
  const fields = {};
  const re = /(\w+)=(\S+)/g;
  let m;
  while ((m = re.exec(line)) !== null) {
    fields[m[1]] = m[2];
  }
  return fields;
}

function fillRegisterFormFromSerialLine() {
  const line = el("serial-paste").value.trim();
  if (!line) return;
  const f = parseSerialLine(line);
  if (f.DeviceID) el("f-device-id").value = f.DeviceID;
  if (f.IdentityPub) el("f-identity-pub").value = f.IdentityPub;
  if (f.KEMPub) el("f-kem-pub").value = f.KEMPub;
  if (f.FirmwareHash) el("f-firmware-hash").value = f.FirmwareHash;
  if (f.Checksum) el("f-checksum").value = f.Checksum;
}

async function submitRegisterForm(ev) {
  ev.preventDefault();
  const errBox = el("register-error");
  errBox.classList.add("hidden");

  const payload = {
    device_id: el("f-device-id").value.trim(),
    identity_pub_hex: el("f-identity-pub").value.trim(),
    kem_pub_hex: el("f-kem-pub").value.trim(),
    firmware_hash_hex: el("f-firmware-hash").value.trim(),
    checksum: el("f-checksum").value.trim(),
    sig_algorithm: el("f-sig-alg").value,
  };

  try {
    const resp = await api("/api/v1/devices", { method: "POST", body: JSON.stringify(payload) });
    const body = await safeJSON(resp);
    if (!resp.ok) {
      throw new Error((body && body.error) || "status " + resp.status);
    }
    showToast("Устройство зарегистрировано", "ok");
    closeDrawer("register");
    el("register-form").reset();
    el("serial-paste").value = "";
    loadDevices();
  } catch (e) {
    errBox.textContent = e.message;
    errBox.classList.remove("hidden");
  }
}

/* ---------- drawers (универсально) ---------- */

function openDrawer(name) {
  el(name + "-overlay").classList.remove("hidden");
  el(name + "-drawer").classList.remove("hidden");
}
function closeDrawer(name) {
  el(name + "-overlay").classList.add("hidden");
  el(name + "-drawer").classList.add("hidden");
}

/* ---------- токен ---------- */

function openTokenDrawer() {
  el("token-input").value = token;
  openDrawer("token");
}

function saveToken() {
  token = el("token-input").value.trim();
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_KEY);
  }
  closeDrawer("token");
  showToast("Токен сохранён в этом браузере", "ok");
  loadGatewayInfo();
  loadDevices();
}

function clearToken() {
  token = "";
  localStorage.removeItem(TOKEN_KEY);
  el("token-input").value = "";
  closeDrawer("token");
  loadGatewayInfo();
  loadDevices();
}

/* =====================================================================
   МОНИТОРИНГ: графики на чистом SVG (без внешних библиотек/CDN — проект
   для изолированных сетей) + история пакетов.
   ===================================================================== */

const CHART_COLORS = ["#d98e3b", "#4fa8c9", "#5fb87a", "#d9636b", "#9a7bd9", "#c9a14f", "#5fc9b8", "#c97bb0"];
const CHART_GRID_COLOR = "#2a2e38";
const CHART_AXIS_TEXT_COLOR = "#6b6e78";
const CHART_GUIDE_COLOR = "#3a3f4b";

/* ---- чистая математика графика (покрыта тестами в /tmp/chart_math_test.js
   на этапе разработки; здесь — финальная версия для встраивания) ---- */

function chartComputeScales(seriesList) {
  let tMin = Infinity, tMax = -Infinity, vMin = Infinity, vMax = -Infinity;
  for (const s of seriesList) {
    for (const p of s.points) {
      if (p.t < tMin) tMin = p.t;
      if (p.t > tMax) tMax = p.t;
      if (p.v < vMin) vMin = p.v;
      if (p.v > vMax) vMax = p.v;
    }
  }
  if (!isFinite(tMin)) { tMin = 0; tMax = 1; }
  if (tMin === tMax) { tMax = tMin + 1; }
  if (!isFinite(vMin)) { vMin = 0; vMax = 1; }
  if (vMin === vMax) {
    const pad = Math.abs(vMin) > 0 ? Math.abs(vMin) * 0.1 : 1;
    vMin -= pad; vMax += pad;
  } else {
    const pad = (vMax - vMin) * 0.08;
    vMin -= pad; vMax += pad;
  }
  return { tMin, tMax, vMin, vMax };
}

function chartProjectX(t, scales, plot) {
  const ratio = (t - scales.tMin) / (scales.tMax - scales.tMin);
  return plot.left + ratio * plot.width;
}
function chartProjectY(v, scales, plot) {
  const ratio = (v - scales.vMin) / (scales.vMax - scales.vMin);
  return plot.top + (1 - ratio) * plot.height;
}

function chartBuildPolyline(points, scales, plot) {
  return points.map((p) =>
    chartProjectX(p.t, scales, plot).toFixed(1) + "," + chartProjectY(p.v, scales, plot).toFixed(1)
  ).join(" ");
}

function chartNiceTicks(min, max, count) {
  const ticks = [];
  for (let i = 0; i <= count; i++) ticks.push(min + (max - min) * (i / count));
  return ticks;
}

function chartFindNearestIndex(points, targetT) {
  if (points.length === 0) return -1;
  let lo = 0, hi = points.length - 1;
  if (targetT <= points[0].t) return 0;
  if (targetT >= points[hi].t) return hi;
  while (lo < hi) {
    const mid = (lo + hi) >> 1;
    if (points[mid].t < targetT) lo = mid + 1; else hi = mid;
  }
  if (lo > 0) {
    const dLo = Math.abs(points[lo].t - targetT);
    const dPrev = Math.abs(points[lo - 1].t - targetT);
    return dPrev <= dLo ? lo - 1 : lo;
  }
  return lo;
}

function formatAxisNumber(v) {
  if (Math.abs(v) >= 100) return Math.round(v).toString();
  if (Math.abs(v) >= 10) return v.toFixed(1);
  return v.toFixed(2);
}

function formatAxisTime(t, full) {
  const d = new Date(t);
  if (full) return d.toLocaleString("ru-RU", { hour12: false });
  return d.toLocaleTimeString("ru-RU", { hour12: false, hour: "2-digit", minute: "2-digit" });
}

/* ---- размер графиков (переключатель на панели периода) ---------------- */
const CHART_SIZE_KEY = "lacert.chartSize";
const CHART_HEIGHTS = { m: 240, l: 300, xl: 380 };

function chartSizeMode() {
  const v = localStorage.getItem(CHART_SIZE_KEY);
  return CHART_HEIGHTS[v] ? v : "m";
}
function chartHeightPx() {
  return CHART_HEIGHTS[chartSizeMode()];
}

/* Прореживание: при длинных интервалах (сутки и т.п.) точек приходит намного
   больше, чем пикселей по ширине, и линия превращается в неразборчивую «кашу».
   Схлопываем точки в корзины по времени и берём среднее значение в корзине —
   форма графика сохраняется, читаемость резко растёт. Первая и последняя точки
   сохраняются как есть, чтобы границы диапазона не «уезжали». */
function chartDownsample(points, maxPoints) {
  if (!points || points.length <= maxPoints || maxPoints < 3) return points;
  const first = points[0];
  const last = points[points.length - 1];
  const span = last.t - first.t;
  if (span <= 0) return points;

  const buckets = maxPoints - 2;
  const out = [first];
  let idx = 1;
  for (let b = 0; b < buckets; b++) {
    const tEnd = first.t + (span * (b + 1)) / buckets;
    let sumV = 0, sumT = 0, n = 0;
    while (idx < points.length - 1 && points[idx].t <= tEnd) {
      sumV += points[idx].v; sumT += points[idx].t; n++; idx++;
    }
    if (n > 0) out.push({ t: sumT / n, v: sumV / n });
  }
  out.push(last);
  return out;
}

const SVG_NS = "http://www.w3.org/2000/svg";

function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  for (const k in attrs) node.setAttribute(k, attrs[k]);
  return node;
}

/**
 * renderLineChart рисует линейный график без внешних библиотек: оси,
 * сетка, легенда, наведение мышью с тултипом. series — массив
 * {label, color, points:[{t,v},...]} в хронологическом порядке.
 */
function renderLineChart(container, seriesList) {
  container.innerHTML = "";
  const width = container.clientWidth || 380;
  // Высота берётся из выбранного размера графиков и совпадает с резервом
  // высоты карточки (--chart-h в CSS) — иначе вернётся «прыжок скролла».
  const height = chartHeightPx();
  const plot = { left: 48, top: 10, width: width - 48 - 12, height: height - 10 - 28 };

  let nonEmpty = seriesList.filter((s) => s.points && s.points.length > 0);
  // Не рисуем больше ~2 точек на пиксель ширины: при интервалах в часы/сутки
  // это главная причина нечитаемости.
  const maxPoints = Math.max(60, Math.round(plot.width / 2));
  nonEmpty = nonEmpty.map((s) => ({ ...s, points: chartDownsample(s.points, maxPoints) }));
  if (nonEmpty.length === 0) {
    const div = document.createElement("div");
    div.className = "chart-empty";
    div.textContent = "нет данных за выбранный период";
    container.appendChild(div);
    return;
  }

  const scales = chartComputeScales(nonEmpty);
  const svg = svgEl("svg", { viewBox: "0 0 " + width + " " + height, width: "100%", height: String(height) });

  chartNiceTicks(scales.vMin, scales.vMax, 4).forEach((tv) => {
    const y = chartProjectY(tv, scales, plot);
    svg.appendChild(svgEl("line", { x1: plot.left, x2: plot.left + plot.width, y1: y, y2: y, stroke: CHART_GRID_COLOR, "stroke-width": "1" }));
    const label = svgEl("text", { x: plot.left - 8, y: y + 3, "text-anchor": "end", "font-size": "9.5", fill: CHART_AXIS_TEXT_COLOR });
    label.textContent = formatAxisNumber(tv);
    svg.appendChild(label);
  });

  // Подписи времени: чем шире график, тем больше отметок (раньше всегда 3 —
  // на широком мониторе ось получалась почти пустой).
  const xTickCount = Math.max(2, Math.min(9, Math.floor(plot.width / 140)));
  for (let i = 0; i <= xTickCount; i++) {
    const tv = scales.tMin + ((scales.tMax - scales.tMin) * i) / xTickCount;
    const x = chartProjectX(tv, scales, plot);
    // лёгкая вертикальная сетка по времени
    if (i > 0 && i < xTickCount) {
      svg.appendChild(svgEl("line", {
        x1: x, x2: x, y1: plot.top, y2: plot.top + plot.height,
        stroke: CHART_GRID_COLOR, "stroke-width": "1", opacity: "0.5",
      }));
    }
    const anchorPos = i === 0 ? "start" : i === xTickCount ? "end" : "middle";
    const label = svgEl("text", { x: x, y: plot.top + plot.height + 17, "text-anchor": anchorPos, "font-size": "9.5", fill: CHART_AXIS_TEXT_COLOR });
    label.textContent = formatAxisTime(tv, false);
    svg.appendChild(label);
  }

  const guideline = svgEl("line", { y1: plot.top, y2: plot.top + plot.height, stroke: CHART_GUIDE_COLOR, "stroke-width": "1" });
  guideline.style.display = "none";

  nonEmpty.forEach((s, idx) => {
    const color = s.color || CHART_COLORS[idx % CHART_COLORS.length];
    svg.appendChild(svgEl("polyline", {
      points: chartBuildPolyline(s.points, scales, plot),
      fill: "none", stroke: color, "stroke-width": "1.6",
    }));
    const last = s.points[s.points.length - 1];
    svg.appendChild(svgEl("circle", {
      cx: chartProjectX(last.t, scales, plot), cy: chartProjectY(last.v, scales, plot), r: "2.5", fill: color,
    }));
  });

  svg.appendChild(guideline);

  const wrap = document.createElement("div");
  wrap.className = "chart-svg-wrap";
  wrap.appendChild(svg);

  const tooltip = document.createElement("div");
  tooltip.className = "chart-tooltip";
  wrap.appendChild(tooltip);

  svg.addEventListener("mousemove", (ev) => {
    const rect = svg.getBoundingClientRect();
    if (rect.width === 0) return;
    const scaleX = width / rect.width;
    const xPix = (ev.clientX - rect.left) * scaleX;
    if (xPix < plot.left || xPix > plot.left + plot.width) {
      tooltip.style.display = "none";
      guideline.style.display = "none";
      return;
    }
    const targetT = scales.tMin + ((xPix - plot.left) / plot.width) * (scales.tMax - scales.tMin);

    const refIdx = chartFindNearestIndex(nonEmpty[0].points, targetT);
    const tAtCursor = nonEmpty[0].points[refIdx].t;

    const lines = nonEmpty.map((s) => {
      const idx = chartFindNearestIndex(s.points, tAtCursor);
      const p = s.points[idx];
      return '<div><span class="swatch" style="background:' + (s.color) + '"></span>' +
        escapeHTML(s.label) + ": <b>" + formatAxisNumber(p.v) + "</b></div>";
    });

    guideline.setAttribute("x1", chartProjectX(tAtCursor, scales, plot));
    guideline.setAttribute("x2", chartProjectX(tAtCursor, scales, plot));
    guideline.style.display = "block";

    tooltip.innerHTML = "<div>" + formatAxisTime(tAtCursor, true) + "</div>" + lines.join("");
    tooltip.style.display = "block";
    const tipLeft = Math.min(Math.max(xPix - 50, 0), width - 160);
    tooltip.style.left = tipLeft + "px";
    tooltip.style.top = "2px";
  });
  svg.addEventListener("mouseleave", () => {
    tooltip.style.display = "none";
    guideline.style.display = "none";
  });

  container.appendChild(wrap);

  const legend = document.createElement("div");
  legend.className = "chart-legend";
  nonEmpty.forEach((s, idx) => {
    const color = s.color || CHART_COLORS[idx % CHART_COLORS.length];
    const item = document.createElement("span");
    item.innerHTML = '<span class="swatch" style="background:' + color + '"></span>' + escapeHTML(s.label);
    legend.appendChild(item);
  });
  container.appendChild(legend);
}

/* ---- загрузка и группировка данных мониторинга ---- */

function computeRangeWindow() {
  if (monState.customSince) {
    return { since: monState.customSince, until: monState.customUntil || new Date() };
  }
  const ms = RANGE_MS[monState.range] || RANGE_MS["1h"];
  return { since: new Date(Date.now() - ms), until: null };
}

// monRequestSeq — счётчик "какой запрос телеметрии сейчас самый актуальный".
// Нужен для защиты от race condition: периодический опрос (каждые 3с, см.
// startPolling) и ручной клик по кнопке диапазона могут запустить два
// запроса почти одновременно, и сетевые ответы могут прийти В ОБРАТНОМ
// порядке относительно того, в котором запросы были отправлены. Без этой
// защиты ответ на УЖЕ НЕАКТУАЛЬНЫЙ (более старый по смыслу выбора
// пользователя) запрос, долетевший позже, перезаписывал бы график данными
// по старому диапазону поверх только что применённого нового — визуально
// это выглядело так, будто смена периода (30мин/1/6/12/24ч) вообще не
// действует. Формально: любой ответ, чей номер запроса не совпадает с
// последним отправленным на момент получения ответа, отбрасывается.
let monRequestSeq = 0;

async function loadMonitoring() {
  const mySeq = ++monRequestSeq;

  const range = computeRangeWindow();
  const params = new URLSearchParams();
  // REST-эндпоинт телеметрии принимает только одно значение device_id, поэтому
  // сервером фильтруем лишь когда выбрано ровно одно устройство — это самый
  // частый случай и самая выгодная экономия. При нескольких выбранных запрос
  // идёт без фильтра, а лишние записи отсеиваются ниже, уже на клиенте. Объём
  // при этом не больше, чем в режиме «все устройства», который существовал и
  // раньше, так что нагрузка на шлюз не растёт.
  const picked = Array.from(monState.deviceIDs);
  if (picked.length === 1) params.set("device_id", picked[0]);
  if (range.since) params.set("since", range.since.toISOString());
  if (range.until) params.set("until", range.until.toISOString());
  // Лимит служит только страховкой от чрезмерно больших выборок. Он должен
  // быть заведомо больше, чем число точек в самом длинном диапазоне (24 часа
  // на несколько устройств), иначе выборка обрезается ПО КОЛИЧЕСТВУ раньше,
  // чем по ВРЕМЕНИ, и график показывает не весь выбранный период, а лишь
  // последние N точек (это выглядит как "данные только за ~25 минут").
  params.set("limit", "50000");

  let resp;
  try {
    resp = await api("/api/v1/telemetry?" + params.toString());
  } catch (e) {
    showToast("Не удалось загрузить телеметрию", "error");
    return;
  }
  if (mySeq !== monRequestSeq) return; // подоспел более новый запрос — этот ответ устарел, игнорируем
  if (resp.status === 401) return; // баннер авторизации виден на вкладке "Устройства"
  if (!resp.ok) {
    showToast("Ошибка загрузки телеметрии (status " + resp.status + ")", "error");
    return;
  }
  let readings = (await resp.json()) || [];
  if (mySeq !== monRequestSeq) return; // повторная проверка: гонка могла возникнуть и во время .json()
  if (picked.length > 1) {
    const want = monState.deviceIDs;
    readings = readings.filter((r) => want.has(r.device_id));
  }
  renderMonitoring(readings);
}

/* Применяет выбранный размер к сетке графиков (класс задаёт --chart-h и
   число колонок; JS берёт ту же высоту через chartHeightPx). */
function applyChartSizeClass(chartsEl) {
  if (!chartsEl) return;
  const mode = chartSizeMode();
  chartsEl.classList.remove("size-l", "size-xl");
  if (mode === "l") chartsEl.classList.add("size-l");
  else if (mode === "xl") chartsEl.classList.add("size-xl");
}

/* Кнопки «Графики: обычные / крупные / во всю ширину». Выбор сохраняется. */
function initChartSizeButtons() {
  const wrap = document.querySelector(".chart-size");
  if (!wrap) return;
  const buttons = wrap.querySelectorAll(".size-btn");
  const sync = () => {
    const mode = chartSizeMode();
    buttons.forEach((b) => b.classList.toggle("active", b.dataset.size === mode));
  };
  buttons.forEach((btn) => {
    btn.addEventListener("click", () => {
      localStorage.setItem(CHART_SIZE_KEY, btn.dataset.size);
      sync();
      applyChartSizeClass(el("mon-charts"));
      // перерисовываем уже загруженные данные — без повторного запроса
      if (monState.lastReadings) renderMonitoring(monState.lastReadings);
    });
  });
  sync();
}

function renderMonitoring(readings) {
  const chartsEl = el("mon-charts");
  monState.lastReadings = readings; // для мгновенной перерисовки при смене размера
  applyChartSizeClass(chartsEl);
  const emptyEl = el("mon-empty");
  emptyEl.classList.toggle("hidden", readings.length !== 0);

  const metrics = new Set();
  const byDevice = {};
  readings.forEach((r) => {
    (byDevice[r.device_id] = byDevice[r.device_id] || []).push(r);
    Object.keys(r.parsed || {}).forEach((k) => metrics.add(k));
  });
  const deviceIDs = Object.keys(byDevice).sort();
  const sortedMetrics = Array.from(metrics).sort();

  // Строим весь новый набор карточек ОФФЛАЙН (не в живом документе) и
  // подменяем содержимое chartsEl одним атомарным действием
  // (replaceChildren), вместо "innerHTML='' затем append по одной".
  //
  // Критично: НЕ читаем container.clientWidth (через renderLineChart) на
  // этом этапе — только создаём структуру DOM. Раньше renderLineChart
  // вызывался для каждой карточки СРАЗУ по мере её добавления в chartsEl,
  // и чтение clientWidth внутри нее форсирует синхронный reflow браузера
  // ("forced synchronous layout"). Это давало сразу два независимых
  // визуальных дефекта из одного корня:
  //   (а) на момент этого форсированного reflow первая карточка часто
  //       оказывалась ЕДИНСТВЕННОЙ в CSS grid (repeat(auto-fit, ...)) —
  //       остальные ещё не были добавлены в DOM на той итерации цикла —
  //       поэтому grid растягивал её на всю ширину; когда позже
  //       добавлялись остальные карточки, реальная ширина колонки
  //       уменьшалась, но SVG viewBox уже был посчитан под старую
  //       (широкую) ширину — весь график визуально сжимался/масштабировался
  //       вниз, текст осей становился нечитаемым;
  //   (б) сам forced reflow срабатывал в момент, когда общая высота
  //       документа была временно МЕНЬШЕ, чем до перерисовки (старые
  //       карточки уже удалены через innerHTML="", новые добавлены не
  //       все) — если текущая scroll-позиция превышала эту временно
  //       уменьшенную высоту, браузер немедленно (синхронно, при самом
  //       reflow) клэмпил scrollY вниз; после того как высота
  //       восстанавливалась, scroll не возвращался обратно — пользователь
  //       визуально видел "страницу, прыгающую наверх" при каждом
  //       автообновлении (каждые 3 секунды).
  //
  // Решение: сначала полностью построить все карточки-контейнеры (без
  // чтения layout), затем ОДНИМ действием вставить их в документ, и
  // только ПОСЛЕ этого — вторым проходом, когда grid уже в финальном
  // состоянии с полным набором карточек — вызвать renderLineChart для
  // каждой. К этому моменту первый forced reflow (при чтении clientWidth)
  // застаёт уже стабильный, полный layout.
  const newCards = [];
  const chartContainers = []; // пары [container, series] для второго прохода

  sortedMetrics.forEach((metric) => {
    const card = document.createElement("div");
    card.className = "chart-card";
    const h3 = document.createElement("h3");
    h3.textContent = metric;
    card.appendChild(h3);
    const chartDiv = document.createElement("div");
    card.appendChild(chartDiv);
    newCards.push(card);

    const series = deviceIDs.map((devID, idx) => ({
      label: devID,
      color: CHART_COLORS[idx % CHART_COLORS.length],
      points: byDevice[devID]
        .filter((r) => r.parsed && Object.prototype.hasOwnProperty.call(r.parsed, metric))
        .map((r) => ({ t: new Date(r.received_at).getTime(), v: r.parsed[metric] })),
    }));
    chartContainers.push([chartDiv, series]);
  });

  if (sortedMetrics.length === 0 && readings.length > 0) {
    const card = document.createElement("div");
    card.className = "chart-card";
    card.innerHTML = '<div class="chart-empty">Нет числовых полей для графиков (см. сырые данные в истории ниже).</div>';
    newCards.push(card);
  }

  // Атомарная замена содержимого — единственная точка, где старые карточки
  // исчезают и новые появляются, за одно синхронное действие без чтения
  // layout-свойств до и после.
  chartsEl.replaceChildren(...newCards);

  // Второй проход: grid уже содержит ВСЕ карточки в финальном порядке —
  // теперь можно безопасно читать ширину каждого контейнера.
  chartContainers.forEach(([chartDiv, series]) => renderLineChart(chartDiv, series));

  const histPanel = el("mon-history-panel");
  // Таблица сырых записей имеет смысл только для одного устройства: при
  // нескольких выбранных строки от разных источников перемешались бы, а
  // колонки «устройство» в этой таблице нет.
  const onlyOne = monState.deviceIDs.size === 1 ? Array.from(monState.deviceIDs)[0] : "";
  if (onlyOne) {
    histPanel.classList.remove("hidden");
    el("mon-history-device").textContent = onlyOne;
    const own = (byDevice[onlyOne] || []).slice().reverse().slice(0, 300);
    el("mon-history-count").textContent = (byDevice[onlyOne] || []).length + " записей";
    el("mon-history-rows").innerHTML = own.map((r) =>
      '<tr><td class="dim-cell mono">' + fmtTime(r.received_at) + '</td><td class="mono">' + escapeHTML(r.raw_payload) + "</td></tr>"
    ).join("") || '<tr><td colspan="2" class="dim-cell">Нет данных</td></tr>';
  } else {
    histPanel.classList.add("hidden");
  }
}

/* =====================================================================
   ЖУРНАЛ РОТАЦИЙ КЛЮЧЕЙ
   ===================================================================== */

// rotRequestSeq — тот же паттерн защиты от гонки, что и monRequestSeq выше:
// смена фильтра по устройству и периодический опрос могут вызвать
// loadRotations() почти одновременно, и без этой защиты устаревший ответ,
// долетевший позже, перезаписал бы уже применённый фильтр.
let rotRequestSeq = 0;

/* ---- Проверки целостности прошивки -----------------------------------
   Шлюз пишет события firmware_check (пройдена) и firmware_check_rejected
   (отклонена) в журнал. Здесь показываем их сводно по всем устройствам. */
let fwRequestSeq = 0;

async function loadFirmwareChecks() {
  const mySeq = ++fwRequestSeq;

  const deviceID = el("fw-device-select").value;
  const params = new URLSearchParams();
  if (deviceID) params.set("device_id", deviceID);
  params.set("limit", "300");

  let resp;
  try {
    resp = await api("/api/v1/firmware-checks?" + params.toString());
  } catch (e) {
    showToast("Не удалось загрузить журнал проверок прошивки", "error");
    return;
  }
  if (mySeq !== fwRequestSeq) return;   // ответ устарел
  if (resp.status === 401) return;
  if (!resp.ok) {
    showToast("Ошибка загрузки проверок прошивки (status " + resp.status + ")", "error");
    return;
  }
  const events = (await resp.json()) || [];
  if (mySeq !== fwRequestSeq) return;
  renderFirmwareChecks(events);
}

function renderFirmwareChecks(events) {
  const tbody = el("fw-rows");
  const table = el("fw-table");
  const emptyEl = el("fw-empty");
  const summaryEl = el("fw-summary");

  if (events.length === 0) {
    table.classList.add("hidden");
    emptyEl.classList.remove("hidden");
    summaryEl.innerHTML = "";
    tbody.innerHTML = "";
    return;
  }
  emptyEl.classList.add("hidden");
  table.classList.remove("hidden");

  const passed = events.filter((e) => e.event_type === "firmware_check").length;
  const rejected = events.length - passed;
  summaryEl.innerHTML =
    '<div class="fw-stat fw-stat-ok"><span class="fw-stat-num">' + passed + '</span>' +
      '<span class="fw-stat-label">пройдено</span></div>' +
    '<div class="fw-stat ' + (rejected > 0 ? "fw-stat-bad" : "") + '">' +
      '<span class="fw-stat-num">' + rejected + '</span>' +
      '<span class="fw-stat-label">отклонено</span></div>';

  tbody.innerHTML = events.map((e) => {
    const ok = e.event_type === "firmware_check";
    const statusClass = ok ? "status-online" : "status-revoked";
    const verdict = ok
      ? '<span class="fw-ok">пройдена</span>'
      : '<span class="fw-bad">ОТКЛОНЕНА</span>';
    return (
      "<tr>" +
        '<td class="col-status"><span class="status-dot ' + statusClass + '">●</span></td>' +
        '<td class="dim-cell mono">' + fmtTime(e.created_at) + "</td>" +
        '<td class="device-id-cell mono">' + escapeHTML(e.device_id) + "</td>" +
        "<td>" + verdict + "</td>" +
        '<td class="dim-cell">' + escapeHTML(e.detail || "") + "</td>" +
      "</tr>"
    );
  }).join("");
}

async function loadRotations() {
  const mySeq = ++rotRequestSeq;

  const deviceID = el("rot-device-select").value;
  const params = new URLSearchParams();
  if (deviceID) params.set("device_id", deviceID);
  params.set("limit", "300");

  let resp;
  try {
    resp = await api("/api/v1/rotations?" + params.toString());
  } catch (e) {
    showToast("Не удалось загрузить журнал ротаций", "error");
    return;
  }
  if (mySeq !== rotRequestSeq) return; // подоспел более новый запрос — этот ответ устарел
  if (resp.status === 401) return;
  if (!resp.ok) {
    showToast("Ошибка загрузки журнала ротаций (status " + resp.status + ")", "error");
    return;
  }
  const entries = (await resp.json()) || [];
  if (mySeq !== rotRequestSeq) return;
  renderRotations(entries);
}

function renderRotations(entries) {
  // Три состояния: режим включён, выключен и неизвестен (нет токена — шлюз
  // служебное поле не отдал). В последнем случае не утверждаем ни того, ни
  // другого и не показываем баннер вовсе.
  el("rot-mode-banner").classList.toggle("hidden", gatewayLogSessionKeys !== true);
  el("rot-mode-banner-off").classList.toggle("hidden", gatewayLogSessionKeys !== false);

  const tbody = el("rot-rows");
  const table = el("rot-table");
  const emptyEl = el("rot-empty");

  if (entries.length === 0) {
    table.classList.add("hidden");
    emptyEl.classList.remove("hidden");
    tbody.innerHTML = "";
    return;
  }
  emptyEl.classList.add("hidden");
  table.classList.remove("hidden");

  tbody.innerHTML = entries.map((e) => {
    const statusClass = e.success ? "status-online" : "status-revoked";
    const statusTitle = e.success ? "успешно" : ("ошибка: " + (e.error_text || ""));
    const oldKey = e.old_key_hex ? '<span class="mono">' + shortHex(e.old_key_hex, 20) + "</span>" : '<span class="dim-cell">скрыто</span>';
    const newKey = e.new_key_hex ? '<span class="mono">' + shortHex(e.new_key_hex, 20) + "</span>" : '<span class="dim-cell">скрыто</span>';
    return (
      "<tr>" +
        '<td class="col-status"><span class="status-dot ' + statusClass + '" title="' + escapeHTML(statusTitle) + '">●</span></td>' +
        '<td class="dim-cell mono">' + fmtTime(e.created_at) + "</td>" +
        '<td class="device-id-cell mono">' + escapeHTML(e.device_id) + "</td>" +
        "<td>" + escapeHTML(e.initiator) + "</td>" +
        '<td class="dim-cell">' + (e.rotation_count || "—") + "</td>" +
        "<td>" + oldKey + "</td>" +
        "<td>" + newKey + "</td>" +
      "</tr>"
    );
  }).join("");
}

/* ---------- метрики ---------- */

// Список полей метрик и соответствующих им id элементов-значений.
const METRIC_KEYS = [
  "handshakes_completed", "handshakes_rejected", "replays_blocked",
  "rotations_succeeded", "rotations_failed",
  "firmware_checks_passed", "firmware_checks_failed", "firmware_checks_rejected",
  "devices_revoked",
  "data_replays_blocked",
  "telemetry_dropped",
];

// metricsRequestSeq — та же защита от гонки, что и для телеметрии/ротаций:
// периодический опрос и ручное обновление могут прийти в обратном порядке.
let metricsRequestSeq = 0;

async function loadMetrics() {
  const mySeq = ++metricsRequestSeq;

  let resp;
  try {
    resp = await api("/api/v1/metrics");
  } catch (e) {
    showToast("Не удалось загрузить метрики", "error");
    return;
  }
  if (mySeq !== metricsRequestSeq) return; // подоспел более новый запрос
  if (resp.status === 401) return; // баннер авторизации виден на вкладке "Устройства"
  if (!resp.ok) {
    showToast("Ошибка загрузки метрик (status " + resp.status + ")", "error");
    return;
  }
  const data = (await resp.json()) || {};
  if (mySeq !== metricsRequestSeq) return;
  renderMetrics(data);
}

function renderMetrics(data) {
  METRIC_KEYS.forEach((key) => {
    const cell = el("m-" + key);
    if (!cell) return;
    const value = Number(data[key] || 0);
    cell.textContent = value.toLocaleString("ru-RU");
    // Подсветка «тревожных» карточек только при ненулевом значении.
    const card = cell.closest(".metric-card");
    if (card && card.classList.contains("metric-accent-danger")) {
      card.classList.toggle("metric-hot", value > 0);
    }
  });
  el("metrics-updated").textContent = "обновлено " + fmtTime(new Date().toISOString());
}

/* ---------- инициализация ---------- */

function wireEvents() {
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => switchView(btn.getAttribute("data-view")));
  });

  el("refresh-btn").addEventListener("click", loadDevices);
  el("register-btn").addEventListener("click", () => openDrawer("register"));
  el("register-close").addEventListener("click", () => closeDrawer("register"));
  el("register-overlay").addEventListener("click", () => closeDrawer("register"));
  el("register-form").addEventListener("submit", submitRegisterForm);
  el("serial-paste").addEventListener("input", fillRegisterFormFromSerialLine);

  el("token-btn").addEventListener("click", openTokenDrawer);
  el("auth-banner-btn").addEventListener("click", openTokenDrawer);
  el("token-close").addEventListener("click", () => closeDrawer("token"));
  el("token-overlay").addEventListener("click", () => closeDrawer("token"));
  el("token-save").addEventListener("click", saveToken);
  el("token-clear").addEventListener("click", clearToken);

  el("events-close").addEventListener("click", () => closeDrawer("events"));
  el("events-overlay").addEventListener("click", () => closeDrawer("events"));
  el("events-open-monitoring").addEventListener("click", () => {
    if (!openEventsDeviceID) return;
    const deviceID = openEventsDeviceID;
    closeDrawer("events");
    switchView("monitoring");
    // Переход из журнала событий показывает именно это устройство, поэтому
    // прежняя выборка заменяется, а не дополняется.
    monState.deviceIDs = new Set([deviceID]);
    renderDeviceChecks(monKnownDevices);
    loadMonitoring();
  });

  document.querySelectorAll(".range-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".range-btn").forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      monState.range = btn.getAttribute("data-range");
      monState.customSince = null;
      monState.customUntil = null;
      loadMonitoring();
    });
  });
  el("range-apply").addEventListener("click", () => {
    const sinceVal = el("range-since").value;
    const untilVal = el("range-until").value;
    if (!sinceVal) {
      showToast("Укажите начало периода", "error");
      return;
    }
    document.querySelectorAll(".range-btn").forEach((b) => b.classList.remove("active"));
    monState.customSince = new Date(sinceVal);
    monState.customUntil = untilVal ? new Date(untilVal) : new Date();
    loadMonitoring();
  });
  // Флажки создаются заново при каждом обновлении реестра, поэтому слушатель
  // висит на контейнере, а не на самих элементах: иначе его пришлось бы
  // переподключать после каждой перерисовки.
  el("mon-device-checks").addEventListener("change", (ev) => {
    const input = ev.target;
    if (!input || input.type !== "checkbox") return;
    if (input.checked) monState.deviceIDs.add(input.value);
    else monState.deviceIDs.delete(input.value);
    const chip = input.closest(".dev-chip");
    if (chip) chip.classList.toggle("checked", input.checked);
    updateDeviceSummary();
    loadMonitoring();
  });
  el("mon-dev-all").addEventListener("click", () => {
    monKnownDevices.forEach((id) => monState.deviceIDs.add(id));
    renderDeviceChecks(monKnownDevices);
    loadMonitoring();
  });
  el("mon-dev-none").addEventListener("click", () => {
    monState.deviceIDs.clear();
    renderDeviceChecks(monKnownDevices);
    loadMonitoring();
  });
  el("mon-refresh").addEventListener("click", () => {
    // "Обновить" на мониторинге сбрасывает пользовательский диапазон дат
    // (поля since/until) и возвращает выбор к активной кнопке периода, затем
    // перезагружает данные. Так кнопка одновременно и обновляет данные, и
    // очищает ручной поиск по датам.
    monState.customSince = null;
    monState.customUntil = null;
    el("range-since").value = "";
    el("range-until").value = "";
    // Если ни одна кнопка периода не активна (был задан кастомный диапазон) —
    // возвращаемся к периоду по умолчанию (1 час).
    const anyActive = document.querySelector(".range-btn.active");
    if (!anyActive) {
      const def = document.querySelector('.range-btn[data-range="1h"]');
      if (def) {
        def.classList.add("active");
        monState.range = "1h";
      }
    }
    loadMonitoring();
  });

  el("rot-device-select").addEventListener("change", loadRotations);
  el("rot-refresh").addEventListener("click", loadRotations);
  el("fw-device-select").addEventListener("change", loadFirmwareChecks);
  el("fw-refresh").addEventListener("click", loadFirmwareChecks);

  el("metrics-refresh").addEventListener("click", loadMetrics);

  document.addEventListener("keydown", (ev) => {
    if (ev.key === "Escape") {
      closeDrawer("register");
      closeDrawer("token");
      closeDrawer("events");
    }
  });
}

function startPolling() {
  if (pollTimer) clearInterval(pollTimer);
  pollTimer = setInterval(() => {
    // Сохраняем позицию прокрутки на время обновления данных. Периодическая
    // перерисовка таблиц (устройства/ротации) через innerHTML на мгновение
    // может уменьшить высоту документа; если пользователь был прокручен вниз,
    // браузер «подтягивает» скролл вверх и не возвращает обратно — из-за чего
    // страница прыгала наверх при каждом автообновлении. Запоминаем scrollY
    // до обновления и восстанавливаем после того, как DOM перестроен.
    const savedScroll = window.scrollY;
    const restoreScroll = () => {
      if (Math.abs(window.scrollY - savedScroll) > 1) {
        window.scrollTo({ top: savedScroll, behavior: "instant" in window ? "instant" : "auto" });
      }
    };

    Promise.resolve()
      .then(() => loadDevices())
      .then(() => {
        if (openEventsDeviceID && !el("events-drawer").classList.contains("hidden")) {
          return openEventsDrawer(openEventsDeviceID);
        }
      })
      .then(() => {
        if (currentView === "monitoring") return loadMonitoring();
        if (currentView === "rotations") return loadRotations();
        if (currentView === "firmware") return loadFirmwareChecks();
        if (currentView === "metrics") return loadMetrics();
      })
      .finally(() => {
        // Восстанавливаем скролл после перерисовки (в следующем кадре, когда
        // layout уже устаканился).
        requestAnimationFrame(restoreScroll);
      });
  }, 3000);
}

document.addEventListener("DOMContentLoaded", () => {
  wireEvents();
  initChartSizeButtons();
  loadGatewayInfo();
  loadDevices();
  startPolling();
});
