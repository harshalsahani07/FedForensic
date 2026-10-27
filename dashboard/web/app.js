// =============================================================
// FedForensic Dashboard — app.js
// Pure vanilla JS, no frameworks or dependencies beyond Chart.js
// =============================================================

'use strict';

// ─── 1. Constants ────────────────────────────────────────────
const API = {
  demo:        '/api/demo',
  analyzeCsv:  '/api/analyze',
  analyzePcap: '/api/analyze/pcap',
  health:      '/api/health',
};

const THREAT_COLORS = {
  Reconnaissance:  '#f59e0b',
  WebAttack:       '#ec4899',
  C2_Botnet:       '#8b5cf6',
  LateralMovement: '#f97316',
  Exfiltration:    '#3b82f6',
  DDoS:            '#ef4444',
  Benign:          '#10b981',
};

const THREAT_LABELS = {
  Reconnaissance:  'Recon',
  WebAttack:       'Web Atk',
  C2_Botnet:       'C2/Botnet',
  LateralMovement: 'Lateral',
  Exfiltration:    'Exfil',
  DDoS:            'DDoS',
  Benign:          'Benign',
};

const KILL_CHAIN_ORDER = [
  'Reconnaissance', 'WebAttack', 'C2_Botnet',
  'LateralMovement', 'Exfiltration', 'DDoS',
];

const LEVEL_COLORS = {
  CRITICAL: '#ef4444',
  HIGH:     '#f97316',
  MEDIUM:   '#f59e0b',
  LOW:      '#10b981',
};

// ─── 2. Application state ────────────────────────────────────
const state = {
  data:       null,          // current API response
  allEvents:  [],            // full events array (capped at 500)
  filtered:   [],            // events after filter applied
  filterType: 'all',
  sortCol:    'severity',
  sortDir:    'desc',
  charts:     {},            // Chart.js instances keyed by canvas id
};

// ─── 3. DOM references ───────────────────────────────────────
const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

const el = {
  threatBadge:      $('#threatBadge'),
  threatLabel:      $('#threatLabel'),
  dataSourceBadge:  $('#dataSourceBadge'),
  dataSourceLabel:  $('#dataSourceLabel'),
  timestamp:        $('#analysisTimestamp'),
  modelList:        $('#modelList'),
  statThreat:       $('#statThreat'),
  statFlows:        $('#statFlows'),
  statFlowsSub:     $('#statFlowsSub'),
  statAttacks:      $('#statAttacks'),
  statAttacksSub:   $('#statAttacksSub'),
  statChain:        $('#statChain'),
  statConf:         $('#statConf'),
  killChainNodes:   $('#killChainNodes'),
  kcStageBadge:     $('#kcStageBadge'),
  timelineSubtitle: $('#timelineSubtitle'),
  distSubtitle:     $('#distSubtitle'),
  alertFilter:      $('#alertFilter'),
  alertCount:       $('#alertCount'),
  alertTbody:       $('#alertTbody'),
  narrativeText:    $('#narrativeText'),
  uploadOverlay:    $('#uploadOverlay'),
  uploadDropzone:   $('#uploadDropzone'),
  uploadProgress:   $('#uploadProgress'),
  progressLabel:    $('#progressLabel'),
  progressBar:      $('#progressBar'),
  fileInput:        $('#fileInput'),
  pcapBar:          $('#pcapBar'),
  pcapFlows:        $('#pcapFlows'),
  pcapPkts:         $('#pcapPkts'),
  pcapProtos:       $('#pcapProtos'),
  pcapIPs:          $('#pcapIPs'),
  btnUpload:        $('#btnUpload'),
  btnExportCSV:     $('#btnExportCSV'),
  btnExportPDF:     $('#btnExportPDF'),
  uploadClose:      $('#uploadClose'),
};

// ─── 4. API calls ─────────────────────────────────────────────

async function fetchDemo() {
  const res = await fetch(API.demo);
  if (!res.ok) throw new Error(`Demo data error: ${res.status}`);
  return res.json();
}

async function uploadFile(file) {
  const form = new FormData();
  form.append('file', file);

  const isPcap = /\.(pcap|pcapng|cap)$/i.test(file.name);
  const url    = isPcap ? API.analyzePcap : API.analyzeCsv;

  const res = await fetch(url, { method: 'POST', body: form });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || 'Upload failed');
  }
  return res.json();
}

async function checkHealth() {
  try {
    const res = await fetch(API.health);
    return res.ok ? res.json() : null;
  } catch {
    return null;
  }
}

// ─── 5. Render: stats ────────────────────────────────────────

function animateCount(el, target, isFloat = false, prefix = '', suffix = '') {
  const start    = 0;
  const duration = 900;
  const step     = 16;
  const steps    = Math.ceil(duration / step);
  let   current  = 0;

  const timer = setInterval(() => {
    current++;
    const progress = current / steps;
    // Ease out cubic
    const eased = 1 - Math.pow(1 - progress, 3);
    const value  = start + (target - start) * eased;

    el.textContent = prefix + (isFloat
      ? (value * 100).toFixed(1) + '%'
      : Math.round(value).toLocaleString()) + suffix;

    if (current >= steps) {
      clearInterval(timer);
      el.textContent = prefix + (isFloat
        ? (target * 100).toFixed(1) + '%'
        : Math.round(target).toLocaleString()) + suffix;
    }
  }, step);
}

function renderStats(data) {
  const { threat_level, total_flows, attack_count, stages_detected, avg_confidence } = data;
  const benign_pct = ((total_flows - attack_count) / total_flows * 100).toFixed(1);
  const atk_pct    = (attack_count / total_flows * 100).toFixed(1);

  // Threat level
  el.statThreat.textContent = threat_level;
  el.statThreat.style.color = LEVEL_COLORS[threat_level] || '#f1f5f9';
  el.statThreat.style.textShadow = `0 0 24px ${LEVEL_COLORS[threat_level]}44`;

  // Sidebar threat badge
  el.threatBadge.setAttribute('data-level', threat_level);
  el.threatLabel.textContent = threat_level;

  // Counts with animation
  animateCount(el.statFlows, total_flows);
  el.statFlowsSub.textContent = `${benign_pct}% benign`;

  animateCount(el.statAttacks, attack_count);
  el.statAttacksSub.textContent = `${atk_pct}% of traffic`;

  el.statChain.textContent = `${stages_detected} / 6`;

  // Confidence
  animateCount(el.statConf, avg_confidence, true);
}

// ─── 6. Render: source badge ─────────────────────────────────

function renderSourceBadge(data) {
  const labels = { demo: 'Demo Data', csv: 'Live — CSV', pcap: 'Live — PCAP' };
  el.dataSourceLabel.textContent = labels[data.source] || data.source;

  const dot = $('.source-dot', el.dataSourceBadge);
  if (dot) {
    dot.style.background = data.source === 'demo' ? '#f59e0b' : '#10b981';
    dot.style.boxShadow  = `0 0 5px ${dot.style.background}`;
  }

  const ts = new Date(data.analyzed_at);
  el.timestamp.textContent = isNaN(ts)
    ? ''
    : ts.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

// ─── 7. Render: PCAP info bar ────────────────────────────────

function renderPcapBar(info) {
  if (!info) { el.pcapBar.hidden = true; return; }

  el.pcapFlows.textContent = `${(info.flow_count || 0).toLocaleString()} flows`;
  el.pcapPkts.textContent  = `${(info.pkt_count  || 0).toLocaleString()} pkts`;
  el.pcapProtos.textContent = `TCP:${info.tcp_flows} UDP:${info.udp_flows} ICMP:${info.icmp_flows}`;
  el.pcapIPs.textContent   = `${info.unique_src_ips} src IPs → ${info.unique_dst_ips} dst IPs`;
  el.pcapBar.hidden = false;
}

// ─── 8. Render: model health dots ────────────────────────────

function renderModelHealth(health) {
  const items = $$('.model-item', el.modelList);
  if (!health) {
    items.forEach(li => {
      const dot = $('.model-dot', li);
      dot.className = 'model-dot model-dot--error';
    });
    return;
  }
  // First item = master, rest = specialists
  items.forEach((li, i) => {
    const dot = $('.model-dot', li);
    const ok  = i === 0 ? health.master_loaded : (i <= health.specialist_count);
    dot.className = `model-dot ${ok ? 'model-dot--ok' : 'model-dot--error'}`;
  });
}

// ─── 9. Render: Kill Chain ────────────────────────────────────

function renderKillChain(kc) {
  el.killChainNodes.innerHTML = '';

  const detectedCount = Object.keys(kc).length;
  el.kcStageBadge.textContent = `${detectedCount} of 6 stages · Lockheed Martin`;

  KILL_CHAIN_ORDER.forEach((cat, idx) => {
    const info   = kc[cat];
    const active = !!info;
    const color  = info?.color || THREAT_COLORS[cat] || '#888';

    const node = document.createElement('div');
    node.className = `kc-node ${active ? 'kc-node--active' : 'kc-node--inactive'}`;
    node.setAttribute('role', 'listitem');
    node.setAttribute('aria-label', `${cat}: ${active ? info.count + ' events' : 'not detected'}`);

    if (active) {
      node.style.borderLeftColor = color;
      node.style.boxShadow       = `0 0 20px ${color}18`;
    }

    const confPct = active ? Math.round(info.confidence * 100) : 0;

    node.innerHTML = `
      <span class="kc-stage-num">S${info?.stage ?? idx + 1}</span>
      <span class="kc-icon">${info?.icon ?? ''}</span>
      <span class="kc-name">${info?.short ?? cat.replace(/([A-Z])/g, ' $1').trim()}</span>
      ${active
        ? `<span class="kc-count">${info.count.toLocaleString()}</span>
           <div class="kc-conf-wrap">
             <span class="kc-conf-label">${confPct}% conf.</span>
             <div class="kc-conf-bar">
               <div class="kc-conf-fill" style="width:${confPct}%; background:${color};"></div>
             </div>
           </div>`
        : `<span class="kc-count kc-count--inactive">Not detected</span>`
      }
    `;

    // Staggered fade-in
    node.style.opacity   = '0';
    node.style.transform = 'translateY(6px)';
    node.style.transition = `opacity 0.4s ease ${idx * 60}ms, transform 0.4s ease ${idx * 60}ms`;

    el.killChainNodes.appendChild(node);

    // Trigger animation
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        node.style.opacity   = active ? '1' : '0.4';
        node.style.transform = 'translateY(0)';
      });
    });
  });
}

// ─── 10. Charts ──────────────────────────────────────────────

const CHART_DEFAULTS = {
  animation:    { duration: 600 },
  responsive:   true,
  maintainAspectRatio: false,
  plugins: {
    legend: {
      labels: {
        color:     '#94a3b8',
        font:      { family: "'Inter', sans-serif", size: 11 },
        boxWidth:  10,
        padding:   12,
      },
    },
    tooltip: {
      backgroundColor: '#ffffff',
      borderColor:     'rgba(0,0,0,0.1)',
      borderWidth:     1,
      titleColor:      '#212529',
      bodyColor:       '#475569',
      padding:         10,
      cornerRadius:    8,
      displayColors:   true,
      boxWidth:        8,
      boxHeight:       8,
    },
  },
};

function destroyChart(id) {
  if (state.charts[id]) {
    state.charts[id].destroy();
    delete state.charts[id];
  }
}

// Timeline scatter chart
function renderTimelineChart(events) {
  destroyChart('chartTimeline');

  // Sample up to 400 events to keep the chart fast
  const sample  = events.filter(e => e.predicted !== 'Benign').slice(0, 400);
  const byType  = {};
  sample.forEach((ev, i) => {
    const t = ev.predicted;
    if (!byType[t]) byType[t] = [];
    byType[t].push({ x: i, y: ev.severity + (Math.random() - 0.5) * 0.3 });
  });

  const datasets = Object.entries(byType).map(([type, pts]) => ({
    label:           THREAT_LABELS[type] || type,
    data:            pts,
    backgroundColor: `${THREAT_COLORS[type] || '#888'}cc`,
    pointRadius:     3,
    pointHoverRadius: 5,
  }));

  el.timelineSubtitle.textContent = `${sample.length} attack events`;

  const ctx = $('#chartTimeline').getContext('2d');
  state.charts['chartTimeline'] = new Chart(ctx, {
    type: 'scatter',
    data: { datasets },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: {
          grid:  { color: 'rgba(0,0,0,0.05)' },
          ticks: { color: '#475569', maxTicksLimit: 6, font: { family: "'JetBrains Mono', monospace", size: 10 } },
          title: { display: true, text: 'Event index', color: '#475569', font: { size: 10 } },
        },
        y: {
          grid:  { color: 'rgba(0,0,0,0.05)' },
          ticks: { color: '#475569', font: { family: "'JetBrains Mono', monospace", size: 10 }, stepSize: 1 },
          title: { display: true, text: 'Severity', color: '#475569', font: { size: 10 } },
          min: 0, max: 10,
        },
      },
    },
  });
}

// Distribution donut
function renderDistChart(kc) {
  destroyChart('chartDist');

  const labels = [], counts = [], colors = [], borders = [];
  Object.entries(kc).forEach(([cat, info]) => {
    labels.push(info.short || THREAT_LABELS[cat] || cat);
    counts.push(info.count);
    colors.push(`${info.color}cc`);
    borders.push(info.color);
  });

  const total = counts.reduce((a, b) => a + b, 0);
  el.distSubtitle.textContent = `${total.toLocaleString()} attack events`;

  const ctx = $('#chartDist').getContext('2d');
  state.charts['chartDist'] = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels,
      datasets: [{ data: counts, backgroundColor: colors, borderColor: borders, borderWidth: 1.5, hoverOffset: 8 }],
    },
    options: {
      ...CHART_DEFAULTS,
      cutout: '65%',
      plugins: {
        ...CHART_DEFAULTS.plugins,
        legend: { ...CHART_DEFAULTS.plugins.legend, position: 'right' },
      },
    },
  });
}

// Confidence horizontal bar
function renderConfChart(kc) {
  destroyChart('chartConf');

  const labels  = [], values = [], colors = [];
  KILL_CHAIN_ORDER.forEach(cat => {
    if (!kc[cat]) return;
    labels.push(kc[cat].short || THREAT_LABELS[cat] || cat);
    values.push(+(kc[cat].confidence * 100).toFixed(1));
    colors.push(`${kc[cat].color}cc`);
  });

  const ctx = $('#chartConf').getContext('2d');
  state.charts['chartConf'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Confidence (%)',
        data: values,
        backgroundColor: colors,
        borderColor: colors.map(c => c.replace('cc', '')),
        borderWidth: 1,
        borderRadius: 4,
      }],
    },
    options: {
      ...CHART_DEFAULTS,
      scales: {
        x: { grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { color: '#475569', font: { family: "'JetBrains Mono', monospace", size: 10 } } },
        y: { grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { color: '#475569', font: { family: "'JetBrains Mono', monospace", size: 10 } }, min: 0, max: 100 },
      },
    },
  });
}

// Event volume horizontal bar
function renderVolumeChart(kc) {
  destroyChart('chartVolume');

  const labels = [], values = [], colors = [];
  KILL_CHAIN_ORDER.forEach(cat => {
    if (!kc[cat]) return;
    labels.push(kc[cat].short || THREAT_LABELS[cat] || cat);
    values.push(kc[cat].count);
    colors.push(`${kc[cat].color}99`);
  });

  const ctx = $('#chartVolume').getContext('2d');
  state.charts['chartVolume'] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels,
      datasets: [{
        label: 'Events',
        data: values,
        backgroundColor: colors,
        borderRadius: 4,
      }],
    },
    options: {
      ...CHART_DEFAULTS,
      indexAxis: 'y',
      scales: {
        x: { grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { color: '#475569', font: { family: "'JetBrains Mono', monospace", size: 10 } } },
        y: { grid: { display: false }, ticks: { color: '#94a3b8', font: { family: "'Inter', sans-serif", size: 11 } } },
      },
    },
  });
}

function renderAllCharts(data) {
  renderTimelineChart(data.events || []);
  renderDistChart(data.kill_chain || {});
  renderConfChart(data.kill_chain || {});
  renderVolumeChart(data.kill_chain || {});
}

// ─── 11. Render: Alert table ──────────────────────────────────

function getThreatBadgeHtml(type) {
  const color = THREAT_COLORS[type] || '#888';
  const label = THREAT_LABELS[type] || type;
  const bg    = `${color}22`;
  const border= `${color}55`;
  return `<span class="threat-badge" style="color:${color};background:${bg};border:1px solid ${border};">${label}</span>`;
}

function getSeverityPips(sev) {
  const n = Math.round(Math.min(Math.max(sev, 0), 10));
  let html = '<span class="sev-pip">';
  for (let i = 0; i < 10; i++) {
    html += `<span${i < n ? ' class="lit"' : ''}></span>`;
  }
  return html + '</span>';
}

function getConfBar(conf) {
  const pct   = Math.round(conf * 100);
  const color = pct > 85 ? '#10b981' : pct > 65 ? '#f59e0b' : '#ef4444';
  return `<span class="conf-cell">
    <span style="font-family:'JetBrains Mono',monospace;font-size:11px;">${pct}%</span>
    <span class="conf-bar"><span class="conf-fill" style="width:${pct}%;background:${color};"></span></span>
  </span>`;
}

function sortEvents(events) {
  const { sortCol, sortDir } = state;
  return [...events].sort((a, b) => {
    let va = a[sortCol], vb = b[sortCol];
    if (typeof va === 'string') return sortDir === 'asc' ? va.localeCompare(vb) : vb.localeCompare(va);
    return sortDir === 'asc' ? va - vb : vb - va;
  });
}

function renderAlertTable() {
  const { filtered, filterType } = state;
  const toShow  = filterType === 'all' ? filtered : filtered.filter(e => e.predicted === filterType);
  const sorted  = sortEvents(toShow);
  const display = sorted.slice(0, 150);   // show top 150 in table

  el.alertCount.textContent = `${toShow.length.toLocaleString()} events`;

  el.alertTbody.innerHTML = display.map(ev => {
    const ts = ev.timestamp ? ev.timestamp.split('T')[1]?.slice(0, 8) ?? ev.timestamp : '—';
    return `<tr>
      <td style="color:#64748b;">${ts}</td>
      <td>${getThreatBadgeHtml(ev.predicted)}</td>
      <td>${getConfBar(ev.confidence ?? 0)}</td>
      <td>${getSeverityPips(ev.severity ?? 0)}</td>
    </tr>`;
  }).join('');

  // Update sort arrow indicators
  $$('th.sortable').forEach(th => {
    const arrow = th.querySelector('.sort-arrow');
    if (th.dataset.col === state.sortCol) {
      arrow.className = `sort-arrow sort-arrow--${state.sortDir}`;
    } else {
      arrow.className = 'sort-arrow';
    }
  });
}

// ─── 12. Render: Narrative ────────────────────────────────────

function renderNarrative(text) {
  el.narrativeText.textContent = text || '— No narrative available —';
}

// ─── 13. Master render ───────────────────────────────────────

function renderAll(data) {
  state.data      = data;
  state.allEvents = data.events || [];
  state.filtered  = state.allEvents.filter(e => e.predicted !== 'Benign');

  renderSourceBadge(data);
  renderStats(data);
  renderPcapBar(data.pcap_info);
  renderKillChain(data.kill_chain || {});
  renderAllCharts(data);
  renderAlertTable();
  renderNarrative(data.narrative);
}

// ─── 14. Upload flow ─────────────────────────────────────────

function openUpload() {
  el.uploadOverlay.classList.add('is-open');
  el.uploadOverlay.setAttribute('aria-hidden', 'false');
  el.uploadDropzone.hidden   = false;
  el.uploadProgress.hidden   = true;
  el.progressBar.style.width = '0';
}

function closeUpload() {
  el.uploadOverlay.classList.remove('is-open');
  el.uploadOverlay.setAttribute('aria-hidden', 'true');
}

function showProgress(label, pct) {
  el.uploadDropzone.hidden   = true;
  el.uploadProgress.hidden   = false;
  el.progressLabel.textContent = label;
  el.progressBar.style.width   = `${pct}%`;
}

async function handleFileUpload(file) {
  if (!file) return;

  const isPcap  = /\.(pcap|pcapng|cap)$/i.test(file.name);
  const sizeMB  = (file.size / 1024 / 1024).toFixed(1);

  showProgress(`Reading ${file.name} (${sizeMB} MB)…`, 15);

  try {
    showProgress(isPcap ? 'Reconstructing network flows…' : 'Parsing CSV…', 35);
    await new Promise(r => setTimeout(r, 200));

    showProgress('Running 8 ML models…', 65);
    const data = await uploadFile(file);

    showProgress('Building kill chain…', 90);
    await new Promise(r => setTimeout(r, 150));

    closeUpload();
    renderAll(data);
  } catch (err) {
    el.progressLabel.textContent = `Error: ${err.message}`;
    el.progressBar.style.background = '#ef4444';
    setTimeout(closeUpload, 3000);
  }
}

// ─── 15. Export functions ────────────────────────────────────

function exportCSV() {
  if (!state.filtered.length) return;

  const cols = ['timestamp', 'predicted', 'confidence', 'severity'];
  const rows = [cols.join(',')];
  state.filtered.forEach(ev => {
    rows.push(cols.map(c => JSON.stringify(ev[c] ?? '')).join(','));
  });

  const blob = new Blob([rows.join('\n')], { type: 'text/csv' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `fedforensic_events_${new Date().toISOString().slice(0,10)}.csv`;
  a.click();
  URL.revokeObjectURL(url);
}

function exportPDF() {
  if (!state.data) return;

  const { threat_level, total_flows, attack_count, stages_detected, avg_confidence, kill_chain } = state.data;
  const ts = new Date().toLocaleString();

  const content = `
    <html>
    <head>
      <meta charset="UTF-8"/>
      <title>FedForensic Incident Report</title>
      <style>
        body { font-family: 'Arial', sans-serif; margin: 32px; color: #111; font-size: 13px; }
        h1   { font-size: 20px; border-bottom: 2px solid #2563eb; padding-bottom: 8px; margin-bottom: 6px; }
        h2   { font-size: 14px; color: #374151; margin-top: 24px; margin-bottom: 8px; }
        .meta { color: #6b7280; font-size: 11px; margin-bottom: 20px; }
        .badge { display: inline-block; padding: 3px 10px; border-radius: 4px; font-weight: 700; font-size: 13px; }
        .CRITICAL { background: #fee2e2; color: #b91c1c; }
        .HIGH     { background: #ffedd5; color: #c2410c; }
        .MEDIUM   { background: #fef3c7; color: #b45309; }
        .LOW      { background: #d1fae5; color: #065f46; }
        table  { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th,td  { padding: 8px 12px; text-align: left; border-bottom: 1px solid #e5e7eb; font-size: 12px; }
        th     { background: #f9fafb; font-weight: 600; color: #374151; }
        .stats { display: flex; gap: 20px; flex-wrap: wrap; margin: 14px 0; }
        .stat  { background: #f9fafb; border: 1px solid #e5e7eb; border-radius: 6px; padding: 10px 16px; min-width: 110px; }
        .stat-n { font-size: 20px; font-weight: 700; margin: 4px 0 2px; }
        .stat-l { font-size: 10px; text-transform: uppercase; letter-spacing: 0.5px; color: #6b7280; }
        pre   { background: #f0fdf4; border: 1px solid #bbf7d0; border-radius: 6px; padding: 14px; font-size: 11px; line-height: 1.7; color: #14532d; overflow-wrap: break-word; white-space: pre-wrap; }
        footer { margin-top: 32px; border-top: 1px solid #e5e7eb; padding-top: 10px; color: #9ca3af; font-size: 10px; }
      </style>
    </head>
    <body>
      <h1>🛡 FedForensic — Incident Report</h1>
      <p class="meta">Generated: ${ts}</p>

      <p>Threat Level: <span class="badge ${threat_level}">${threat_level}</span></p>

      <div class="stats">
        <div class="stat"><div class="stat-l">Total Flows</div><div class="stat-n">${total_flows.toLocaleString()}</div></div>
        <div class="stat"><div class="stat-l">Attack Events</div><div class="stat-n">${attack_count.toLocaleString()}</div></div>
        <div class="stat"><div class="stat-l">Chain Stages</div><div class="stat-n">${stages_detected} / 6</div></div>
        <div class="stat"><div class="stat-l">Avg Confidence</div><div class="stat-n">${(avg_confidence*100).toFixed(1)}%</div></div>
      </div>

      <h2>Kill Chain Breakdown</h2>
      <table>
        <thead><tr><th>Stage</th><th>Threat</th><th>Events</th><th>Confidence</th><th>Severity</th></tr></thead>
        <tbody>
          ${Object.entries(kill_chain).map(([cat, info]) =>
            `<tr>
              <td>S${info.stage}</td>
              <td>${info.icon} ${cat}</td>
              <td>${info.count.toLocaleString()}</td>
              <td>${(info.confidence * 100).toFixed(1)}%</td>
              <td>${'█'.repeat(info.severity)}${'░'.repeat(10 - info.severity)} ${info.severity}/10</td>
            </tr>`
          ).join('')}
        </tbody>
      </table>

      <h2>Incident Narrative</h2>
      <pre>${state.data.narrative || '—'}</pre>

      <footer>FedForensic · CIC-IoT 2023 · 7 ML Models · Lockheed Martin Kill Chain</footer>
    </body>
    </html>
  `;

  const win = window.open('', '_blank');
  if (!win) { alert('Allow pop-ups to export the PDF report.'); return; }
  win.document.write(content);
  win.document.close();
  win.focus();
  setTimeout(() => { win.print(); }, 600);
}

// ─── 16. Event wiring ────────────────────────────────────────

function wireEvents() {
  // Upload modal
  el.btnUpload.addEventListener('click', openUpload);
  el.uploadClose.addEventListener('click', closeUpload);
  el.uploadOverlay.addEventListener('click', e => { if (e.target === el.uploadOverlay) closeUpload(); });

  // File input
  el.fileInput.addEventListener('change', e => handleFileUpload(e.target.files[0]));

  // Drag and drop
  el.uploadDropzone.addEventListener('dragover', e => {
    e.preventDefault();
    el.uploadDropzone.classList.add('is-dragging');
  });
  el.uploadDropzone.addEventListener('dragleave', () => {
    el.uploadDropzone.classList.remove('is-dragging');
  });
  el.uploadDropzone.addEventListener('drop', e => {
    e.preventDefault();
    el.uploadDropzone.classList.remove('is-dragging');
    const file = e.dataTransfer?.files[0];
    if (file) handleFileUpload(file);
  });

  // Alert filter
  el.alertFilter.addEventListener('change', () => {
    state.filterType = el.alertFilter.value;
    renderAlertTable();
  });

  // Sort columns
  $$('th.sortable').forEach(th => {
    th.addEventListener('click', () => {
      const col = th.dataset.col;
      if (state.sortCol === col) {
        state.sortDir = state.sortDir === 'desc' ? 'asc' : 'desc';
      } else {
        state.sortCol = col;
        state.sortDir = 'desc';
      }
      renderAlertTable();
    });
  });

  // Nav links — smooth scroll to section
  $$('.nav-item').forEach(link => {
    link.addEventListener('click', e => {
      $$('.nav-item').forEach(l => l.classList.remove('nav-item--active'));
      link.classList.add('nav-item--active');
    });
  });

  // Export buttons
  el.btnExportCSV.addEventListener('click', exportCSV);
  el.btnExportPDF.addEventListener('click', exportPDF);

  // Keyboard escape closes modal
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') closeUpload();
  });
}

// ─── 17. Init ────────────────────────────────────────────────

async function init() {
  wireEvents();

  // Check model health in background
  checkHealth().then(health => {
    renderModelHealth(health);
  });

  // Load demo data
  try {
    const data = await fetchDemo();
    renderAll(data);
  } catch (err) {
    el.narrativeText.textContent = `Failed to load demo data:\n${err.message}\n\nMake sure the FedForensic API server is running.`;
    el.threatLabel.textContent   = 'API Offline';
    el.threatBadge.setAttribute('data-level', 'LOW');
  }
}

document.addEventListener('DOMContentLoaded', init);
