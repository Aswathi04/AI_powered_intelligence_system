/* dashboard.js — Sentinel AI Flask frontend */

/* ── SSE Alert Stream ── */
function initAlertStream() {
  const es = new EventSource('/alerts_stream');

  es.onmessage = function(e) {
    const data = JSON.parse(e.data);
    updateStatus(data);
    updateMetrics(data);
    updateLog(data.log || []);
  };

  es.onerror = function() {
    const banner = document.getElementById('status-banner');
    if (banner) {
      banner.textContent = '⚠️ Connection lost — reconnecting...';
      banner.className   = 'status-banner alert';
    }
  };
}

/* ── Status banner ── */
function updateStatus(data) {
  const banner = document.getElementById('status-banner');
  if (!banner) return;

  if (data.secure) {
    banner.textContent = '✅ SYSTEM SECURE';
    banner.className   = 'status-banner secure';
  } else {
    const alerts = (data.alerts || []).join(' + ');
    banner.textContent = `🚨 ALERT: ${alerts}`;
    banner.className   = 'status-banner alert';
  }
}

/* ── Metrics ── */
function updateMetrics(data) {
  const score = data.threat_score || 0;

  // Update threat gauge visualization
  updateThreatGauge(score);

  // Update metric values
  _set('m-people',   data.people || 0);
  _set('m-dist',     data.min_dist && data.min_dist < 999 ? data.min_dist + ' px' : '—');
  _set('m-encircle', (data.encircle_pct || 0) + '%');

  // Color-code metric cards based on threat level
  const threatLevel = score > 70 ? 'high' : score > 40 ? 'med' : 'low';
  const cards = ['metric-people-card', 'metric-dist-card', 'metric-encircle-card'];
  cards.forEach(cardId => {
    const card = document.getElementById(cardId);
    if (card) {
      // Remove old threat class
      card.classList.remove('threat-low', 'threat-med', 'threat-high');
      // Add new threat class
      card.classList.add(`threat-${threatLevel}`);
    }
  });

  _set('fps-badge', (data.fps || '--') + ' FPS');
}

/* ── Threat Gauge Animation ── */
function updateThreatGauge(score) {
  const arc = document.getElementById('gauge-arc');
  const scoreDisplay = document.getElementById('threat-score-val');
  if (!arc || !scoreDisplay) return;

  // SVG circle circumference ≈ 345.57 (for radius 55)
  const circumference = 345.57;
  const progress = (Math.min(score, 100) / 100) * circumference;
  arc.style.strokeDasharray = `${progress} ${circumference}`;

  // Update score display and color
  scoreDisplay.textContent = score;
  const threatLevel = score > 70 ? 'high' : score > 40 ? 'med' : 'low';
  scoreDisplay.className = `threat-score-display ${threatLevel}`;

  // Update arc color
  const color = score > 70 ? 'var(--danger)' : score > 40 ? 'var(--warning)' : 'var(--success)';
  arc.style.stroke = color;
}

/* ── Live log with structured events ── */
function updateLog(lines) {
  const el = document.getElementById('live-log');
  if (!el) return;

  // If no events, show placeholder
  if (!lines || !lines.length) {
    el.innerHTML = '<li class="event-item muted" style="justify-content: center;">Waiting for events...</li>';
    return;
  }

  // Parse and render events
  let html = '';
  lines.slice(-10).reverse().forEach(line => {  // Show last 10, most recent first
    const event = parseEventLog(line);
    html += renderEventItem(event);
  });
  el.innerHTML = html;
}

/* ── Parse event log line ── */
function parseEventLog(line) {
  // Example line: "PROXIMITY: 2 people, 145px"
  // Extract type and message
  const match = line.match(/^(\w+):\s*(.+)$/);
  if (!match) return { type: 'INFO', message: line, icon: 'ℹ️' };

  const [, type, message] = match;
  const typeMap = {
    'PROXIMITY': { icon: '⚠️', class: 'event-proximity' },
    'SPEED': { icon: '🏃', class: 'event-speed' },
    'ENCIRCLEMENT': { icon: '🔄', class: 'event-encircle' },
    'LOITERING': { icon: '⏱️', class: 'event-loiter' },
    'TAILGATING': { icon: '👥', class: 'event-tailgate' },
  };
  const typeInfo = typeMap[type] || { icon: 'ℹ️', class: 'event-info' };

  return { type, message, ...typeInfo, timestamp: new Date().toLocaleTimeString() };
}

/* ── Render event item ── */
function renderEventItem(event) {
  return `
    <li class="event-item">
      <span class="event-icon">${event.icon}</span>
      <div class="event-content">
        <div class="event-type ${event.class}">${event.type}</div>
        <div>${event.message}</div>
        <div class="event-time">${event.timestamp}</div>
      </div>
    </li>
  `;
}

/* ── Incident list ── */
function loadIncidents() {
  const el = document.getElementById('incident-list');
  if (!el) return;

  fetch('/api/incidents')
    .then(r => r.json())
    .then(incidents => {
      if (!incidents.length) {
        el.innerHTML = '<p class="muted">No incidents recorded yet.</p>';
        return;
      }
      renderIncidents(incidents, el);
    })
    .catch(() => {
      el.innerHTML = '<p class="muted">Could not load incidents.</p>';
    });
}

function renderIncidents(incidents, container) {
  let html = '';
  incidents.forEach(inc => {
    const icon  = inc.review_status === 'CONFIRMED'  ? '🔴'
                : inc.review_status === 'FALSE_ALARM' ? '⚪' : '🟡';
    const score = inc.threat_score || 0;
    const ts    = (inc.timestamp || '').substring(0, 19).replace('T', ' ');
    const isPending = !inc.review_status || inc.review_status === 'PENDING';

    // _folder comes from app.py as "day_folder/inc_folder" e.g. "2026-03-31/incident_001"
    // We pass it as-is — the /evidence/<path> route handles the rest
    const folder = inc._folder || '';

    html += `
    <div class="incident-card">
      <div class="incident-header">
        <span>${icon} <strong>${inc.incident_id || '—'}</strong></span>
        <span class="badge-type">${inc.detection_type || 'UNKNOWN'}</span>
        <span>${score}/100</span>
        <span class="muted">${ts}</span>
        <span class="badge-status-${(inc.review_status || 'pending').toLowerCase()}">
          ${inc.review_status || 'PENDING'}
        </span>
      </div>

      ${inc.reviewed_by
        ? `<div class="incident-details muted">
             Reviewed by ${inc.reviewed_by}
             ${inc.review_note ? ' · ' + inc.review_note : ''}
           </div>`
        : ''}

      <div style="display:flex; gap:8px; flex-wrap:wrap; margin-top:8px;">
        <button class="btn-sm" onclick="viewEvidence('${folder}', '${inc.incident_id || ''}')">
          ▶️ View Evidence
        </button>
        ${isPending ? `
        <button class="btn-sm" style="color:var(--success)"
          onclick="reviewIncident('${folder}', 'CONFIRMED', '${inc.incident_id || ''}')">
          ✅ Confirm
        </button>
        <button class="btn-sm btn-danger"
          onclick="reviewIncident('${folder}', 'FALSE_ALARM', '${inc.incident_id || ''}')">
          ❌ False Alarm
        </button>` : ''}
      </div>
    </div>`;
  });
  container.innerHTML = html;
}

/* ── Review incident ── */
function reviewIncident(folder, status, incidentId) {
  const note = prompt(
    `${status === 'CONFIRMED' ? 'Confirm threat' : 'Mark as false alarm'}\n` +
    'Add a note (optional):', ''
  );
  if (note === null) return;  // user cancelled

  // FIX: report_path must be the full filesystem path that os.path.exists() can find.
  // app.py _get_all_incidents() builds _folder as "day_folder/inc_folder"
  // EVIDENCE_ROOT in app.py is prepended by the server — but /api/incident/review
  // receives report_path and calls os.path.exists() directly, so we need the full path.
  // The safest approach: ask the server to look it up by folder key instead.
  // Since we can't change the API right now, send the path that matches EVIDENCE_ROOT layout.
  const reportPath = folder + '/report.json';

  fetch('/api/incident/review', {
    method:  'POST',
    headers: {'Content-Type': 'application/json'},
    body:    JSON.stringify({ report_path: reportPath, status, note }),
  })
  .then(r => r.json())
  .then(d => {
    if (d.ok) {
      alert(`✅ ${incidentId} marked as ${status}`);
      loadIncidents();
    } else {
      // Show the actual server error so we can debug path issues
      alert('Error: ' + d.error + '\n\nPath tried: ' + reportPath);
    }
  });
}

/* ── Evidence viewer ── */
function viewEvidence(folder, incidentId) {
  const modal = document.getElementById('incident-modal');
  const title = document.getElementById('modal-title');
  const body  = document.getElementById('modal-body');
  if (!modal) return;

  title.textContent = `Evidence: ${incidentId}`;

  // The /evidence/<path> route serves from EVIDENCE_ROOT.
  // folder = "2026-03-31/incident_001" → URL = /evidence/2026-03-31/incident_001/clip.mp4
  // We try multiple common filenames via <source> fallback chain.
  body.innerHTML = `
    <div style="margin-bottom:14px;">
      <p class="muted" style="font-size:12px; margin-bottom:8px;">
        📁 Folder: <code>${folder}</code>
      </p>

      <p style="font-size:13px; font-weight:500; margin-bottom:8px;">🎬 Incident Footage</p>
      <video id="evidence-video" width="100%" controls autoplay muted
             style="border-radius:8px; border:1px solid var(--border); background:#000; display:block;">
        <source src="/evidence/${folder}/clip.mp4"     type="video/mp4">
        <source src="/evidence/${folder}/evidence.mp4" type="video/mp4">
        <source src="/evidence/${folder}/video.mp4"    type="video/mp4">
        <source src="/evidence/${folder}/clip.avi"     type="video/x-msvideo">
        <source src="/evidence/${folder}/evidence.avi" type="video/x-msvideo">
        Your browser does not support the video tag.
      </video>

      <div id="video-error-hint" style="display:none; margin-top:8px;
           padding:10px; background:var(--bg3); border-radius:var(--radius);
           font-size:12px; color:var(--warning);">
        ⚠️ Video not loading. Check that your evidence saver writes a file named
        <code>clip.mp4</code> or <code>evidence.mp4</code> inside each incident folder,
        and that it uses H.264 encoding (not XVID/AVI).
      </div>
    </div>

    <div style="margin-bottom:14px;">
      <p style="font-size:13px; font-weight:500; margin-bottom:8px;">📸 Peak Threat Snapshot</p>
      <img src="/evidence/${folder}/snapshot.jpg"
           onerror="this.src='/evidence/${folder}/thumbnail.jpg'"
           onload="this.style.display='block'"
           style="width:100%; border-radius:8px; border:1px solid var(--border); display:block;"/>
    </div>`;

  modal.classList.remove('hidden');

  // Show hint if video fails to load within 3 seconds
  const video = document.getElementById('evidence-video');
  const hint  = document.getElementById('video-error-hint');
  video.addEventListener('error', () => { hint.style.display = 'block'; });
  setTimeout(() => {
    if (video.readyState === 0) hint.style.display = 'block';
  }, 3000);
}

function closeModal() {
  const modal = document.getElementById('incident-modal');
  if (modal) {
    modal.classList.add('hidden');
    const video = modal.querySelector('video');
    if (video) { video.pause(); video.src = ''; }
  }
}

/* ── Utility ── */
function _set(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

/* Close modal on backdrop click */
document.addEventListener('click', function(e) {
  const modal = document.getElementById('incident-modal');
  if (modal && e.target === modal) closeModal();
});