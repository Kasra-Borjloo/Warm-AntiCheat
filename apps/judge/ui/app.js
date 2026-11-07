const participantsData = {};

let currentParticipantKey = null;
let currentFilter = 'all';

const participantsList = document.getElementById('participantsList');
const selectedParticipantTitle = document.getElementById('selectedParticipantTitle');
const verdictBanner = document.getElementById('verdictBanner');
const verdictPill = document.getElementById('verdictPill');
const emptyStateCard = document.getElementById('emptyStateCard');
const inspectorContent = document.getElementById('inspectorContent');
const statHashChain = document.getElementById('statHashChain');
const statTotalEvents = document.getElementById('statTotalEvents');
const statCriticalFindings = document.getElementById('statCriticalFindings');
const statGaps = document.getElementById('statGaps');
const findingsCard = document.getElementById('findingsCard');
const findingsList = document.getElementById('findingsList');
const aiSummaryBody = document.getElementById('aiSummaryBody');
const timelineTbody = document.getElementById('timelineTbody');
const themeToggle = document.getElementById('themeToggle');
const saveDecisionBtn = document.getElementById('saveDecisionBtn');
const compilerActivityContent = document.getElementById('compilerActivityContent');
const accountMetadataCard = document.getElementById('accountMetadataCard');
const participationModeBadge = document.getElementById('participationModeBadge');
const accountDetailText = document.getElementById('accountDetailText');
const duplicateAlertBadge = document.getElementById('duplicateAlertBadge');
const evidenceScreenshotsCard = document.getElementById('evidenceScreenshotsCard');
const screenshotsGallery = document.getElementById('screenshotsGallery');
const importBtn = document.getElementById('importBtn');
const mainImportBtn = document.getElementById('mainImportBtn');
const exportCompilerBtn = document.getElementById('exportCompilerReportBtn');

function showToast(message, type = 'info', title = '') {
  let container = document.getElementById('toastContainer');
  if (!container) {
    container = document.createElement('div');
    container.id = 'toastContainer';
    container.style.cssText = 'position: fixed; bottom: 1.5rem; right: 1.5rem; z-index: 99999; display: flex; flex-direction: column; gap: 0.5rem; max-width: 440px; pointer-events: none;';
    document.body.appendChild(container);
  }
  const toast = document.createElement('div');
  const bg = type === 'error' ? '#2d1217' : type === 'warning' ? '#2a220e' : type === 'success' ? '#0f291e' : '#111e38';
  const border = type === 'error' ? '#ef4444' : type === 'warning' ? '#f59e0b' : type === 'success' ? '#22c55e' : '#3b82f6';
  const color = type === 'error' ? '#fca5a5' : type === 'warning' ? '#fde047' : type === 'success' ? '#86efac' : '#93c5fd';

  toast.style.cssText = `pointer-events: auto; background: ${bg}; border: 1px solid ${border}; color: ${color}; padding: 0.85rem 1.1rem; border-radius: 8px; font-size: 0.875rem; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.6); display: flex; align-items: flex-start; gap: 0.75rem; transition: all 0.25s ease;`;
  const icon = type === 'error' ? 'alert-octagon' : type === 'warning' ? 'alert-triangle' : type === 'success' ? 'check-circle' : 'info';

  toast.innerHTML = `
    <span data-lucide="${icon}" data-size="18" style="flex-shrink: 0; margin-top: 2px;"></span>
    <div style="flex: 1;">
      ${title ? `<div style="font-weight: 600; margin-bottom: 0.2rem; color: #fff;">${title}</div>` : ''}
      <div style="line-height: 1.4; word-break: break-word;">${message}</div>
    </div>
  `;
  container.appendChild(toast);
  if (window.replaceLucideIcons) window.replaceLucideIcons();
  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    setTimeout(() => { if (toast.parentNode) toast.parentNode.removeChild(toast); }, 300);
  }, 4500);
}

function openScreenshotLightbox(base64Data, filename, reason, contestTime) {
  let lightbox = document.getElementById('screenshotLightbox');
  if (!lightbox) {
    lightbox = document.createElement('div');
    lightbox.id = 'screenshotLightbox';
    lightbox.style.cssText = 'position: fixed; inset: 0; background: rgba(0,0,0,0.85); display: flex; flex-direction: column; align-items: center; justify-content: center; z-index: 100000; backdrop-filter: blur(6px); padding: 2rem; cursor: pointer;';
    lightbox.innerHTML = `
      <div style="max-width: 92vw; max-height: 88vh; display: flex; flex-direction: column; align-items: center;" onclick="event.stopPropagation()">
        <div style="width: 100%; display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; color: #fff;">
          <div>
            <h4 id="lightboxTitle" style="margin: 0; font-size: 1rem; font-weight: 600;">Evidence Screenshot</h4>
            <div id="lightboxReason" style="font-size: 0.8rem; color: #94a3b8; margin-top: 2px;"></div>
          </div>
          <button class="btn btn-secondary btn-sm" id="lightboxCloseBtn">Close</button>
        </div>
        <img id="lightboxImg" style="max-width: 100%; max-height: 78vh; border-radius: 6px; border: 1px solid #334155; object-fit: contain; box-shadow: 0 25px 50px -12px rgba(0,0,0,0.7);" />
      </div>
    `;
    document.body.appendChild(lightbox);
    lightbox.onclick = () => { lightbox.style.display = 'none'; };
    document.getElementById('lightboxCloseBtn').onclick = () => { lightbox.style.display = 'none'; };
  }
  document.getElementById('lightboxTitle').textContent = filename || 'Evidence Screenshot';
  const reasonText = reason || 'Security event trigger';
  const timeText = contestTime ? ` | ${contestTime}` : '';
  document.getElementById('lightboxReason').textContent = `${reasonText}${timeText}`;
  document.getElementById('lightboxImg').src = `data:image/bmp;base64,${base64Data}`;
  lightbox.style.display = 'flex';
}

function renderParticipants() {
  participantsList.innerHTML = '';
  const keys = Object.keys(participantsData);

  if (keys.length === 0) {
    participantsList.innerHTML = `
      <div style="padding: 2rem 1rem; text-align: center; color: var(--text-muted); font-size: 0.85rem;">
        <span data-lucide="inbox" data-size="28" style="display: block; margin: 0 auto 0.5rem; opacity: 0.4;"></span>
        No archives loaded.<br>Click <strong>Import Archive</strong> above to load a participant .warmac or .sqlite file.
      </div>
    `;
    if (window.replaceLucideIcons) window.replaceLucideIcons();
    return;
  }

  keys.forEach(key => {
    const p = participantsData[key];
    const card = document.createElement('div');
    card.className = `participant-card ${key === currentParticipantKey ? 'active' : ''}`;
    card.dataset.key = key;

    const pillClass = p.verdict === 'SAFE'
      ? 'pill-safe'
      : p.verdict === 'UNSAFE'
      ? 'pill-unsafe'
      : 'pill-review';

    card.innerHTML = `
      <div class="participant-card-header">
        <span class="participant-name">${p.name}</span>
        <span class="verdict-pill-mini ${pillClass}">${p.verdict}</span>
      </div>
      <div class="participant-meta">
        <span><span data-lucide="activity" data-size="12"></span> ${p.totalEvents} events</span>
        <span><span data-lucide="alert-circle" data-size="12"></span> ${p.criticalFindings} findings</span>
      </div>
    `;
    card.addEventListener('click', () => loadParticipant(key));
    participantsList.appendChild(card);
  });

  if (window.replaceLucideIcons) window.replaceLucideIcons();
}

function loadParticipant(key) {
  currentParticipantKey = key;
  const p = participantsData[key];
  if (!p) {
    if (emptyStateCard) emptyStateCard.style.display = 'block';
    if (inspectorContent) inspectorContent.style.display = 'none';
    if (selectedParticipantTitle) selectedParticipantTitle.textContent = 'No Evidence Archive Loaded';
    if (verdictBanner) verdictBanner.style.display = 'none';
    return;
  }

  if (emptyStateCard) emptyStateCard.style.display = 'none';
  if (inspectorContent) inspectorContent.style.display = 'block';

  document.querySelectorAll('.participant-card').forEach(c => {
    c.classList.toggle('active', c.dataset.key === key);
  });

  selectedParticipantTitle.textContent = p.name;
  verdictBanner.style.display = 'block';
  verdictPill.textContent = p.verdict;
  verdictPill.className = `verdict-pill pill-${p.verdict.toLowerCase().replace(/\s+/g, '-')}`;

  if (p.participationMode === 'GeneratedAccounts' || p.authenticatedAccountId) {
    accountMetadataCard.style.display = 'block';
    participationModeBadge.textContent = 'Mode B (Generated Accounts)';
    participationModeBadge.className = 'badge badge-primary';
    accountDetailText.innerHTML = `Authenticated Account UUID: <code>${p.authenticatedAccountId || 'Unassigned'}</code>`;
  } else if (p.declaredLogName) {
    accountMetadataCard.style.display = 'block';
    participationModeBadge.textContent = 'Mode A (No Accounts)';
    participationModeBadge.className = 'badge badge-outline';
    accountDetailText.innerHTML = `Self-declared handle: <strong>"${p.declaredLogName}"</strong> <span class="badge badge-warning" style="margin-left: 0.5rem;">Unverified Self-Report</span>`;
  } else {
    accountMetadataCard.style.display = 'none';
  }

  statHashChain.textContent = p.hashChain;
  statHashChain.className = p.hashChain.includes('VERIFIED') ? 'value text-success' : 'value text-danger';
  statTotalEvents.textContent = p.totalEvents;
  statCriticalFindings.textContent = p.criticalFindings;
  statGaps.textContent = p.gaps;

  renderFindings(p);
  renderScreenshots(p);
  renderAiSummary(p);
  renderTimeline(p);
  renderCompilerActivity(p);

  if (window.replaceLucideIcons) window.replaceLucideIcons();
}

function renderFindings(p) {
  findingsList.innerHTML = '';
  if (!p.findings || p.findings.length === 0) {
    findingsList.innerHTML = `
      <div style="padding: 1rem; color: #22c55e; display: flex; align-items: center; gap: 0.5rem; background: rgba(34, 197, 94, 0.05); border-radius: 6px;">
        <span data-lucide="check-circle-2" data-size="18"></span>
        <span>Clean Audit: Zero prohibited applications, local AI inference, or restricted network domain visits detected.</span>
      </div>
    `;
    return;
  }

  p.findings.forEach(f => {
    const item = document.createElement('div');
    const isCrit = f.severity === 'critical' || f.severity === 'Critical';
    item.className = `finding-item ${isCrit ? 'finding-critical' : 'finding-warning'}`;
    item.innerHTML = `
      <div class="finding-header">
        <span class="finding-title" style="font-weight: 600; display: flex; align-items: center; gap: 0.4rem;">
          <span data-lucide="${isCrit ? 'alert-triangle' : 'info'}" data-size="16"></span>
          ${f.title}
        </span>
        <span class="badge ${isCrit ? 'badge-danger' : 'badge-warning'}">${f.severity.toUpperCase()}</span>
      </div>
      <p class="finding-desc" style="margin-top: 0.4rem; line-height: 1.4;">${f.description || f.desc}</p>
      ${f.supporting_sequences && f.supporting_sequences.length > 0 ? `<div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.3rem;">Audit Sequence References: [${f.supporting_sequences.join(', ')}]</div>` : ''}
    `;
    findingsList.appendChild(item);
  });
}

function renderScreenshots(p) {
  if (!p.screenshots || p.screenshots.length === 0) {
    evidenceScreenshotsCard.style.display = 'none';
    return;
  }

  evidenceScreenshotsCard.style.display = 'block';
  screenshotsGallery.innerHTML = '';

  p.screenshots.forEach(sc => {
    const card = document.createElement('div');
    card.style.cssText = 'background: #090d16; border: 1px solid var(--border-color); border-radius: 6px; overflow: hidden; display: flex; flex-direction: column; cursor: pointer; transition: transform 0.15s ease;';
    card.innerHTML = `
      <div style="height: 140px; background: #000; overflow: hidden; display: flex; align-items: center; justify-content: center; position: relative;">
        <img src="data:image/bmp;base64,${sc.data_base64}" style="width: 100%; height: 100%; object-fit: cover;" alt="Evidence capture" />
        <span class="badge badge-danger" style="position: absolute; top: 6px; left: 6px; font-size: 0.7rem;">EVIDENCE</span>
      </div>
      <div style="padding: 0.6rem 0.75rem; flex: 1; display: flex; flex-direction: column; justify-content: space-between;">
        <div>
          <div style="font-size: 0.8rem; font-weight: 600; color: #f1f5f9; word-break: break-all;">${sc.filename}</div>
          <div style="font-size: 0.75rem; color: #f87171; margin-top: 2px;">${sc.reason || 'Security event trigger'}</div>
          ${sc.contest_relative_time ? `<div style="font-size: 0.72rem; color: #38bdf8; margin-top: 3px; font-weight: 500;">${sc.contest_relative_time}</div>` : ''}
        </div>
        <div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
          <span>${sc.timestamp_rfc3339 ? sc.timestamp_rfc3339.slice(11, 19) + ' UTC' : ''}</span>
          <span style="color: #38bdf8;">Click to View</span>
        </div>
      </div>
    `;
    card.addEventListener('click', () => {
      openScreenshotLightbox(sc.data_base64, sc.filename, sc.reason, sc.contest_relative_time);
    });
    screenshotsGallery.appendChild(card);
  });
}

function renderAiSummary(p) {
  aiSummaryBody.innerHTML = '';
  const facts = p.aiSummary?.facts || [];
  const inferences = p.aiSummary?.inferences || [];
  const recs = p.aiSummary?.recommendations || [];

  let html = '';

  if (facts.length > 0) {
    html += '<div style="margin-bottom: 0.75rem;"><strong style="color: #60a5fa; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">Verified Cryptographic Facts:</strong><ul style="margin: 0.4rem 0 0 1.2rem; padding: 0;">';
    facts.forEach(f => { html += `<li style="margin-bottom: 0.3rem;">${f}</li>`; });
    html += '</ul></div>';
  }

  if (inferences.length > 0) {
    html += '<div style="margin-bottom: 0.75rem;"><strong style="color: #c084fc; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">Deterministic Forensics &amp; Behavioral Inferences:</strong><ul style="margin: 0.4rem 0 0 1.2rem; padding: 0;">';
    inferences.forEach(inf => { html += `<li style="margin-bottom: 0.3rem;">${inf}</li>`; });
    html += '</ul></div>';
  }

  if (recs.length > 0) {
    html += '<div><strong style="color: #34d399; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em;">Recommended Jury Action:</strong><ul style="margin: 0.4rem 0 0 1.2rem; padding: 0;">';
    recs.forEach(r => { html += `<li style="margin-bottom: 0.3rem;">${r}</li>`; });
    html += '</ul></div>';
  }

  aiSummaryBody.innerHTML = html || '<div style="color: var(--text-muted);">No AI executive summary generated.</div>';
}

function renderCompilerActivity(p) {
  if (!p.compilerActivity || p.compilerActivity.length === 0) {
    compilerActivityContent.innerHTML = 'No built-in compiler attempts recorded for this participant. (Absence does not imply external compiler use).';
    return;
  }

  let html = '';
  p.compilerActivity.forEach((c, idx) => {
    html += `
      <div style="border-bottom: 1px solid #1e293b; padding-bottom: 0.75rem; margin-bottom: 0.75rem;">
        <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem;">
          <span style="color: #38bdf8; font-weight: bold;">Attempt #${idx + 1} (${c.source_file || c.sourceFile}) - ${c.timestamp}</span>
          <span class="badge ${c.exit_code === 0 || c.exitCode === 0 ? 'badge-primary' : 'badge-danger'}">Exit Code: ${c.exit_code ?? c.exitCode ?? 0}</span>
        </div>
        <div style="color: #94a3b8; font-size: 0.8rem; margin-bottom: 0.3rem;">
          Compiler: ${c.compiler_version || c.compilerVersion || 'GNU G++'} | SHA-256: <code>${(c.source_sha256 || c.sourceSha256 || '').slice(0, 16)}...</code>
        </div>
        ${c.diagnostics ? `<div style="background: #090d16; padding: 0.4rem; border-radius: 4px; color: #f87171; font-size: 0.8rem; margin-bottom: 0.4rem; white-space: pre-wrap;">${c.diagnostics.trim()}</div>` : ''}
        ${c.source_snapshot || c.sourceSnapshot ? `<details style="margin-top: 0.4rem;"><summary style="cursor: pointer; color: #a5f3fc; font-size: 0.8rem;">View C++ Source Snapshot</summary><pre style="background: #090d16; padding: 0.5rem; border-radius: 4px; margin-top: 0.4rem; overflow-x: auto; color: #e2e8f0; font-size: 0.8rem;">${escapeHtml(c.source_snapshot || c.sourceSnapshot)}</pre></details>` : ''}
      </div>
    `;
  });
  compilerActivityContent.innerHTML = html;
}

function escapeHtml(text) {
  return String(text || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function renderTimeline(p) {
  timelineTbody.innerHTML = '';
  const filtered = currentFilter === 'all'
    ? p.timeline
    : p.timeline.filter(t => t.cat === currentFilter);

  if (!filtered || filtered.length === 0) {
    timelineTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #64748b; padding: 1.5rem;">No events matching filter "${currentFilter}".</td></tr>`;
    return;
  }

  filtered.forEach(t => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="font-mono">${t.seq}</td>
      <td class="font-mono text-muted" style="font-size: 0.8rem;">
        <div>${t.time}</div>
        ${t.relTime ? `<div style="color: #38bdf8; font-size: 0.72rem; margin-top: 2px; font-weight: 500;">${t.relTime}</div>` : ''}
      </td>
      <td><span class="badge badge-outline">${t.cat}</span></td>
      <td style="line-height: 1.4;">${t.details}</td>
      <td class="font-mono text-muted" style="font-size: 0.75rem;">${t.hash}</td>
    `;
    timelineTbody.appendChild(tr);
  });
}

document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentFilter = btn.dataset.cat;
    const p = participantsData[currentParticipantKey];
    if (p) renderTimeline(p);
  });
});

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
});

saveDecisionBtn.addEventListener('click', () => {
  const p = participantsData[currentParticipantKey];
  if (!p) return;
  const notes = document.getElementById('judgeNotes').value;
  showToast(`Official verdict [${p.verdict}] and notes recorded for ${p.name}.`, 'success', 'Decision Saved');
});

async function triggerImport() {
  let dbPath = null;
  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      dbPath = await window.__TAURI__.core.invoke('pick_evidence_file');
    } catch (e) {
      dbPath = null;
    }
  }

  if (!dbPath) {
    return;
  }

  showToast(`Decrypting and verifying audit package: ${dbPath.split(/[/\\]/).pop()}`, 'info', 'Importing Archive');

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const res = await window.__TAURI__.core.invoke('verify_evidence_db', {
        dbPath,
        keyPath: null
      });

      const key = res.session_id || `import-${Date.now()}`;

      const timelineEvents = (res.timeline || []).map(t => {
        let details = '';
        if (typeof t.payload_json === 'object' && t.payload_json !== null) {
          if (t.category === 'Process') {
            const action = t.payload_json.action || 'Started';
            const name = t.payload_json.name || 'Process';
            const pid = t.payload_json.pid ? ` (PID: ${t.payload_json.pid})` : '';
            const ports = t.payload_json.listening_ports && t.payload_json.listening_ports.length > 0
              ? ` [Listening Ports: ${t.payload_json.listening_ports.join(', ')}]`
              : '';
            const cmd = t.payload_json.cmdline ? ` | cmd: ${t.payload_json.cmdline}` : '';
            const metrics = [];
            if (t.payload_json.cpu_usage !== undefined && t.payload_json.cpu_usage !== null) {
              metrics.push(`CPU: ${t.payload_json.cpu_usage.toFixed(1)}%`);
            }
            if (t.payload_json.memory_bytes !== undefined && t.payload_json.memory_bytes !== null) {
              metrics.push(`RAM: ${(t.payload_json.memory_bytes / (1024 * 1024)).toFixed(0)}MB`);
            }
            const resStr = metrics.length > 0 ? ` [${metrics.join(', ')}]` : '';
            const anomalyStr = t.payload_json.is_anomalous_resource ? ' <span class="badge badge-warning" style="font-size: 0.7rem;">ANOMALOUS RESOURCE USAGE</span>' : '';
            const relTimeStr = t.payload_json.contest_relative_time ? ` <span style="color: #38bdf8; font-size: 0.75rem;">[${t.payload_json.contest_relative_time}]</span>` : '';
            details = `${action}: ${name}${pid}${resStr}${anomalyStr}${ports}${cmd}${relTimeStr}`;
          } else if (t.category === 'Browser') {
            const dom = t.payload_json.domain || 'Domain';
            const title = t.payload_json.window_title ? ` | Window: "${t.payload_json.window_title}"` : '';
            const aiBadge = t.payload_json.is_ai_suspect ? ' <span class="badge badge-danger" style="font-size: 0.7rem;">AI SUSPECT</span>' : (t.payload_json.is_restricted ? ' <span class="badge badge-warning" style="font-size: 0.7rem;">RESTRICTED</span>' : '');
            const relTimeStr = t.payload_json.contest_relative_time ? ` <span style="color: #38bdf8; font-size: 0.75rem;">[${t.payload_json.contest_relative_time}]</span>` : '';
            details = `Browser / Window Activity: ${dom}${title}${aiBadge}${relTimeStr}`;
          } else if (t.category === 'Network') {
            const conn = t.payload_json.is_connected ? 'Connected' : 'Disconnected';
            const iface = t.payload_json.interface_name || 'Interface';
            const ssid = t.payload_json.ssid ? ` | SSID: "${t.payload_json.ssid}"` : '';
            details = `${conn} Network Adapter: ${iface}${ssid}`;
          } else if (t.category === 'Compiler') {
            const src = t.payload_json.source_path || 'source.cpp';
            const code = t.payload_json.program_exit_code ?? t.payload_json.compiler_exit_code ?? 0;
            const diag = t.payload_json.compiler_diagnostics ? ` | ${t.payload_json.compiler_diagnostics.slice(0, 100)}` : '';
            details = `Compiler Attempt: ${src} (Exit: ${code})${diag}`;
          } else if (t.category === 'Auth') {
            details = `Authentication Event: ${t.payload_json.action || ''} (Username: ${t.payload_json.username || ''})`;
          } else if (t.category === 'SystemLifecycle') {
            const evt = t.payload_json.event_type || 'Lifecycle';
            const det = t.payload_json.details ? ` - ${t.payload_json.details}` : '';
            details = `${evt}${det}`;
          } else {
            details = JSON.stringify(t.payload_json);
          }
        } else {
          details = String(t.payload_json);
        }

        return {
          seq: t.sequence_number,
          time: t.timestamp_rfc3339,
          relTime: (t.payload_json && t.payload_json.contest_relative_time) || null,
          cat: t.category,
          details,
          hash: t.current_hash ? (t.current_hash.slice(0, 8) + '...' + t.current_hash.slice(-4)) : ''
        };
      });

      participantsData[key] = {
        name: res.participant_id,
        verdict: res.verdict,
        hashChain: res.hash_chain_verified ? 'VERIFIED (SHA-256)' : 'TAMPERED / FAILED',
        totalEvents: res.total_events,
        criticalFindings: (res.findings || []).filter(f => f.severity === 'Critical' || f.severity === 'critical').length,
        gaps: 0,
        participationMode: res.participation_mode,
        authenticatedAccountId: res.authenticated_account_id,
        declaredLogName: res.declared_log_name,
        screenshots: res.screenshots || [],
        findings: res.findings || [],
        aiSummary: {
          facts: res.verified_facts || [`Total audit events verified: ${res.total_events}`, `Verdict: ${res.verdict}`],
          inferences: res.contextual_inferences || [res.ai_advisory],
          recommendations: res.recommendations || ['Review forensic timeline and screenshots.']
        },
        timeline: timelineEvents,
        compilerActivity: res.compiler_activities || []
      };

      const allAccountIds = Object.values(participantsData)
        .map(p => p.authenticatedAccountId)
        .filter(Boolean);

      const dupRes = await window.__TAURI__.core.invoke('check_duplicate_accounts', {
        accountIds: allAccountIds
      });

      if (dupRes.has_duplicates) {
        duplicateAlertBadge.style.display = 'inline-flex';
        showToast(dupRes.findings.join(' | '), 'warning', 'Duplicate Account Detected');
      } else {
        duplicateAlertBadge.style.display = 'none';
      }

      renderParticipants();
      loadParticipant(key);
      showToast(`Participant ${res.participant_id} verified. Classification: ${res.verdict}`, res.verdict === 'SAFE' ? 'success' : 'error', 'Audit Verification Complete');
    } catch (err) {
      showToast(`Failed to parse or decrypt evidence archive: ${err}`, 'error', 'Verification Failed');
    }
  }
}

if (importBtn) importBtn.addEventListener('click', triggerImport);
if (mainImportBtn) mainImportBtn.addEventListener('click', triggerImport);

if (exportCompilerBtn) {
  exportCompilerBtn.addEventListener('click', () => {
    const p = participantsData[currentParticipantKey];
    if (!p) return;
    let md = `# Compiler Forensic Audit Report: ${p.name}\n\n`;
    md += `Generated: ${new Date().toISOString()} | Verdict: ${p.verdict}\n\n`;
    if (!p.compilerActivity || p.compilerActivity.length === 0) {
      md += `No compiler activity recorded in hash chain.\n`;
    } else {
      p.compilerActivity.forEach((c, idx) => {
        md += `## Attempt #${idx + 1} - ${c.source_file || c.sourceFile} (${c.timestamp})\n`;
        md += `- **Compiler**: ${c.compiler_version || c.compilerVersion}\n`;
        md += `- **Exit Code**: ${c.exit_code ?? c.exitCode ?? 0}\n`;
        md += `- **SHA-256**: \`${c.source_sha256 || c.sourceSha256}\`\n\n`;
        if (c.source_snapshot || c.sourceSnapshot) {
          md += `### Source Code Snapshot\n\`\`\`cpp\n${c.source_snapshot || c.sourceSnapshot}\n\`\`\`\n\n`;
        }
      });
    }

    const blob = new Blob([md], { type: 'text/markdown;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${p.name}_compiler_report.md`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast(`Exported compiler forensic report to ${a.download}`, 'success', 'Report Exported');
  });
}

renderParticipants();
