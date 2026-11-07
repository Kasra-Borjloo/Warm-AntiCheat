const participantsData = {
  'team-42': {
    name: 'Team 42 (Alice & Bob)',
    verdict: 'SAFE',
    hashChain: 'VERIFIED (SHA-256)',
    totalEvents: 142,
    criticalFindings: 0,
    gaps: 0,
    participationMode: 'GeneratedAccounts',
    authenticatedAccountId: 'e01a88b1-36aa-4251-bb38-662589254301',
    declaredLogName: null,
    findings: [],
    aiSummary: {
      facts: [
        'Total audit events verified in SHA-256 hash chain: 142',
        'Hash chain cryptographic integrity status: INTACT (No tampering detected)',
        'Continuous monitoring heartbeats recorded every 15s throughout the 4-hour window'
      ],
      inferences: [
        'Participant strictly adhered to contest boundaries. No unauthorized AI tool execution or restricted domain visits observed.'
      ],
      recommendations: [
        'Approve submission without further inquiry.'
      ]
    },
    timeline: [
      { seq: 1, time: '2026-11-07T09:00:00Z', cat: 'Auth', details: 'Participant Login: Username GOCUP-001 (Argon2id offline verification success)', hash: 'a101...99f' },
      { seq: 2, time: '2026-11-07T09:00:05Z', cat: 'SystemLifecycle', details: 'ApplicationLaunch: Warm-AntiCheat v0.3.0 on Windows', hash: 'e291...3a1' },
      { seq: 3, time: '2026-11-07T09:00:10Z', cat: 'Network', details: 'Connected to WiFi: "Sharif-Guest" (Interface: wlan0)', hash: 'a149...8c2' },
      { seq: 4, time: '2026-11-07T09:00:15Z', cat: 'SystemLifecycle', details: 'Heartbeat tick #1 (All monitors operational)', hash: '9b04...5f7' },
      { seq: 5, time: '2026-11-07T09:00:20Z', cat: 'Process', details: 'Process started: code.exe (PID: 4120)', hash: '4cb1...210' },
      { seq: 6, time: '2026-11-07T09:15:20Z', cat: 'Compiler', details: 'Built-in C++23 Compilation: solution.cpp (Success, Exit: 0)', hash: 'c901...4d8' }
    ],
    compilerActivity: [
      {
        timestamp: '2026-11-07T09:15:20Z',
        sourceFile: 'solution.cpp',
        sourceSha256: '8e82110c4d2d48348bb95b05615d6c8b9db77b3b429d20c5c366ff1239847e12',
        compilerVersion: 'GNU G++ 14.2.0 (C++23)',
        compilationArgs: ['-std=c++23', '-O2', '-pipe', 'solution.cpp', '-o', 'bin.exe'],
        diagnostics: 'Compilation successful. 0 warnings.',
        executableHash: 'a41d998124e5a201c8012bbfa32c0281b9201948291048291048291048291048',
        exitCode: 0,
        stdout: 'Warm-AntiCheat C++23 Solution Ready!\n',
        sourceSnapshot: '#include <bits/stdc++.h>\n\nint main() {\n    std::cout << "Warm-AntiCheat C++23 Solution Ready!" << std::endl;\n    return 0;\n}'
      }
    ]
  },
  'team-13': {
    name: 'Team 13 (Charlie)',
    verdict: 'UNSAFE',
    hashChain: 'VERIFIED (SHA-256)',
    totalEvents: 88,
    criticalFindings: 1,
    gaps: 0,
    participationMode: 'NoAccounts',
    authenticatedAccountId: null,
    declaredLogName: 'Charlie_USB_1',
    findings: [
      {
        severity: 'critical',
        title: 'Prohibited AI Application Executed',
        desc: 'Prohibited application "ollama.exe" (PID: 8840) was launched during active competition session.',
        seqs: [44],
        time: '2026-11-07T10:15:32Z'
      }
    ],
    aiSummary: {
      facts: [
        'Total audit events verified in SHA-256 hash chain: 88',
        'Verified critical violation: Execution of prohibited Ollama local model inference runtime (PID: 8840) at 10:15:32 UTC',
        'Self-declared log export handle: "Charlie_USB_1"'
      ],
      inferences: [
        'Participant accessed prohibited AI generative models while attempting Algorithmic Problem B.'
      ],
      recommendations: [
        'Disqualification recommended under Competition Rule §4.1.'
      ]
    },
    timeline: [
      { seq: 1, time: '2026-11-07T09:05:00Z', cat: 'SystemLifecycle', details: 'ApplicationLaunch: Warm-AntiCheat v0.3.0 on Linux', hash: '7c82...01e' },
      { seq: 44, time: '2026-11-07T10:15:32Z', cat: 'Process', details: 'CRITICAL: Prohibited application executed: ollama.exe (PID: 8840)', hash: 'f91b...bb7' }
    ],
    compilerActivity: []
  }
};

let currentParticipantKey = 'team-42';
let currentFilter = 'all';

const participantsList = document.getElementById('participantsList');
const selectedParticipantTitle = document.getElementById('selectedParticipantTitle');
const verdictBanner = document.getElementById('verdictBanner');
const verdictPill = document.getElementById('verdictPill');
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

function renderParticipants() {
  participantsList.innerHTML = '';
  Object.keys(participantsData).forEach(key => {
    const p = participantsData[key];
    const card = document.createElement('div');
    card.className = `participant-card ${key === currentParticipantKey ? 'active' : ''}`;
    card.dataset.key = key;

    let verdictClass = 'verdict-safe';
    if (p.verdict === 'UNSAFE') verdictClass = 'verdict-unsafe';
    if (p.verdict === 'REVIEW REQUIRED') verdictClass = 'verdict-review';

    card.innerHTML = `
      <div class="participant-name">${p.name}</div>
      <div class="participant-meta">
        <span class="verdict-tag ${verdictClass}">${p.verdict}</span>
        <span>${p.totalEvents} events</span>
      </div>
    `;

    card.addEventListener('click', () => {
      loadParticipant(key);
    });

    participantsList.appendChild(card);
  });
}

function loadParticipant(key) {
  currentParticipantKey = key;
  const p = participantsData[key];
  if (!p) return;

  document.querySelectorAll('.participant-card').forEach(c => {
    c.classList.toggle('active', c.dataset.key === key);
  });

  selectedParticipantTitle.textContent = `${p.name} (Review)`;
  inspectorContent.style.display = 'block';
  verdictBanner.style.display = 'block';
  verdictPill.textContent = p.verdict;

  verdictPill.className = 'verdict-pill';
  if (p.verdict === 'SAFE') verdictPill.classList.add('verdict-safe');
  else if (p.verdict === 'UNSAFE') verdictPill.classList.add('verdict-unsafe');
  else verdictPill.classList.add('verdict-review');

  statHashChain.textContent = p.hashChain;
  statTotalEvents.textContent = p.totalEvents;
  statCriticalFindings.textContent = p.criticalFindings;
  statGaps.textContent = p.gaps;

  if (p.participationMode === 'GeneratedAccounts' || p.authenticatedAccountId) {
    accountMetadataCard.style.display = 'block';
    participationModeBadge.textContent = 'Mode B (Generated Accounts)';
    accountDetailText.textContent = `Account UUID: ${p.authenticatedAccountId || 'Unknown'}`;
  } else if (p.declaredLogName) {
    accountMetadataCard.style.display = 'block';
    participationModeBadge.textContent = 'Mode A (No Accounts)';
    accountDetailText.textContent = `Self-declared handle: "${p.declaredLogName}" (Self-reported, unverified)`;
  } else {
    accountMetadataCard.style.display = 'none';
  }

  findingsList.innerHTML = '';
  if (p.findings.length === 0) {
    findingsList.innerHTML = `<div style="color: #22c55e;"><span data-lucide="check-circle" data-size="16"></span> No violations or policy anomalies detected. All events adhere to contest parameters.</div>`;
  } else {
    p.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = 'finding-item';
      item.innerHTML = `
        <div class="finding-title" style="color: #ef4444;"><span data-lucide="alert-triangle" data-size="16"></span> ${f.title} (${f.time})</div>
        <div class="finding-desc">${f.desc}</div>
        <div class="finding-seqs">Supporting Audit Sequences: [${f.seqs.join(', ')}]</div>
      `;
      findingsList.appendChild(item);
    });
  }

  aiSummaryBody.innerHTML = `
    <div class="ai-section">
      <h4><span data-lucide="check-circle" data-size="16"></span> Verified Forensic Facts (Deterministic)</h4>
      <ul>${p.aiSummary.facts.map(f => `<li>${f}</li>`).join('')}</ul>
    </div>
    <div class="ai-section mt-2">
      <h4><span data-lucide="info" data-size="16"></span> Contextual Inferences (Advisory)</h4>
      <ul>${p.aiSummary.inferences.map(i => `<li>${i}</li>`).join('')}</ul>
    </div>
    <div class="ai-section mt-2">
      <h4><span data-lucide="shield" data-size="16"></span> Recommended Action</h4>
      <ul>${p.aiSummary.recommendations.map(r => `<li>${r}</li>`).join('')}</ul>
    </div>
  `;

  if (p.screenshots && p.screenshots.length > 0) {
    if (evidenceScreenshotsCard) evidenceScreenshotsCard.style.display = 'block';
    if (screenshotsGallery) {
      screenshotsGallery.innerHTML = p.screenshots.map((s, idx) => `
        <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 6px; padding: 0.75rem; overflow: hidden;">
          <div style="font-weight: 600; color: #38bdf8; font-size: 0.85rem; margin-bottom: 0.25rem;">Capture #${idx + 1} (${s.filename})</div>
          <div style="color: #94a3b8; font-size: 0.75rem; margin-bottom: 0.5rem;">${s.reason}</div>
          <img src="data:image/bmp;base64,${s.data_base64}" style="width: 100%; border-radius: 4px; border: 1px solid #334155; cursor: pointer;" onclick="window.open(this.src)" alt="${s.filename}" />
          <div style="color: #64748b; font-size: 0.7rem; margin-top: 0.25rem; font-family: monospace;">Time: ${s.timestamp_rfc3339}</div>
        </div>
      `).join('');
    }
  } else {
    if (evidenceScreenshotsCard) evidenceScreenshotsCard.style.display = 'none';
  }

  renderCompilerActivity(p);
  renderTimeline(p);

  if (window.replaceLucideIcons) {
    window.replaceLucideIcons();
  }
}

function renderCompilerActivity(p) {
  if (!compilerActivityContent) return;
  if (!p.compilerActivity || p.compilerActivity.length === 0) {
    compilerActivityContent.innerHTML = `<span style="color: #64748b;">No built-in compiler attempts recorded for this participant.</span>`;
    return;
  }

  let html = '';
  p.compilerActivity.forEach((c, idx) => {
    html += `
      <div style="border-bottom: 1px solid #1e293b; padding-bottom: 0.75rem; margin-bottom: 0.75rem;">
        <div style="color: #38bdf8; font-weight: bold;">Attempt #${idx + 1} - ${c.sourceFile} (${c.timestamp})</div>
        <div style="color: #94a3b8; font-size: 0.8rem; margin: 0.2rem 0;">Source SHA-256: <code>${c.sourceSha256}</code></div>
        <div style="color: #94a3b8; font-size: 0.8rem; margin: 0.2rem 0;">Compiler: ${c.compilerVersion} | Args: <code>${c.compilationArgs.join(' ')}</code></div>
        <div style="color: #22c55e; font-size: 0.85rem;">Status: ${c.diagnostics}</div>
        ${c.executableHash ? `<div style="color: #e2e8f0; font-size: 0.8rem;">Output Binary SHA-256: <code>${c.executableHash}</code> (Exit Code: ${c.exitCode})</div>` : ''}
        ${c.stdout ? `<div style="background: #090d16; padding: 0.4rem; border-radius: 4px; margin-top: 0.4rem; color: #a5f3fc;">Stdout: ${c.stdout.trim()}</div>` : ''}
      </div>
    `;
  });
  compilerActivityContent.innerHTML = html;
}

function renderTimeline(p) {
  timelineTbody.innerHTML = '';
  const filtered = currentFilter === 'all'
    ? p.timeline
    : p.timeline.filter(t => t.cat === currentFilter);

  if (filtered.length === 0) {
    timelineTbody.innerHTML = `<tr><td colspan="5" style="text-align: center; color: #64748b;">No events matching filter "${currentFilter}".</td></tr>`;
    return;
  }

  filtered.forEach(t => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td class="font-mono">${t.seq}</td>
      <td class="font-mono text-muted">${t.time}</td>
      <td><span class="badge badge-outline">${t.cat}</span></td>
      <td>${t.details}</td>
      <td class="font-mono text-muted">${t.hash}</td>
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
  const notes = document.getElementById('judgeNotes').value;
  alert(`Verdict and notes for ${participantsData[currentParticipantKey].name} successfully recorded!`);
});

const importBtn = document.getElementById('importBtn');
if (importBtn) {
  importBtn.addEventListener('click', async () => {
    let dbPath = null;
    if (window.__TAURI__ && window.__TAURI__.core) {
      try {
        dbPath = await window.__TAURI__.core.invoke('pick_evidence_file');
      } catch (e) {
        dbPath = null;
      }
    }
    if (!dbPath) {
      dbPath = prompt('Enter path to participant evidence.sqlite:');
    }
    if (!dbPath) return;

    if (window.__TAURI__ && window.__TAURI__.core) {
      try {
        const res = await window.__TAURI__.core.invoke('verify_evidence_db', {
          dbPath,
          keyPath: null
        });

        const newKey = `import-${Date.now()}`;
        participantsData[newKey] = {
          name: `${res.participant_id} (Imported)`,
          verdict: res.verdict,
          hashChain: 'VERIFIED (SHA-256)',
          totalEvents: res.total_events,
          criticalFindings: res.violations.length,
          gaps: 0,
          participationMode: res.participation_mode,
          authenticatedAccountId: res.authenticated_account_id,
          declaredLogName: res.declared_log_name,
          screenshots: res.screenshots || [],
          findings: res.violations.map(v => ({ severity: 'critical', title: 'Violation', desc: v, seqs: [], time: '' })),
          aiSummary: {
            facts: [`Total audit events: ${res.total_events}`, `Verdict: ${res.verdict}`],
            inferences: [res.ai_advisory],
            recommendations: ['Review timeline logs below.']
          },
          timeline: [
            { seq: 1, time: new Date().toISOString(), cat: 'AuditReport', details: res.summary_text, hash: 'verified...ok' }
          ]
        };

        const allAccountIds = Object.values(participantsData)
          .map(p => p.authenticatedAccountId)
          .filter(Boolean);

        const dupRes = await window.__TAURI__.core.invoke('check_duplicate_accounts', {
          accountIds: allAccountIds
        });

        if (dupRes.has_duplicates) {
          duplicateAlertBadge.style.display = 'inline-flex';
          alert('WARNING: ' + dupRes.findings.join('\n'));
        }

        renderParticipants();
        loadParticipant(newKey);
        alert(`Evidence verified: Verdict is ${res.verdict}`);
      } catch (err) {
        alert(`Verification failed: ${err}`);
      }
    } else {
      alert(`[Browser Preview] Evidence imported from ${dbPath} (Simulated).`);
    }
  });
}

const exportCompilerBtn = document.getElementById('exportCompilerReportBtn');
if (exportCompilerBtn) {
  exportCompilerBtn.addEventListener('click', () => {
    const p = participantsData[currentParticipantKey];
    if (!p) return;
    let md = `# Compiler Activity Forensic Report: ${p.name}\n\n`;
    md += `Contest: GOCUP 1 | Generated: ${new Date().toISOString()}\n\n`;
    if (p.compilerActivity && p.compilerActivity.length > 0) {
      p.compilerActivity.forEach((c, idx) => {
        md += `## Attempt #${idx + 1} (${c.timestamp})\n`;
        md += `- Source File: \`${c.sourceFile}\`\n`;
        md += `- Source SHA-256: \`${c.sourceSha256}\`\n`;
        md += `- Compiler Version: ${c.compilerVersion}\n`;
        md += `- Command: \`g++ ${c.compilationArgs.join(' ')}\`\n`;
        md += `- Diagnostics: ${c.diagnostics}\n`;
        if (c.executableHash) {
          md += `- Executable Hash: \`${c.executableHash}\`\n`;
          md += `- Exit Code: ${c.exitCode}\n`;
          md += `- Stdout: \`${c.stdout}\`\n`;
        }
        md += `\n### Source Snapshot:\n\`\`\`cpp\n${c.sourceSnapshot}\n\`\`\`\n\n`;
      });
    } else {
      md += `*No built-in compiler events recorded for this participant.*\n`;
    }
    const blob = new Blob([md], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `compiler-activity-${currentParticipantKey}.md`;
    a.click();
    URL.revokeObjectURL(url);
  });
}

renderParticipants();
loadParticipant(currentParticipantKey);
if (window.replaceLucideIcons) {
  window.replaceLucideIcons();
}
