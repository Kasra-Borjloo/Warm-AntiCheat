// Mock participants dataset for Judge Verifier UI
const participantsData = {
  'team-42': {
    name: 'Team 42 (Alice & Bob)',
    verdict: 'SAFE',
    hashChain: 'VERIFIED (SHA-256)',
    totalEvents: 142,
    criticalFindings: 0,
    gaps: 0,
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
      { seq: 1, time: '2026-11-07T09:00:00Z', cat: 'SystemLifecycle', details: 'ApplicationLaunch: Warm-AntiCheat v0.1.0 on Windows', hash: 'e291...3a1' },
      { seq: 2, time: '2026-11-07T09:00:05Z', cat: 'Network', details: 'Connected to WiFi: "Sharif-Guest" (Interface: wlan0)', hash: 'a149...8c2' },
      { seq: 3, time: '2026-11-07T09:00:15Z', cat: 'SystemLifecycle', details: 'Heartbeat tick #1 (All monitors operational)', hash: '9b04...5f7' },
      { seq: 4, time: '2026-11-07T09:00:20Z', cat: 'Process', details: 'Process started: code.exe (PID: 4120)', hash: '4cb1...210' },
      { seq: 5, time: '2026-11-07T09:00:30Z', cat: 'Process', details: 'Process started: rustc.exe (PID: 5192)', hash: 'f782...aa4' },
      { seq: 6, time: '2026-11-07T09:15:20Z', cat: 'Compiler', details: 'Built-in C++23 Compilation: solution.cpp (Success, Exit: 0)', hash: 'c901...4d8' }
    ],
    compilerActivity: [
      {
        timestamp: '2026-11-07T09:15:20Z',
        sourceFile: 'solution.cpp',
        sourceSha256: '8e82110c4d2d48348bb95b05615d6c8b9db77b3b429d20c5c366ff1239847e12',
        compilerVersion: 'GNU G++ 16.2.0 (C++23)',
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
        'Hash chain cryptographic integrity status: INTACT',
        'CRITICAL FINDING: Prohibited application "ollama.exe" (PID: 8840) launched at sequence 44 (2026-11-07T10:15:32Z)'
      ],
      inferences: [
        'High probability of unauthorized local LLM code generation. The process was executed for 14 minutes before being manually terminated.'
      ],
      recommendations: [
        'Escalate to Lead Jury for official disqualification review and participant interview.'
      ]
    },
    timeline: [
      { seq: 42, time: '2026-11-07T10:14:00Z', cat: 'SystemLifecycle', details: 'Heartbeat tick #38', hash: 'c901...33d' },
      { seq: 43, time: '2026-11-07T10:15:00Z', cat: 'Process', details: 'Process started: cmd.exe (PID: 8812)', hash: 'bb82...19a' },
      { seq: 44, time: '2026-11-07T10:15:32Z', cat: 'Process', details: 'PROHIBITED: Process started: ollama.exe (PID: 8840)', hash: 'dd14...780' },
      { seq: 45, time: '2026-11-07T10:29:45Z', cat: 'Process', details: 'Process terminated: ollama.exe (PID: 8840)', hash: '517a...b8c' }
    ]
  },
  'team-07': {
    name: 'Team 07 (Dave)',
    verdict: 'REVIEW REQUIRED',
    hashChain: 'ANOMALY DETECTED',
    totalEvents: 45,
    criticalFindings: 0,
    gaps: 1,
    findings: [
      {
        severity: 'warning',
        title: 'Monitoring Interruption / Sleep Gap',
        desc: 'Unexplained time gap of 420s (7 minutes) detected between sequence 21 and 22.',
        seqs: [21, 22],
        time: '2026-11-07T09:45:10Z'
      }
    ],
    aiSummary: {
      facts: [
        'Total audit events verified in SHA-256 hash chain: 45',
        'Hash chain cryptographic integrity status: INTACT, but has unexplained 7-minute monitoring gap'
      ],
      inferences: [
        'Device may have gone into sleep mode or monitoring process was suspended. Verification required from proctor desk.'
      ],
      recommendations: [
        'Conduct physical proctor inquiry regarding the observed 7-minute timeline gap.'
      ]
    },
    timeline: [
      { seq: 20, time: '2026-11-07T09:37:00Z', cat: 'SystemLifecycle', details: 'Heartbeat tick #20', hash: '88a1...12c' },
      { seq: 21, time: '2026-11-07T09:38:00Z', cat: 'SystemLifecycle', details: 'SleepDetected: Device suspended / gap starts', hash: '33e1...78b' },
      { seq: 22, time: '2026-11-07T09:45:00Z', cat: 'SystemLifecycle', details: 'WakeDetected: Monitoring resumed after 420s', hash: 'ff02...99a' }
    ]
  }
};

let currentParticipantKey = 'team-42';
let currentCategoryFilter = 'all';

// DOM references
const participantsList = document.getElementById('participantsList');
const selectedParticipantTitle = document.getElementById('selectedParticipantTitle');
const verdictBanner = document.getElementById('verdictBanner');
const verdictPill = document.getElementById('verdictPill');
const inspectorContent = document.getElementById('inspectorContent');
const statHashChain = document.getElementById('statHashChain');
const statTotalEvents = document.getElementById('statTotalEvents');
const statCriticalFindings = document.getElementById('statCriticalFindings');
const statGaps = document.getElementById('statGaps');
const findingsList = document.getElementById('findingsList');
const aiSummaryBody = document.getElementById('aiSummaryBody');
const timelineTbody = document.getElementById('timelineTbody');
const themeToggle = document.getElementById('themeToggle');

function renderParticipants() {
  participantsList.innerHTML = '';
  Object.keys(participantsData).forEach(key => {
    const p = participantsData[key];
    const item = document.createElement('div');
    item.className = `participant-item ${key === currentParticipantKey ? 'active' : ''}`;
    item.dataset.key = key;

    let pillClass = 'pill-safe';
    if (p.verdict === 'UNSAFE') pillClass = 'pill-unsafe';
    if (p.verdict === 'REVIEW REQUIRED') pillClass = 'pill-review';

    item.innerHTML = `
      <span class="p-name">${p.name}</span>
      <span class="p-pill ${pillClass}">${p.verdict}</span>
    `;

    item.addEventListener('click', () => {
      currentParticipantKey = key;
      renderParticipants();
      loadParticipant(key);
    });

    participantsList.appendChild(item);
  });
}

function loadParticipant(key) {
  const p = participantsData[key];
  if (!p) return;

  inspectorContent.style.display = 'block';
  verdictBanner.style.display = 'block';
  selectedParticipantTitle.textContent = p.name;

  // Verdict pill
  verdictPill.textContent = p.verdict;
  verdictPill.className = 'verdict-pill';
  if (p.verdict === 'SAFE') verdictPill.classList.add('pill-safe');
  else if (p.verdict === 'UNSAFE') verdictPill.classList.add('pill-unsafe');
  else verdictPill.classList.add('pill-review');

  // Stats
  statHashChain.textContent = p.hashChain;
  statTotalEvents.textContent = p.totalEvents;
  statCriticalFindings.textContent = p.criticalFindings;
  statGaps.textContent = p.gaps;

  // Findings
  findingsList.innerHTML = '';
  if (p.findings.length === 0) {
    findingsList.innerHTML = '<p class="text-secondary" style="font-size: 13px;">No critical or warning findings observed.</p>';
  } else {
    p.findings.forEach(f => {
      const item = document.createElement('div');
      item.className = `finding-item finding-${f.severity}`;
      item.innerHTML = `
        <div class="finding-title">${f.title}</div>
        <div class="finding-desc">${f.desc} (Seqs: ${f.seqs.join(', ')})</div>
      `;
      findingsList.appendChild(item);
    });
  }

  // AI Advisory Body
  aiSummaryBody.innerHTML = `
    <div class="ai-section">
      <strong>Verified Cryptographic Facts:</strong>
      <ul>${p.aiSummary.facts.map(f => `<li>${f}</li>`).join('')}</ul>
    </div>
    <div class="ai-section">
      <strong>Contextual Inferences:</strong>
      <ul>${p.aiSummary.inferences.map(i => `<li>${i}</li>`).join('')}</ul>
    </div>
    <div class="ai-section">
      <strong>Recommended Jury Action:</strong>
      <ul>${p.aiSummary.recommendations.map(r => `<li>${r}</li>`).join('')}</ul>
    </div>
  `;

  // Compiler Activity Box
  const compBox = document.getElementById('compilerActivityContent');
  if (compBox) {
    if (p.compilerActivity && p.compilerActivity.length > 0) {
      compBox.innerHTML = p.compilerActivity.map(c => `
        <div style="border-bottom: 1px solid #1e293b; padding-bottom: 0.75rem; margin-bottom: 0.75rem;">
          <div style="display: flex; justify-content: space-between; color: #38bdf8; margin-bottom: 0.25rem;">
            <span><strong>Source:</strong> ${c.sourceFile} (SHA-256: ${c.sourceSha256.substring(0, 16)}...)</span>
            <span>${c.timestamp}</span>
          </div>
          <div><strong>Compiler:</strong> ${c.compilerVersion} | <strong>Args:</strong> ${c.compilationArgs.join(' ')}</div>
          <div><strong>Diagnostics:</strong> ${c.diagnostics}</div>
          ${c.executableHash ? `<div><strong>Binary Hash:</strong> ${c.executableHash.substring(0, 16)}... | <strong>Exit Code:</strong> ${c.exitCode}</div>` : ''}
          ${c.stdout ? `<div style="margin-top: 0.25rem; color: #4ade80;"><strong>Stdout:</strong> ${c.stdout}</div>` : ''}
          <details style="margin-top: 0.5rem; cursor: pointer;">
            <summary style="color: #94a3b8;">View Submitted Source Snapshot</summary>
            <pre style="background: #0f172a; padding: 0.5rem; border-radius: 4px; margin-top: 0.25rem; color: #f8fafc; font-size: 0.85rem;">${c.sourceSnapshot}</pre>
          </details>
        </div>
      `).join('');
    } else {
      compBox.innerHTML = `<span style="color: #64748b;">No built-in compiler attempts recorded for this participant. (Note: Absence does not indicate external compiler use).</span>`;
    }
  }

  renderTimeline(p.timeline);
}

function renderTimeline(timeline) {
  timelineTbody.innerHTML = '';
  const filtered = currentCategoryFilter === 'all'
    ? timeline
    : timeline.filter(t => t.cat === currentCategoryFilter);

  filtered.forEach(row => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>#${row.seq}</td>
      <td class="font-mono">${row.time}</td>
      <td><strong>${row.cat}</strong></td>
      <td>${row.details}</td>
      <td class="hash-cell">${row.hash}</td>
    `;
    timelineTbody.appendChild(tr);
  });
}

// Filter buttons
document.querySelectorAll('.filter-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    currentCategoryFilter = btn.dataset.cat;
    renderTimeline(participantsData[currentParticipantKey].timeline);
  });
});

// Theme toggle
themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
});

// Import Button
const importBtn = document.getElementById('importBtn');
if (importBtn) {
  importBtn.addEventListener('click', async () => {
    const dbPath = prompt('Enter path to participant evidence SQLite file:', './participant_audit.sqlite');
    if (!dbPath) return;

    if (window.__TAURI__ && window.__TAURI__.core) {
      try {
        const res = await window.__TAURI__.core.invoke('verify_evidence_db', { dbPath: dbPath, keyPath: null });
        const newKey = `import-${Date.now()}`;
        participantsData[newKey] = {
          name: `Imported (${res.participant_id})`,
          verdict: res.verdict,
          hashChain: 'VERIFIED (SHA-256)',
          totalEvents: res.total_events,
          criticalFindings: res.violations.length,
          gaps: 0,
          findings: res.violations.map(v => ({ severity: 'critical', title: 'Security Finding', desc: v, seqs: [1], time: new Date().toISOString() })),
          aiSummary: {
            facts: [`Total audit events: ${res.total_events}`, `Verdict: ${res.verdict}`],
            inferences: [res.ai_advisory],
            recommendations: ['Review timeline logs below.']
          },
          timeline: [
            { seq: 1, time: new Date().toISOString(), cat: 'AuditReport', details: res.summary_text, hash: 'verified...ok' }
          ]
        };
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

// Export Compiler Report
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

// Init
renderParticipants();
loadParticipant(currentParticipantKey);
