const state = {
  currentStep: 1,
  contestUuid: '550e8400-e29b-41d4-a716-446655440000',
  prohibitedApps: [
    'ollama', 'ollama.exe', 'ollama_llama_server.exe',
    'lmstudio', 'lmstudio.exe', 'lm-studio',
    'llama-cli', 'llama-cli.exe', 'llama-server',
    'text-generation-webui', 'jan.exe', 'gpt4all'
  ],
  restrictedDomains: [
    'chatgpt.com', 'openai.com', 'claude.ai',
    'anthropic.com', 'gemini.google.com',
    'copilot.microsoft.com', 'perplexity.ai', 'deepseek.com'
  ],
  generatedCsv: '',
  generatedHtml: ''
};

const contestTitleInput = document.getElementById('contestTitle');
const contestIdInput = document.getElementById('contestId');
const appsContainer = document.getElementById('appsContainer');
const newAppInput = document.getElementById('newAppInput');
const addAppBtn = document.getElementById('addAppBtn');
const domainsContainer = document.getElementById('domainsContainer');
const newDomainInput = document.getElementById('newDomainInput');
const addDomainBtn = document.getElementById('addDomainBtn');
const themeToggle = document.getElementById('themeToggle');
const generateBtn = document.getElementById('generateBtn');
const logsContainer = document.getElementById('logsContainer');
const logOutput = document.getElementById('logOutput');

const participationModeSelect = document.getElementById('participationMode');
const accountCountGroup = document.getElementById('accountCountGroup');
const accountCountInput = document.getElementById('accountCount');
const accountsActionGroup = document.getElementById('accountsActionGroup');
const previewAccountsBtn = document.getElementById('previewAccountsBtn');
const accountsPreviewArea = document.getElementById('accountsPreviewArea');
const accountsStatusBadge = document.getElementById('accountsStatusBadge');
const downloadCsvBtn = document.getElementById('downloadCsvBtn');
const downloadPrintableBtn = document.getElementById('downloadPrintableBtn');

function slugify(title) {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'contest';
}

function initDateTimes() {
  const now = new Date();
  const start = new Date(now.getTime() + 60 * 60 * 1000);
  const end = new Date(now.getTime() + 5 * 60 * 60 * 1000);

  const formatLocal = (d) => {
    const pad = (n) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  };

  document.getElementById('startTime').value = formatLocal(start);
  document.getElementById('endTime').value = formatLocal(end);
}

function renderApps() {
  appsContainer.innerHTML = '';
  state.prohibitedApps.forEach((app, idx) => {
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.innerHTML = `<span>${app}</span><span class="tag-remove" data-idx="${idx}">&times;</span>`;
    appsContainer.appendChild(tag);
  });
}

function renderDomains() {
  domainsContainer.innerHTML = '';
  state.restrictedDomains.forEach((domain, idx) => {
    const tag = document.createElement('span');
    tag.className = 'tag';
    tag.innerHTML = `<span>${domain}</span><span class="tag-remove" data-idx="${idx}">&times;</span>`;
    domainsContainer.appendChild(tag);
  });
}

function goToStep(step) {
  state.currentStep = step;
  document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

  document.getElementById(`step${step}`).classList.add('active');
  document.querySelector(`.nav-item[data-step="${step}"]`).classList.add('active');

  if (step === 4) {
    updateSummary();
  }
  if (window.replaceLucideIcons) {
    window.replaceLucideIcons();
  }
}

function updateSummary() {
  const title = contestTitleInput.value.trim() || 'GOCUP 1';
  const id = contestIdInput.value;
  const organizer = document.getElementById('organizerName').value;
  const outDir = document.getElementById('outputDirectory').value;
  const isAccounts = participationModeSelect.value === 'generated_accounts';
  const count = accountCountInput.value;

  document.getElementById('summaryTitle').textContent = title;
  document.getElementById('summaryId').textContent = id;
  document.getElementById('summaryOrganizer').textContent = organizer;
  document.getElementById('summaryMode').textContent = isAccounts 
    ? `Mode B (Generated Accounts: ${count} accounts)`
    : 'Mode A (No Accounts - Default)';
  document.getElementById('summaryAppsCount').textContent = state.prohibitedApps.length;
  document.getElementById('summaryDomainsCount').textContent = state.restrictedDomains.length;
  document.getElementById('summaryOutput').textContent = `${outDir}/${id}/`;
}

contestTitleInput.addEventListener('input', (e) => {
  contestIdInput.value = slugify(e.target.value);
});

participationModeSelect.addEventListener('change', () => {
  const isGen = participationModeSelect.value === 'generated_accounts';
  accountCountGroup.style.display = isGen ? 'block' : 'none';
  accountsActionGroup.style.display = isGen ? 'block' : 'none';
});

previewAccountsBtn.addEventListener('click', async (e) => {
  e.preventDefault();
  const count = parseInt(accountCountInput.value || '50', 10);
  const title = contestTitleInput.value || 'GOCUP 1';
  const id = contestIdInput.value || 'gocup-1';

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const res = await window.__TAURI__.core.invoke('generate_accounts_preview', {
        contestTitle: title,
        contestId: id,
        count
      });
      if (res.success) {
        state.generatedCsv = res.csv_content;
        state.generatedHtml = res.html_content;
        accountsPreviewArea.style.display = 'block';
        accountsStatusBadge.textContent = `Generated ${res.count} secure accounts (Argon2id offline verifiers)`;
      } else {
        alert('Account generation failed: ' + res.error);
      }
    } catch (err) {
      alert('IPC error: ' + err);
    }
  } else {
    state.generatedCsv = `Contest Name,Contest ID,Participant Username,Password,Account UUID\n"${title}",${id},GOCUP-001,A7k2P9x4,00000000-0000-0000-0000-000000000001\n`;
    state.generatedHtml = `<h1>${title} Credentials</h1><p>GOCUP-001: A7k2P9x4</p>`;
    accountsPreviewArea.style.display = 'block';
    accountsStatusBadge.textContent = `Generated ${count} preview accounts`;
  }
});

function downloadTextFile(filename, content, mimeType) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

downloadCsvBtn.addEventListener('click', (e) => {
  e.preventDefault();
  if (state.generatedCsv) {
    downloadTextFile(`${contestIdInput.value || 'contest'}_credentials.csv`, state.generatedCsv, 'text/csv');
  }
});

downloadPrintableBtn.addEventListener('click', (e) => {
  e.preventDefault();
  if (state.generatedHtml) {
    const win = window.open('', '_blank');
    win.document.write(state.generatedHtml);
    win.document.close();
  }
});

addAppBtn.addEventListener('click', (e) => {
  e.preventDefault();
  const val = newAppInput.value.trim().toLowerCase();
  if (val && !state.prohibitedApps.includes(val)) {
    state.prohibitedApps.push(val);
    newAppInput.value = '';
    renderApps();
  }
});

appsContainer.addEventListener('click', (e) => {
  if (e.target.classList.contains('tag-remove')) {
    const idx = parseInt(e.target.dataset.idx, 10);
    state.prohibitedApps.splice(idx, 1);
    renderApps();
  }
});

addDomainBtn.addEventListener('click', (e) => {
  e.preventDefault();
  const val = newDomainInput.value.trim().toLowerCase();
  if (val && !state.restrictedDomains.includes(val)) {
    state.restrictedDomains.push(val);
    newDomainInput.value = '';
    renderDomains();
  }
});

domainsContainer.addEventListener('click', (e) => {
  if (e.target.classList.contains('tag-remove')) {
    const idx = parseInt(e.target.dataset.idx, 10);
    state.restrictedDomains.splice(idx, 1);
    renderDomains();
  }
});

document.querySelectorAll('.next-step').forEach(btn => {
  btn.addEventListener('click', () => {
    const next = parseInt(btn.dataset.next, 10);
    goToStep(next);
  });
});

document.querySelectorAll('.prev-step').forEach(btn => {
  btn.addEventListener('click', () => {
    const prev = parseInt(btn.dataset.prev, 10);
    goToStep(prev);
  });
});

document.querySelectorAll('.nav-item').forEach(btn => {
  btn.addEventListener('click', () => {
    const step = parseInt(btn.dataset.step, 10);
    goToStep(step);
  });
});

themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
});

generateBtn.addEventListener('click', async () => {
  logsContainer.style.display = 'block';
  logOutput.textContent = `[INFO] Initializing Contest Generation Pipeline...\n`;

  const isAccounts = participationModeSelect.value === 'generated_accounts';
  const count = parseInt(accountCountInput.value || '50', 10);

  const params = {
    title: contestTitleInput.value || 'GOCUP 1',
    organizer: document.getElementById('organizerName')?.value || 'Sharif University Computer Society',
    description: document.getElementById('contestDesc')?.value || 'Official Algorithmic Contest',
    start_time: document.getElementById('startTime')?.value ? new Date(document.getElementById('startTime').value).toISOString() : null,
    end_time: document.getElementById('endTime')?.value ? new Date(document.getElementById('endTime').value).toISOString() : null,
    prohibited_apps: state.prohibitedApps,
    restricted_domains: state.restrictedDomains,
    supported_platforms: ['windows', 'linux', 'macos'],
    branding_theme: document.documentElement.getAttribute('data-theme') || 'dark',
    output_dir: './dist',
    enable_cpp_compiler: document.getElementById('enableCppCompiler')?.checked || false,
    participation_mode: isAccounts ? 'generated_accounts' : 'no_accounts',
    account_count: isAccounts ? count : 0
  };

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      logOutput.textContent += `[TAURI] Invoking native Rust build pipeline...\n`;
      const res = await window.__TAURI__.core.invoke('generate_contest', { params });
      if (res.success) {
        logOutput.textContent += `[SUCCESS] Contest distribution bundle created!\n`;
        logOutput.textContent += `    Contest ID:    ${res.contest_id}\n`;
        logOutput.textContent += `    Root Package:  ${res.root_dir}\n`;
        logOutput.textContent += `    Manifest:      ${res.manifest_path}\n`;
        logOutput.textContent += `    Checksums:     ${res.checksums_path}\n`;
        logOutput.textContent += `    Judge PrivKey: ${res.judge_private_key_path}\n`;
        if (isAccounts) {
          logOutput.textContent += `    Judge Creds:   ${res.root_dir}/judge/credentials.csv\n`;
        }
        logOutput.textContent += `[INFO] Private decryption key quarantined in offline directory.\n`;
        logOutput.textContent += `[READY] All packages and verification instructions successfully emitted!\n`;
      } else {
        logOutput.textContent += `[ERROR] Build pipeline failed: ${res.error}\n`;
      }
    } catch (err) {
      logOutput.textContent += `[ERROR] Native IPC error: ${err}\n`;
    }
  } else {
    logOutput.textContent += `[INFO] Running in browser preview mode\n`;
    logOutput.textContent += `[SUCCESS] dist/${contestIdInput.value}/ created with manifests, configuration, and checksums.\n`;
    if (isAccounts) {
      logOutput.textContent += `[INFO] Generated ${count} Argon2id participant credentials into judge/credentials.csv\n`;
    }
    logOutput.textContent += `[READY] All packages and verification instructions successfully emitted!\n`;
  }
});

initDateTimes();
renderApps();
renderDomains();
if (window.replaceLucideIcons) {
  window.replaceLucideIcons();
}
