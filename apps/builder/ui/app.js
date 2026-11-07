const state = {
  currentStep: 1,
  contestUuid: '550e8400-e29b-41d4-a716-446655440000',
  prohibitedApps: [
    'ollama', 'ollama.exe', 'ollama_llama_server.exe',
    'lmstudio', 'lmstudio.exe', 'lm-studio',
    'llama-cli', 'llama-cli.exe', 'llama-server', 'llama-server.exe',
    'llama-bench', 'llama-quantize',
    'text-generation-webui', 'jan.exe', 'jan',
    'gpt4all', 'gpt4all.exe', 'localai', 'local-ai',
    'koboldcpp', 'koboldcpp.exe', 'vllm', 'transformers-cli',
    'tabby', 'tabby.exe'
  ],
  restrictedDomains: [
    'chatgpt.com', 'openai.com', 'claude.ai',
    'anthropic.com', 'gemini.google.com',
    'copilot.microsoft.com', 'perplexity.ai', 'deepseek.com'
  ],
  accountsList: [],
  csvContent: '',
  htmlContent: '',
  pdfBase64: ''
};

const contestTitleInput = document.getElementById('contestTitle');
const contestIdInput = document.getElementById('contestId');
const organizerNameInput = document.getElementById('organizerName');
const contestDescInput = document.getElementById('contestDesc');
const outputDirectoryInput = document.getElementById('outputDirectory');
const browseOutputDirBtn = document.getElementById('browseOutputDirBtn');

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
const generationSuccessCard = document.getElementById('generationSuccessCard');
const generationSuccessMessage = document.getElementById('generationSuccessMessage');

const participationModeSelect = document.getElementById('participationMode');
const accountCountGroup = document.getElementById('accountCountGroup');
const accountCountInput = document.getElementById('accountCount');
const accountsActionGroup = document.getElementById('accountsActionGroup');
const previewAccountsBtn = document.getElementById('previewAccountsBtn');
const regenerateAccountsBtn = document.getElementById('regenerateAccountsBtn');
const copyAllCredsBtn = document.getElementById('copyAllCredsBtn');
const downloadCsvBtn = document.getElementById('downloadCsvBtn');
const downloadPdfBtn = document.getElementById('downloadPdfBtn');
const accountsPreviewArea = document.getElementById('accountsPreviewArea');
const accountsStatusBadge = document.getElementById('accountsStatusBadge');
const accountsTableBody = document.getElementById('accountsTableBody');
const accountsSearchInput = document.getElementById('accountsSearchInput');

function slugify(title) {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'contest';
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

function renderAccountsTable(filterText = '') {
  accountsTableBody.innerHTML = '';
  const filter = filterText.toLowerCase().trim();
  const filtered = state.accountsList.filter(acc => {
    return acc.username.toLowerCase().includes(filter) ||
           acc.account_id.toLowerCase().includes(filter);
  });

  if (filtered.length === 0) {
    const row = document.createElement('tr');
    row.innerHTML = `<td colspan="5" style="text-align: center; padding: 1rem; color: var(--text-muted);">No accounts found matching filter.</td>`;
    accountsTableBody.appendChild(row);
    return;
  }

  filtered.forEach(acc => {
    const row = document.createElement('tr');
    row.style.borderBottom = '1px solid var(--border-color)';
    row.innerHTML = `
      <td style="padding: 0.4rem 0.5rem; color: var(--text-muted); font-size: 0.8rem;">${acc.index}</td>
      <td style="padding: 0.4rem 0.5rem; font-weight: 600;"><code>${acc.username}</code></td>
      <td style="padding: 0.4rem 0.5rem; font-family: monospace; color: #0284c7; font-weight: bold;">${acc.password}</td>
      <td style="padding: 0.4rem 0.5rem; font-family: monospace; font-size: 0.75rem; color: var(--text-muted);">${acc.account_id}</td>
      <td style="padding: 0.4rem 0.5rem; text-align: center;">
        <button class="btn btn-secondary btn-sm copy-btn" data-type="user" data-val="${acc.username}" title="Copy Username">User</button>
        <button class="btn btn-secondary btn-sm copy-btn" data-type="pass" data-val="${acc.password}" title="Copy Password">Pass</button>
        <button class="btn btn-secondary btn-sm copy-btn" data-type="all" data-user="${acc.username}" data-pass="${acc.password}" title="Copy Account">Both</button>
      </td>
    `;
    accountsTableBody.appendChild(row);
  });
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).catch(() => {
    const ta = document.createElement('textarea');
    ta.value = text;
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
  });
}

accountsTableBody.addEventListener('click', (e) => {
  const btn = e.target.closest('.copy-btn');
  if (!btn) return;
  const type = btn.dataset.type;
  if (type === 'user' || type === 'pass') {
    copyToClipboard(btn.dataset.val);
  } else if (type === 'all') {
    copyToClipboard(`Username: ${btn.dataset.user}\nPassword: ${btn.dataset.pass}`);
  }
  const origText = btn.textContent;
  btn.textContent = 'Copied!';
  setTimeout(() => { btn.textContent = origText; }, 1200);
});

copyAllCredsBtn.addEventListener('click', () => {
  if (state.accountsList.length === 0) return;
  const sheet = state.accountsList.map(a => `${a.username} | ${a.password} | ${a.account_id}`).join('\n');
  copyToClipboard(sheet);
  const orig = copyAllCredsBtn.innerHTML;
  copyAllCredsBtn.textContent = 'All Copied!';
  setTimeout(() => { copyAllCredsBtn.innerHTML = orig; if (window.replaceLucideIcons) window.replaceLucideIcons(); }, 1500);
});

accountsSearchInput.addEventListener('input', (e) => {
  renderAccountsTable(e.target.value);
});

async function triggerGenerateAccounts() {
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
        state.accountsList = res.accounts;
        state.csvContent = res.csv_content;
        state.htmlContent = res.html_content;
        state.pdfBase64 = res.pdf_base64;

        accountsPreviewArea.style.display = 'block';
        regenerateAccountsBtn.style.display = 'inline-flex';
        copyAllCredsBtn.style.display = 'inline-flex';
        downloadCsvBtn.style.display = 'inline-flex';
        downloadPdfBtn.style.display = 'inline-flex';
        previewAccountsBtn.style.display = 'none';

        accountsStatusBadge.textContent = `${res.count} Accounts Generated (Argon2id Salted Hashes)`;
        renderAccountsTable();
        if (window.replaceLucideIcons) window.replaceLucideIcons();
      } else {
        alert('Account generation failed: ' + res.error);
      }
    } catch (err) {
      alert('IPC error: ' + err);
    }
  } else {
    state.accountsList = Array.from({ length: count }, (_, i) => ({
      index: i + 1,
      username: `${id.toUpperCase()}-${String(i + 1).padStart(3, '0')}`,
      password: 'A7' + Math.random().toString(36).substring(2, 8).toUpperCase(),
      account_id: '00000000-0000-0000-0000-' + String(i + 1).padStart(12, '0'),
      contest_id: id
    }));
    accountsPreviewArea.style.display = 'block';
    regenerateAccountsBtn.style.display = 'inline-flex';
    copyAllCredsBtn.style.display = 'inline-flex';
    downloadCsvBtn.style.display = 'inline-flex';
    downloadPdfBtn.style.display = 'inline-flex';
    previewAccountsBtn.style.display = 'none';
    accountsStatusBadge.textContent = `${count} Preview Accounts`;
    renderAccountsTable();
    if (window.replaceLucideIcons) window.replaceLucideIcons();
  }
}

previewAccountsBtn.addEventListener('click', (e) => {
  e.preventDefault();
  triggerGenerateAccounts();
});

regenerateAccountsBtn.addEventListener('click', (e) => {
  e.preventDefault();
  if (confirm('Regenerate all participant passwords? Existing un-exported credentials will be replaced.')) {
    triggerGenerateAccounts();
  }
});

downloadCsvBtn.addEventListener('click', async (e) => {
  e.preventDefault();
  const id = contestIdInput.value || 'contest';
  const defaultName = `${id}_credentials.csv`;

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const saved = await window.__TAURI__.core.invoke('save_credentials_file', {
        format: 'csv',
        defaultName,
        content: state.csvContent
      });
      alert(`Credentials CSV exported successfully:\n${saved}`);
    } catch (err) {
      if (err !== 'Export cancelled by user') {
        alert('Failed to export CSV: ' + err);
      }
    }
  } else {
    downloadBrowserBlob(defaultName, state.csvContent, 'text/csv');
  }
});

downloadPdfBtn.addEventListener('click', async (e) => {
  e.preventDefault();
  const id = contestIdInput.value || 'contest';
  const defaultName = `${id}_credentials.pdf`;

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const saved = await window.__TAURI__.core.invoke('save_credentials_file', {
        format: 'pdf',
        defaultName,
        content: state.pdfBase64
      });
      alert(`Printable Credentials PDF exported successfully:\n${saved}`);
    } catch (err) {
      if (err !== 'Export cancelled by user') {
        alert('Failed to export PDF: ' + err);
      }
    }
  } else {
    alert('PDF export available in native desktop application.');
  }
});

function downloadBrowserBlob(filename, content, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

browseOutputDirBtn.addEventListener('click', async () => {
  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const selected = await window.__TAURI__.core.invoke('pick_output_directory');
      if (selected) {
        outputDirectoryInput.value = selected;
        updateSummary();
      }
    } catch (err) {
      console.warn('Folder picker failed:', err);
    }
  }
});

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
  const organizer = organizerNameInput.value;
  const outDir = outputDirectoryInput.value.trim() || './dist';
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
  generationSuccessCard.style.display = 'none';
  logOutput.textContent = `[INFO] Initializing Contest Generation Pipeline...\n`;

  const isAccounts = participationModeSelect.value === 'generated_accounts';
  const count = parseInt(accountCountInput.value || '50', 10);
  const outDir = outputDirectoryInput.value.trim() || './dist';

  const params = {
    title: contestTitleInput.value || 'GOCUP 1',
    organizer: organizerNameInput.value || 'Sharif University Computer Society',
    description: contestDescInput.value || 'Official Algorithmic Contest',
    prohibited_apps: state.prohibitedApps,
    restricted_domains: state.restrictedDomains,
    supported_platforms: ['windows', 'linux', 'macos'],
    branding_theme: document.documentElement.getAttribute('data-theme') || 'dark',
    output_dir: outDir,
    enable_cpp_compiler: document.getElementById('enableCppCompiler')?.checked || false,
    participation_mode: isAccounts ? 'generated_accounts' : 'no_accounts',
    account_count: isAccounts ? count : 0
  };

  logOutput.textContent += `[INFO] Generating cryptographic keypairs for contest '${params.title}'...\n`;
  logOutput.textContent += `[INFO] Output destination set to: ${outDir}\n`;

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      logOutput.textContent += `[TAURI] Invoking native Rust build pipeline...\n`;
      const res = await window.__TAURI__.core.invoke('generate_contest', { params });
      if (res.success) {
        logOutput.textContent += `[SUCCESS] Contest distribution bundle created!\n`;
        logOutput.textContent += `    Contest ID:       ${res.contest_id}\n`;
        logOutput.textContent += `    Root Package:     ${res.root_dir}\n`;
        logOutput.textContent += `    Participant Pkg:  ${res.client_dir}\n`;
        logOutput.textContent += `    Signed Manifest:  ${res.manifest_path}\n`;
        logOutput.textContent += `    SHA-256 Hashes:   ${res.checksums_path}\n`;
        logOutput.textContent += `    Judge PrivateKey: ${res.judge_private_key_path}\n`;
        logOutput.textContent += `    USB Export Token: ${res.root_dir}/judge/usb_token/warm_export_auth.token\n`;
        if (isAccounts) {
          logOutput.textContent += `    Judge Creds CSV:  ${res.root_dir}/judge/credentials.csv\n`;
          logOutput.textContent += `    Judge Creds PDF:  ${res.root_dir}/judge/credentials.pdf\n`;
        }
        logOutput.textContent += `[INFO] Private decryption key quarantined in offline judge directory.\n`;
        logOutput.textContent += `[READY] All packages, Participant Client files, and verification instructions emitted!\n`;

        generationSuccessMessage.innerHTML = `Participant Client package is ready at: <br><strong style="word-break: break-all;">${res.client_dir}</strong><br>Distribute this folder to participants via USB or local network.`;
        generationSuccessCard.style.display = 'block';
      } else {
        logOutput.textContent += `[ERROR] Build pipeline failed: ${res.error}\n`;
        alert('Generation failed: ' + res.error);
      }
    } catch (err) {
      logOutput.textContent += `[ERROR] Native IPC error: ${err}\n`;
      alert('Native IPC error: ' + err);
    }
  } else {
    logOutput.textContent += `[INFO] Running in browser preview mode\n`;
    logOutput.textContent += `[SUCCESS] ${outDir}/${contestIdInput.value}/ created with manifests, configuration, and checksums.\n`;
    generationSuccessMessage.textContent = `Contest package created at ${outDir}/${contestIdInput.value}/`;
    generationSuccessCard.style.display = 'block';
  }
});

renderApps();
renderDomains();
if (window.replaceLucideIcons) {
  window.replaceLucideIcons();
}
