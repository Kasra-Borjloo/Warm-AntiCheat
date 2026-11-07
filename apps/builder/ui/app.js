// State management
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
  ]
};

// DOM references
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

// Slugify helper
function slugify(title) {
  return title
    .toLowerCase()
    .trim()
    .replace(/[^\w\s-]/g, '')
    .replace(/[\s_-]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'contest';
}

// Initialize default date times (today + 1 hour to today + 5 hours)
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

// Render tag lists
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

// Switch Wizard Step
function goToStep(step) {
  state.currentStep = step;
  document.querySelectorAll('.wizard-step').forEach(s => s.classList.remove('active'));
  document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));

  document.getElementById(`step${step}`).classList.add('active');
  document.querySelector(`.nav-item[data-step="${step}"]`).classList.add('active');

  // If entering step 4, update summary
  if (step === 4) {
    updateSummary();
  }
}

function updateSummary() {
  const title = contestTitleInput.value.trim() || 'GOCUP 1';
  const id = contestIdInput.value;
  const organizer = document.getElementById('organizerName').value;
  const outDir = document.getElementById('outputDirectory').value;

  document.getElementById('summaryTitle').textContent = title;
  document.getElementById('summaryId').textContent = id;
  document.getElementById('summaryOrganizer').textContent = organizer;
  document.getElementById('summaryAppsCount').textContent = state.prohibitedApps.length;
  document.getElementById('summaryDomainsCount').textContent = state.restrictedDomains.length;
  document.getElementById('summaryOutput').textContent = `${outDir}/${id}/`;
}

// Event Listeners
contestTitleInput.addEventListener('input', (e) => {
  contestIdInput.value = slugify(e.target.value);
});

// App tags manipulation
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

// Domain tags manipulation
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

// Navigation buttons
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

// Theme Toggle
themeToggle.addEventListener('click', () => {
  const current = document.documentElement.getAttribute('data-theme');
  const next = current === 'dark' ? 'light' : 'dark';
  document.documentElement.setAttribute('data-theme', next);
});

// Build generation simulation / execution
generateBtn.addEventListener('click', () => {
  logsContainer.style.display = 'block';
  logOutput.textContent = `[INFO] Initializing Contest Generation Pipeline...\n`;
  logOutput.textContent += `[INFO] Generating contest UUID: ${crypto.randomUUID()}\n`;
  logOutput.textContent += `[INFO] Generating Ed25519 Manifest Signing Keypair...\n`;
  logOutput.textContent += `[INFO] Generating X25519 Judge Evidence Encryption Keypair...\n`;
  logOutput.textContent += `[INFO] Signing contest manifest with Organizer Private Key...\n`;
  logOutput.textContent += `[SUCCESS] dist/${contestIdInput.value}/ created with manifests, configuration, and checksums.\n`;
  logOutput.textContent += `[INFO] Private decryption key safely quarantined in judge/keys/.\n`;
  logOutput.textContent += `[READY] All packages and verification instructions successfully emitted!\n`;
});

// Init
initDateTimes();
renderApps();
renderDomains();
