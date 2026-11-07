const state = {
  participantId: 'team-42',
  enrollmentToken: 'WARM-GOCUP-1-TEAM42-VALIDTOKEN',
  sessionActive: false,
  startTime: null,
  eventsCount: 0,
  timerInterval: null,
  requiresLogin: false,
  authenticatedAccountId: null,
  contestId: 'gocup-1'
};

const windowTitle = document.getElementById('windowTitle');
const startSessionBtn = document.getElementById('startSessionBtn');
const concludeSessionBtn = document.getElementById('concludeSessionBtn');
const enrollmentCard = document.getElementById('enrollmentCard');
const activeSessionCard = document.getElementById('activeSessionCard');
const activeParticipantId = document.getElementById('activeParticipantId');
const elapsedTimer = document.getElementById('elapsedTimer');
const eventsCountEl = document.getElementById('eventsCount');
const sessionStatusIndicator = document.getElementById('sessionStatusIndicator');
const sessionStatusText = document.getElementById('sessionStatusText');
const exportBtn = document.getElementById('exportBtn');
const exportResult = document.getElementById('exportResult');
const exportResultText = document.getElementById('exportResultText');
const exportPathInput = document.getElementById('exportPathInput');

const loginCard = document.getElementById('loginCard');
const loginUsernameInput = document.getElementById('loginUsername');
const loginPasswordInput = document.getElementById('loginPassword');
const submitLoginBtn = document.getElementById('submitLoginBtn');
const loginError = document.getElementById('loginError');
const loginErrorText = document.getElementById('loginErrorText');

const exportModalOverlay = document.getElementById('exportModalOverlay');
const modalLogNameInput = document.getElementById('modalLogNameInput');
const modalLogNameError = document.getElementById('modalLogNameError');
const modalCancelBtn = document.getElementById('modalCancelBtn');
const modalConfirmExportBtn = document.getElementById('modalConfirmExportBtn');
const loginNoticeAck = document.getElementById('loginNoticeAck');
const enrollNoticeAck = document.getElementById('enrollNoticeAck');

if (loginNoticeAck) {
  loginNoticeAck.addEventListener('change', () => {
    submitLoginBtn.disabled = !loginNoticeAck.checked;
  });
}

if (enrollNoticeAck) {
  enrollNoticeAck.addEventListener('change', () => {
    startSessionBtn.disabled = !enrollNoticeAck.checked;
  });
}

const compileRunBtn = document.getElementById('compileRunBtn');
const stopExecutionBtn = document.getElementById('stopExecutionBtn');
const cppSourceEditor = document.getElementById('cppSourceEditor');
const cppFileInput = document.getElementById('cppFileInput');
const terminalStdin = document.getElementById('terminalStdin');
const terminalOutput = document.getElementById('terminalOutput');
const toolchainBadge = document.getElementById('toolchainBadge');

document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    btn.classList.add('active');
    const tabId = btn.dataset.tab;
    const tabContent = document.getElementById(tabId);
    if (tabContent) {
      tabContent.classList.add('active');
    }
    if (window.replaceLucideIcons) {
      window.replaceLucideIcons();
    }
  });
});

async function checkParticipationMode() {
  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const info = await window.__TAURI__.core.invoke('get_app_info');
      if (info && info.contest_title) {
        const titleEl = document.getElementById('contestHeaderTitle');
        if (titleEl) titleEl.textContent = info.contest_title;
        document.title = `Warm-AntiCheat | ${info.contest_title}`;
      }
    } catch (e) {
      console.warn('App info error:', e);
    }

    try {
      const modeInfo = await window.__TAURI__.core.invoke('get_participation_mode');
      state.contestId = modeInfo.contest_id || 'warm-contest';
      state.requiresLogin = modeInfo.requires_login;

      if (state.requiresLogin) {
        enrollmentCard.style.display = 'none';
        loginCard.style.display = 'block';
      }
    } catch (e) {
      console.warn('Mode check error:', e);
    }
  }
}

submitLoginBtn.addEventListener('click', async () => {
  const username = loginUsernameInput.value.trim();
  const password = loginPasswordInput.value.trim();

  loginError.style.display = 'none';

  if (!username || !password) {
    loginErrorText.textContent = 'Please enter both username and password';
    loginError.style.display = 'block';
    return;
  }

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const res = await window.__TAURI__.core.invoke('login_participant_account', {
        contestId: state.contestId,
        username,
        password
      });

      if (res.success) {
        state.authenticatedAccountId = res.account_id;
        state.participantId = res.username;
        loginCard.style.display = 'none';
        enrollmentCard.style.display = 'block';
        document.getElementById('participantId').value = res.username;
        startSession();
      }
    } catch (err) {
      loginErrorText.textContent = typeof err === 'string' ? err : 'Invalid credentials';
      loginError.style.display = 'block';
    }
  } else {
    loginCard.style.display = 'none';
    enrollmentCard.style.display = 'block';
    startSession();
  }
});

function startSession() {
  state.participantId = document.getElementById('participantId').value.trim() || 'team-42';
  state.sessionActive = true;
  state.startTime = new Date();
  state.eventsCount = 1;

  enrollmentCard.style.display = 'none';
  activeSessionCard.style.display = 'block';
  activeParticipantId.textContent = state.participantId;

  sessionStatusIndicator.className = 'status-indicator status-active';
  sessionStatusText.textContent = 'Active Monitoring';

  state.timerInterval = setInterval(updateTimer, 1000);
  if (window.__TAURI__ && window.__TAURI__.core) {
    window.__TAURI__.core.invoke('start_monitoring_session', { participantId: state.participantId });
  }
}

startSessionBtn.addEventListener('click', () => {
  startSession();
});

concludeSessionBtn.addEventListener('click', async () => {
  state.sessionActive = false;
  clearInterval(state.timerInterval);

  sessionStatusIndicator.className = 'status-indicator status-idle';
  sessionStatusText.textContent = 'Session Concluded';

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      await window.__TAURI__.core.invoke('conclude_session');
    } catch (e) {
      console.warn('Conclude error:', e);
    }
  }

  alert('Session concluded. Navigate to Export Evidence tab to export your audit log.');
});

const browseExportDirBtn = document.getElementById('browseExportDirBtn');
if (browseExportDirBtn) {
  browseExportDirBtn.addEventListener('click', async () => {
    if (window.__TAURI__ && window.__TAURI__.core) {
      try {
        const selected = await window.__TAURI__.core.invoke('pick_export_folder');
        if (selected) {
          exportPathInput.value = selected;
        }
      } catch (e) {
        console.error('Directory picker error:', e);
      }
    }
  });
}

function updateTimer() {
  if (!state.startTime) return;
  const now = new Date();
  const diff = Math.floor((now - state.startTime) / 1000);

  const hours = String(Math.floor(diff / 3600)).padStart(2, '0');
  const mins = String(Math.floor((diff % 3600) / 60)).padStart(2, '0');
  const secs = String(diff % 60).padStart(2, '0');

  elapsedTimer.textContent = `${hours}:${mins}:${secs}`;
}

exportBtn.addEventListener('click', async () => {
  if (state.requiresLogin) {
    exportResult.style.display = 'none';
    const dest = exportPathInput.value.trim() || './export';

    if (window.__TAURI__ && window.__TAURI__.core) {
      try {
        const res = await window.__TAURI__.core.invoke('export_contest_log', {
          destFolder: dest,
          declaredLogName: null
        });

        exportResult.style.display = 'block';
        if (res.success) {
          exportResultText.textContent = `${res.message} Archive: ${res.export_path} (SHA-256: ${res.checksum})`;
        } else {
          exportResultText.textContent = res.message;
        }
      } catch (err) {
        exportResult.style.display = 'block';
        exportResultText.textContent = `Export error: ${err}`;
      }
    } else {
      exportResult.style.display = 'block';
      exportResultText.textContent = `Evidence package exported for account ${state.participantId}`;
    }
  } else {
    modalLogNameInput.value = state.participantId || '';
    modalLogNameError.style.display = 'none';
    exportModalOverlay.style.display = 'flex';
  }
});

modalCancelBtn.addEventListener('click', () => {
  exportModalOverlay.style.display = 'none';
});

modalConfirmExportBtn.addEventListener('click', async () => {
  const declaredName = modalLogNameInput.value.trim();
  modalLogNameError.style.display = 'none';

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const valid = await window.__TAURI__.core.invoke('validate_log_name', { name: declaredName });
      const dest = exportPathInput.value.trim() || './export';
      const res = await window.__TAURI__.core.invoke('export_contest_log', {
        destFolder: dest,
        declaredLogName: valid
      });

      exportModalOverlay.style.display = 'none';
      exportResult.style.display = 'block';
      if (res.success) {
        exportResultText.textContent = `${res.message} Archive: ${res.export_path} (SHA-256: ${res.checksum})`;
      } else {
        exportResultText.textContent = res.message;
      }
    } catch (err) {
      modalLogNameError.textContent = typeof err === 'string' ? err : 'Invalid name';
      modalLogNameError.style.display = 'block';
    }
  } else {
    exportModalOverlay.style.display = 'none';
    exportResult.style.display = 'block';
    exportResultText.textContent = `Evidence package exported as ${declaredName}_evidence.sqlite`;
  }
});

cppFileInput.addEventListener('change', (e) => {
  const file = e.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = (evt) => {
    cppSourceEditor.value = evt.target.result;
  };
  reader.readAsText(file);
});

compileRunBtn.addEventListener('click', async () => {
  const code = cppSourceEditor.value;
  const stdin = terminalStdin.value;

  terminalOutput.textContent = '[Compiling using bundled GNU G++ (C++23) -O2 -pipe...]\n';

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const res = await window.__TAURI__.core.invoke('compile_and_run_cpp', {
        sourceCode: code,
        stdinInput: stdin || null
      });

      if (!res.compilation_success) {
        terminalOutput.textContent = `[COMPILATION FAILED (${res.compilation_duration_ms}ms)]\n${res.compilation_diagnostics}`;
        return;
      }

      let out = `[COMPILATION SUCCEEDED (${res.compilation_duration_ms}ms)]\n`;
      if (res.compilation_diagnostics) {
        out += `Diagnostics:\n${res.compilation_diagnostics}\n`;
      }

      if (res.execution_started) {
        out += `\n[PROGRAM OUTPUT (Exit Code: ${res.exit_code}, Duration: ${res.execution_duration_ms}ms)]\n`;
        if (res.stdout) out += res.stdout;
        if (res.stderr) out += `\n[stderr]\n${res.stderr}`;
        if (res.timed_out) out += `\n[EXECUTION TIMED OUT]\n`;
      }

      terminalOutput.textContent = out;
    } catch (err) {
      terminalOutput.textContent = `[ERROR] ${err}`;
    }
  } else {
    terminalOutput.textContent = `[MOCK RUN]\nWarm-AntiCheat C++23 Solution Ready!\nExit Code: 0`;
  }
});

stopExecutionBtn.addEventListener('click', () => {
  terminalOutput.textContent += '\n[Execution process terminated by participant.]\n';
});

async function checkCompilerStatus() {
  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const status = await window.__TAURI__.core.invoke('get_compiler_status');
      if (status.enabled && status.toolchain_available) {
        toolchainBadge.innerHTML = `<span data-lucide="check-circle" data-size="14"></span> Bundled GNU G++ ${status.toolchain_version} (${status.cxx_standard})`;
      } else {
        toolchainBadge.innerHTML = `<span data-lucide="alert-triangle" data-size="14"></span> Compiler Not Available`;
        toolchainBadge.style.color = '#f59e0b';
      }
    } catch (e) {
      console.warn('Compiler status check error:', e);
    }
  }
}

setInterval(async () => {
  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const stats = await window.__TAURI__.core.invoke('get_session_stats');
      if (stats) {
        state.eventsCount = stats.event_count;
        eventsCountEl.textContent = stats.event_count;
        if (!stats.running && state.sessionActive) {
          state.sessionActive = false;
          if (state.timerInterval) clearInterval(state.timerInterval);
          sessionStatusIndicator.className = 'status-indicator status-idle';
          sessionStatusText.textContent = 'Session Concluded';
        }
      }

      const usb = await window.__TAURI__.core.invoke('get_usb_status');
      if (usb && usb.success) {
        const usbAlert = document.getElementById('usbExportAlert');
        const usbText = document.getElementById('usbAlertText');
        if (usbAlert && usbText) {
          usbText.textContent = `${usb.message} (SHA-256: ${usb.checksum})`;
          usbAlert.style.display = 'block';
          if (window.replaceLucideIcons) window.replaceLucideIcons();
        }
      }
    } catch (e) {}
  }
}, 2000);

checkParticipationMode();
checkCompilerStatus();
if (window.replaceLucideIcons) {
  window.replaceLucideIcons();
}
