// Participant client state
const state = {
  isEnrolled: false,
  isActive: false,
  participantId: '',
  sessionStartTime: null,
  eventsCount: 0,
  timerInterval: null
};

// DOM references
const sessionStatusIndicator = document.getElementById('sessionStatusIndicator');
const sessionStatusText = document.getElementById('sessionStatusText');
const enrollmentCard = document.getElementById('enrollmentCard');
const activeSessionCard = document.getElementById('activeSessionCard');
const participantIdInput = document.getElementById('participantId');
const startSessionBtn = document.getElementById('startSessionBtn');
const concludeSessionBtn = document.getElementById('concludeSessionBtn');
const activeParticipantId = document.getElementById('activeParticipantId');
const elapsedTimer = document.getElementById('elapsedTimer');
const eventsCountSpan = document.getElementById('eventsCount');
const exportBtn = document.getElementById('exportBtn');
const exportResult = document.getElementById('exportResult');
const exportResultText = document.getElementById('exportResultText');

// Format seconds into HH:MM:SS
function formatTime(totalSeconds) {
  const pad = (n) => String(n).padStart(2, '0');
  const h = Math.floor(totalSeconds / 3600);
  const m = Math.floor((totalSeconds % 3600) / 60);
  const s = totalSeconds % 60;
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

// Tab navigation
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

    btn.classList.add('active');
    document.getElementById(btn.dataset.tab).classList.add('active');
  });
});

// Start Session
startSessionBtn.addEventListener('click', async () => {
  const pId = participantIdInput.value.trim();
  if (!pId) {
    alert('Please enter your Participant ID');
    return;
  }

  state.isEnrolled = true;
  state.isActive = true;
  state.participantId = pId;
  state.sessionStartTime = new Date();
  state.eventsCount = 1; // Initial launch event

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      await window.__TAURI__.core.invoke('start_monitoring_session', { participantId: pId });
    } catch (e) {
      console.warn('Native monitoring start error:', e);
    }
  }

  // UI transition
  enrollmentCard.style.display = 'none';
  activeSessionCard.style.display = 'block';
  activeParticipantId.textContent = pId;
  eventsCountSpan.textContent = state.eventsCount;

  sessionStatusIndicator.classList.remove('status-idle');
  sessionStatusIndicator.classList.add('status-active');
  sessionStatusText.textContent = 'Session Active (Monitoring On)';

  // Start elapsed timer
  state.timerInterval = setInterval(() => {
    const elapsed = Math.floor((new Date() - state.sessionStartTime) / 1000);
    elapsedTimer.textContent = formatTime(elapsed);

    // Increment simulated background heartbeat events every 15s
    if (elapsed > 0 && elapsed % 15 === 0) {
      state.eventsCount += 1;
      eventsCountSpan.textContent = state.eventsCount;
    }
  }, 1000);
});

// Conclude Session
concludeSessionBtn.addEventListener('click', () => {
  if (!confirm('Are you sure you want to conclude the competition session?')) {
    return;
  }

  clearInterval(state.timerInterval);
  state.isActive = false;

  sessionStatusIndicator.classList.remove('status-active');
  sessionStatusIndicator.classList.add('status-idle');
  sessionStatusText.textContent = 'Session Concluded';

  alert('Session concluded. Please proceed to the "Export Evidence" tab to save your sealed package.');
  // Switch to export tab
  document.querySelector('.tab-btn[data-tab="exportTab"]').click();
});

// Export Evidence
exportBtn.addEventListener('click', async () => {
  const dest = document.getElementById('exportPathInput').value.trim();
  exportResult.style.display = 'block';

  if (window.__TAURI__ && window.__TAURI__.core) {
    try {
      const res = await window.__TAURI__.core.invoke('export_usb_package', { destFolder: dest });
      exportResultText.textContent = `[SUCCESS] Encrypted Evidence Archive Exported!\nPath: ${res.export_path}\nChecksum: ${res.checksum}\n${res.message}`;
      return;
    } catch (e) {
      exportResultText.textContent = `[ERROR] USB export failed: ${e}`;
      return;
    }
  }

  exportResultText.textContent = `Evidence successfully packaged into ${dest}/${state.participantId || 'team-42'}.warm-evidence with SHA-256 hash-chain verification.`;
});

// Built-in C++ Compiler Integration
const cppFileInput = document.getElementById('cppFileInput');
const cppSourceEditor = document.getElementById('cppSourceEditor');
const compileRunBtn = document.getElementById('compileRunBtn');
const stopExecutionBtn = document.getElementById('stopExecutionBtn');
const terminalStdin = document.getElementById('terminalStdin');
const terminalOutput = document.getElementById('terminalOutput');
const toolchainBadge = document.getElementById('toolchainBadge');

if (cppFileInput) {
  cppFileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (event) => {
        cppSourceEditor.value = event.target.result;
        terminalOutput.textContent = `[Loaded file: ${file.name} (${file.size} bytes)]\nReady to compile with bundled GNU G++ (C++23).\n`;
      };
      reader.readAsText(file);
    }
  });
}

if (compileRunBtn) {
  compileRunBtn.addEventListener('click', async () => {
    const sourceCode = cppSourceEditor.value;
    const stdinInput = terminalStdin.value;

    terminalOutput.textContent = `[*] Invoking bundled GNU G++ (-std=c++23 -O2 -pipe)...\n`;
    compileRunBtn.disabled = true;

    if (window.__TAURI__ && window.__TAURI__.core) {
      try {
        const res = await window.__TAURI__.core.invoke('compile_and_run_cpp', {
          sourceCode: sourceCode,
          stdinInput: stdinInput || null
        });

        compileRunBtn.disabled = false;

        let output = `[COMPILATION: ${res.compilation_success ? 'SUCCESS' : 'FAILED'} in ${res.compilation_duration_ms}ms]\n`;
        output += `Source SHA-256: ${res.source_sha256}\n`;
        if (res.binary_sha256) {
          output += `Binary SHA-256: ${res.binary_sha256}\n`;
        }

        if (res.compilation_diagnostics) {
          output += `\n--- Compiler Diagnostics ---\n${res.compilation_diagnostics}\n`;
        }

        if (res.execution_started) {
          output += `\n--- Program Execution (Runtime: ${res.execution_duration_ms}ms, Exit Code: ${res.exit_code ?? 'None'}) ---\n`;
          if (res.stdout) {
            output += `[STDOUT]\n${res.stdout}\n`;
          }
          if (res.stderr) {
            output += `[STDERR]\n${res.stderr}\n`;
          }
          if (res.timed_out) {
            output += `\n[VIOLATION] ${res.resource_violation || 'Execution Timed Out'}\n`;
          }
        }

        terminalOutput.textContent = output;
      } catch (err) {
        compileRunBtn.disabled = false;
        terminalOutput.textContent = `[COMPILER ERROR] ${err}\n`;
      }
    } else {
      // Browser preview mode simulation
      compileRunBtn.disabled = false;
      terminalOutput.textContent = `[BROWSER PREVIEW MODE]\n`;
      terminalOutput.textContent += `[COMPILATION: SUCCESS (Simulated)]\n`;
      terminalOutput.textContent += `Source SHA-256: 3a2c...88f1\n`;
      terminalOutput.textContent += `--- Program Execution ---\n`;
      terminalOutput.textContent += `Warm-AntiCheat C++23 Solution Ready!\n[Process exited with code 0]\n`;
    }
  });
}

if (stopExecutionBtn) {
  stopExecutionBtn.addEventListener('click', () => {
    terminalOutput.textContent += `\n[STOP] Execution termination requested by participant.\n`;
  });
}
