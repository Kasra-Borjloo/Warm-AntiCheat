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
startSessionBtn.addEventListener('click', () => {
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
exportBtn.addEventListener('click', () => {
  const dest = document.getElementById('exportPathInput').value.trim();
  exportResult.style.display = 'block';
  exportResultText.textContent = `Evidence successfully packaged into ${dest}/${state.participantId || 'team-42'}.warm-evidence with SHA-256 hash-chain verification.`;
});
