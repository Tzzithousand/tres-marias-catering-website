/**
 * TRES MARIAS ADMIN - LOGIN & AUTHENTICATION SCRIPT
 * File: assets/js/login.js
 * Description: Client-side validation, OTP auto-advance, and backend authentication via MySQL.
 */

// Dynamic API Base: Works when opened via file:/// or other local ports, falls back to http://localhost:3000
const API_BASE = (window.location.protocol === 'file:' || !window.location.origin.includes(':3000'))
  ? 'http://localhost:3000'
  : '';

// ==========================================================
// 0. AUTHENTICATION ROUTE GUARD (REVERSE GUARD)
// ==========================================================
// Prevent already authenticated admins from viewing the login page
async function redirectIfAlreadyAuthenticated() {
  const token = sessionStorage.getItem('tres_marias_token');
  const isLoggedIn = sessionStorage.getItem('tres_marias_admin_logged_in');

  if (isLoggedIn === 'true' && token) {
    try {
      const response = await fetch(`${API_BASE}/api/verify-session`, {
        method: 'GET',
        headers: { 'Authorization': `Bearer ${token}` }
      });
      const data = await response.json();
      if (data.valid) {
        window.location.replace('dashboard.html');
      } else {
        // Token is invalid/expired - clear stale storage
        sessionStorage.removeItem('tres_marias_token');
        sessionStorage.removeItem('tres_marias_admin_logged_in');
        sessionStorage.removeItem('tres_marias_admin_user');
      }
    } catch (e) {
      // If server unreachable, maintain current location
    }
  }
}
redirectIfAlreadyAuthenticated();

// Handle browser Back-Forward Cache (BFCache) when navigating via Back button
window.addEventListener('pageshow', (event) => {
  redirectIfAlreadyAuthenticated();
  if (typeof updateSendOtpButtonState === 'function') {
    updateSendOtpButtonState();
  }
});

const loginForm = document.getElementById('login-form');
const usernameInput = document.getElementById('username-input');
const passwordInput = document.getElementById('password-input');
const togglePasswordBtn = document.getElementById('toggle-password');
const btnSendOtp = document.getElementById('btn-send-otp');
const btnLogin = document.getElementById('btn-login');
const alertBox = document.getElementById('login-alert');
const alertIcon = document.getElementById('alert-icon');
const alertText = document.getElementById('alert-text');
const usernameError = document.getElementById('username-error');
const passwordError = document.getElementById('password-error');
const otpError = document.getElementById('otp-error');

// 4 OTP Input Boxes
const otpBoxes = [
  document.getElementById('otp1'),
  document.getElementById('otp2'),
  document.getElementById('otp3'),
  document.getElementById('otp4')
];

// Helper functions for alerts and errors
function showAlert(message, type = 'error') {
  if (!alertBox || !alertIcon || !alertText) return;
  alertBox.className = `login-alert visible login-alert-${type}`;
  if (type === 'locked') {
    alertIcon.textContent = '🔒';
  } else if (type === 'error') {
    alertIcon.textContent = '⚠️';
  } else if (type === 'success') {
    alertIcon.textContent = '✅';
  } else {
    alertIcon.textContent = 'ℹ️';
  }
  alertText.textContent = message;
}

function clearAlert() {
  // Do not clear alert if account or OTP entry is actively locked
  if (isAccountLocked() || isOtpLocked()) return;

  if (alertBox && alertText) {
    alertBox.className = 'login-alert';
    alertText.textContent = '';
  }
  if (usernameError) usernameError.classList.remove('visible');
  if (passwordError) passwordError.classList.remove('visible');
  if (otpError) otpError.classList.remove('visible');
  if (usernameInput) usernameInput.classList.remove('has-error');
  if (passwordInput) passwordInput.classList.remove('has-error');
  otpBoxes.forEach(b => {
    if (b) b.classList.remove('has-error');
  });
}

function triggerShake() {
  if (!loginForm) return;
  loginForm.classList.remove('shake');
  void loginForm.offsetWidth; // trigger reflow
  loginForm.classList.add('shake');
}

// ==========================================================
// Account Lockout State & Countdown Timer (Password Brute-force: 5 mins)
// ==========================================================
let lockoutTimerInterval = null;
const LOCKOUT_STORAGE_KEY = 'tres_marias_admin_lockout_until';

function isAccountLocked() {
  const storedUntil = localStorage.getItem(LOCKOUT_STORAGE_KEY);
  return storedUntil ? parseInt(storedUntil, 10) > Date.now() : false;
}

function setFormLockedState(locked) {
  if (usernameInput) usernameInput.disabled = locked;
  if (passwordInput) passwordInput.disabled = locked;
  otpBoxes.forEach(b => { if (b) b.disabled = locked; });
  if (btnSendOtp) btnSendOtp.disabled = locked;
  if (btnLogin) btnLogin.disabled = locked;
  if (loginForm) {
    if (locked) loginForm.classList.add('is-locked');
    else loginForm.classList.remove('is-locked');
  }
  if (!locked) {
    updateSendOtpButtonState();
  }
}

function updateLockoutUI() {
  const storedUntil = localStorage.getItem(LOCKOUT_STORAGE_KEY);
  if (!storedUntil) return;

  const remainingMs = parseInt(storedUntil, 10) - Date.now();
  if (remainingMs <= 0) {
    stopLockoutCountdown();
    showAlert('Lockout period has expired. You may now attempt to log in.', 'info');
    return;
  }

  const totalSec = Math.ceil(remainingMs / 1000);
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  const timeStr = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;

  showAlert(`Account locked due to 5 failed attempts. Please wait ${timeStr} before trying again.`, 'locked');
  if (btnLogin) {
    btnLogin.textContent = `Locked (${timeStr})`;
  }
}

function startLockoutCountdown(seconds) {
  if (lockoutTimerInterval) {
    clearInterval(lockoutTimerInterval);
  }

  const expireTimestamp = Date.now() + (seconds * 1000);
  localStorage.setItem(LOCKOUT_STORAGE_KEY, expireTimestamp.toString());
  setFormLockedState(true);
  updateLockoutUI();

  lockoutTimerInterval = setInterval(() => {
    const storedUntil = localStorage.getItem(LOCKOUT_STORAGE_KEY);
    if (!storedUntil || parseInt(storedUntil, 10) <= Date.now()) {
      stopLockoutCountdown();
      showAlert('Lockout period has expired. You may now attempt to log in.', 'info');
    } else {
      updateLockoutUI();
    }
  }, 1000);
}

function stopLockoutCountdown() {
  if (lockoutTimerInterval) {
    clearInterval(lockoutTimerInterval);
    lockoutTimerInterval = null;
  }
  localStorage.removeItem(LOCKOUT_STORAGE_KEY);
  setFormLockedState(false);
  if (btnLogin) {
    btnLogin.textContent = 'Log In';
  }
  updateSendOtpButtonState();
}

// ==========================================================
// OTP Lockout State & Countdown Timer (REQ-007: 2 mins after 5 failed OTPs)
// ==========================================================
let otpLockoutTimerInterval = null;
const OTP_LOCKOUT_STORAGE_KEY = 'tres_marias_admin_otp_lockout_until';

function isOtpLocked() {
  const storedUntil = localStorage.getItem(OTP_LOCKOUT_STORAGE_KEY);
  return storedUntil ? parseInt(storedUntil, 10) > Date.now() : false;
}

function setOtpFieldsLockedState(locked) {
  otpBoxes.forEach(b => { 
    if (b) {
      b.disabled = locked;
      if (locked) b.classList.add('has-error');
      else b.classList.remove('has-error');
    }
  });
  if (btnSendOtp) btnSendOtp.disabled = locked;
  if (btnLogin) {
    btnLogin.disabled = locked;
    if (!locked && !isAccountLocked()) {
      btnLogin.textContent = 'Log In';
    }
  }
  if (!locked) {
    updateSendOtpButtonState();
  }
}

function updateOtpLockoutUI() {
  const storedUntil = localStorage.getItem(OTP_LOCKOUT_STORAGE_KEY);
  if (!storedUntil) return;

  const remainingMs = parseInt(storedUntil, 10) - Date.now();
  if (remainingMs <= 0) {
    stopOtpLockoutCountdown();
    showAlert('OTP lockout period has expired. You may now request and enter a new OTP.', 'info');
    return;
  }

  const totalSec = Math.ceil(remainingMs / 1000);
  const mins = Math.floor(totalSec / 60);
  const secs = totalSec % 60;
  const timeStr = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;

  showAlert(`OTP entry is locked due to 5 failed attempts. Please wait ${timeStr} before trying again.`, 'locked');
  if (btnSendOtp) {
    btnSendOtp.textContent = `Locked (${timeStr})`;
  }
  if (btnLogin) {
    btnLogin.disabled = true;
    btnLogin.textContent = `Locked (${timeStr})`;
  }
}

function startOtpLockoutCountdown(seconds) {
  if (otpLockoutTimerInterval) {
    clearInterval(otpLockoutTimerInterval);
  }

  const expireTimestamp = Date.now() + (seconds * 1000);
  localStorage.setItem(OTP_LOCKOUT_STORAGE_KEY, expireTimestamp.toString());
  setOtpFieldsLockedState(true);
  updateOtpLockoutUI();

  otpLockoutTimerInterval = setInterval(() => {
    const storedUntil = localStorage.getItem(OTP_LOCKOUT_STORAGE_KEY);
    if (!storedUntil || parseInt(storedUntil, 10) <= Date.now()) {
      stopOtpLockoutCountdown();
      showAlert('OTP lockout period has expired. You may now request and enter a new OTP.', 'info');
    } else {
      updateOtpLockoutUI();
    }
  }, 1000);
}

function stopOtpLockoutCountdown() {
  if (otpLockoutTimerInterval) {
    clearInterval(otpLockoutTimerInterval);
    otpLockoutTimerInterval = null;
  }
  localStorage.removeItem(OTP_LOCKOUT_STORAGE_KEY);
  setOtpFieldsLockedState(false);
  if (btnSendOtp) {
    btnSendOtp.textContent = 'Send OTP';
  }
  if (btnLogin && !isAccountLocked()) {
    btnLogin.disabled = false;
    btnLogin.textContent = 'Log In';
  }
  updateSendOtpButtonState();
}

// Check on page load if account or OTP is currently locked out in this browser
function checkLockoutOnPageLoad() {
  // Check password account lockout
  const storedUntil = localStorage.getItem(LOCKOUT_STORAGE_KEY);
  if (storedUntil) {
    const remainingMs = parseInt(storedUntil, 10) - Date.now();
    if (remainingMs > 0) {
      startLockoutCountdown(Math.ceil(remainingMs / 1000));
    } else {
      localStorage.removeItem(LOCKOUT_STORAGE_KEY);
    }
  }

  // Check OTP lockout
  const storedOtpUntil = localStorage.getItem(OTP_LOCKOUT_STORAGE_KEY);
  if (storedOtpUntil) {
    const remainingMs = parseInt(storedOtpUntil, 10) - Date.now();
    if (remainingMs > 0) {
      startOtpLockoutCountdown(Math.ceil(remainingMs / 1000));
    } else {
      localStorage.removeItem(OTP_LOCKOUT_STORAGE_KEY);
    }
  }
}
checkLockoutOnPageLoad();
updateSendOtpButtonState();

// Handle session timeout redirection from dashboard (REQ-008: 15-minute inactivity)
function checkSessionTimeoutNotice() {
  const urlParams = new URLSearchParams(window.location.search);
  if (urlParams.get('reason') === 'inactivity') {
    showAlert('Your session has timed out due to 15 minutes of inactivity. Please log in again.', 'info');
    if (window.history && window.history.replaceState) {
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  }
}
checkSessionTimeoutNotice();

// Auto-advance through OTP input boxes
otpBoxes.forEach((box, index) => {
  if (!box) return;

  box.addEventListener('focus', () => {
    box.select();
    box.classList.remove('has-error');
    if (otpError) otpError.classList.remove('visible');
  });

  box.addEventListener('click', () => box.select());

  // 1. Move to next box when a digit is entered
  box.addEventListener('input', () => {
    box.classList.remove('has-error');
    if (/^[0-9]$/.test(box.value) && index < otpBoxes.length - 1) {
      otpBoxes[index + 1].focus();
    }
  });

  // 2. Backspace navigation
  box.addEventListener('keydown', (e) => {
    if (e.key === 'Backspace' && box.value === '' && index > 0) {
      otpBoxes[index - 1].focus();
    }
  });

  // 3. Paste support for 4 digits
  box.addEventListener('paste', (e) => {
    e.preventDefault();
    const text = (e.clipboardData || window.clipboardData).getData('text').trim();
    if (/^[0-9]{4}$/.test(text)) {
      otpBoxes.forEach((b, i) => { 
        if (b) {
          b.value = text[i]; 
          b.classList.remove('has-error');
        }
      });
      if (otpBoxes[3]) otpBoxes[3].focus();
    }
  });
});

// Dynamic Send OTP button readiness state (requires both username/email and password)
function updateSendOtpButtonState() {
  if (isAccountLocked() || isOtpLocked()) return;

  const hasUsername = Boolean(usernameInput && usernameInput.value.trim().length > 0);
  const hasPassword = Boolean(passwordInput && passwordInput.value.length > 0);
  const isReady = hasUsername && hasPassword;

  if (btnSendOtp) {
    btnSendOtp.disabled = !isReady;
    if (isReady) {
      btnSendOtp.classList.add('active-ready');
    } else {
      btnSendOtp.classList.remove('active-ready');
    }
  }
}

// Clear error highlights on user input and update button readiness
if (usernameInput) {
  usernameInput.addEventListener('input', () => {
    usernameInput.classList.remove('has-error');
    if (usernameError) usernameError.classList.remove('visible');
    updateSendOtpButtonState();
  });
  usernameInput.addEventListener('change', updateSendOtpButtonState);
}

if (passwordInput) {
  passwordInput.addEventListener('input', () => {
    passwordInput.classList.remove('has-error');
    if (passwordError) passwordError.classList.remove('visible');
    updateSendOtpButtonState();
  });
  passwordInput.addEventListener('change', updateSendOtpButtonState);
}

// Toggle password visibility (show/hide)
if (togglePasswordBtn && passwordInput) {
  const eyeIconShow = togglePasswordBtn.querySelector('.eye-icon-show');
  const eyeIconHide = togglePasswordBtn.querySelector('.eye-icon-hide');

  togglePasswordBtn.addEventListener('click', () => {
    const isPassword = passwordInput.getAttribute('type') === 'password';
    passwordInput.setAttribute('type', isPassword ? 'text' : 'password');
    if (eyeIconShow && eyeIconHide) {
      eyeIconShow.style.display = isPassword ? 'none' : 'block';
      eyeIconHide.style.display = isPassword ? 'block' : 'none';
    }
  });
}

// ==========================================================
// Send OTP Button: Retrieves actual OTP from MySQL via API
// ==========================================================
if (btnSendOtp) {
  btnSendOtp.addEventListener('click', async () => {
    clearAlert();
    const enteredUsername = usernameInput ? usernameInput.value.trim() : '';
    const enteredPassword = passwordInput ? passwordInput.value : '';
    
    if (!enteredUsername) {
      if (usernameInput) usernameInput.classList.add('has-error');
      if (usernameError) {
        usernameError.textContent = 'Please enter your username or email first.';
        usernameError.classList.add('visible');
      }
      showAlert('Please enter your username or email before requesting an OTP.', 'error');
      if (usernameInput) usernameInput.focus();
      triggerShake();
      return;
    }

    if (!enteredPassword) {
      if (passwordInput) passwordInput.classList.add('has-error');
      if (passwordError) {
        passwordError.textContent = 'Please enter your password first.';
        passwordError.classList.add('visible');
      }
      showAlert('Please enter your password before requesting an OTP.', 'error');
      if (passwordInput) passwordInput.focus();
      triggerShake();
      return;
    }

    btnSendOtp.disabled = true;
    btnSendOtp.textContent = 'Sending...';

    try {
      const response = await fetch(`${API_BASE}/api/send-otp`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ 
          usernameOrEmail: enteredUsername,
          password: enteredPassword
        })
      });

      const result = await response.json();

      if (result.success) {
        showAlert(`${result.message} (Demo OTP: ${result.demoOtp})`, 'info');
        if (otpBoxes[0]) otpBoxes[0].focus();
      } else if (result.locked) {
        startLockoutCountdown(result.lockRemainingSeconds || 300);
        triggerShake();
      } else if (result.otpLocked) {
        startOtpLockoutCountdown(result.lockRemainingSeconds || 120);
        triggerShake();
      } else {
        showAlert(result.message || 'Unable to send OTP.', 'error');
        if (result.field === 'username' && usernameInput && usernameError) {
          usernameInput.classList.add('has-error');
          usernameError.textContent = result.message;
          usernameError.classList.add('visible');
          usernameInput.focus();
        } else if (result.field === 'password' && passwordInput && passwordError) {
          passwordInput.classList.add('has-error');
          passwordError.textContent = result.message;
          passwordError.classList.add('visible');
          passwordInput.focus();
        }
        triggerShake();
      }
    } catch (err) {
      console.error('Fetch error:', err);
      showAlert('Unable to connect to server.', 'error');
    } finally {
      if (!isAccountLocked() && !isOtpLocked()) {
        btnSendOtp.textContent = 'Send OTP';
        updateSendOtpButtonState();
      }
    }
  });
}

// ==========================================================
// Form Submission: Validates credentials against MySQL Database
// ==========================================================
if (loginForm) {
  loginForm.addEventListener('submit', async (e) => {
    e.preventDefault();

    // Prevent submission if account or OTP is currently locked out
    if (isAccountLocked()) {
      showAlert('Account is temporarily locked. Please wait for the timer to expire.', 'locked');
      triggerShake();
      return;
    }

    if (isOtpLocked()) {
      showAlert('OTP entry is locked due to 5 failed attempts. Please wait for the timer to expire.', 'locked');
      triggerShake();
      return;
    }

    clearAlert();

    const userVal = usernameInput ? usernameInput.value.trim() : '';
    const passVal = passwordInput ? passwordInput.value : '';
    const otpVal = otpBoxes.map(b => (b ? b.value : '')).join('');

    let hasError = false;

    // 1. Basic Frontend Check
    if (!userVal) {
      if (usernameInput) usernameInput.classList.add('has-error');
      if (usernameError) {
        usernameError.textContent = 'Username or email is required.';
        usernameError.classList.add('visible');
      }
      hasError = true;
    }

    if (!passVal) {
      if (passwordInput) passwordInput.classList.add('has-error');
      if (passwordError) {
        passwordError.textContent = 'Password is required.';
        passwordError.classList.add('visible');
      }
      hasError = true;
    }

    if (otpVal.length < 4) {
      otpBoxes.forEach(b => { 
        if (b && !b.value) b.classList.add('has-error'); 
      });
      if (otpError) {
        otpError.textContent = 'Please enter the complete 4-digit OTP code.';
        otpError.classList.add('visible');
      }
      hasError = true;
    }

    if (hasError) {
      showAlert('Access denied. Please check the highlighted fields.', 'error');
      triggerShake();
      return;
    }

    // 2. Send to MySQL Backend API for verification
    if (btnLogin) {
      btnLogin.disabled = true;
      btnLogin.textContent = 'Verifying with Database...';
    }

    try {
      const response = await fetch(`${API_BASE}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          usernameOrEmail: userVal,
          password: passVal,
          otp: otpVal
        })
      });

      const result = await response.json();

      if (result.success) {
        // Login successful!
        stopLockoutCountdown();
        stopOtpLockoutCountdown();
        showAlert(result.message, 'success');
        if (btnLogin) {
          btnLogin.textContent = 'Redirecting...';
          btnLogin.style.opacity = '0.8';
        }

        // Save Admin session and JWT token in browser
        if (result.token) {
          sessionStorage.setItem('tres_marias_token', result.token);
        }
        sessionStorage.setItem('tres_marias_admin_logged_in', 'true');
        sessionStorage.setItem('tres_marias_admin_user', JSON.stringify(result.user));

        setTimeout(() => {
          window.location.replace('dashboard.html');
        }, 600);
        return;
      }

      // Handle Lockout states if returned
      if (result.locked) {
        startLockoutCountdown(result.lockRemainingSeconds || 300);
      } else if (result.otpLocked) {
        startOtpLockoutCountdown(result.lockRemainingSeconds || 120);
      } else {
        if (btnLogin) {
          btnLogin.disabled = false;
          btnLogin.textContent = 'Log In';
        }
      }

      showAlert(result.message, (result.locked || result.otpLocked) ? 'locked' : 'error');
      triggerShake();

      // Highlight invalid fields
      if (result.field === 'both') {
        // Highlight BOTH password and OTP fields simultaneously
        if (passwordInput) {
          passwordInput.classList.add('has-error');
        }
        if (passwordError) {
          passwordError.textContent = result.passwordMessage || 'Incorrect password.';
          passwordError.classList.add('visible');
        }

        otpBoxes.forEach(b => { if (b) b.classList.add('has-error'); });
        if (otpError) {
          otpError.textContent = result.otpMessage || 'Invalid OTP code.';
          otpError.classList.add('visible');
        }
        if (passwordInput) passwordInput.focus();

      } else if (result.field === 'username') {
        if (usernameInput) {
          usernameInput.classList.add('has-error');
          usernameInput.focus();
        }
        if (usernameError) {
          usernameError.textContent = result.message;
          usernameError.classList.add('visible');
        }

      } else if (result.field === 'password') {
        if (passwordInput) {
          passwordInput.classList.add('has-error');
          passwordInput.focus();
        }
        if (passwordError) {
          passwordError.textContent = result.passwordMessage || result.message;
          passwordError.classList.add('visible');
        }

      } else if (result.field === 'otp') {
        otpBoxes.forEach(b => { if (b) b.classList.add('has-error'); });
        if (otpError) {
          otpError.textContent = result.otpMessage || result.message;
          otpError.classList.add('visible');
        }
        if (otpBoxes[0] && !isOtpLocked()) otpBoxes[0].focus();
      }

    } catch (err) {
      console.error('Fetch error:', err);
      if (btnLogin && !isAccountLocked() && !isOtpLocked()) {
        btnLogin.disabled = false;
        btnLogin.textContent = 'Log In';
      }
      showAlert('Unable to connect to MySQL Backend Server on port 3000. Please ensure the server is running.', 'error');
      triggerShake();
    } finally {
      if (!isAccountLocked() && !isOtpLocked()) {
        if (btnLogin && btnLogin.textContent === 'Verifying with Database...') {
          btnLogin.disabled = false;
          btnLogin.textContent = 'Log In';
        }
      }
    }
  });
}
