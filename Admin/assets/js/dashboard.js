/**
 * TRES MARIAS CATERING SERVICES - ADMIN DASHBOARD SCRIPT
 * File: assets/js/dashboard.js
 * Description: Core logic for the Dashboard UI (Auth guard, Sidebar toggle, Logout, Search bar).
 */

// Dynamic API Base: Automatically adapts across Localhost, Live Server (custom dev ports), Local Wi-Fi IP, and Production VPS
const API_BASE = (() => {
  if (window.location.protocol === 'file:') {
    return 'http://localhost:3000';
  }
  // When running via local development server on a different port (e.g. Live Server on :5500)
  const host = window.location.hostname;
  const port = window.location.port;
  if ((host === 'localhost' || host === '127.0.0.1') && port !== '3000' && port !== '') {
    return `http://${host}:3000`;
  }
  // In all other cases (running on Node Express port 3000, local Wi-Fi IP, or production VPS domain), use relative path
  return '';
})();

// ==================== 0. AUTHENTICATION ROUTE GUARD & HISTORY TRAP ====================
// Protect dashboard against direct URL visits and console tampering using JWT
// Enforces REQ-008: Automatic session termination upon 15 minutes of inactivity or window close
const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes in milliseconds
const LAST_ACTIVITY_KEY = 'tres_marias_admin_last_activity';

// State to track the verified token in memory and legitimate logout intent
let activeVerifiedToken = sessionStorage.getItem('tres_marias_token');
let isIntentionalLogout = false;

// Helper: Check if token is well-formed JWT (3 dot-separated Base64URL parts) with valid payload
function isJwtStructurallyValid(token) {
  if (!token || typeof token !== 'string') return false;
  const parts = token.trim().split('.');
  if (parts.length !== 3) return false;
  try {
    const base64Url = parts[1];
    const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
    const jsonPayload = decodeURIComponent(
      atob(base64)
        .split('')
        .map((c) => '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2))
        .join('')
    );
    const payload = JSON.parse(jsonPayload);
    if (!payload || typeof payload !== 'object') return false;
    if (payload.exp && (payload.exp * 1000) < Date.now()) return false;
    return true;
  } catch (e) {
    return false;
  }
}

function terminateTamperedSession(reason) {
  if (isIntentionalLogout) return;
  isIntentionalLogout = true;
  console.warn(`[Session Security] Session terminated: ${reason}`);
  try {
    sessionStorage.removeItem('tres_marias_token');
    sessionStorage.removeItem('tres_marias_admin_logged_in');
    sessionStorage.removeItem('tres_marias_admin_user');
    sessionStorage.removeItem(LAST_ACTIVITY_KEY);
  } catch (e) {}
  window.location.replace('login.html?reason=tampered');
}

function terminateInactivitySession() {
  if (isIntentionalLogout) return;
  isIntentionalLogout = true;
  console.warn('[Session Security] Session terminated due to 15 minutes of inactivity.');
  sessionStorage.removeItem('tres_marias_token');
  sessionStorage.removeItem('tres_marias_admin_logged_in');
  sessionStorage.removeItem('tres_marias_admin_user');
  sessionStorage.removeItem(LAST_ACTIVITY_KEY);
  window.location.replace('login.html?reason=inactivity');
}

// Real-Time Storage Tamper Detection (Runs every 300ms + on every user activity)
function checkRealTimeStorageIntegrity() {
  if (isIntentionalLogout) return;

  const currentToken = sessionStorage.getItem('tres_marias_token');
  const isLoggedIn = sessionStorage.getItem('tres_marias_admin_logged_in');

  // Check 1: Credentials were removed or wiped
  if (isLoggedIn !== 'true' || !currentToken) {
    terminateTamperedSession('Session token was removed or deleted from storage.');
    return;
  }

  // Check 2: Token was altered/edited in DevTools compared to verified in-memory token
  if (activeVerifiedToken && currentToken !== activeVerifiedToken) {
    terminateTamperedSession('Session token was modified or altered in storage.');
    return;
  }

  // Check 3: Token is structurally malformed
  if (!isJwtStructurallyValid(currentToken)) {
    terminateTamperedSession('Malformed or corrupted JWT token detected.');
    return;
  }
}

function checkInactivityTimeout() {
  const token = sessionStorage.getItem('tres_marias_token');
  if (!token) return;

  const lastActivity = sessionStorage.getItem(LAST_ACTIVITY_KEY);
  if (!lastActivity) {
    sessionStorage.setItem(LAST_ACTIVITY_KEY, Date.now().toString());
    return;
  }

  const elapsed = Date.now() - parseInt(lastActivity, 10);
  if (elapsed >= INACTIVITY_TIMEOUT_MS) {
    terminateInactivitySession();
  }
}

let lastRecordedTime = Date.now();
function recordUserActivity() {
  checkRealTimeStorageIntegrity();
  const now = Date.now();
  // Throttle updates to sessionStorage to once every 2 seconds
  if (now - lastRecordedTime >= 2000) {
    lastRecordedTime = now;
    sessionStorage.setItem(LAST_ACTIVITY_KEY, now.toString());
  }
}

function initInactivityTracker() {
  // Check immediately
  checkInactivityTimeout();
  checkRealTimeStorageIntegrity();

  // Listen to user activity across the document
  const activityEvents = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'];
  activityEvents.forEach((evt) => {
    window.addEventListener(evt, recordUserActivity, { passive: true });
  });

  // Rapid real-time watchdog: checks storage integrity every 300ms
  setInterval(checkRealTimeStorageIntegrity, 300);

  // Periodically check elapsed inactivity time every 5 seconds
  setInterval(checkInactivityTimeout, 5000);

  // Check immediately when user switches back to this tab or window (e.g. from DevTools or other tab)
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      checkInactivityTimeout();
      checkRealTimeStorageIntegrity();
      verifyAuthentication();
    }
  });
  window.addEventListener('focus', () => {
    checkInactivityTimeout();
    checkRealTimeStorageIntegrity();
    verifyAuthentication();
  });
}

// Intercept JavaScript console tampering directly via Storage prototype
try {
  const _origSetItem = Storage.prototype.setItem;
  const _origRemoveItem = Storage.prototype.removeItem;
  Storage.prototype.setItem = function(key, val) {
    if (this === window.sessionStorage && key === 'tres_marias_token' && activeVerifiedToken && val !== activeVerifiedToken && !isIntentionalLogout) {
      _origSetItem.apply(this, arguments);
      terminateTamperedSession('Session token modified via console script.');
      return;
    }
    return _origSetItem.apply(this, arguments);
  };
  Storage.prototype.removeItem = function(key) {
    if (this === window.sessionStorage && (key === 'tres_marias_token' || key === 'tres_marias_admin_logged_in') && !isIntentionalLogout) {
      _origRemoveItem.apply(this, arguments);
      terminateTamperedSession('Session token deleted via console script.');
      return;
    }
    return _origRemoveItem.apply(this, arguments);
  };
} catch (e) {}

async function verifyAuthentication() {
  checkInactivityTimeout();

  const token = sessionStorage.getItem('tres_marias_token');
  const isLoggedIn = sessionStorage.getItem('tres_marias_admin_logged_in');

  if (!token || isLoggedIn !== 'true' || !isJwtStructurallyValid(token)) {
    terminateTamperedSession('Invalid or malformed session token.');
    return;
  }

  // Cryptographically verify token signature with Express backend
  try {
    const response = await fetch(`${API_BASE}/api/verify-session`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      terminateTamperedSession('Server rejected token verification.');
    } else {
      const data = await response.json();
      if (!data.valid) {
        terminateTamperedSession('Server marked session as invalid.');
      } else {
        // Lock verified token in memory
        activeVerifiedToken = token;
        if (!sessionStorage.getItem(LAST_ACTIVITY_KEY)) {
          sessionStorage.setItem(LAST_ACTIVITY_KEY, Date.now().toString());
        }
      }
    }
  } catch (err) {
    console.error('[Session Security] Error connecting to verification server:', err);
    if (!isJwtStructurallyValid(token)) {
      terminateTamperedSession('Corrupted JWT token structure.');
    }
  }
}
verifyAuthentication();
initInactivityTracker();

// Handle browser Back-Forward Cache (BFCache) when navigating
window.addEventListener('pageshow', (event) => {
  verifyAuthentication();
});

// Prevent browser Back button from navigating back to login
// Keeps the authenticated admin on the dashboard
history.pushState(null, '', window.location.href);
window.addEventListener('popstate', () => {
  history.pushState(null, '', window.location.href);
});

document.addEventListener('DOMContentLoaded', () => {
  initSidebar();
  initSearch();
  initProfileDropdown();
  initNotifications();
});

/* ==================== 1. SIDEBAR TOGGLE ==================== */
function initSidebar() {
  const sidebar = document.getElementById('sidebar');
  const toggleBtn = document.getElementById('sidebar-toggle');

  if (toggleBtn && sidebar) {
    toggleBtn.addEventListener('click', () => {
      sidebar.classList.toggle('collapsed');
      
      // Persist state preference in localStorage
      const isCollapsed = sidebar.classList.contains('collapsed');
      localStorage.setItem('tres_marias_sidebar_collapsed', isCollapsed ? '1' : '0');
    });

    // Restore previous collapsed state if saved
    if (localStorage.getItem('tres_marias_sidebar_collapsed') === '1') {
      sidebar.classList.add('collapsed');
    }
  }
}

/* ==================== 2. GLOBAL SEARCH BAR ==================== */
function initSearch() {
  const searchInput = document.getElementById('global-search-input');
  if (!searchInput) return;

  searchInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      const query = searchInput.value.trim();
      if (query) {
        console.log(`[Dashboard Search] Query: "${query}"`);
      }
    }
  });
}

/* ==================== 3. PROFILE DROPDOWN & TOPBAR LOGOUT ==================== */
function initProfileDropdown() {
  const profileBtn = document.getElementById('profile-menu-btn');
  const dropdown = document.getElementById('profile-dropdown');
  const topbarLogoutBtn = document.getElementById('btn-topbar-logout');

  // Populate dynamic admin name and role from session
  const storedUser = sessionStorage.getItem('tres_marias_admin_user');
  if (storedUser) {
    try {
      const userObj = JSON.parse(storedUser);
      const nameEl = document.getElementById('topbar-admin-name');
      const roleEl = document.getElementById('topbar-admin-role');
      if (nameEl && userObj.name) nameEl.textContent = userObj.name;
      if (roleEl && userObj.role) roleEl.textContent = userObj.role.toUpperCase();
    } catch (e) {
      console.error('Failed to parse user session:', e);
    }
  }

  // Toggle profile dropdown menu
  if (profileBtn && dropdown) {
    profileBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      dropdown.classList.toggle('show');

      // Close notification dropdown if open
      const notifDropdown = document.getElementById('notification-dropdown');
      if (notifDropdown) notifDropdown.classList.remove('open');
    });

    // Close dropdown on outside click
    document.addEventListener('click', (e) => {
      if (!profileBtn.contains(e.target) && !dropdown.contains(e.target)) {
        dropdown.classList.remove('show');
      }
    });
  }

  // Wire logout trigger and confirmation modal
  const logoutModal = document.getElementById('logout-modal');
  const cancelLogoutBtn = document.getElementById('btn-cancel-logout');
  const confirmLogoutBtn = document.getElementById('btn-confirm-logout');

  const openLogoutModal = (e) => {
    if (e) e.preventDefault();
    if (dropdown) dropdown.classList.remove('show');
    if (logoutModal) {
      logoutModal.classList.add('active');
      if (cancelLogoutBtn) cancelLogoutBtn.focus();
    }
  };

  const closeLogoutModal = () => {
    if (logoutModal) {
      logoutModal.classList.remove('active');
    }
  };

  if (topbarLogoutBtn) {
    topbarLogoutBtn.addEventListener('click', openLogoutModal);
  }

  const sidebarLogoutBtn = document.getElementById('btn-sidebar-logout');
  if (sidebarLogoutBtn) {
    sidebarLogoutBtn.addEventListener('click', openLogoutModal);
  }

  if (cancelLogoutBtn) {
    cancelLogoutBtn.addEventListener('click', closeLogoutModal);
  }

  if (logoutModal) {
    // Close on outside backdrop click
    logoutModal.addEventListener('click', (e) => {
      if (e.target === logoutModal) {
        closeLogoutModal();
      }
    });

    // Close on Escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && logoutModal.classList.contains('active')) {
        closeLogoutModal();
      }
    });
  }

  if (confirmLogoutBtn) {
    confirmLogoutBtn.addEventListener('click', () => {
      isIntentionalLogout = true;
      // Clear authenticated session keys and JWT token
      sessionStorage.removeItem('tres_marias_token');
      sessionStorage.removeItem('tres_marias_admin_logged_in');
      sessionStorage.removeItem('tres_marias_admin_user');
      sessionStorage.removeItem(LAST_ACTIVITY_KEY);

      // Redirect to logo screen
      window.location.replace('logo.html');
    });
  }
}

/* ==================== 4. NOTIFICATIONS DROPDOWN ==================== */
function initNotifications() {
  const notifBtn = document.getElementById('btn-notifications');
  const notifDropdown = document.getElementById('notification-dropdown');
  const markReadBtn = document.getElementById('btn-mark-all-read');
  const notifBadge = document.getElementById('notification-badge');

  if (notifBtn && notifDropdown) {
    notifBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      notifDropdown.classList.toggle('open');

      // Close profile dropdown if open
      const profileDropdown = document.getElementById('profile-dropdown');
      if (profileDropdown) profileDropdown.classList.remove('show');
    });

    // Close on outside click
    document.addEventListener('click', (e) => {
      if (!notifBtn.contains(e.target) && !notifDropdown.contains(e.target)) {
        notifDropdown.classList.remove('open');
      }
    });
  }

  if (markReadBtn && notifBadge) {
    markReadBtn.addEventListener('click', () => {
      notifBadge.style.display = 'none';
      notifBadge.textContent = '0';
    });
  }
}
