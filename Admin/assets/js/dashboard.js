/**
 * TRES MARIAS CATERING SERVICES - ADMIN DASHBOARD SCRIPT
 * File: assets/js/dashboard.js
 * Description: Core logic for the Dashboard UI (Auth guard, Sidebar toggle, Logout, Search bar).
 */

// Dynamic API Base: Works when opened via file:/// or other local ports, falls back to http://localhost:3000
const API_BASE = (window.location.protocol === 'file:' || !window.location.origin.includes(':3000'))
  ? 'http://localhost:3000'
  : '';

// ==================== 0. AUTHENTICATION ROUTE GUARD & HISTORY TRAP ====================
// Protect dashboard against direct URL visits and console tampering using JWT
// Enforces REQ-008: Automatic session termination upon 15 minutes of inactivity or window close
const INACTIVITY_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutes in milliseconds
const LAST_ACTIVITY_KEY = 'tres_marias_admin_last_activity';

function terminateInactivitySession() {
  console.warn('[Session Security] Session terminated due to 15 minutes of inactivity.');
  sessionStorage.removeItem('tres_marias_token');
  sessionStorage.removeItem('tres_marias_admin_logged_in');
  sessionStorage.removeItem('tres_marias_admin_user');
  sessionStorage.removeItem(LAST_ACTIVITY_KEY);
  window.location.replace('login.html?reason=inactivity');
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

  // Listen to user activity across the document
  const activityEvents = ['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'];
  activityEvents.forEach((evt) => {
    window.addEventListener(evt, recordUserActivity, { passive: true });
  });

  // Periodically check elapsed inactivity time every 5 seconds
  setInterval(checkInactivityTimeout, 5000);

  // Check immediately when user switches back to this tab or window
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'visible') {
      checkInactivityTimeout();
    }
  });
  window.addEventListener('focus', checkInactivityTimeout);
}

async function verifyAuthentication() {
  // First check if already timed out by inactivity
  checkInactivityTimeout();

  const token = sessionStorage.getItem('tres_marias_token');
  const isLoggedIn = sessionStorage.getItem('tres_marias_admin_logged_in');

  if (!token || isLoggedIn !== 'true') {
    // Missing token or session flag: redirect directly to login page
    sessionStorage.removeItem('tres_marias_token');
    sessionStorage.removeItem('tres_marias_admin_logged_in');
    sessionStorage.removeItem('tres_marias_admin_user');
    sessionStorage.removeItem(LAST_ACTIVITY_KEY);
    window.location.replace('login.html');
    return;
  }

  // Cryptographically verify token with Express backend
  try {
    const response = await fetch(`${API_BASE}/api/verify-session`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!response.ok) {
      console.warn('[Session Security] Invalid or expired JWT token. Redirecting to login.');
      sessionStorage.removeItem('tres_marias_token');
      sessionStorage.removeItem('tres_marias_admin_logged_in');
      sessionStorage.removeItem('tres_marias_admin_user');
      sessionStorage.removeItem(LAST_ACTIVITY_KEY);
      window.location.replace('login.html');
    } else {
      const data = await response.json();
      if (!data.valid) {
        sessionStorage.removeItem('tres_marias_token');
        sessionStorage.removeItem('tres_marias_admin_logged_in');
        sessionStorage.removeItem('tres_marias_admin_user');
        sessionStorage.removeItem(LAST_ACTIVITY_KEY);
        window.location.replace('login.html');
      } else {
        // Initialize or update activity timestamp on successful verification
        if (!sessionStorage.getItem(LAST_ACTIVITY_KEY)) {
          sessionStorage.setItem(LAST_ACTIVITY_KEY, Date.now().toString());
        }
      }
    }
  } catch (err) {
    console.error('[Session Security] Error checking session token:', err);
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
      // Clear authenticated session keys and JWT token
      sessionStorage.removeItem('tres_marias_token');
      sessionStorage.removeItem('tres_marias_admin_logged_in');
      sessionStorage.removeItem('tres_marias_admin_user');
      sessionStorage.removeItem(LAST_ACTIVITY_KEY);

      // Redirect to login screen
      window.location.replace('login.html');
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
