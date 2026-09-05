/**
 * TRES MARIAS CATERING SERVICES - ADMIN DASHBOARD SCRIPT
 * File: assets/js/dashboard.js
 * Description: Core logic for the Dashboard UI (Auth guard, Sidebar toggle, Logout, Search bar).
 */

// ==================== 0. AUTHENTICATION ROUTE GUARD & HISTORY TRAP ====================
// Protect dashboard against direct URL visits by unauthorized users
function verifyAuthentication() {
  const isLoggedIn = sessionStorage.getItem('tres_marias_admin_logged_in');
  if (isLoggedIn !== 'true') {
    // Not authenticated: redirect directly to login page
    window.location.replace('login.html');
  }
}
verifyAuthentication();

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

  // Wire topbar and sidebar logout buttons
  const handleLogout = (e) => {
    e.preventDefault();
    const confirmed = window.confirm('Are you sure you want to log out of the Admin Dashboard?');
    if (confirmed) {
      // Clear authenticated session keys
      sessionStorage.removeItem('tres_marias_admin_logged_in');
      sessionStorage.removeItem('tres_marias_admin_user');

      // Redirect to login screen
      window.location.replace('login.html');
    }
  };

  if (topbarLogoutBtn) {
    topbarLogoutBtn.addEventListener('click', handleLogout);
  }

  const sidebarLogoutBtn = document.getElementById('btn-sidebar-logout');
  if (sidebarLogoutBtn) {
    sidebarLogoutBtn.addEventListener('click', handleLogout);
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
