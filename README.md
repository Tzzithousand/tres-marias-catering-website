# Tres Marias Admin - Management Portal & Backend

Clean, organized frontend architecture paired with an Express.js and MySQL backend for secure admin authentication.

---

## Folder and File Structure

```text
Capstone Website/
└── Admin/
    ├── assets/
    │   ├── css/
    │   │   ├── dashboard.css           # Dashboard layout, topbar, and sidebar styles
    │   │   └── style.css               # Combined stylesheet for logo and login
    │   ├── images/
    │   │   └── logo.jpg                # Official Tres Marias brand logo
    │   └── js/
    │       ├── dashboard.js            # Sidebar toggle and search interactions
    │       └── login.js                # Frontend authentication, OTP auto-advance, and API calls
    ├── database/
    │   ├── db.js                       # MySQL database connection pool (mysql2/promise)
    │   └── schema.sql                  # Database schema (users table, seed admin credentials)
    ├── pages/
    │   ├── dashboard.html              # Admin Dashboard (Sidebar, Top Logo, Search Bar)
    │   ├── login.html                  # Admin Login Screen with OTP verification
    │   └── logo.html                   # Logo Splash Screen (links to login.html)
    ├── index.html                      # Entry point (auto-redirect to pages/logo.html)
    ├── package.json                    # Node dependencies and scripts
    ├── package-lock.json               # Locked dependency tree
    └── server.js                       # Express.js REST API server & static file host
```

---

## Getting Started & Running the Project

### 1. Database Setup (MySQL)

1. Ensure your MySQL server is running on `localhost:3306`.
2. Import `Capstone Website/Admin/database/schema.sql` into your MySQL instance:
   ```bash
   mysql -u root -p < "Capstone Website/Admin/database/schema.sql"
   ```
3. The seed credentials for the admin account:
   - **Email / Username**: `admin@email.com`
   - **Password**: `Password123`
   - **Default OTP**: `1234`

### 2. Backend Server (Express.js)

1. Navigate to the Admin directory and install dependencies:
   ```bash
   cd "Capstone Website/Admin"
   npm install
   ```
2. Start the server:
   ```bash
   npm start
   ```
3. The server starts at `http://localhost:3000` and serves both the API endpoints (`/api/login`, `/api/send-otp`, `/api/health`, `/api/check-lockout`) and static frontend pages.

### 3. Frontend Static Pages

- You can access the application through the running server at `http://localhost:3000/pages/login.html` (or `http://localhost:3000`).
- Alternatively, you can open `index.html` or `pages/logo.html` directly in any modern browser.

---

## Pages Overview

1. **`index.html` (Main Entry Point)**:
   - Located at the root of the `Admin` directory.
   - Automatically redirects to `pages/logo.html`.

2. **`pages/logo.html` (Logo Splash Screen)**:
   - Displays the official logo of **Tres Marias Catering Services** (`assets/images/logo.jpg`).
   - Framed in a modern circle with a gold accent border and soft ambient glow.
   - Clicking the logo navigates to `login.html`.

3. **`pages/login.html` (Admin Login Screen)**:
   - Modern elevated card with gold accents and ambient glow.
   - Connected to `assets/js/login.js` for clean client-side validation and OTP auto-advancing.
   - Requests real-time OTP from the MySQL database via the Express API (`/api/send-otp`) and verifies credentials via (`/api/login`).

4. **`pages/dashboard.html` (Admin Dashboard)**:
   - Minimalist, focused administrative dashboard layout displaying exclusively:
     - **The Sidebar**: Full navigation structure with collapse/expand toggle.
     - **The Top Logo**: Official brand logo and title in the sticky header.
     - **The Search Bar**: Global search bar with responsive focus effects.
