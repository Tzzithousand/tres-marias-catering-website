/**
 * TRES MARIAS ADMIN - BACKEND API SERVER
 * File: server.js
 * Description: Express.js server connecting to MySQL for Admin Login & OTP.  
 */

const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const db = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3000;

// Middlewares
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Serve frontend static files (HTML, CSS, JS, Images)
// Prevent browsers from caching sensitive HTML pages (Login & Dashboard)
app.use(express.static(path.join(__dirname), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
  }
}));

// Helper: Format remaining seconds into human-readable English string
function formatRemainingTime(seconds) {
  const mins = Math.floor(seconds / 60);
  const secs = seconds % 60;
  if (mins > 0) {
    return `${mins} minute${mins > 1 ? 's' : ''} and ${secs} second${secs !== 1 ? 's' : ''}`;
  }
  return `${secs} second${secs !== 1 ? 's' : ''}`;
}

// In-memory IP rate limiter to mitigate automated brute-force attacks
const ipRateLimits = new Map();
const RATE_LIMIT_WINDOW_MS = 5 * 60 * 1000; // 5 minutes
const RATE_LIMIT_MAX_REQUESTS = 30; // 30 requests per 5 minutes per IP

function rateLimiter(req, res, next) {
  const ip = req.ip || (req.connection && req.connection.remoteAddress) || 'unknown-ip';
  const now = Date.now();

  let record = ipRateLimits.get(ip);
  if (!record || (now - record.startTime) > RATE_LIMIT_WINDOW_MS) {
    record = { count: 1, startTime: now };
    ipRateLimits.set(ip, record);
    return next();
  }

  record.count += 1;
  if (record.count > RATE_LIMIT_MAX_REQUESTS) {
    const retryAfterSec = Math.ceil((record.startTime + RATE_LIMIT_WINDOW_MS - now) / 1000);
    return res.status(429).json({
      success: false,
      message: `Too many requests from this IP address. Please try again in ${retryAfterSec} seconds.`
    });
  }

  next();
}

// Apply rate limiter to authentication endpoints
app.use('/api/login', rateLimiter);
app.use('/api/send-otp', rateLimiter);

// ==========================================================
// 1. HEALTH CHECK ENDPOINT
// ==========================================================
app.get('/api/health', async (req, res) => {
  try {
    const [rows] = await db.query('SELECT 1 + 1 AS result');
    res.json({ status: 'online', database: 'connected', time: new Date() });
  } catch (error) {
    res.status(500).json({ status: 'error', database: error.message });
  }
});

// ==========================================================
// 2. CHECK LOCKOUT STATUS ENDPOINT (POST /api/check-lockout)
// ==========================================================
app.post('/api/check-lockout', async (req, res) => {
  try {
    const { usernameOrEmail } = req.body;
    if (!usernameOrEmail) {
      return res.json({ locked: false });
    }

    const [rows] = await db.query(
      `SELECT user_id, failed_login_attempts, lockout_until 
       FROM users 
       WHERE (email = ? OR full_name = ?) 
       LIMIT 1`,
      [usernameOrEmail.trim(), usernameOrEmail.trim()]
    );

    if (rows.length === 0 || !rows[0].lockout_until) {
      return res.json({ locked: false });
    }

    const user = rows[0];
    const lockExpiry = new Date(user.lockout_until).getTime();
    const now = Date.now();

    if (lockExpiry > now) {
      const remainingSeconds = Math.ceil((lockExpiry - now) / 1000);
      return res.json({
        locked: true,
        lockRemainingSeconds: remainingSeconds,
        message: `Account is temporarily locked. Try again in ${formatRemainingTime(remainingSeconds)}.`
      });
    } else {
      // Lockout duration has expired; reset
      await db.query(
        'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = ?',
        [user.user_id]
      );
      return res.json({ locked: false });
    }
  } catch (err) {
    return res.json({ locked: false });
  }
});

// ==========================================================
// 3. SEND OTP ENDPOINT (POST /api/send-otp)
// ==========================================================
app.post('/api/send-otp', async (req, res) => {
  try {
    const { usernameOrEmail } = req.body;

    if (!usernameOrEmail) {
      return res.status(400).json({ 
        success: false, 
        message: 'Please enter your username or email first.' 
      });
    }

    // Find admin in the database
    const [users] = await db.query(
      `SELECT user_id, full_name, email, phone_number, role, lockout_until 
       FROM users 
       WHERE (email = ? OR full_name = ?) AND role IN ('admin', 'staff')
       LIMIT 1`,
      [usernameOrEmail.trim(), usernameOrEmail.trim()]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false, 
        field: 'username',
        message: 'No Admin account found with that username or email.' 
      });
    }

    const admin = users[0];

    // Check if account is currently locked out
    if (admin.lockout_until) {
      const lockExpiry = new Date(admin.lockout_until).getTime();
      const now = Date.now();

      if (lockExpiry > now) {
        const remainingSeconds = Math.ceil((lockExpiry - now) / 1000);
        return res.status(423).json({
          success: false,
          locked: true,
          lockRemainingSeconds: remainingSeconds,
          message: `Account is locked. OTP cannot be requested. Please try again in ${formatRemainingTime(remainingSeconds)}.`
        });
      } else {
        // Lockout expired; reset lockout state
        await db.query(
          'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = ?',
          [admin.user_id]
        );
      }
    }

    // Generate a new 4-digit OTP code (Example: 4821)
    const newOtp = Math.floor(1000 + Math.random() * 9000).toString();

    // Save the new OTP to the MySQL database (valid for 10 minutes)
    await db.query(
      `UPDATE users 
       SET otp_code = ?, otp_expires_at = DATE_ADD(NOW(), INTERVAL 10 MINUTE) 
       WHERE user_id = ?`,
      [newOtp, admin.user_id]
    );

    console.log(`[OTP GENERATED] for Admin ${admin.email}: ${newOtp}`);

    return res.json({
      success: true,
      message: `OTP sent to the account of ${admin.full_name}.`,
      // Return generated OTP in demo mode for quick testing without SMS gateway
      demoOtp: newOtp
    });

  } catch (error) {
    console.error('Error in /api/send-otp:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'A database server error occurred: ' + error.message 
    });
  }
});

// ==========================================================
// 4. LOGIN ENDPOINT (POST /api/login)
// ==========================================================
app.post('/api/login', async (req, res) => {
  try {
    const { usernameOrEmail, password, otp } = req.body;

    // Basic input validation
    if (!usernameOrEmail) {
      return res.status(400).json({ 
        success: false, 
        field: 'username', 
        message: 'Username or email is required.' 
      });
    }
    if (!password) {
      return res.status(400).json({ 
        success: false, 
        field: 'password', 
        message: 'Password is required.' 
      });
    }
    if (!otp) {
      return res.status(400).json({ 
        success: false, 
        field: 'otp', 
        message: 'Please enter the 4-digit OTP code.' 
      });
    }

    // 1. Query MySQL database for user
    const [rows] = await db.query(
      `SELECT user_id, full_name, email, password_hash, role, otp_code, otp_expires_at, status, failed_login_attempts, lockout_until 
       FROM users 
       WHERE (email = ? OR full_name = ?) 
       LIMIT 1`,
      [usernameOrEmail.trim(), usernameOrEmail.trim()]
    );

    if (rows.length === 0) {
      return res.status(401).json({ 
        success: false, 
        field: 'username', 
        message: 'Invalid username or email.' 
      });
    }

    const user = rows[0];

    // 2. Verify if role is admin or staff
    if (user.role !== 'admin' && user.role !== 'staff') {
      return res.status(403).json({ 
        success: false, 
        field: 'username', 
        message: 'Access denied: This account is not an Admin.' 
      });
    }

    // 3. Verify if account is active
    if (user.status !== 'active') {
      return res.status(403).json({ 
        success: false, 
        message: 'This account is deactivated. Please contact management.' 
      });
    }

    // 4. Check Account Lockout Status
    if (user.lockout_until) {
      const lockExpiry = new Date(user.lockout_until).getTime();
      const now = Date.now();

      if (lockExpiry > now) {
        const remainingSeconds = Math.ceil((lockExpiry - now) / 1000);
        return res.status(423).json({
          success: false,
          locked: true,
          lockRemainingSeconds: remainingSeconds,
          message: `Account is temporarily locked due to 5 consecutive failed login attempts. Please try again in ${formatRemainingTime(remainingSeconds)}.`
        });
      } else {
        // Lock period has expired, automatically reset counter
        await db.query(
          'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = ?',
          [user.user_id]
        );
        user.failed_login_attempts = 0;
        user.lockout_until = null;
      }
    }

    // 5. Verify Password using bcrypt hash
    let isPasswordValid = false;
    if (user.password_hash && (user.password_hash.startsWith('$2y$') || user.password_hash.startsWith('$2a$') || user.password_hash.startsWith('$2b$'))) {
      // Convert PHP $2y$ blowfish to $2a$ for bcryptjs compatibility if from phpMyAdmin
      const normalizedHash = user.password_hash.replace('$2y$', '$2a$');
      isPasswordValid = await bcrypt.compare(password, normalizedHash);
    }

    // If password is incorrect: track failed attempts and trigger lockout at 5 attempts
    if (!isPasswordValid) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;

      if (newAttempts >= 5) {
        // 5 consecutive failed attempts: lock account for 5 minutes
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?, lockout_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE) 
           WHERE user_id = ?`,
          [newAttempts, user.user_id]
        );

        console.warn(`🔒 [ACCOUNT LOCKED] Admin "${user.full_name}" (${user.email}) locked for 5 minutes after 5 failed attempts.`);

        return res.status(423).json({
          success: false,
          locked: true,
          lockRemainingSeconds: 300,
          field: 'password',
          message: 'Account locked! You have exceeded 5 failed login attempts. Access is locked for 5 minutes.'
        });
      } else {
        // Increment failed attempts and return remaining attempts
        await db.query(
          'UPDATE users SET failed_login_attempts = ? WHERE user_id = ?',
          [newAttempts, user.user_id]
        );

        const attemptsRemaining = 5 - newAttempts;
        return res.status(401).json({
          success: false,
          field: 'password',
          attemptsRemaining: attemptsRemaining,
          message: `Incorrect password. ${attemptsRemaining} attempt${attemptsRemaining > 1 ? 's' : ''} remaining before account lockout.`
        });
      }
    }

    // 6. Verify 4-digit OTP Code
    if (!user.otp_code || user.otp_code.trim() !== otp.trim()) {
      return res.status(401).json({ 
        success: false, 
        field: 'otp', 
        message: 'Invalid OTP code.' 
      });
    }

    // 7. Login successful! Reset failed attempts and clear lockout
    await db.query(
      `UPDATE users 
       SET last_login = NOW(), failed_login_attempts = 0, lockout_until = NULL 
       WHERE user_id = ?`,
      [user.user_id]
    );

    console.log(`🎉 [SUCCESSFUL LOGIN] Admin "${user.full_name}" (${user.email}) logged in successfully.`);

    return res.json({
      success: true,
      message: 'Login successful! Redirecting to Dashboard...',
      user: {
        id: user.user_id,
        name: user.full_name,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Error in /api/login:', error);
    return res.status(500).json({ 
      success: false, 
      message: 'A server error occurred: ' + error.message 
    });
  }
});

// Fallback route for index
app.get('/', (req, res) => {
  res.redirect('/pages/login.html');
});

// Start server
app.listen(PORT, () => {
  console.log(`Tres Marias Admin Server running at: http://localhost:${PORT}`);
  console.log(`Login Page URL: http://localhost:${PORT}/pages/login.html`);
});
