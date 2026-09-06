/**
 * TRES MARIAS ADMIN - BACKEND API SERVER
 * File: server.js
 * Description: Express.js server connecting to MySQL for Admin Login & OTP.  
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./database/db');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'tres_marias_c4t3r1ng_s3cur3_jwt_t0k3n_k3y_9824_vps_2026';

// Middlewares
app.set('trust proxy', true);
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Root landing page route: direct entry point to logo landing page
app.get('/', (req, res) => {
  res.redirect('/pages/logo.html');
});

// Serve frontend static files (HTML, CSS, JS, Images)
// Prevent browsers from caching sensitive assets (Login, Dashboard, JS logic)
app.use(express.static(path.join(__dirname), {
  setHeaders: (res, filePath) => {
    if (filePath.endsWith('.html') || filePath.endsWith('.js') || filePath.endsWith('.css')) {
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
// 2. CHECK LOCKOUT STATUS ENDPOINT (POST & GET /api/check-lockout)
// ==========================================================
const handleCheckLockout = async (req, res) => {
  try {
    const rawVal = req.body?.usernameOrEmail || req.query?.usernameOrEmail || req.query?.email;
    const usernameOrEmail = rawVal ? rawVal.trim() : '';
    if (!usernameOrEmail) {
      return res.json({ locked: false, otpLocked: false });
    }

    const [rows] = await db.query(
      `SELECT user_id, failed_login_attempts, lockout_until, failed_otp_attempts, otp_lockout_until 
       FROM users 
       WHERE (email = ? OR full_name = ?) 
       LIMIT 1`,
      [usernameOrEmail, usernameOrEmail]
    );

    if (rows.length === 0) {
      return res.json({ locked: false, otpLocked: false });
    }

    const user = rows[0];
    const now = Date.now();
    let isAccountLocked = false;
    let accountLockRemaining = 0;
    let isOtpLocked = false;
    let otpLockRemaining = 0;

    // Check account lockout (5-minute lock after 5 failed passwords)
    if (user.lockout_until) {
      const lockExpiry = new Date(user.lockout_until).getTime();
      if (lockExpiry > now) {
        isAccountLocked = true;
        accountLockRemaining = Math.ceil((lockExpiry - now) / 1000);
      } else {
        await db.query(
          'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE user_id = ?',
          [user.user_id]
        );
      }
    }

    // Check OTP lockout (2-minute lock after 5 failed OTP attempts per REQ-007)
    if (user.otp_lockout_until) {
      const otpLockExpiry = new Date(user.otp_lockout_until).getTime();
      if (otpLockExpiry > now) {
        isOtpLocked = true;
        otpLockRemaining = Math.ceil((otpLockExpiry - now) / 1000);
      } else {
        await db.query(
          'UPDATE users SET failed_otp_attempts = 0, otp_lockout_until = NULL WHERE user_id = ?',
          [user.user_id]
        );
      }
    }

    if (isAccountLocked) {
      return res.json({
        locked: true,
        lockRemainingSeconds: accountLockRemaining,
        message: `Account is temporarily locked due to 5 failed login attempts. Try again in ${formatRemainingTime(accountLockRemaining)}.`
      });
    }

    if (isOtpLocked) {
      return res.json({
        locked: false,
        otpLocked: true,
        otpLockRemainingSeconds: otpLockRemaining,
        message: `OTP entry is locked due to 5 failed OTP attempts. Try again in ${formatRemainingTime(otpLockRemaining)}.`
      });
    }

    return res.json({ locked: false, otpLocked: false });
  } catch (err) {
    return res.json({ locked: false, otpLocked: false });
  }
};

app.post('/api/check-lockout', handleCheckLockout);
app.get('/api/check-lockout', handleCheckLockout);

// ==========================================================
// 3. SEND OTP ENDPOINT (POST /api/send-otp)
// ==========================================================
app.post('/api/send-otp', async (req, res) => {
  try {
    const { usernameOrEmail, email, password } = req.body;
    const accountIdentifier = (usernameOrEmail || email || '').trim();

    if (!accountIdentifier) {
      return res.status(400).json({ 
        success: false, 
        field: 'username',
        message: 'Please enter your username or email first.' 
      });
    }

    if (!password) {
      return res.status(400).json({ 
        success: false, 
        field: 'password',
        message: 'Please enter your password before requesting an OTP.' 
      });
    }

    // Find admin in the database
    const [users] = await db.query(
      `SELECT user_id, full_name, email, password_hash, status, phone_number, role, 
              failed_login_attempts, lockout_until, failed_otp_attempts, otp_lockout_until 
       FROM users 
       WHERE (email = ? OR full_name = ?) AND role IN ('admin', 'staff')
       LIMIT 1`,
      [accountIdentifier, accountIdentifier]
    );

    if (users.length === 0) {
      return res.status(404).json({ 
        success: false, 
        field: 'username',
        message: 'No Admin account found with that username or email.' 
      });
    }

    const admin = users[0];
    const now = Date.now();

    // Check account status
    if (admin.status !== 'active') {
      return res.status(403).json({ 
        success: false, 
        message: 'This account is deactivated. Please contact management.' 
      });
    }

    // Check if account is currently locked out (Password brute-force: 5 minutes)
    if (admin.lockout_until) {
      const lockExpiry = new Date(admin.lockout_until).getTime();

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
        admin.failed_login_attempts = 0;
        admin.lockout_until = null;
      }
    }

    // Check if OTP entry is currently locked out (5 failed OTP attempts - 2-minute lockout per REQ-007)
    if (admin.otp_lockout_until) {
      const otpLockExpiry = new Date(admin.otp_lockout_until).getTime();

      if (otpLockExpiry > now) {
        const remainingSeconds = Math.ceil((otpLockExpiry - now) / 1000);
        return res.status(423).json({
          success: false,
          otpLocked: true,
          lockRemainingSeconds: remainingSeconds,
          message: `OTP entry is locked due to 5 consecutive failed OTP attempts. Please try again in ${formatRemainingTime(remainingSeconds)}.`
        });
      } else {
        // OTP Lockout expired; reset OTP lockout state
        await db.query(
          'UPDATE users SET failed_otp_attempts = 0, otp_lockout_until = NULL WHERE user_id = ?',
          [admin.user_id]
        );
        admin.failed_otp_attempts = 0;
        admin.otp_lockout_until = null;
      }
    }

    // Validate password
    let isPasswordValid = false;
    if (admin.password_hash && (admin.password_hash.startsWith('$2y$') || admin.password_hash.startsWith('$2a$') || admin.password_hash.startsWith('$2b$'))) {
      const normalizedHash = admin.password_hash.replace('$2y$', '$2a$');
      isPasswordValid = await bcrypt.compare(password, normalizedHash);
    } else if (admin.password_hash && admin.password_hash === password) {
      // Plain-text development fallback
      isPasswordValid = true;
    }

    if (!isPasswordValid) {
      const newAttempts = (admin.failed_login_attempts || 0) + 1;

      if (newAttempts >= 5) {
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?, lockout_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE) 
           WHERE user_id = ?`,
          [newAttempts, admin.user_id]
        );

        console.warn(`🔒 [ACCOUNT LOCKED via Send OTP] Admin "${admin.full_name}" (${admin.email}) locked for 5 minutes after 5 failed password attempts.`);

        return res.status(423).json({
          success: false,
          locked: true,
          lockRemainingSeconds: 300,
          field: 'password',
          passwordMessage: 'Account locked! You have exceeded 5 failed login attempts. Access is locked for 5 minutes.',
          message: 'Account locked! You have exceeded 5 failed login attempts. Access is locked for 5 minutes.'
        });
      } else {
        await db.query(
          'UPDATE users SET failed_login_attempts = ? WHERE user_id = ?',
          [newAttempts, admin.user_id]
        );

        const attemptsRemaining = 5 - newAttempts;
        const msg = `Incorrect password. ${attemptsRemaining} attempt${attemptsRemaining > 1 ? 's' : ''} remaining before account lockout.`;
        return res.status(401).json({
          success: false,
          field: 'password',
          attemptsRemaining: attemptsRemaining,
          passwordMessage: msg,
          message: msg
        });
      }
    }

    // Password is valid! Generate a new 4-digit OTP code (Example: 4821)
    const newOtp = Math.floor(1000 + Math.random() * 9000).toString();

    // Save the new OTP to the MySQL database (valid for 5 minutes per REQ-004)
    await db.query(
      `UPDATE users 
       SET otp_code = ?, otp_expires_at = DATE_ADD(NOW(), INTERVAL 5 MINUTE) 
       WHERE user_id = ?`,
      [newOtp, admin.user_id]
    );

    console.log(`[OTP GENERATED] for Admin ${admin.email}: ${newOtp} (Expires in 5 minutes)`);

    return res.json({
      success: true,
      message: `OTP sent to the account of ${admin.full_name}. Valid for 5 minutes.`,
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
      `SELECT user_id, full_name, email, password_hash, role, otp_code, otp_expires_at, status, 
              failed_login_attempts, lockout_until, failed_otp_attempts, otp_lockout_until 
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

    // 4a. Check Account Lockout Status (Password brute-force: 5 minutes per user specification)
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

    // 4b. Check OTP Lockout Status (REQ-007: 2 minutes lock after 5 failed OTP attempts)
    if (user.otp_lockout_until) {
      const otpLockExpiry = new Date(user.otp_lockout_until).getTime();
      const now = Date.now();

      if (otpLockExpiry > now) {
        const remainingSeconds = Math.ceil((otpLockExpiry - now) / 1000);
        return res.status(423).json({
          success: false,
          otpLocked: true,
          lockRemainingSeconds: remainingSeconds,
          field: 'otp',
          message: `OTP entry is temporarily locked due to 5 consecutive failed OTP attempts. Please try again in ${formatRemainingTime(remainingSeconds)}.`
        });
      } else {
        // OTP lock period has expired, reset counter
        await db.query(
          'UPDATE users SET failed_otp_attempts = 0, otp_lockout_until = NULL WHERE user_id = ?',
          [user.user_id]
        );
        user.failed_otp_attempts = 0;
        user.otp_lockout_until = null;
      }
    }

    // 5. Check Password Validity
    let isPasswordValid = false;
    if (user.password_hash && (user.password_hash.startsWith('$2y$') || user.password_hash.startsWith('$2a$') || user.password_hash.startsWith('$2b$'))) {
      const normalizedHash = user.password_hash.replace('$2y$', '$2a$');
      isPasswordValid = await bcrypt.compare(password, normalizedHash);
    } else if (user.password_hash && user.password_hash === password) {
      // Fallback for plain-text testing/development in phpMyAdmin
      isPasswordValid = true;
    }

    // 6. Check OTP Validity and Expiration (REQ-004: 5-minute expiration limit)
    let isOtpValid = false;
    let isOtpExpired = false;
    if (user.otp_expires_at && new Date(user.otp_expires_at).getTime() < Date.now()) {
      isOtpExpired = true;
    } else if (user.otp_code && user.otp_code.trim() === otp.trim()) {
      isOtpValid = true;
    }

    // CASE A: BOTH Password and OTP are INVALID
    if (!isPasswordValid && !isOtpValid) {
      const newPasswordAttempts = (user.failed_login_attempts || 0) + 1;
      const newOtpAttempts = (user.failed_otp_attempts || 0) + 1;

      const isPasswordLocked = newPasswordAttempts >= 5;
      const isOtpLocked = newOtpAttempts >= 5;

      // Update both attempt counters in MySQL
      if (isPasswordLocked && isOtpLocked) {
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?, lockout_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE),
               failed_otp_attempts = ?, otp_lockout_until = DATE_ADD(NOW(), INTERVAL 2 MINUTE) 
           WHERE user_id = ?`,
          [newPasswordAttempts, newOtpAttempts, user.user_id]
        );
      } else if (isPasswordLocked) {
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?, lockout_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE),
               failed_otp_attempts = ? 
           WHERE user_id = ?`,
          [newPasswordAttempts, newOtpAttempts, user.user_id]
        );
      } else if (isOtpLocked) {
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?,
               failed_otp_attempts = ?, otp_lockout_until = DATE_ADD(NOW(), INTERVAL 2 MINUTE) 
           WHERE user_id = ?`,
          [newPasswordAttempts, newOtpAttempts, user.user_id]
        );
      } else {
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?, failed_otp_attempts = ? 
           WHERE user_id = ?`,
          [newPasswordAttempts, newOtpAttempts, user.user_id]
        );
      }

      const passRemaining = Math.max(0, 5 - newPasswordAttempts);
      const otpRemaining = Math.max(0, 5 - newOtpAttempts);

      const otpMsg = isOtpExpired
        ? 'OTP code has expired (5-minute limit). Please request a new code.'
        : (!user.otp_code 
            ? 'No active OTP found. Please click "Send OTP" first.'
            : `Invalid OTP code. ${otpRemaining} attempt${otpRemaining !== 1 ? 's' : ''} remaining before OTP lockout.`);

      const passMsg = isPasswordLocked
        ? 'Account locked! 5 failed password attempts reached. Locked for 5 minutes.'
        : `Incorrect password. ${passRemaining} attempt${passRemaining !== 1 ? 's' : ''} remaining before account lockout.`;

      if (isPasswordLocked) {
        return res.status(423).json({
          success: false,
          field: 'both',
          locked: true,
          otpLocked: isOtpLocked,
          lockRemainingSeconds: 300,
          passwordMessage: passMsg,
          otpMessage: otpMsg,
          message: 'Account locked due to 5 failed login attempts.'
        });
      }

      if (isOtpLocked) {
        return res.status(423).json({
          success: false,
          field: 'both',
          locked: false,
          otpLocked: true,
          lockRemainingSeconds: 120,
          passwordMessage: passMsg,
          otpMessage: otpMsg,
          message: 'OTP entry locked due to 5 failed OTP attempts. Locked for 2 minutes.'
        });
      }

      return res.status(401).json({
        success: false,
        field: 'both',
        passwordMessage: passMsg,
        otpMessage: otpMsg,
        passwordAttemptsRemaining: passRemaining,
        otpAttemptsRemaining: otpRemaining,
        message: 'Incorrect password and invalid OTP code. Please check both fields.'
      });
    }

    // CASE B: ONLY Password is INVALID
    if (!isPasswordValid) {
      const newAttempts = (user.failed_login_attempts || 0) + 1;

      if (newAttempts >= 5) {
        await db.query(
          `UPDATE users 
           SET failed_login_attempts = ?, lockout_until = DATE_ADD(NOW(), INTERVAL 5 MINUTE) 
           WHERE user_id = ?`,
          [newAttempts, user.user_id]
        );

        console.warn(`🔒 [ACCOUNT LOCKED] Admin "${user.full_name}" (${user.email}) locked for 5 minutes after 5 failed password attempts.`);

        return res.status(423).json({
          success: false,
          locked: true,
          lockRemainingSeconds: 300,
          field: 'password',
          passwordMessage: 'Account locked! You have exceeded 5 failed login attempts. Access is locked for 5 minutes.',
          message: 'Account locked! You have exceeded 5 failed login attempts. Access is locked for 5 minutes.'
        });
      } else {
        await db.query(
          'UPDATE users SET failed_login_attempts = ? WHERE user_id = ?',
          [newAttempts, user.user_id]
        );

        const attemptsRemaining = 5 - newAttempts;
        const msg = `Incorrect password. ${attemptsRemaining} attempt${attemptsRemaining > 1 ? 's' : ''} remaining before account lockout.`;
        return res.status(401).json({
          success: false,
          field: 'password',
          attemptsRemaining: attemptsRemaining,
          passwordMessage: msg,
          message: msg
        });
      }
    }

    // CASE C: ONLY OTP is INVALID
    if (!isOtpValid) {
      const newOtpAttempts = (user.failed_otp_attempts || 0) + 1;

      if (newOtpAttempts >= 5) {
        await db.query(
          `UPDATE users 
           SET failed_otp_attempts = ?, otp_lockout_until = DATE_ADD(NOW(), INTERVAL 2 MINUTE) 
           WHERE user_id = ?`,
          [newOtpAttempts, user.user_id]
        );

        console.warn(`🔒 [OTP LOCKED] Admin "${user.full_name}" (${user.email}) OTP entry locked for 2 minutes after 5 failed OTP attempts.`);

        return res.status(423).json({
          success: false,
          otpLocked: true,
          lockRemainingSeconds: 120,
          field: 'otp',
          otpMessage: 'OTP entry locked! You have exceeded 5 failed OTP attempts. OTP entry is locked for 2 minutes.',
          message: 'OTP entry locked! You have exceeded 5 failed OTP attempts. OTP entry is locked for 2 minutes.'
        });
      } else {
        await db.query(
          'UPDATE users SET failed_otp_attempts = ? WHERE user_id = ?',
          [newOtpAttempts, user.user_id]
        );

        const otpAttemptsRemaining = 5 - newOtpAttempts;
        const msg = isOtpExpired
          ? 'OTP code has expired (5-minute expiration limit). Please click "Send OTP" to request a new code.'
          : (!user.otp_code 
              ? 'No active OTP found. Please click "Send OTP" to receive your 4-digit code.'
              : `Invalid OTP code. ${otpAttemptsRemaining} attempt${otpAttemptsRemaining > 1 ? 's' : ''} remaining before OTP lockout.`);

        return res.status(401).json({ 
          success: false, 
          field: 'otp', 
          expired: isOtpExpired,
          attemptsRemaining: otpAttemptsRemaining,
          otpMessage: msg,
          message: msg 
        });
      }
    }

    // 7. Login successful! Reset failed attempts, clear lockouts, and clear OTP to prevent reuse
    await db.query(
      `UPDATE users 
       SET last_login = NOW(), 
           failed_login_attempts = 0, 
           lockout_until = NULL,
           failed_otp_attempts = 0,
           otp_lockout_until = NULL,
           otp_code = NULL,
           otp_expires_at = NULL
       WHERE user_id = ?`,
      [user.user_id]
    );

    console.log(`🎉 [SUCCESSFUL LOGIN] Admin "${user.full_name}" (${user.email}) logged in successfully.`);

    // Generate signed JWT token (valid for 8 hours)
    const token = jwt.sign(
      {
        id: user.user_id,
        name: user.full_name,
        email: user.email,
        role: user.role
      },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    return res.json({
      success: true,
      message: 'Login successful! Redirecting to Dashboard...',
      token: token,
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

// ==========================================================
// 5. VERIFY SESSION ENDPOINT (GET /api/verify-session)
// ==========================================================
app.get('/api/verify-session', (req, res) => {
  const authHeader = req.headers['authorization'];
  if (!authHeader) {
    return res.status(401).json({
      valid: false,
      message: 'Access denied. No authentication token provided.'
    });
  }

  const parts = authHeader.split(' ');
  const token = parts.length === 2 && parts[0] === 'Bearer' ? parts[1] : authHeader;

  if (!token) {
    return res.status(401).json({
      valid: false,
      message: 'Access denied. Malformed authorization token.'
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    console.log(`[SESSION VERIFIED] Active session valid for user: ${decoded.username || decoded.email || decoded.id || 'admin'}`);
    return res.json({
      valid: true,
      message: 'Session is active and valid.',
      user: decoded
    });
  } catch (err) {
    console.warn(`[SESSION REJECTED] JWT Verification failed: ${err.name} - ${err.message}`);
    if (err.name === 'TokenExpiredError') {
      return res.status(401).json({
        valid: false,
        expired: true,
        message: 'Session has expired. Please log in again.'
      });
    }
    return res.status(401).json({
      valid: false,
      message: 'Invalid session token. Access denied.'
    });
  }
});

// Landing page route (redirects root to logo landing page)
app.get('/', (req, res) => {
  res.redirect('/pages/logo.html');
});

// Start server
app.listen(PORT, () => {
  console.log(`Tres Marias Admin Server running at: http://localhost:${PORT}`);
  console.log(`Landing Page URL: http://localhost:${PORT}/pages/logo.html`);
});
