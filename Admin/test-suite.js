/**
 * TRES MARIAS ADMIN - AUTOMATED END-TO-END TEST SUITE
 * File: test-suite.js
 * Description: Automated test runner covering all endpoints, validations,
 *              lockout logic, OTP lifecycles, and session verification.
 * 
 * Run via: node test-suite.js  OR  npm test
 */

const db = require('./database/db');

const BASE_URL = process.env.BASE_URL || 'http://localhost:3000';
let passedCount = 0;
let failedCount = 0;

// Color formatting helpers for terminal output
const green = (text) => `\x1b[32m${text}\x1b[0m`;
const red = (text) => `\x1b[31m${text}\x1b[0m`;
const yellow = (text) => `\x1b[33m${text}\x1b[0m`;
const cyan = (text) => `\x1b[36m${text}\x1b[0m`;
const bold = (text) => `\x1b[1m${text}\x1b[0m`;

function assert(condition, message) {
  if (condition) {
    passedCount++;
    console.log(`  ${green('✓ PASS')} - ${message}`);
  } else {
    failedCount++;
    console.log(`  ${red('✗ FAIL')} - ${message}`);
  }
}

async function resetAdminAccount() {
  await db.query(`
    UPDATE users 
    SET failed_login_attempts = 0, 
        lockout_until = NULL, 
        failed_otp_attempts = 0, 
        otp_lockout_until = NULL,
        otp_code = '1234',
        otp_expires_at = DATE_ADD(NOW(), INTERVAL 5 MINUTE),
        status = 'active'
    WHERE email = 'admin@email.com'
  `);
}

async function runTestSuite() {
  console.log('\n' + cyan('================================================================'));
  console.log(cyan(bold('   TRES MARIAS ADMIN - COMPREHENSIVE AUTOMATED TEST SUITE')));
  console.log(cyan('================================================================\n'));

  // Ensure fresh DB state
  await resetAdminAccount();

  let generatedOtp = null;
  let authToken = null;

  // -------------------------------------------------------------
  // TEST GROUP 1: SERVER HEALTH & DATABASE CONNECTIVITY
  // -------------------------------------------------------------
  console.log(bold('\n[GROUP 1] Server Health & Database Connection'));
  try {
    const res = await fetch(`${BASE_URL}/api/health`);
    const data = await res.json();
    assert(res.status === 200, 'GET /api/health returns HTTP 200');
    assert(data.status === 'online', 'Server reports status: online');
    assert(data.database === 'connected', 'Database reports status: connected');
  } catch (err) {
    assert(false, `Health check failed: ${err.message}`);
  }

  // -------------------------------------------------------------
  // TEST GROUP 2: SEND OTP VALIDATION & LOGIC
  // -------------------------------------------------------------
  console.log(bold('\n[GROUP 2] Send OTP Validation & Generation (/api/send-otp)'));
  try {
    // 2.1 Missing all fields
    const resEmpty = await fetch(`${BASE_URL}/api/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({})
    });
    assert(resEmpty.status === 400, 'Empty body returns HTTP 400 Bad Request');

    // 2.2 Missing password
    const resNoPass = await fetch(`${BASE_URL}/api/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com' })
    });
    assert(resNoPass.status === 400, 'Missing password returns HTTP 400');

    // 2.3 Non-existent user
    const resNonExistent = await fetch(`${BASE_URL}/api/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'nonexistent@email.com', password: 'Password123' })
    });
    assert(resNonExistent.status === 404, 'Non-existent user returns HTTP 404 Not Found');

    // 2.4 Wrong password
    const resWrongPass = await fetch(`${BASE_URL}/api/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'WrongPassword999' })
    });
    const wrongPassData = await resWrongPass.json();
    assert(resWrongPass.status === 401, 'Wrong password returns HTTP 401 Unauthorized');
    assert(wrongPassData.attemptsRemaining === 4, 'Failed attempts counter tracks remaining attempts (4 remaining)');

    // Reset attempts before proceeding
    await resetAdminAccount();

    // 2.5 Successful OTP Request with valid credentials
    const resValid = await fetch(`${BASE_URL}/api/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'Password123' })
    });
    const validData = await resValid.json();
    assert(resValid.status === 200, 'Valid credentials return HTTP 200 OK');
    assert(validData.success === true, 'Response contains success: true');
    assert(typeof validData.demoOtp === 'string' && validData.demoOtp.length === 4, 'Demo OTP generated (4 digits): ' + validData.demoOtp);
    generatedOtp = validData.demoOtp;
  } catch (err) {
    assert(false, `Send OTP tests failed: ${err.message}`);
  }

  // -------------------------------------------------------------
  // TEST GROUP 3: LOGIN ENDPOINT VALIDATION (/api/login)
  // -------------------------------------------------------------
  console.log(bold('\n[GROUP 3] Login Credentials & OTP Verification (/api/login)'));
  try {
    // 3.1 Missing fields
    const resMissing = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com' })
    });
    assert(resMissing.status === 400, 'Missing password and OTP returns HTTP 400');

    // 3.2 Wrong username
    const resWrongUser = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'unknown_admin', password: 'Password123', otp: '1234' })
    });
    assert(resWrongUser.status === 401, 'Invalid username returns HTTP 401');

    // 3.3 Wrong password only
    const resBadPass = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'IncorrectPassword', otp: generatedOtp })
    });
    const badPassData = await resBadPass.json();
    assert(resBadPass.status === 401, 'Incorrect password only returns HTTP 401');
    assert(badPassData.field === 'password', 'Returns field: "password" for targeted UI highlight');

    // 3.4 Wrong OTP only
    const resBadOtp = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'Password123', otp: '0000' })
    });
    const badOtpData = await resBadOtp.json();
    assert(resBadOtp.status === 401, 'Incorrect OTP only returns HTTP 401');
    assert(badOtpData.field === 'otp', 'Returns field: "otp" for targeted UI highlight');

    // 3.5 SIMULTANEOUS: BOTH Wrong Password AND Wrong OTP
    const resBothBad = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'IncorrectPassword', otp: '9999' })
    });
    const bothBadData = await resBothBad.json();
    assert(resBothBad.status === 401, 'Both invalid returns HTTP 401');
    assert(bothBadData.field === 'both', 'Returns field: "both" for simultaneous UI highlighting');
    assert(Boolean(bothBadData.passwordMessage) && Boolean(bothBadData.otpMessage), 'Provides both passwordMessage and otpMessage');

    // 3.6 SUCCESSFUL LOGIN with valid password and generated OTP
    const resSuccess = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'Password123', otp: generatedOtp })
    });
    const successData = await resSuccess.json();
    assert(resSuccess.status === 200, 'Successful login returns HTTP 200 OK');
    assert(successData.success === true, 'Login response has success: true');
    assert(typeof successData.token === 'string' && successData.token.split('.').length === 3, 'Returns signed JWT Bearer Token');
    authToken = successData.token;

    // 3.7 OTP SINGLE-USE CHECK (Re-using the same OTP must fail)
    const resReuse = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'Password123', otp: generatedOtp })
    });
    assert(resReuse.status === 401, 'Re-using same OTP is blocked (OTP cleared upon successful login)');
  } catch (err) {
    assert(false, `Login tests failed: ${err.message}`);
  }

  // -------------------------------------------------------------
  // TEST GROUP 4: SESSION VERIFICATION & ROUTE GUARDS (/api/verify-session)
  // -------------------------------------------------------------
  console.log(bold('\n[GROUP 4] Session Security & JWT Verification (/api/verify-session)'));
  try {
    // 4.1 Missing Authorization Header
    const resNoAuth = await fetch(`${BASE_URL}/api/verify-session`);
    assert(resNoAuth.status === 401, 'Missing token returns HTTP 401 Unauthorized');

    // 4.2 Tampered / Malformed Token
    const resTampered = await fetch(`${BASE_URL}/api/verify-session`, {
      headers: { 'Authorization': 'Bearer tampered.fake.jwt.token' }
    });
    assert(resTampered.status === 401, 'Tampered JWT token returns HTTP 401');

    // 4.3 Valid Authenticated Token
    const resValidToken = await fetch(`${BASE_URL}/api/verify-session`, {
      headers: { 'Authorization': `Bearer ${authToken}` }
    });
    const validTokenData = await resValidToken.json();
    assert(resValidToken.status === 200, 'Valid JWT token returns HTTP 200 OK');
    assert(validTokenData.valid === true, 'Session is verified as valid: true');
    assert(validTokenData.user.email === 'admin@email.com', 'Token payload contains correct user email');
  } catch (err) {
    assert(false, `Session verification tests failed: ${err.message}`);
  }

  // -------------------------------------------------------------
  // TEST GROUP 5: LOCKOUT CHECK ENDPOINT (/api/check-lockout)
  // -------------------------------------------------------------
  console.log(bold('\n[GROUP 5] Real-Time Lockout Status API (/api/check-lockout)'));
  try {
    const resCheckUnlocked = await fetch(`${BASE_URL}/api/check-lockout?usernameOrEmail=admin@email.com`);
    const checkData = await resCheckUnlocked.json();
    assert(resCheckUnlocked.status === 200, 'GET /api/check-lockout returns HTTP 200');
    assert(checkData.locked === false, 'Account initially unlocked: locked === false');
    assert(checkData.otpLocked === false, 'OTP entry initially unlocked: otpLocked === false');
  } catch (err) {
    assert(false, `Lockout check tests failed: ${err.message}`);
  }

  // -------------------------------------------------------------
  // TEST GROUP 6: BRUTE-FORCE SIMULATION & LOCKOUT ENFORCEMENT
  // -------------------------------------------------------------
  console.log(bold('\n[GROUP 6] Brute-force Protection (5 Failed Attempts -> HTTP 423 Lockout)'));
  try {
    await resetAdminAccount();

    // Send 5 incorrect password attempts in a row
    for (let i = 1; i <= 4; i++) {
      await fetch(`${BASE_URL}/api/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: `WrongPass${i}`, otp: '1234' })
      });
    }

    // 5th failed attempt should trigger 5-minute lockout
    const res5th = await fetch(`${BASE_URL}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'WrongPass5', otp: '1234' })
    });
    const lockData = await res5th.json();
    assert(res5th.status === 423, '5th consecutive failed password triggers HTTP 423 Locked');
    assert(lockData.locked === true, 'Response payload confirms locked: true');
    assert(lockData.lockRemainingSeconds > 0, `Lockout duration returned: ${lockData.lockRemainingSeconds} seconds`);

    // Verify /api/check-lockout now also reports account as locked
    const resLockCheck = await fetch(`${BASE_URL}/api/check-lockout?usernameOrEmail=admin@email.com`);
    const lockCheckData = await resLockCheck.json();
    assert(lockCheckData.locked === true, '/api/check-lockout immediately reflects locked status');

    // Attempting to request OTP while locked must also be rejected
    const resOtpWhileLocked = await fetch(`${BASE_URL}/api/send-otp`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ usernameOrEmail: 'admin@email.com', password: 'Password123' })
    });
    assert(resOtpWhileLocked.status === 423, 'Requesting OTP while locked is rejected with HTTP 423');
  } catch (err) {
    assert(false, `Brute-force tests failed: ${err.message}`);
  }

  // -------------------------------------------------------------
  // CLEANUP & FINAL REPORT
  // -------------------------------------------------------------
  console.log(bold('\n[CLEANUP] Resetting Admin Account to Active...'));
  await resetAdminAccount();
  console.log(green('  ✓ Admin account reset to active with default OTP: 1234'));

  console.log('\n' + cyan('================================================================'));
  console.log(bold(`   TEST RESULTS: ${green(`${passedCount} PASSED`)} | ${failedCount > 0 ? red(`${failedCount} FAILED`) : green('0 FAILED')}`));
  console.log(cyan('================================================================\n'));

  // Close database pool connection so script exits gracefully
  await db.end();

  if (failedCount > 0) {
    process.exit(1);
  } else {
    process.exit(0);
  }
}

runTestSuite().catch(async (err) => {
  console.error(red('\nFatal error in test suite:'), err);
  try {
    await db.end();
  } catch (e) {}
  process.exit(1);
});
