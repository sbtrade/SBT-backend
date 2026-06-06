const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const db = require('../config/db');
const { authLimiter } = require('../middleware/rateLimiter');
const { authenticateToken } = require('../middleware/auth');

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'super_secret_access_key_change_me_in_production_12345';
const JWT_REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'super_secret_refresh_key_change_me_in_production_12345';

// Helper to log audit actions
async function logAudit(userId, role, action, ip, details) {
  try {
    await db.query(
      'INSERT INTO audit_logs (actor_id, actor_role, action, ip_address, details) VALUES ($1, $2, $3, $4, $5)',
      [userId, role, action, ip, details]
    );
  } catch (err) {
    console.error('Audit Log Insertion Error:', err);
  }
}

// Helper to generate temporary password
function generateTempPassword() {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*';
  let temp = 'SBT';
  temp += Math.floor(Math.random() * 10);
  temp += chars[Math.floor(Math.random() * chars.length)];
  for (let i = 0; i < 6; i++) {
    temp += chars[Math.floor(Math.random() * chars.length)];
  }
  return temp;
}

// Helper to generate a 6-digit numeric OTP
function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

// 1. Register Account Route
router.post('/register', authLimiter, async (req, res) => {
  const { fullname, phone, email, address, password } = req.body;
  const ip = req.ip || '127.0.0.1';

  if (!fullname || fullname.length < 3 || fullname.length > 100) {
    return res.status(400).json({ error: 'Name must be between 3 and 100 characters.' });
  }
  if (!phone || !/^\d{10}$/.test(phone)) {
    return res.status(400).json({ error: 'Phone number must be exactly 10 digits.' });
  }
  if (!email || !/\S+@\S+\.\S+/.test(email)) {
    return res.status(400).json({ error: 'Please specify a valid email address.' });
  }
  if (!address || address.length < 10) {
    return res.status(400).json({ error: 'Address must be at least 10 characters.' });
  }
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters.' });
  }

  try {
    const userCheck = await db.query('SELECT id FROM users WHERE email = $1 OR phone = $2', [email, phone]);
    if (userCheck.rows.length > 0) {
      return res.status(400).json({ error: 'Email or phone number is already registered.' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const userIdSeed = 'USR' + Math.floor(1000 + Math.random() * 9000);

    const result = await db.query(
      `INSERT INTO users (user_id, fullname, email, phone, address, role, status, password_hash, must_change_password)
       VALUES ($1, $2, $3, $4, $5, 'USER', 'PENDING_APPROVAL', $6, FALSE) RETURNING id, user_id`,
      [userIdSeed, fullname, email, phone, address, hashedPassword]
    );

    const newUser = result.rows[0];
    await db.query('INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)', [newUser.id, hashedPassword]);
    await logAudit(newUser.id, 'USER', 'ACCOUNT_REGISTRATION', ip, `User registered with User ID: ${newUser.user_id}`);

    res.status(201).json({
      message: 'Registration submitted successfully. Pending Admin approval.',
      user_id: newUser.user_id
    });
  } catch (err) {
    console.error('Registration Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 2. Login Route (Supports 2FA gate for Admins)
router.post('/login', authLimiter, async (req, res) => {
  const { user_id, password } = req.body;
  const ip = req.ip || '127.0.0.1';
  const deviceInfo = req.headers['user-agent'] || 'Unknown Device';

  if (!user_id || !password) {
    return res.status(400).json({ error: 'User ID and Password are required.' });
  }

  try {
    const result = await db.query('SELECT * FROM users WHERE user_id = $1', [user_id]);

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid User ID or password.' });
    }

    const user = result.rows[0];

    // Check account lockout
    if (user.account_locked_until && new Date(user.account_locked_until) > new Date()) {
      return res.status(403).json({
        error: `Account is locked due to too many failed attempts. Try again after ${new Date(user.account_locked_until).toLocaleTimeString()}.`
      });
    }

    // Check status
    if (user.status === 'PENDING_APPROVAL') {
      return res.status(403).json({ error: 'Your account is pending administrator approval.' });
    }
    if (user.status === 'REJECTED') {
      return res.status(403).json({ error: 'Your registration request was rejected by the administrator.' });
    }
    if (user.status === 'SUSPENDED') {
      return res.status(403).json({ error: 'Your account is suspended. Please contact support.' });
    }

    // Verify password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      const failedCount = user.failed_login_attempts + 1;
      if (failedCount >= 5) {
        const lockoutTime = new Date(Date.now() + 30 * 60 * 1000); // 30 minutes
        await db.query(
          'UPDATE users SET failed_login_attempts = $1, account_locked_until = $2 WHERE id = $3',
          [failedCount, lockoutTime, user.id]
        );
        await logAudit(user.id, user.role, 'ACCOUNT_LOCKOUT', ip, `Account locked due to 5 failed attempts.`);
        return res.status(403).json({ error: 'Account locked for 30 minutes due to 5 consecutive failed login attempts.' });
      } else {
        await db.query('UPDATE users SET failed_login_attempts = $1 WHERE id = $2', [failedCount, user.id]);
        await logAudit(user.id, user.role, 'FAILED_LOGIN_ATTEMPT', ip, `Failed login attempt ${failedCount}/5`);
        return res.status(401).json({ error: 'Invalid User ID or password.' });
      }
    }

    // Reset failed attempts on successful login
    await db.query(
      'UPDATE users SET failed_login_attempts = 0, account_locked_until = NULL WHERE id = $1',
      [user.id]
    );

    // If Admin/Super Admin, require 2FA
    if (user.role === 'ADMIN' || user.role === 'SUPER_ADMIN') {
      const twoFactorOtp = generateOTP();
      const expiresAt = new Date(Date.now() + 5 * 60 * 1000); // 5 min expiry

      // Store OTP
      await db.query('DELETE FROM otp_verifications WHERE user_id = $1', [user.id]);
      await db.query(
        'INSERT INTO otp_verifications (user_id, email_otp, sms_otp, expires_at) VALUES ($1, $2, $2, $3)',
        [user.id, twoFactorOtp, expiresAt]
      );

      // Print in console for local developer testing convenience
      console.log(`\n--- [2FA ENGINE] OTP GENERATED FOR ADMINISTRATIVE USER [${user.user_id}] ---`);
      console.log(`Your 2FA Login Code: ${twoFactorOtp}`);
      console.log(`Expiry: 5 minutes\n------------------------------------------------------------\n`);

      // Generate a temporary restricted token
      const tempToken = jwt.sign(
        { id: user.id, user_id: user.user_id, role: 'TEMP_2FA_ROLE' },
        JWT_ACCESS_SECRET,
        { expiresIn: '5m' }
      );

      await logAudit(user.id, user.role, '2FA_OTP_GENERATED', ip, '2FA gate triggered. Verification code generated.');

      return res.json({
        requires_2fa: true,
        temp_token: tempToken,
        user_id: user.user_id
      });
    }

    // Standard User Login (Generate real tokens directly)
    const accessToken = jwt.sign(
      { id: user.id, user_id: user.user_id, role: user.role },
      JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    const refreshExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await db.query(
      'INSERT INTO sessions (user_id, refresh_token, device_info, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [user.id, refreshToken, deviceInfo, ip, refreshExpires]
    );

    await logAudit(user.id, user.role, 'USER_LOGIN', ip, `Customer logged in from device: ${deviceInfo}`);

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        user_id: user.user_id,
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        role: user.role,
        must_change_password: user.must_change_password
      }
    });
  } catch (err) {
    console.error('Login Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 3. 2FA Verification Route
router.post('/2fa/verify', async (req, res) => {
  const { temp_token, code } = req.body;
  const ip = req.ip || '127.0.0.1';
  const deviceInfo = req.headers['user-agent'] || 'Unknown Device';

  if (!temp_token || !code) {
    return res.status(400).json({ error: 'Temp Token and 2FA Code are required.' });
  }

  try {
    const decoded = jwt.verify(temp_token, JWT_ACCESS_SECRET);
    if (decoded.role !== 'TEMP_2FA_ROLE') {
      return res.status(403).json({ error: 'Invalid authentication context.' });
    }

    const userRes = await db.query('SELECT * FROM users WHERE id = $1', [decoded.id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }

    const user = userRes.rows[0];

    // Check OTP
    const otpRes = await db.query('SELECT * FROM otp_verifications WHERE user_id = $1', [user.id]);
    if (otpRes.rows.length === 0) {
      return res.status(400).json({ error: 'No active 2FA session found. Please log in again.' });
    }

    const otpData = otpRes.rows[0];

    // Validate attempts
    if (otpData.attempts >= 3) {
      await db.query('DELETE FROM otp_verifications WHERE id = $1', [otpData.id]);
      return res.status(400).json({ error: 'Maximum attempts exceeded. Please restart login.' });
    }

    // Validate expiry
    if (new Date(otpData.expires_at) < new Date()) {
      await db.query('DELETE FROM otp_verifications WHERE id = $1', [otpData.id]);
      return res.status(400).json({ error: '2FA code expired. Please log in again.' });
    }

    // Compare code
    if (otpData.email_otp !== code) {
      await db.query('UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = $1', [otpData.id]);
      await logAudit(user.id, user.role, '2FA_VERIFICATION_FAILED', ip, `Incorrect 2FA input. Attempt ${otpData.attempts + 1}/3`);
      return res.status(400).json({ error: 'Invalid 2FA code.' });
    }

    // Validated! Clear OTP and issue official production credentials
    await db.query('DELETE FROM otp_verifications WHERE id = $1', [otpData.id]);

    const accessToken = jwt.sign(
      { id: user.id, user_id: user.user_id, role: user.role },
      JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    const refreshToken = jwt.sign(
      { id: user.id },
      JWT_REFRESH_SECRET,
      { expiresIn: '7d' }
    );

    const refreshExpires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);
    await db.query(
      'INSERT INTO sessions (user_id, refresh_token, device_info, ip_address, expires_at) VALUES ($1, $2, $3, $4, $5)',
      [user.id, refreshToken, deviceInfo, ip, refreshExpires]
    );

    await logAudit(user.id, user.role, '2FA_VERIFICATION_SUCCESS', ip, '2FA verification succeeded. Admin session authorized.');

    res.json({
      accessToken,
      refreshToken,
      user: {
        id: user.id,
        user_id: user.user_id,
        fullname: user.fullname,
        email: user.email,
        phone: user.phone,
        role: user.role,
        must_change_password: user.must_change_password
      }
    });
  } catch (err) {
    console.error('2FA Verification error:', err);
    res.status(403).json({ error: 'Expired or invalid 2FA session token.' });
  }
});

// 4. Refresh Token Route
router.post('/refresh', async (req, res) => {
  const { refreshToken } = req.body;

  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token is required.' });
  }

  try {
    const sessionRes = await db.query('SELECT * FROM sessions WHERE refresh_token = $1', [refreshToken]);
    if (sessionRes.rows.length === 0) {
      return res.status(403).json({ error: 'Invalid session.' });
    }

    const session = sessionRes.rows[0];

    if (new Date(session.expires_at) < new Date()) {
      await db.query('DELETE FROM sessions WHERE id = $1', [session.id]);
      return res.status(403).json({ error: 'Session expired. Please log in again.' });
    }

    const decoded = jwt.verify(refreshToken, JWT_REFRESH_SECRET);
    const userRes = await db.query('SELECT id, user_id, role, status FROM users WHERE id = $1', [decoded.id]);
    
    if (userRes.rows.length === 0 || userRes.rows[0].status === 'SUSPENDED') {
      return res.status(403).json({ error: 'User not authorized.' });
    }

    const user = userRes.rows[0];
    const accessToken = jwt.sign(
      { id: user.id, user_id: user.user_id, role: user.role },
      JWT_ACCESS_SECRET,
      { expiresIn: '15m' }
    );

    res.json({ accessToken });
  } catch (err) {
    console.error('Token Refresh Error:', err);
    res.status(403).json({ error: 'Invalid refresh token.' });
  }
});

// 5. Force Change Password Route
router.post('/change-password', authenticateToken, async (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const ip = req.ip || '127.0.0.1';
  const userId = req.user.id;

  if (!newPassword || newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }

  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*])/;
  if (!passwordRegex.test(newPassword)) {
    return res.status(400).json({
      error: 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character (e.g. SBTWallet@2026).'
    });
  }

  try {
    const userRes = await db.query('SELECT password_hash FROM users WHERE id = $1', [userId]);
    const user = userRes.rows[0];

    const isMatch = await bcrypt.compare(oldPassword, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ error: 'Incorrect current password.' });
    }

    const historyRes = await db.query('SELECT password_hash FROM password_history WHERE user_id = $1 ORDER BY created_at DESC LIMIT 5', [userId]);
    for (let row of historyRes.rows) {
      const isReused = await bcrypt.compare(newPassword, row.password_hash);
      if (isReused) {
        return res.status(400).json({ error: 'You cannot reuse any of your last 5 passwords.' });
      }
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.query(
      `UPDATE users 
       SET password_hash = $1, 
           temporary_password = NULL, 
           temporary_password_created_at = NULL, 
           must_change_password = FALSE 
       WHERE id = $2`,
      [newHash, userId]
    );

    await db.query('INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)', [userId, newHash]);
    await logAudit(userId, req.user.role, 'PASSWORD_CHANGE', ip, 'User updated account password successfully.');

    res.json({ message: 'Password updated successfully. Access granted.' });
  } catch (err) {
    console.error('Password Change Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 6. Logout Route
router.post('/logout', async (req, res) => {
  const { refreshToken, logoutAll } = req.body;
  if (!refreshToken) {
    return res.status(400).json({ error: 'Refresh token required for logout.' });
  }

  try {
    const decoded = jwt.decode(refreshToken);
    if (decoded && decoded.id) {
      if (logoutAll) {
        await db.query('DELETE FROM sessions WHERE user_id = $1', [decoded.id]);
        await logAudit(decoded.id, 'UNKNOWN', 'LOGOUT_ALL_DEVICES', req.ip || '127.0.0.1', 'Logged out from all devices.');
      } else {
        await db.query('DELETE FROM sessions WHERE refresh_token = $1', [refreshToken]);
        await logAudit(decoded.id, 'UNKNOWN', 'LOGOUT', req.ip || '127.0.0.1', 'User logged out.');
      }
    }
    res.json({ message: 'Logged out successfully.' });
  } catch (err) {
    console.error('Logout Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 7. Forgot Password Request
router.post('/forgot-password/request', async (req, res) => {
  const { user_id, email, phone } = req.body;
  const ip = req.ip || '127.0.0.1';

  if (!user_id || !email || !phone) {
    return res.status(400).json({ error: 'All fields are required.' });
  }

  try {
    const userRes = await db.query(
      'SELECT id, role, password_reset_count FROM users WHERE user_id = $1 AND email = $2 AND phone = $3',
      [user_id, email, phone]
    );

    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid details provided.' });
    }

    const user = userRes.rows[0];

    if (user.password_reset_count >= 2) {
      const requestRes = await db.query(
        "SELECT id FROM password_reset_requests WHERE user_id = $1 AND status = 'PENDING'",
        [user.id]
      );
      
      if (requestRes.rows.length === 0) {
        await db.query('INSERT INTO password_reset_requests (user_id, status) VALUES ($1, \'PENDING\')', [user.id]);
        await logAudit(user.id, user.role, 'PASSWORD_RESET_SUBMITTED_TO_ADMIN', ip, 'Subsequent reset request locked; pending Admin approval.');
      }

      return res.status(202).json({
        requires_admin_approval: true,
        message: 'Your password has been reset multiple times. Reset request has been submitted to the Admin for approval.'
      });
    }

    const emailOtp = generateOTP();
    const smsOtp = generateOTP();
    const expiresAt = new Date(Date.now() + 5 * 60 * 1000);

    await db.query('DELETE FROM otp_verifications WHERE user_id = $1', [user.id]);
    await db.query(
      'INSERT INTO otp_verifications (user_id, email_otp, sms_otp, expires_at) VALUES ($1, $2, $3, $4)',
      [user.id, emailOtp, smsOtp, expiresAt]
    );

    console.log(`\n--- REAL-TIME OTP GENERATOR LOG FOR USER [${user_id}] ---`);
    console.log(`Email OTP Code: ${emailOtp}`);
    console.log(`SMS OTP Code: ${smsOtp}`);
    console.log(`Expiry: 5 minutes\n--------------------------------------------\n`);

    await logAudit(user.id, user.role, 'OTP_CODES_GENERATED', ip, 'Verification codes generated for password reset.');

    res.json({
      message: 'OTPs sent successfully to your registered email and phone number.',
      expires_in_seconds: 300,
      debug_otp_logs: { emailOtp, smsOtp }
    });
  } catch (err) {
    console.error('Forgot Password Request Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 8. Forgot Password Verify & Reset
router.post('/forgot-password/verify', authLimiter, async (req, res) => {
  const { user_id, email_otp, sms_otp } = req.body;
  const ip = req.ip || '127.0.0.1';

  if (!user_id || !email_otp || !sms_otp) {
    return res.status(400).json({ error: 'User ID and both OTP codes are required.' });
  }

  try {
    const userRes = await db.query('SELECT id, role, password_reset_count FROM users WHERE user_id = $1', [user_id]);
    if (userRes.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid User ID.' });
    }

    const user = userRes.rows[0];

    if (user.password_reset_count >= 2) {
      return res.status(400).json({ error: 'This reset requires manual Admin approval.' });
    }

    const otpRes = await db.query('SELECT * FROM otp_verifications WHERE user_id = $1', [user.id]);
    if (otpRes.rows.length === 0) {
      return res.status(400).json({ error: 'No active OTP verification session found.' });
    }

    const otpData = otpRes.rows[0];

    if (otpData.attempts >= 3) {
      await db.query('DELETE FROM otp_verifications WHERE id = $1', [otpData.id]);
      return res.status(400).json({ error: 'Maximum attempts reached. Please request new OTP codes.' });
    }

    if (new Date(otpData.expires_at) < new Date()) {
      await db.query('DELETE FROM otp_verifications WHERE id = $1', [otpData.id]);
      return res.status(400).json({ error: 'OTP codes have expired.' });
    }

    const isEmailValid = otpData.email_otp === email_otp;
    const isSmsValid = otpData.sms_otp === sms_otp;

    if (!isEmailValid || !isSmsValid) {
      await db.query('UPDATE otp_verifications SET attempts = attempts + 1 WHERE id = $1', [otpData.id]);
      await logAudit(user.id, user.role, 'OTP_VERIFICATION_FAILED', ip, `Incorrect OTP input. Attempt ${otpData.attempts + 1}/3`);
      return res.status(400).json({ error: 'Incorrect Email OTP or SMS OTP code.' });
    }

    await db.query('DELETE FROM otp_verifications WHERE id = $1', [otpData.id]);
    
    const tempPassword = generateTempPassword();
    const tempHash = await bcrypt.hash(tempPassword, 10);
    const newResetCount = user.password_reset_count + 1;

    await db.query(
      `UPDATE users 
       SET password_hash = $1, 
           temporary_password = $2, 
           temporary_password_created_at = NOW(), 
           must_change_password = TRUE, 
           password_reset_count = $3 
       WHERE id = $4`,
      [tempHash, tempPassword, newResetCount, user.id]
    );

    await db.query('INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)', [user.id, tempHash]);
    await logAudit(user.id, user.role, 'TEMPORARY_PASSWORD_GENERATED', ip, 'Forgot Password verification succeeded. Temporary password generated.');

    res.json({
      message: 'OTP verification successful.',
      temporary_password: tempPassword,
      must_change_password: true
    });
  } catch (err) {
    console.error('OTP Verification Error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// 9. Debug OTP Endpoint
router.get('/debug/otps/:user_id', async (req, res) => {
  const { user_id } = req.params;
  try {
    const userRes = await db.query('SELECT id FROM users WHERE user_id = $1', [user_id]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: 'User not found' });

    const otpRes = await db.query('SELECT email_otp, sms_otp, expires_at FROM otp_verifications WHERE user_id = $1', [userRes.rows[0].id]);
    if (otpRes.rows.length === 0) return res.status(404).json({ error: 'No OTP generated' });

    res.json(otpRes.rows[0]);
  } catch (err) {
    res.status(500).json({ error: 'Server error' });
  }
});

module.exports = router;
