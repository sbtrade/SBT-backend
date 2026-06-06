const express = require('express');
const router = express.Router();
const db = require('../config/db');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');

// Apply role lock to all routes in this file (Super Admins only)
router.use(authenticateToken);
router.use(authorizeRoles('SUPER_ADMIN'));

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

// 1. Fetch System-Wide Statistics
router.get('/stats', async (req, res) => {
  try {
    // Total Users (normal users)
    const usersRes = await db.query("SELECT COUNT(*) FROM users WHERE role = 'USER'");
    const totalUsers = parseInt(usersRes.rows[0].count);

    // Total Active Users
    const activeUsersRes = await db.query("SELECT COUNT(*) FROM users WHERE role = 'USER' AND status = 'ACTIVE'");
    const totalActiveUsers = parseInt(activeUsersRes.rows[0].count);

    // Total Wallet Balance in System (excluding Admin Master Wallet and Super Admin)
    const systemBalanceRes = await db.query(
      "SELECT SUM(w.balance) FROM wallets w JOIN users u ON w.user_id = u.id WHERE u.role = 'USER'"
    );
    const totalWalletBalance = parseFloat(systemBalanceRes.rows[0].sum || 0.00);

    // Total Transactions count
    const txCountRes = await db.query("SELECT COUNT(*) FROM transactions");
    const totalTransactions = parseInt(txCountRes.rows[0].count);

    // Total Pending Requests count (registration, kyc, fund, transfer, withdrawal)
    const pendingRegs = await db.query("SELECT COUNT(*) FROM users WHERE status = 'PENDING_APPROVAL'");
    const pendingKycs = await db.query("SELECT COUNT(*) FROM kyc_documents WHERE status = 'PENDING'");
    const pendingFunds = await db.query("SELECT COUNT(*) FROM fund_requests WHERE status = 'PENDING'");
    const pendingTransfers = await db.query("SELECT COUNT(*) FROM transfer_requests WHERE status = 'PENDING'");
    const pendingWithdrawals = await db.query("SELECT COUNT(*) FROM withdrawal_requests WHERE status = 'PENDING'");
    
    const totalPendingRequests = 
      parseInt(pendingRegs.rows[0].count) +
      parseInt(pendingKycs.rows[0].count) +
      parseInt(pendingFunds.rows[0].count) +
      parseInt(pendingTransfers.rows[0].count) +
      parseInt(pendingWithdrawals.rows[0].count);

    // Admin Status
    const adminRes = await db.query("SELECT user_id, fullname, email, status FROM users WHERE role = 'ADMIN' LIMIT 1");
    const adminDetails = adminRes.rows.length > 0 ? adminRes.rows[0] : null;

    res.json({
      totalUsers,
      totalActiveUsers,
      totalWalletBalance,
      totalTransactions,
      totalPendingRequests,
      admin: adminDetails
    });
  } catch (err) {
    console.error('Fetch Super Admin Stats Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 2. Fetch Admin Details
router.get('/admins', async (req, res) => {
  try {
    const result = await db.query(
      "SELECT id, user_id, fullname, email, phone, status, created_at FROM users WHERE role = 'ADMIN'"
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Admins Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 3. Suspend / Unsuspend Admin
router.post('/admins/suspend', async (req, res) => {
  const { id, suspend } = req.body; // suspend is a boolean
  const superAdminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Admin database ID is required.' });
  }

  const newStatus = suspend ? 'SUSPENDED' : 'ACTIVE';
  const actionText = suspend ? 'SUSPEND_ADMIN' : 'UNSUSPEND_ADMIN';

  try {
    const result = await db.query(
      "UPDATE users SET status = $1 WHERE id = $2 AND role = 'ADMIN' RETURNING id, user_id",
      [newStatus, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Admin account not found.' });
    }

    const adminUser = result.rows[0];
    await logAudit(superAdminId, 'SUPER_ADMIN', actionText, ip, `Super Admin ${newStatus.toLowerCase()}ed Admin account: ${adminUser.user_id}`);

    res.json({ message: `Admin account has been ${newStatus.toLowerCase()}ed successfully.` });
  } catch (err) {
    console.error('Admin Suspension Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 4. Fetch All System Audit Logs
router.get('/audit-logs', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT a.id, a.actor_role, a.action, a.ip_address, a.details, a.created_at, u.user_id AS actor_user_id
       FROM audit_logs a
       LEFT JOIN users u ON a.actor_id = u.id
       ORDER BY a.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Audit Logs Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 5. Fetch Security Events (Specific failed logins, resets, and locks)
router.get('/security-events', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT a.id, a.actor_role, a.action, a.ip_address, a.details, a.created_at, u.user_id AS actor_user_id
       FROM audit_logs a
       LEFT JOIN users u ON a.actor_id = u.id
       WHERE a.action IN ('FAILED_LOGIN_ATTEMPT', 'ACCOUNT_LOCKOUT', 'PASSWORD_CHANGE', 'MANUAL_PASSWORD_RESET_APPROVAL', 'TEMPORARY_PASSWORD_GENERATED')
       ORDER BY a.created_at DESC
       LIMIT 50`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Security Events Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 6. Fetch Users Filtered by Admin ID
router.get('/users-by-admin/:adminId', async (req, res) => {
  const { adminId } = req.params;
  try {
    const result = await db.query(
      `SELECT u.id, u.user_id, u.fullname, u.email, u.phone, u.address, u.status, u.created_at, w.balance 
       FROM users u 
       LEFT JOIN wallets w ON u.id = w.user_id 
       WHERE u.role = 'USER' AND u.parent_id = $1 
       ORDER BY u.created_at DESC`,
      [adminId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Users By Admin Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
