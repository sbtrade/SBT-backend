const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const db = require('../config/db');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');
const { broadcastBitcoinWithdrawal } = require('../utils/custody');

// Apply admin role lock to all routes in this file
router.use(authenticateToken);
router.use(authorizeRoles('ADMIN'));

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

// Helper to generate a random strong temporary password
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

// 1. Get List of Normal Users
router.get('/users', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT u.id, u.user_id, u.fullname, u.email, u.phone, u.address, u.status, u.created_at, w.balance 
       FROM users u 
       LEFT JOIN wallets w ON u.id = w.user_id 
       WHERE u.role = 'USER' AND COALESCE(u.is_deleted, FALSE) = FALSE
       ORDER BY u.created_at DESC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Users Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 1b. Get KYC for a specific user database ID
router.get('/users/:id/kyc', async (req, res) => {
  const { id } = req.params;
  try {
    const result = await db.query(
      `SELECT id, front_id_url, back_id_url, status, remarks, created_at, updated_at 
       FROM kyc_documents 
       WHERE user_id = $1 
       ORDER BY created_at DESC LIMIT 1`,
      [id]
    );
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'No KYC documents found for this user.' });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Fetch User KYC Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 2. Deposit into Admin Master Wallet
router.post('/deposit', async (req, res) => {
  const { amount } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!amount || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Deposit amount must be greater than zero.' });
  }

  const numAmount = parseFloat(amount);

  try {
    let walletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [adminId]);
    if (walletRes.rows.length === 0) {
      await db.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0.00)', [adminId]);
      walletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [adminId]);
    }

    const wallet = walletRes.rows[0];
    const newBalance = parseFloat(wallet.balance) + numAmount;
    const newCredits = parseFloat(wallet.total_credits) + numAmount;

    await db.query(
      'UPDATE wallets SET balance = $1, total_credits = $2 WHERE user_id = $3',
      [newBalance, newCredits, adminId]
    );

    // Record transaction
    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status)
       VALUES (NULL, $1, $2, 'DEPOSIT', 'Admin deposited funds to master wallet', 'COMPLETED')`,
      [adminId, numAmount]
    );

    await logAudit(adminId, 'ADMIN', 'MASTER_WALLET_DEPOSIT', ip, `Admin deposited $${numAmount.toFixed(2)} to master wallet.`);

    res.json({ message: 'Deposit successful.', balance: newBalance });
  } catch (err) {
    console.error('Admin Deposit Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 3. Fetch Admin Master Wallet Balance
router.get('/wallet', async (req, res) => {
  try {
    const result = await db.query('SELECT balance, total_credits, total_debits FROM wallets WHERE user_id = $1', [req.user.id]);
    if (result.rows.length === 0) {
      return res.json({ balance: 0.00, total_credits: 0.00, total_debits: 0.00 });
    }
    res.json(result.rows[0]);
  } catch (err) {
    console.error('Fetch Admin Wallet Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 4. Get Pending Registrations
router.get('/registrations', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT id, fullname, email, phone, address, created_at 
       FROM users 
       WHERE status = 'PENDING_APPROVAL' AND role = 'USER' 
       ORDER BY created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Pending Registrations Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 5. Approve User Registration
router.post('/registrations/approve', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'User database ID is required.' });
  }

  try {
    const userRes = await db.query('SELECT fullname, email, phone FROM users WHERE id = $1 AND status = \'PENDING_APPROVAL\'', [id]);
    if (userRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending registration request not found.' });
    }

    const lastUserRes = await db.query(
      `SELECT user_id FROM users 
       WHERE user_id LIKE 'USR%' 
       ORDER BY CAST(SUBSTRING(user_id FROM 4) AS INTEGER) DESC LIMIT 1`
    );

    let nextSeq = 1001;
    if (lastUserRes.rows.length > 0) {
      const lastId = lastUserRes.rows[0].user_id;
      const lastSeq = parseInt(lastId.substring(3));
      nextSeq = lastSeq + 1;
    }

    const generatedUserId = 'USR' + nextSeq;
    const tempPassword = generateTempPassword();
    const tempHash = await bcrypt.hash(tempPassword, 10);

    // Update user status and assign to this admin
    await db.query(
      `UPDATE users 
       SET user_id = $1, 
           password_hash = $2, 
           temporary_password = $3, 
           temporary_password_created_at = NOW(), 
           must_change_password = TRUE, 
           status = 'ACTIVE',
           parent_id = $4
       WHERE id = $5`,
      [generatedUserId, tempHash, tempPassword, adminId, id]
    );

    // Create User Wallet
    const generatedWalletAddress = 'sbt_' + crypto.randomBytes(16).toString('hex');
    await db.query('INSERT INTO wallets (user_id, balance, wallet_address) VALUES ($1, 0.00, $2)', [id, generatedWalletAddress]);

    await logAudit(adminId, 'ADMIN', 'REGISTRATION_APPROVAL', ip, `Approved user registration: ${generatedUserId}. Temporary password generated.`);

    res.json({
      message: 'User approved successfully.',
      credentials: {
        user_id: generatedUserId,
        temporary_password: tempPassword
      }
    });
  } catch (err) {
    console.error('Approve Registration Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 6. Reject User Registration
router.post('/registrations/reject', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'User database ID is required.' });
  }

  try {
    const result = await db.query('UPDATE users SET status = \'REJECTED\' WHERE id = $1 AND status = \'PENDING_APPROVAL\' RETURNING id');
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending registration request not found.' });
    }

    await logAudit(adminId, 'ADMIN', 'REGISTRATION_REJECTION', ip, `Rejected user registration database ID: ${id}`);
    res.json({ message: 'User registration request rejected.' });
  } catch (err) {
    console.error('Reject Registration Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 7. Get Pending KYC Requests
router.get('/kyc', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT k.id, k.front_id_url, k.back_id_url, k.created_at, u.fullname, u.user_id 
       FROM kyc_documents k
       JOIN users u ON k.user_id = u.id
       WHERE k.status = 'PENDING'
       ORDER BY k.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Pending KYCs Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 8. Approve KYC Document
router.post('/kyc/approve', async (req, res) => {
  const { id, remarks } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'KYC Document ID is required.' });
  }

  try {
    const kycRes = await db.query('SELECT user_id FROM kyc_documents WHERE id = $1 AND status = \'PENDING\'', [id]);
    if (kycRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending KYC request not found.' });
    }

    const userId = kycRes.rows[0].user_id;
    await db.query(
      'UPDATE kyc_documents SET status = \'APPROVED\', admin_id = $1, remarks = $2, updated_at = NOW() WHERE id = $3',
      [adminId, remarks || 'Approved by Admin', id]
    );

    await logAudit(adminId, 'ADMIN', 'KYC_APPROVAL', ip, `Approved KYC for user ID: ${userId}`);
    res.json({ message: 'KYC documents approved successfully.' });
  } catch (err) {
    console.error('Approve KYC Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 9. Reject KYC Document
router.post('/kyc/reject', async (req, res) => {
  const { id, remarks } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'KYC Document ID is required.' });
  }

  try {
    const kycRes = await db.query('SELECT user_id FROM kyc_documents WHERE id = $1 AND status = \'PENDING\'', [id]);
    if (kycRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending KYC request not found.' });
    }

    const userId = kycRes.rows[0].user_id;
    await db.query(
      'UPDATE kyc_documents SET status = \'REJECTED\', admin_id = $1, remarks = $2, updated_at = NOW() WHERE id = $3',
      [adminId, remarks || 'Rejected by Admin', id]
    );

    await logAudit(adminId, 'ADMIN', 'KYC_REJECTION', ip, `Rejected KYC for user ID: ${userId}. Remarks: ${remarks}`);
    res.json({ message: 'KYC documents rejected.' });
  } catch (err) {
    console.error('Reject KYC Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 10. Get Pending Fund Requests
router.get('/fund-requests', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT fr.id, fr.amount, fr.remarks, fr.created_at, u.fullname, u.user_id 
       FROM fund_requests fr
       JOIN users u ON fr.user_id = u.id
       WHERE fr.status = 'PENDING'
       ORDER BY fr.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Pending Fund Requests Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 11. Approve Fund Request
router.post('/fund-requests/approve', async (req, res) => {
  const { id, admin_remarks } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Request ID is required.' });
  }

  try {
    const reqRes = await db.query('SELECT user_id, amount FROM fund_requests WHERE id = $1 AND status = \'PENDING\'', [id]);
    if (reqRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending fund request not found.' });
    }

    const { user_id, amount } = reqRes.rows[0];
    const numAmount = parseFloat(amount);

    // Verify Admin Master Wallet has sufficient funds
    const adminWalletRes = await db.query('SELECT balance, total_debits FROM wallets WHERE user_id = $1', [adminId]);
    if (adminWalletRes.rows.length === 0 || parseFloat(adminWalletRes.rows[0].balance) < numAmount) {
      return res.status(400).json({ error: 'Insufficient funds in Admin Master Wallet to fulfill request.' });
    }

    const adminWallet = adminWalletRes.rows[0];
    const newAdminBalance = parseFloat(adminWallet.balance) - numAmount;
    const newAdminDebits = parseFloat(adminWallet.total_debits) + numAmount;

    const userWalletRes = await db.query('SELECT balance, total_credits FROM wallets WHERE user_id = $1', [user_id]);
    if (userWalletRes.rows.length === 0) {
      return res.status(404).json({ error: 'Recipient wallet not found.' });
    }

    const userWallet = userWalletRes.rows[0];
    const newUserBalance = parseFloat(userWallet.balance) + numAmount;
    const newUserCredits = parseFloat(userWallet.total_credits) + numAmount;

    // Update Admin Master Wallet
    await db.query('UPDATE wallets SET balance = $1, total_debits = $2 WHERE user_id = $3', [newAdminBalance, newAdminDebits, adminId]);
    // Update User Wallet
    await db.query('UPDATE wallets SET balance = $1, total_credits = $2 WHERE user_id = $3', [newUserBalance, newUserCredits, user_id]);

    // Approve request
    await db.query(
      'UPDATE fund_requests SET status = \'APPROVED\', admin_id = $1, admin_remarks = $2, updated_at = NOW() WHERE id = $3',
      [adminId, admin_remarks || 'Approved', id]
    );

    // Record Transaction
    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status)
       VALUES ($1, $2, $3, 'CREDIT', 'Wallet credit via fund request approval', 'COMPLETED')`,
      [adminId, user_id, numAmount]
    );

    await logAudit(adminId, 'ADMIN', 'FUND_REQUEST_APPROVAL', ip, `Approved $${numAmount.toFixed(2)} fund request for user ID: ${user_id}`);
    res.json({ message: 'Fund request approved.' });
  } catch (err) {
    console.error('Approve Fund Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 12. Reject Fund Request
router.post('/fund-requests/reject', async (req, res) => {
  const { id, admin_remarks } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Request ID is required.' });
  }

  try {
    const result = await db.query(
      'UPDATE fund_requests SET status = \'REJECTED\', admin_id = $1, admin_remarks = $2, updated_at = NOW() WHERE id = $3 AND status = \'PENDING\' RETURNING user_id, amount',
      [adminId, admin_remarks || 'Rejected', id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending fund request not found.' });
    }

    const { user_id, amount } = result.rows[0];
    await logAudit(adminId, 'ADMIN', 'FUND_REQUEST_REJECTION', ip, `Rejected $${parseFloat(amount).toFixed(2)} fund request for user ID: ${user_id}`);
    res.json({ message: 'Fund request rejected.' });
  } catch (err) {
    console.error('Reject Fund Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 13. Get Pending Transfer Requests
router.get('/transfer-requests', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT tr.id, tr.amount, tr.receiver_user_id, tr.receiver_wallet_address, tr.created_at, u.fullname AS sender_name, u.user_id AS sender_user_id 
       FROM transfer_requests tr
       JOIN users u ON tr.sender_id = u.id
       WHERE tr.status = 'PENDING'
       ORDER BY tr.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Pending Transfers Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 14. Approve Transfer Request
router.post('/transfer-requests/approve', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Request ID is required.' });
  }

  try {
    const reqRes = await db.query('SELECT sender_id, receiver_user_id, receiver_wallet_address, amount FROM transfer_requests WHERE id = $1 AND status = \'PENDING\'', [id]);
    if (reqRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending transfer request not found.' });
    }

    const { sender_id, receiver_user_id, receiver_wallet_address, amount } = reqRes.rows[0];
    const numAmount = parseFloat(amount);

    // Check sender balance
    const senderWalletRes = await db.query('SELECT balance, total_debits FROM wallets WHERE user_id = $1', [sender_id]);
    if (senderWalletRes.rows.length === 0 || parseFloat(senderWalletRes.rows[0].balance) < numAmount) {
      return res.status(400).json({ error: 'Sender has insufficient balance.' });
    }

    const senderWallet = senderWalletRes.rows[0];
    const newSenderBalance = parseFloat(senderWallet.balance) - numAmount;
    const newSenderDebits = parseFloat(senderWallet.total_debits) + numAmount;

    // SCENARIO A: If the receiver is external (outside of our wallet system)
    if (receiver_user_id === 'EXTERNAL') {
      // 1. Deduct sender's wallet
      await db.query('UPDATE wallets SET balance = $1, total_debits = $2 WHERE user_id = $3', [newSenderBalance, newSenderDebits, sender_id]);

      // 2. Approve request
      await db.query('UPDATE transfer_requests SET status = \'APPROVED\', admin_id = $1, updated_at = NOW() WHERE id = $2', [adminId, id]);

      // 3. Record transaction in ledger (receiver_id is null)
      await db.query(
        `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status, transaction_reference)
         VALUES ($1, NULL, $2, 'TRANSFER', $3, 'COMPLETED', $4)`,
        [sender_id, numAmount, `External manual transfer to address: ${receiver_wallet_address}`, receiver_wallet_address]
      );

      await logAudit(adminId, 'ADMIN', 'TRANSFER_REQUEST_APPROVAL_EXTERNAL', ip, `Approved external transfer of $${numAmount.toFixed(2)} from sender ID: ${sender_id} to address: ${receiver_wallet_address}`);

      return res.json({ message: 'External transfer request approved successfully.' });
    }

    // Standard internal transfer:
    const recRes = await db.query('SELECT id FROM users WHERE user_id = $1 AND role = \'USER\' AND status = \'ACTIVE\'', [receiver_user_id]);
    if (recRes.rows.length === 0) {
      return res.status(404).json({ error: 'Receiver user account not active.' });
    }

    const receiverId = recRes.rows[0].id;

    const receiverWalletRes = await db.query('SELECT balance, total_credits FROM wallets WHERE user_id = $1', [receiverId]);
    if (receiverWalletRes.rows.length === 0) {
      return res.status(404).json({ error: 'Receiver wallet not found.' });
    }

    const receiverWallet = receiverWalletRes.rows[0];
    const newReceiverBalance = parseFloat(receiverWallet.balance) + numAmount;
    const newReceiverCredits = parseFloat(receiverWallet.total_credits) + numAmount;

    // Deduct sender & Credit receiver
    await db.query('UPDATE wallets SET balance = $1, total_debits = $2 WHERE user_id = $3', [newSenderBalance, newSenderDebits, sender_id]);
    await db.query('UPDATE wallets SET balance = $1, total_credits = $2 WHERE user_id = $3', [newReceiverBalance, newReceiverCredits, receiverId]);

    // Approve request
    await db.query('UPDATE transfer_requests SET status = \'APPROVED\', admin_id = $1, updated_at = NOW() WHERE id = $2', [adminId, id]);

    // Record Transaction
    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status)
       VALUES ($1, $2, $3, 'TRANSFER', 'Transfer between users', 'COMPLETED')`,
      [sender_id, receiverId, numAmount]
    );

    await logAudit(adminId, 'ADMIN', 'TRANSFER_REQUEST_APPROVAL', ip, `Approved transfer of $${numAmount.toFixed(2)} from sender ID: ${sender_id} to receiver: ${receiver_user_id}`);

    res.json({ message: 'Transfer request approved successfully.' });
  } catch (err) {
    console.error('Approve Transfer Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 15. Reject Transfer Request
router.post('/transfer-requests/reject', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Request ID is required.' });
  }

  try {
    const result = await db.query(
      'UPDATE transfer_requests SET status = \'REJECTED\', admin_id = $1, updated_at = NOW() WHERE id = $2 AND status = \'PENDING\' RETURNING sender_id, amount',
      [adminId, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending transfer request not found.' });
    }

    const { sender_id, amount } = result.rows[0];
    await logAudit(adminId, 'ADMIN', 'TRANSFER_REQUEST_REJECTION', ip, `Rejected transfer request of $${parseFloat(amount).toFixed(2)} from sender ID: ${sender_id}`);
    res.json({ message: 'Transfer request rejected.' });
  } catch (err) {
    console.error('Reject Transfer Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 16. Get Pending Withdrawal Requests
router.get('/withdrawal-requests', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT wr.id, wr.amount, wr.destination_address, wr.btc_address, wr.btc_amount, wr.created_at, u.fullname, u.user_id 
       FROM withdrawal_requests wr
       JOIN users u ON wr.user_id = u.id
       WHERE wr.status = 'PENDING'
       ORDER BY wr.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Pending Withdrawals Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 17. Approve Withdrawal Request (Invokes Bitcoin Custody Engine)
router.post('/withdrawal-requests/approve', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Request ID is required.' });
  }

  try {
    const reqRes = await db.query('SELECT user_id, amount, btc_address, btc_amount FROM withdrawal_requests WHERE id = $1 AND status = \'PENDING\'', [id]);
    if (reqRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending withdrawal request not found.' });
    }

    const { user_id, amount, btc_address, btc_amount } = reqRes.rows[0];
    const numAmount = parseFloat(amount);

    // Verify user balance
    const walletRes = await db.query('SELECT balance, total_debits FROM wallets WHERE user_id = $1', [user_id]);
    if (walletRes.rows.length === 0 || parseFloat(walletRes.rows[0].balance) < numAmount) {
      return res.status(400).json({ error: 'User has insufficient balance for withdrawal.' });
    }

    const wallet = walletRes.rows[0];
    const newBalance = parseFloat(wallet.balance) - numAmount;
    const newDebits = parseFloat(wallet.total_debits) + numAmount;

    // A. Invoke the Custody solution API wrapper to broadcast to the Blockchain
    const custodyResponse = await broadcastBitcoinWithdrawal(btc_address, parseFloat(btc_amount), id);
    const blockchainTxHash = custodyResponse.tx_hash;

    // B. Deduct user wallet
    await db.query('UPDATE wallets SET balance = $1, total_debits = $2 WHERE user_id = $3', [newBalance, newDebits, user_id]);

    // C. Approve request status & record Transaction details
    await db.query(
      'UPDATE withdrawal_requests SET status = \'APPROVED\', admin_id = $1, tx_hash = $2, updated_at = NOW() WHERE id = $3',
      [adminId, blockchainTxHash, id]
    );

    // Record Transaction Ledger
    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status, tx_hash)
       VALUES ($1, NULL, $2, 'WITHDRAWAL', 'Bitcoin custody withdrawal broadcasted', 'COMPLETED', $3)`,
      [user_id, numAmount, blockchainTxHash]
    );

    await logAudit(adminId, 'ADMIN', 'WITHDRAWAL_APPROVAL', ip, `Approved Bitcoin withdrawal of $${numAmount.toFixed(2)} (${parseFloat(btc_amount).toFixed(8)} BTC) for user ID: ${user_id}. Hash: ${blockchainTxHash}`);

    res.json({
      message: 'Bitcoin withdrawal transaction broadcasted successfully. Awaiting blockchain confirmation block increments.',
      tx_hash: blockchainTxHash
    });
  } catch (err) {
    console.error('Approve Withdrawal Error:', err);
    res.status(500).json({ error: err.message || 'Server error.' });
  }
});

// 18. Reject Withdrawal Request
router.post('/withdrawal-requests/reject', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Request ID is required.' });
  }

  try {
    const result = await db.query(
      'UPDATE withdrawal_requests SET status = \'REJECTED\', admin_id = $1, updated_at = NOW() WHERE id = $2 AND status = \'PENDING\' RETURNING user_id, amount',
      [adminId, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending withdrawal request not found.' });
    }

    const { user_id, amount } = result.rows[0];
    await logAudit(adminId, 'ADMIN', 'WITHDRAWAL_REJECTION', ip, `Rejected withdrawal request of $${parseFloat(amount).toFixed(2)} for user ID: ${user_id}`);
    res.json({ message: 'Withdrawal request rejected.' });
  } catch (err) {
    console.error('Reject Withdrawal Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 19. Get Password Reset Requests
router.get('/password-resets', async (req, res) => {
  try {
    const result = await db.query(
      `SELECT pr.id, pr.created_at, u.fullname, u.user_id, u.email, u.phone 
       FROM password_reset_requests pr
       JOIN users u ON pr.user_id = u.id
       WHERE pr.status = 'PENDING'
       ORDER BY pr.created_at ASC`
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Reset Requests Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 20. Approve Password Reset Request
router.post('/password-resets/approve', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Reset request ID is required.' });
  }

  try {
    const reqRes = await db.query('SELECT user_id FROM password_reset_requests WHERE id = $1 AND status = \'PENDING\'', [id]);
    if (reqRes.rows.length === 0) {
      return res.status(404).json({ error: 'Pending reset request not found.' });
    }

    const userId = reqRes.rows[0].user_id;
    const tempPassword = generateTempPassword();
    const tempHash = await bcrypt.hash(tempPassword, 10);

    // Update password, require change
    await db.query(
      `UPDATE users 
       SET password_hash = $1, 
           temporary_password = $2, 
           temporary_password_created_at = NOW(), 
           must_change_password = TRUE 
       WHERE id = $3`,
      [tempHash, tempPassword, userId]
    );

    // Add to history
    await db.query('INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)', [userId, tempHash]);

    // Update request status
    await db.query('UPDATE password_reset_requests SET status = \'APPROVED\', admin_id = $1, updated_at = NOW() WHERE id = $2', [adminId, id]);

    await logAudit(adminId, 'ADMIN', 'MANUAL_PASSWORD_RESET_APPROVAL', ip, `Admin approved manual password reset for user ID: ${userId}. Temp password generated.`);

    res.json({
      message: 'Password reset approved.',
      credentials: {
        temporary_password: tempPassword
      }
    });
  } catch (err) {
    console.error('Approve Password Reset Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 21. Reject Password Reset Request
router.post('/password-resets/reject', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'Reset request ID is required.' });
  }

  try {
    const result = await db.query(
      'UPDATE password_reset_requests SET status = \'REJECTED\', admin_id = $1, updated_at = NOW() WHERE id = $2 AND status = \'PENDING\' RETURNING user_id',
      [adminId, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Pending reset request not found.' });
    }

    const { user_id } = result.rows[0];
    await logAudit(adminId, 'ADMIN', 'MANUAL_PASSWORD_RESET_REJECTION', ip, `Admin rejected manual password reset for user ID: ${user_id}`);
    res.json({ message: 'Password reset request rejected.' });
  } catch (err) {
    console.error('Reject Password Reset Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 22. Suspend / Unsuspend User
router.post('/users/suspend', async (req, res) => {
  const { id, suspend } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'User database ID is required.' });
  }

  const newStatus = suspend ? 'SUSPENDED' : 'ACTIVE';
  const actionText = suspend ? 'SUSPEND_USER' : 'UNSUSPEND_USER';

  try {
    // Prevent modifying admins/superadmins
    const checkRole = await db.query('SELECT role, user_id FROM users WHERE id = $1', [id]);
    if (checkRole.rows.length === 0) {
      return res.status(404).json({ error: 'User not found.' });
    }
    if (checkRole.rows[0].role !== 'USER') {
      return res.status(403).json({ error: 'Administrative accounts cannot be suspended via this route.' });
    }

    await db.query('UPDATE users SET status = $1 WHERE id = $2', [newStatus, id]);
    await logAudit(adminId, 'ADMIN', actionText, ip, `Admin set user ID ${checkRole.rows[0].user_id} status to ${newStatus}`);

    res.json({ message: `User account has been ${newStatus.toLowerCase()}ed successfully.` });
  } catch (err) {
    console.error('User Suspension Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 23. Delete User Account
router.post('/users/delete', async (req, res) => {
  const { id } = req.body;
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'User database ID is required.' });
  }

  try {
    const checkRole = await db.query('SELECT role, user_id, is_deleted FROM users WHERE id = $1', [id]);
    if (checkRole.rows.length === 0 || checkRole.rows[0].is_deleted) {
      return res.status(404).json({ error: 'User not found.' });
    }
    if (checkRole.rows[0].role !== 'USER') {
      return res.status(403).json({ error: 'Administrative accounts cannot be deleted.' });
    }

    const targetUserId = checkRole.rows[0].user_id;

    // Check user balance first
    const walletRes = await db.query('SELECT id, balance, total_debits FROM wallets WHERE user_id = $1', [id]);
    let reclaimAmount = 0.00;
    if (walletRes.rows.length > 0) {
      reclaimAmount = parseFloat(walletRes.rows[0].balance);
    }

    if (reclaimAmount > 0) {
      // 1. Reclaim to Admin Master Wallet
      let adminWalletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [adminId]);
      if (adminWalletRes.rows.length === 0) {
        await db.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0.00)', [adminId]);
        adminWalletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [adminId]);
      }

      const adminWallet = adminWalletRes.rows[0];
      const newAdminBalance = parseFloat(adminWallet.balance) + reclaimAmount;
      const newAdminCredits = parseFloat(adminWallet.total_credits) + reclaimAmount;

      await db.query(
        'UPDATE wallets SET balance = $1, total_credits = $2 WHERE user_id = $3',
        [newAdminBalance, newAdminCredits, adminId]
      );

      // 2. Zero out user wallet balance
      const userWallet = walletRes.rows[0];
      const newUserDebits = parseFloat(userWallet.total_debits || 0) + reclaimAmount;
      await db.query(
        'UPDATE wallets SET balance = 0.00, total_debits = $1 WHERE id = $2',
        [newUserDebits, userWallet.id]
      );

      // 3. Record transaction
      const desc = `Reclaimed balance ($${reclaimAmount.toFixed(2)}) from deleted user ${targetUserId} to Admin Master Wallet`;
      await db.query(
        `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status)
         VALUES ($1, $2, $3, 'TRANSFER', $4, 'COMPLETED')`,
        [id, adminId, reclaimAmount, desc]
      );

      await logAudit(adminId, 'ADMIN', 'USER_DELETE_RECLAIM_FUNDS', ip, desc);
    }

    await db.query('UPDATE users SET is_deleted = TRUE, status = \'SUSPENDED\' WHERE id = $1', [id]);
    await logAudit(adminId, 'ADMIN', 'DELETE_USER', ip, `Admin soft-deleted user account: ${targetUserId}`);

    res.json({ message: 'User account has been deleted.', reclaimedAmount: reclaimAmount });
  } catch (err) {
    console.error('User Deletion Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 24. Adjust Admin Master Wallet Balance (Increase or Decrease)
router.post('/wallet/adjust', async (req, res) => {
  const { amount, action } = req.body; // action: 'INCREASE' or 'DECREASE'
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!amount || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Adjustment amount must be greater than zero.' });
  }
  if (!action || !['INCREASE', 'DECREASE'].includes(action)) {
    return res.status(400).json({ error: 'Action must be either INCREASE or DECREASE.' });
  }

  const numAmount = parseFloat(amount);

  try {
    let walletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [adminId]);
    if (walletRes.rows.length === 0) {
      await db.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0.00)', [adminId]);
      walletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [adminId]);
    }

    const wallet = walletRes.rows[0];
    let newBalance = parseFloat(wallet.balance);
    let newCredits = parseFloat(wallet.total_credits);
    let newDebits = parseFloat(wallet.total_debits);

    if (action === 'INCREASE') {
      newBalance += numAmount;
      newCredits += numAmount;
    } else {
      if (newBalance < numAmount) {
        return res.status(400).json({ error: 'Cannot decrease balance below 0.00.' });
      }
      newBalance -= numAmount;
      newDebits += numAmount;
    }

    await db.query(
      'UPDATE wallets SET balance = $1, total_credits = $2, total_debits = $3 WHERE user_id = $4',
      [newBalance, newCredits, newDebits, adminId]
    );

    // Record transaction
    const desc = action === 'INCREASE'
      ? `Admin adjusted master wallet balance (Deposit: +$${numAmount.toFixed(2)})`
      : `Admin adjusted master wallet balance (Withdrawal: -$${numAmount.toFixed(2)})`;

    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status)
       VALUES (NULL, $1, $2, $3, $4, 'COMPLETED')`,
      [adminId, numAmount, action === 'INCREASE' ? 'DEPOSIT' : 'WITHDRAWAL', desc]
    );

    await logAudit(adminId, 'ADMIN', `MASTER_WALLET_ADJUST_${action}`, ip, desc);

    res.json({ message: 'Balance adjusted successfully.', balance: newBalance });
  } catch (err) {
    console.error('Admin Wallet Adjustment Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 25. Adjust User Wallet Balance directly (Increase or Decrease)
router.post('/users/adjust-balance', async (req, res) => {
  const { id, amount, action } = req.body; // id is user database ID, action is 'INCREASE' or 'DECREASE'
  const adminId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!id) {
    return res.status(400).json({ error: 'User database ID is required.' });
  }
  if (!amount || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Adjustment amount must be greater than zero.' });
  }
  if (!action || !['INCREASE', 'DECREASE'].includes(action)) {
    return res.status(400).json({ error: 'Action must be either INCREASE or DECREASE.' });
  }

  const numAmount = parseFloat(amount);

  try {
    const userCheck = await db.query('SELECT role, user_id, is_deleted FROM users WHERE id = $1', [id]);
    if (userCheck.rows.length === 0 || userCheck.rows[0].is_deleted) {
      return res.status(404).json({ error: 'User not found.' });
    }
    if (userCheck.rows[0].role !== 'USER') {
      return res.status(403).json({ error: 'Administrative wallets cannot be adjusted via this route.' });
    }

    const targetUserId = userCheck.rows[0].user_id;

    let walletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [id]);
    if (walletRes.rows.length === 0) {
      await db.query('INSERT INTO wallets (user_id, balance) VALUES ($1, 0.00)', [id]);
      walletRes = await db.query('SELECT * FROM wallets WHERE user_id = $1', [id]);
    }

    const wallet = walletRes.rows[0];
    let newBalance = parseFloat(wallet.balance);
    let newCredits = parseFloat(wallet.total_credits);
    let newDebits = parseFloat(wallet.total_debits);

    if (action === 'INCREASE') {
      newBalance += numAmount;
      newCredits += numAmount;
    } else {
      if (newBalance < numAmount) {
        return res.status(400).json({ error: 'Cannot decrease balance below 0.00.' });
      }
      newBalance -= numAmount;
      newDebits += numAmount;
    }

    await db.query(
      'UPDATE wallets SET balance = $1, total_credits = $2, total_debits = $3 WHERE user_id = $4',
      [newBalance, newCredits, newDebits, id]
    );

    const desc = action === 'INCREASE'
      ? `Admin adjusted user ${targetUserId} balance (Credit: +$${numAmount.toFixed(2)})`
      : `Admin adjusted user ${targetUserId} balance (Debit: -$${numAmount.toFixed(2)})`;

    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status)
       VALUES ($1, $2, $3, $4, $5, 'COMPLETED')`,
      [adminId, id, numAmount, action === 'INCREASE' ? 'CREDIT' : 'DEBIT', desc]
    );

    await logAudit(adminId, 'ADMIN', `USER_WALLET_ADJUST_${action}`, ip, desc);

    res.json({ message: 'User balance adjusted successfully.', balance: newBalance });
  } catch (err) {
    console.error('User Balance Adjustment Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
