const express = require('express');
const router = express.Router();
const db = require('../config/db');
const upload = require('../middleware/upload');
const { authenticateToken, authorizeRoles } = require('../middleware/auth');
const { checkAMLRestrictions } = require('../middleware/aml');

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

// Helper to get user's KYC status
async function getKycStatus(userId) {
  const result = await db.query(
    'SELECT status FROM kyc_documents WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
    [userId]
  );
  if (result.rows.length === 0) return 'NOT_SUBMITTED';
  return result.rows[0].status;
}

// ==========================================
// PUBLIC GATEWAY WEBHOOK (Bypasses JWT Auth)
// ==========================================
router.post('/webhook', async (req, res) => {
  const { event, data } = req.body; 
  const ip = req.ip || '127.0.0.1';

  // In production: Validate Stripe/Razorpay signature headers here
  console.log('[PAYMENT GATEWAY WEBHOOK] Received checkout completion callback:', event);

  if (!data || !data.payment_id || !data.user_id) {
    return res.status(400).json({ error: 'Invalid webhook metadata payload.' });
  }

  const { payment_id, user_id, amount, currency, gateway } = data;
  const numAmount = parseFloat(amount);

  try {
    // 1. Replay attack and double credit prevention: Check if payment_id has already been credited
    const replayCheck = await db.query('SELECT id FROM transactions WHERE payment_id = $1', [payment_id]);
    if (replayCheck.rows.length > 0) {
      console.warn(`[AML/PAYMENT ENGINE] Replay payment attempt blocked. Payment ID ${payment_id} already processed.`);
      return res.status(409).json({ error: 'Duplicate transaction. Already processed.' });
    }

    // 2. Look up user wallet
    const walletRes = await db.query('SELECT balance, total_credits FROM wallets WHERE user_id = $1', [user_id]);
    if (walletRes.rows.length === 0) {
      return res.status(404).json({ error: 'User wallet not found.' });
    }

    // 3. Update Wallet Balance
    const wallet = walletRes.rows[0];
    const newBalance = parseFloat(wallet.balance) + numAmount;
    const newCredits = parseFloat(wallet.total_credits) + numAmount;

    await db.query(
      'UPDATE wallets SET balance = $1, total_credits = $2 WHERE user_id = $3',
      [newBalance, newCredits, user_id]
    );

    // 4. Record successful Transaction in Ledger
    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status, payment_id, gateway_reference, currency, payment_status)
       VALUES (NULL, $1, $2, 'DEPOSIT', $3, 'COMPLETED', $4, $5, $6, 'COMPLETED')`,
      [user_id, numAmount, `Deposit via ${gateway || 'Stripe'} Gateway`, payment_id, gateway || 'stripe', currency || 'USD']
    );

    await logAudit(user_id, 'USER', 'DEPOSIT_CONFIRMED', ip, `Real money deposit of $${numAmount.toFixed(2)} confirmed via ${gateway || 'Stripe'}.`);

    res.json({ status: 'SUCCESS', message: 'User wallet credited successfully.' });
  } catch (err) {
    console.error('Webhook processing error:', err.message);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ==========================================
// SECURE USER WALLET ROUTES (Protected JWT)
// ==========================================
router.use(authenticateToken);
router.use(authorizeRoles('USER'));

// 1. Fetch Wallet Balance & Stats
router.get('/balance', async (req, res) => {
  const userId = req.user.id;

  try {
    const walletRes = await db.query(
      'SELECT balance, total_credits, total_debits FROM wallets WHERE user_id = $1',
      [userId]
    );

    const kycStatus = await getKycStatus(userId);

    const wallet = walletRes.rows.length > 0 
      ? walletRes.rows[0] 
      : { balance: '0.00', total_credits: '0.00', total_debits: '0.00' };

    res.json({
      ...wallet,
      kyc_status: kycStatus
    });
  } catch (err) {
    console.error('Fetch Wallet Balance Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 2. Initiate Payment Checkout Session
router.post('/deposit-checkout', checkAMLRestrictions, async (req, res) => {
  const { amount, currency, gateway } = req.body;
  const userId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!amount || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Deposit amount must be greater than zero.' });
  }

  try {
    // Regulatory requirement check: verify KYC is approved
    const kycStatus = await getKycStatus(userId);
    if (kycStatus !== 'APPROVED') {
      return res.status(403).json({ error: 'You must complete and have APPROVED KYC verification to initiate deposits.' });
    }

    const payId = 'pay_' + crypto.randomUUID().substring(0, 18);
    const txnRef = 'txn_' + Math.floor(Math.random() * 1000000);

    // Create a pending transaction entry in the ledger
    await db.query(
      `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status, payment_id, gateway_reference, transaction_reference, currency, payment_status, aml_flagged)
       VALUES (NULL, $1, $2, 'DEPOSIT', $3, 'PENDING', $4, $5, $6, $7, 'PENDING', $8)`,
      [userId, parseFloat(amount), `Pending deposit via ${gateway || 'Stripe'}`, payId, gateway || 'stripe', txnRef, currency || 'USD', req.amlFlag || false]
    );

    await logAudit(userId, 'USER', 'DEPOSIT_CHECKOUT_CREATED', ip, `Checkout session created for $${parseFloat(amount).toFixed(2)}. ID: ${payId}`);

    res.json({
      payment_id: payId,
      checkout_url: `http://localhost:5173/payment-checkout-simulator?pay_id=${payId}&user_id=${userId}&amount=${amount}&gateway=${gateway || 'stripe'}`,
      transaction_reference: txnRef
    });
  } catch (err) {
    console.error('Deposit checkout session error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 3. Submit Fund Request
router.post('/fund-request', async (req, res) => {
  const { amount, remarks } = req.body;
  const userId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!amount || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Request amount must be greater than zero.' });
  }

  try {
    const kycStatus = await getKycStatus(userId);
    if (kycStatus !== 'APPROVED') {
      return res.status(403).json({ error: 'You must have APPROVED KYC verification to request credit.' });
    }

    await db.query(
      'INSERT INTO fund_requests (user_id, amount, remarks, status) VALUES ($1, $2, $3, \'PENDING\')',
      [userId, parseFloat(amount), remarks || '']
    );

    await logAudit(userId, 'USER', 'FUND_REQUEST_SUBMITTED', ip, `User requested fund credit of $${parseFloat(amount).toFixed(2)}.`);

    res.status(201).json({ message: 'Fund request submitted successfully. Pending Admin approval.' });
  } catch (err) {
    console.error('Fund Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 4. Submit Transfer Request (User A -> User B)
router.post('/transfer-request', checkAMLRestrictions, async (req, res) => {
  const { receiver_user_id, amount } = req.body;
  const userId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!receiver_user_id || !amount || parseFloat(amount) <= 0) {
    return res.status(400).json({ error: 'Receiver User ID and positive amount are required.' });
  }

  const numAmount = parseFloat(amount);

  try {
    const kycStatus = await getKycStatus(userId);
    if (kycStatus !== 'APPROVED') {
      return res.status(400).json({ error: 'You must have an APPROVED KYC document to request transfers.' });
    }

    const walletRes = await db.query('SELECT balance FROM wallets WHERE user_id = $1', [userId]);
    if (walletRes.rows.length === 0 || parseFloat(walletRes.rows[0].balance) < numAmount) {
      return res.status(400).json({ error: 'Insufficient wallet balance.' });
    }

    if (receiver_user_id === req.user.user_id) {
      return res.status(400).json({ error: 'You cannot request transfers to yourself.' });
    }

    const recRes = await db.query('SELECT id FROM users WHERE user_id = $1 AND role = \'USER\' AND status = \'ACTIVE\'', [receiver_user_id]);
    if (recRes.rows.length === 0) {
      return res.status(400).json({ error: 'Recipient User ID is invalid or account is not active.' });
    }

    await db.query(
      'INSERT INTO transfer_requests (sender_id, receiver_user_id, amount, status) VALUES ($1, $2, $3, \'PENDING\')',
      [userId, receiver_user_id, numAmount]
    );

    await logAudit(userId, 'USER', 'TRANSFER_REQUEST_SUBMITTED', ip, `Requested transfer of $${numAmount.toFixed(2)} to ${receiver_user_id}.`);

    res.status(201).json({ message: 'Transfer request submitted. Pending Admin approval.' });
  } catch (err) {
    console.error('Transfer Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 5. Submit Bitcoin Withdrawal Request
router.post('/withdrawal-request', checkAMLRestrictions, async (req, res) => {
  const { amount, btc_address } = req.body;
  const userId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!amount || parseFloat(amount) <= 0 || !btc_address) {
    return res.status(400).json({ error: 'Withdrawal amount and destination address are required.' });
  }

  const numAmount = parseFloat(amount);

  // Validate Bitcoin Address format roughly (starts with 1, 3, or bc1)
  if (!/^(1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,62}$/.test(btc_address)) {
    return res.status(400).json({ error: 'Invalid Bitcoin destination address format.' });
  }

  try {
    const kycStatus = await getKycStatus(userId);
    if (kycStatus !== 'APPROVED') {
      return res.status(400).json({ error: 'You must have an APPROVED KYC document to request Bitcoin withdrawals.' });
    }

    const walletRes = await db.query('SELECT balance FROM wallets WHERE user_id = $1', [userId]);
    if (walletRes.rows.length === 0 || parseFloat(walletRes.rows[0].balance) < numAmount) {
      return res.status(400).json({ error: 'Insufficient wallet balance.' });
    }

    // Mock BTC rate conversion: $65,000 per BTC
    const btcAmountVal = numAmount / 65000.0;

    await db.query(
      `INSERT INTO withdrawal_requests (user_id, amount, destination_address, btc_address, btc_amount, status)
       VALUES ($1, $2, $3, $3, $4, 'PENDING')`,
      [userId, numAmount, btc_address, btcAmountVal]
    );

    await logAudit(userId, 'USER', 'WITHDRAWAL_REQUEST_SUBMITTED', ip, `Requested Bitcoin withdrawal of $${numAmount.toFixed(2)} (${btcAmountVal.toFixed(8)} BTC) to address: ${btc_address}.`);

    res.status(201).json({ message: 'Bitcoin withdrawal request submitted. Pending Admin approval.' });
  } catch (err) {
    console.error('Withdrawal Request Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 6. Upload KYC Documents (Front & Back)
router.post('/kyc-upload', upload.fields([{ name: 'front' }, { name: 'back' }]), async (req, res) => {
  const userId = req.user.id;
  const ip = req.ip || '127.0.0.1';

  if (!req.files || !req.files.front || !req.files.back) {
    return res.status(400).json({ error: 'Both front and back ID uploads are required.' });
  }

  const frontFile = req.files.front[0];
  const backFile = req.files.back[0];

  try {
    const checkRes = await db.query('SELECT id FROM kyc_documents WHERE user_id = $1 AND status = \'PENDING\'', [userId]);
    if (checkRes.rows.length > 0) {
      return res.status(400).json({ error: 'You already have a KYC document pending review.' });
    }

    const frontUrl = `/uploads/${frontFile.filename}`;
    const backUrl = `/uploads/${backFile.filename}`;

    await db.query(
      'INSERT INTO kyc_documents (user_id, front_id_url, back_id_url, status) VALUES ($1, $2, $3, \'PENDING\')',
      [userId, frontUrl, backUrl]
    );

    await logAudit(userId, 'USER', 'KYC_DOCUMENTS_UPLOADED', ip, 'Uploaded front and back ID files for review.');

    res.status(201).json({ message: 'KYC documents uploaded successfully. Admin review pending.' });
  } catch (err) {
    console.error('KYC Upload Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 7. Fetch Transaction History
router.get('/transactions', async (req, res) => {
  const userId = req.user.id;

  try {
    const result = await db.query(
      `SELECT t.id, t.amount, t.type, t.description, t.status, t.tx_hash, t.created_at, t.aml_flagged, t.payment_id,
              u1.user_id AS sender_id_str, u2.user_id AS receiver_id_str
       FROM transactions t
       LEFT JOIN users u1 ON t.sender_id = u1.id
       LEFT JOIN users u2 ON t.receiver_id = u2.id
       WHERE t.sender_id = $1 OR t.receiver_id = $1
       ORDER BY t.created_at DESC`,
      [userId]
    );
    res.json(result.rows);
  } catch (err) {
    console.error('Fetch Transactions Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

// 8. Fetch All User Requests & Statuses (Fund, Transfer, Withdrawal, KYC)
router.get('/requests', async (req, res) => {
  const userId = req.user.id;

  try {
    const fundReqs = await db.query(
      'SELECT id, amount, remarks, status, admin_remarks, created_at, \'FUND\' as req_type FROM fund_requests WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    const transferReqs = await db.query(
      'SELECT id, amount, receiver_user_id, status, created_at, \'TRANSFER\' as req_type FROM transfer_requests WHERE sender_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    const withdrawReqs = await db.query(
      'SELECT id, amount, btc_address, btc_amount, status, tx_hash, confirmations, created_at, \'WITHDRAWAL\' as req_type FROM withdrawal_requests WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    const kycReqs = await db.query(
      'SELECT id, status, remarks, created_at, \'KYC\' as req_type FROM kyc_documents WHERE user_id = $1 ORDER BY created_at DESC',
      [userId]
    );

    const allRequests = [
      ...fundReqs.rows,
      ...transferReqs.rows,
      ...withdrawReqs.rows,
      ...kycReqs.rows
    ].sort((a, b) => new Date(b.created_at) - new Date(a.created_at));

    res.json(allRequests);
  } catch (err) {
    console.error('Fetch Requests Error:', err);
    res.status(500).json({ error: 'Server error.' });
  }
});

module.exports = router;
