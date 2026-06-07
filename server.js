const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const db = require('./config/db');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS
app.use(cors({
  origin: '*', // For development flexibility. Restrict to specific domains in production.
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parser
app.use(express.json());

// Serve KYC uploads folder statically
const uploadsPath = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadsPath)) {
  fs.mkdirSync(uploadsPath, { recursive: true });
}
app.use('/uploads', express.static(uploadsPath));

// Mount routes
const authRoutes = require('./routes/auth');
const adminRoutes = require('./routes/admin');
const superAdminRoutes = require('./routes/superadmin');
const walletRoutes = require('./routes/wallet');

app.use('/api/auth', authRoutes);
app.use('/api/admin', adminRoutes);
app.use('/api/superadmin', superAdminRoutes);
app.use('/api/wallet', walletRoutes);

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date() });
});

// Seed default accounts
async function seedSystemAccounts() {
  try {
    // Ensure parent_id column exists for user-admin assignments
    await db.query('ALTER TABLE users ADD COLUMN IF NOT EXISTS parent_id INTEGER REFERENCES users(id) ON DELETE SET NULL');

    // Ensure wallet_address column exists in wallets table
    await db.query('ALTER TABLE wallets ADD COLUMN IF NOT EXISTS wallet_address VARCHAR(100) UNIQUE');

    // Generate wallet addresses for any wallets missing one
    const missingWallets = await db.query('SELECT id FROM wallets WHERE wallet_address IS NULL');
    for (const w of missingWallets.rows) {
      const generatedAddr = 'sbt_' + crypto.randomBytes(16).toString('hex');
      await db.query('UPDATE wallets SET wallet_address = $1 WHERE id = $2', [generatedAddr, w.id]);
    }

    // 1. Seed System Auditor
    const superCheck = await db.query("SELECT id FROM users WHERE user_id = 'SUPERADMIN001'");
    if (superCheck.rows.length === 0) {
      console.log('Seeding default System Auditor...');
      const superPassword = 'SuperAdmin@2026';
      const superHash = await bcrypt.hash(superPassword, 10);
      
      const insertSuper = await db.query(
        `INSERT INTO users (user_id, fullname, email, phone, address, role, status, password_hash, temporary_password, must_change_password)
         VALUES ('SUPERADMIN001', 'System Auditor', 'superadmin@sbtwallet.com', '0000000000', 'SBT Head Office', 'SUPER_ADMIN', 'ACTIVE', $1, $2, TRUE)
         RETURNING id`,
        [superHash, superPassword]
      );
      
      const superId = insertSuper.rows[0].id;
      // Add to password history
      await db.query('INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)', [superId, superHash]);
      console.log('System Auditor seeded successfully.');
    }

    // 2. Seed Admin
    const adminCheck = await db.query("SELECT id FROM users WHERE user_id = 'ADMIN001'");
    if (adminCheck.rows.length === 0) {
      console.log('Seeding default Admin...');
      const adminPassword = 'AdminSecret@2026';
      const adminHash = await bcrypt.hash(adminPassword, 10);
      
      const insertAdmin = await db.query(
        `INSERT INTO users (user_id, fullname, email, phone, address, role, status, password_hash, temporary_password, must_change_password)
         VALUES ('ADMIN001', 'System Administrator', 'admin@sbtwallet.com', '1111111111', 'SBT Central Branch', 'ADMIN', 'ACTIVE', $1, $2, TRUE)
         RETURNING id`,
        [adminHash, adminPassword]
      );
      
      const adminId = insertAdmin.rows[0].id;
      // Add to password history
      await db.query('INSERT INTO password_history (user_id, password_hash) VALUES ($1, $2)', [adminId, adminHash]);

      // Seed Master Wallet for Admin with initial deposit $1,000,000.00
      await db.query('INSERT INTO wallets (user_id, balance, total_credits) VALUES ($1, 1000000.00, 1000000.00)', [adminId]);
      console.log('Admin seeded successfully with master wallet.');
    }
  } catch (err) {
    console.error('Error seeding default administrative accounts:', err);
  }
}

// Global Error Handler
app.use((err, req, res, next) => {
  console.error('Unhandled Error:', err.message);
  res.status(500).json({ error: err.message || 'Internal server error.' });
});

// Start listening
app.listen(PORT, async () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode on port ${PORT}`);
  // Run auto-seeding
  await seedSystemAccounts();
});
