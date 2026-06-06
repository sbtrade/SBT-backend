# Production Launch & Integration Guide
## Transitioning SBT Wallet from Sandbox to Live Transactions

This guide details the exact corporate, regulatory, and technical steps required to transition the SBT Wallet Management System from its current local simulation to a live production application handling real fiat currency and real Bitcoin blockchain transactions.

---

## Part 1: Corporate & Compliance Checklist (Legal)

Before writing any live code, your client must establish a secure legal foundation, as money transmission is heavily regulated.

1. **Establish a Legal Entity**: Register a corporate business entity (such as a Corp, LLC, or Pvt Ltd) to sign contracts with bank partners.
2. **Secure Financial Licenses**:
   * **Fiat Operations**: Apply for appropriate payment transmitter licenses (such as Money Services Business (MSB) in the US, Electronic Money Institution (EMI) in the EU, or local central bank approvals).
   * **Crypto Operations**: Apply for Virtual Asset Service Provider (VASP) registration in your target operating countries.
3. **Draft AML / KYC Compliance Policies**: Create formal guidelines defining the Customer Identification Program (CIP) and Suspicious Activity Report (SAR) filing procedures.
4. **Open a Business Bank Account**: Set up corporate banking accounts capable of handling merchant credit processing from your gateways.

---

## Part 2: Real Fiat Deposits (Stripe / Razorpay Integration)

To capture real user money, you must connect the platform to a merchant account. This walkthrough details **Stripe Checkout** integration.

### 1. Technical Steps:
1. Sign up on the [Stripe Dashboard](https://dashboard.stripe.com/).
2. Retrieve your **Publishable Key** (starts with `pk_live_`) and **Secret Key** (starts with `sk_live_`).
3. Set up a Webhook Endpoint in the Stripe Dashboard pointing to: `https://api.yourdomain.com/api/wallet/webhook`
4. Select the event: `checkout.session.completed`
5. Retrieve your **Webhook Signing Secret** (starts with `whsec_`).

### 2. Code Modifications (Backend):
1. Install the official Stripe SDK in your backend directory:
   ```bash
   npm install stripe
   ```
2. Update `backend/.env` with your secrets:
   ```env
   STRIPE_SECRET_KEY=sk_live_...
   STRIPE_WEBHOOK_SECRET=whsec_...
   ```
3. Update [wallet.js](file:///C:/Users/Admin/.gemini/antigravity/scratch/sbt-wallet-system/backend/routes/wallet.js) to construct the Stripe event using raw request bodies (for cryptographic signature verification):

```javascript
// Replacement Code for backend/routes/wallet.js Webhook Route:
const stripe = require('stripe')(process.env.STRIPE_SECRET_KEY);

router.post('/webhook', express.raw({ type: 'application/json' }), async (req, res) => {
  const sig = req.headers['stripe-signature'];
  let event;

  try {
    // Cryptographically verify that the request came directly from Stripe
    event = stripe.webhooks.constructEvent(req.body, sig, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    console.error('Webhook signature verification failed:', err.message);
    return res.status(400).send(`Webhook Error: ${err.message}`);
  }

  // Handle transaction confirmation
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const paymentId = session.id;
    const userId = session.metadata.user_id;
    const amount = session.amount_total / 100; // Stripe represents cents
    const currency = session.currency;

    try {
      // Replay attack check
      const replayCheck = await db.query('SELECT id FROM transactions WHERE payment_id = $1', [paymentId]);
      if (replayCheck.rows.length > 0) {
        return res.status(200).json({ status: 'DUPLICATE' }); // Stripe expects 200 OK
      }

      // Credit wallet balance
      await db.query(
        'UPDATE wallets SET balance = balance + $1, total_credits = total_credits + $1 WHERE user_id = $2',
        [amount, userId]
      );

      // Record transaction
      await db.query(
        `INSERT INTO transactions (sender_id, receiver_id, amount, type, description, status, payment_id, gateway_reference, currency)
         VALUES (NULL, $1, $2, 'DEPOSIT', 'Stripe checkout deposit confirmed', 'COMPLETED', $3, 'stripe', $4)`,
        [userId, amount, paymentId, currency.toUpperCase()]
      );

      console.log(`[STRIPE WEBHOOK] Credited $${amount} to user ID #${userId}`);
    } catch (err) {
      console.error('Database insertion error on Stripe callback:', err.message);
      return res.status(500).send('Internal Server Error');
    }
  }

  res.json({ received: true });
});
```

---

## Part 3: Real Bitcoin withdrawals (Coinbase Developer Platform Integration)

To release real cryptocurrency onto the blockchain, you must swap out the simulated broadcast client for an API-integrated custody service.

### 1. Technical Steps:
1. Sign up on [Coinbase Developer Platform](https://cdp.coinbase.com/) or [BitGo](https://www.bitgo.com/).
2. Create an **API Wallet** and deposit a float of BTC (funding wallet).
3. Generate an API Key, API Secret, and Passphrase. Set permissions to allow **Outbound Withdrawals**.

### 2. Code Modifications (Backend):
1. Install the official Coinbase SDK:
   ```bash
   npm install @coinbase/coinbase-sdk
   ```
2. Update `backend/utils/custody.js` to trigger the actual outbound transfer using the SDK:

```javascript
// Replacement Code for backend/utils/custody.js:
const { Coinbase, Wallet } = require('@coinbase/coinbase-sdk');

// Configure Coinbase Client
Coinbase.configure({
  apiKeyName: process.env.COINBASE_API_KEY_NAME,
  privateKey: process.env.COINBASE_API_PRIVATE_KEY
});

/**
 * Broadcasts a real Bitcoin transfer via Coinbase Developer Platform Custody.
 */
async function broadcastBitcoinWithdrawal(btcAddress, btcAmount, withdrawalId) {
  try {
    // 1. Fetch your corporate custody funding wallet
    const fundingWallet = await Wallet.fetch(process.env.COINBASE_FUNDING_WALLET_ID);
    
    // 2. Create and broadcast the transaction to the Bitcoin blockchain
    const transfer = await fundingWallet.createTransfer({
      amount: btcAmount,
      assetId: 'btc',
      destination: btcAddress
    });

    const txHash = transfer.getTransactionHash();
    console.log(`[CUSTODY SUCCESS] Broadcasted BTC transfer. Transaction Hash: ${txHash}`);

    // 3. Monitor confirmations (Coinbase fires webhooks on block updates, or you can poll the hash)
    pollTransactionConfirmations(txHash, withdrawalId);

    return {
      tx_hash: txHash,
      status: 'BROADCASTED',
      provider: 'COINBASE_DEVELOPER_PLATFORM'
    };
  } catch (err) {
    console.error('[CUSTODY FAILURE] Coinbase transfer failed:', err.message);
    throw new Error(`Bitcoin Custody Transfer Failed: ${err.message}`);
  }
}

/**
 * Polls the Bitcoin blockchain explorer API or Coinbase API to check confirmations.
 */
function pollTransactionConfirmations(txHash, withdrawalId) {
  const interval = setInterval(async () => {
    try {
      // Fetch details from a public blockchain explorer API (e.g. Blockstream)
      const res = await axios.get(`https://blockstream.info/api/tx/${txHash}/status`);
      const confirmed = res.data.confirmed;
      
      if (confirmed) {
        // Retrieve block height to calculate confirmations
        const txRes = await axios.get(`https://blockstream.info/api/tx/${txHash}`);
        const currentBlockHeight = (await axios.get('https://blockstream.info/api/blocks/tip/height')).data;
        const confirmations = currentBlockHeight - txRes.data.status.block_height + 1;

        await db.query(
          'UPDATE withdrawal_requests SET confirmations = $1 WHERE id = $2',
          [confirmations, withdrawalId]
        );

        if (confirmations >= 6) {
          clearInterval(interval);
          // Mark transaction completed
          await db.query(
            "UPDATE withdrawal_requests SET status = 'APPROVED', updated_at = NOW() WHERE id = $1",
            [withdrawalId]
          );
          console.log(`[BLOCKCHAIN] Transfer confirmed with ${confirmations} blocks. Process complete.`);
        }
      }
    } catch (err) {
      console.error('[BLOCKCHAIN MONITOR] Confirmation poll error:', err.message);
    }
  }, 30000); // Check every 30 seconds
}
```

---

## Part 4: Production Hosting & Security Architecture

1. **Secure Environment Variables**: NEVER hardcode secrets. Inject them directly inside Render's dashboard config.
2. **Restrict CORS Policies**: Change frontend CORS origins from `*` to your exact hosted Vercel domain name:
   ```javascript
   app.use(cors({
     origin: 'https://sbtwallet.com',
     methods: ['GET', 'POST', 'PUT', 'DELETE'],
   }));
   ```
3. **Database Security**: Enforce SSL on your Neon connection (`sslmode=require`).
4. **Logging / SIEM**: Connect Render and Neon audit logs to a secure centralized logs aggregator (like Datadog or Loggly) for compliance.
