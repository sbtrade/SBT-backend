const db = require('../config/db');

/**
 * AML middleware checking transaction values and user activity patterns.
 * Flags requests exceeding thresholds ($10,000) or high velocity.
 */
const checkAMLRestrictions = async (req, res, next) => {
  const { amount } = req.body;
  const userId = req.user ? req.user.id : null;
  const ip = req.ip || '127.0.0.1';

  if (!amount) {
    return next();
  }

  const numAmount = parseFloat(amount);
  let amlFlagged = false;
  let amlDetails = '';

  // 1. Large transaction check ($10,000 threshold)
  if (numAmount >= 10000) {
    amlFlagged = true;
    amlDetails = `Large transaction threshold exceeded. Requested: $${numAmount.toFixed(2)}.`;
  }

  // 2. Velocity check (More than 5 transfers/withdrawals in the last 1 hour)
  if (userId) {
    try {
      const velocityRes = await db.query(
        `SELECT COUNT(*) FROM transactions 
         WHERE (sender_id = $1 OR receiver_id = $1) 
           AND created_at > NOW() - INTERVAL '1 hour'`,
        [userId]
      );
      const recentTxCount = parseInt(velocityRes.rows[0].count);
      
      if (recentTxCount >= 5) {
        amlFlagged = true;
        amlDetails += ` High frequency of transactions detected (${recentTxCount + 1} in 1 hour).`;
      }

      req.amlFlag = amlFlagged;
      req.amlDetails = amlDetails;

      if (amlFlagged) {
        console.warn(`[AML ENGINE] ALERT: Suspicious transaction activity flagged for User ID #${userId}. Details: ${amlDetails}`);
        
        // Log suspicious alert to audit logs
        await db.query(
          `INSERT INTO audit_logs (actor_id, actor_role, action, ip_address, details)
           VALUES ($1, $2, 'SUSPICIOUS_ACTIVITY_ALERT', $3, $4)`,
          [userId, req.user.role, ip, `AML WARNING: ${amlDetails}`]
        );
      }
    } catch (err) {
      console.error('[AML ENGINE] Error running compliance checks:', err.message);
    }
  }

  next();
};

module.exports = {
  checkAMLRestrictions
};
