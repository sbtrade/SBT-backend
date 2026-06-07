const jwt = require('jsonwebtoken');
const db = require('../config/db');
require('dotenv').config();

const JWT_ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'super_secret_access_key_change_me_in_production_12345';

// Authenticate user token
const authenticateToken = async (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required.' });
  }

  try {
    const decoded = jwt.verify(token, JWT_ACCESS_SECRET);
    
    // Check if user still exists and get latest status
    const result = await db.query(
      'SELECT id, user_id, fullname, email, role, status, must_change_password FROM users WHERE id = $1',
      [decoded.id]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'User account not found.' });
    }

    const user = result.rows[0];

    if (user.status === 'SUSPENDED') {
      return res.status(403).json({ error: 'Your account has been suspended. Please contact the administrator.' });
    }

    req.user = user;

    // If must change password is active, restrict requests to password-change endpoints
    if (user.must_change_password && req.path !== '/change-password' && req.path !== '/logout') {
      return res.status(403).json({ 
        error: 'Force password change required.', 
        must_change_password: true 
      });
    }

    next();
  } catch (err) {
    if (err.name === 'TokenExpiredError') {
      console.warn(`JWT Access Token Expired for IP: ${req.ip || '127.0.0.1'}`);
    } else {
      console.error('JWT Verification Error:', err);
    }
    return res.status(403).json({ error: 'Invalid or expired access token.' });
  }
};

// Check role permissions
const authorizeRoles = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'Access denied. Unauthorized role.' });
    }
    next();
  };
};

module.exports = {
  authenticateToken,
  authorizeRoles
};
