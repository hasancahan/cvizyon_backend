import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import pool from '../config/database.js';
import crypto from 'crypto';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Helper function to generate UUID
const generateUUID = () => {
  return crypto.randomUUID();
};

// Helper function to normalize IP address (convert IPv6 localhost to IPv4)
const normalizeIp = (ip) => {
  if (!ip || ip === 'unknown') return 'unknown';
  // Convert IPv6-mapped IPv4 to IPv4
  if (ip.startsWith('::ffff:')) {
    return ip.substring(7);
  }
  // Convert IPv6 localhost to IPv4 localhost
  if (ip === '::1' || ip === 'localhost') {
    return '127.0.0.1';
  }
  return ip;
};

// Helper function to create client fingerprint
const createClientFingerprint = (ip, userAgent) => {
  const normalizedIp = normalizeIp(ip);
  const hash = crypto.createHash('sha256');
  hash.update(`${normalizedIp}-${userAgent || ''}`);
  return hash.digest('hex');
};

// Register Endpoint
router.post('/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({
        success: false,
        message: 'Lütfen tüm alanları doldurun'
      });
    }

    if (password.length < 8) {
      return res.status(400).json({
        success: false,
        message: 'Şifre en az 8 karakter olmalıdır'
      });
    }

    // Check if user already exists
    const [existingUsers] = await pool.execute(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );

    if (existingUsers.length > 0) {
      return res.status(409).json({
        success: false,
        message: 'Bu e-posta adresi zaten kayıtlı'
      });
    }

    // Get and normalize IP address
    const rawIp = req.clientIp || req.ip || 'unknown';
    const normalizedIp = normalizeIp(rawIp);
    const userAgent = req.headers['user-agent'] || '';
    const fingerprint = createClientFingerprint(normalizedIp, userAgent);

    // Check if this IP has used free analysis
    const [freeAnalysisRecords] = await pool.execute(
      'SELECT id FROM free_analyses WHERE client_fingerprint = ? OR ip_address = ?',
      [fingerprint, normalizedIp]
    );

    const hasUsedFreeAnalysis = freeAnalysisRecords.length > 0;

    // If user has used free analysis, they can only register with premium
    // For now, we'll allow registration but mark free_analysis_used as true
    // Premium upgrade will be handled separately

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate UUID for user
    const userId = generateUUID();

    // Insert user with IP address and free_analysis_used status
    await pool.execute(
      'INSERT INTO users (id, name, email, password, ip_address, free_analysis_used) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, name, email, hashedPassword, normalizedIp, hasUsedFreeAnalysis]
    );

    console.log('📝 Yeni kullanıcı kaydedildi:', {
      userId,
      email,
      ip: normalizedIp,
      hasUsedFreeAnalysis
    });

    // Generate JWT token
    const token = jwt.sign(
      { userId, email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Calculate expiration date (7 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Generate UUID for session
    const sessionId = generateUUID();

    // Save session to database
    try {
      await pool.execute(
        'INSERT INTO sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)',
        [sessionId, userId, token, expiresAt]
      );
      console.log('✅ Session kaydedildi (register)');
    } catch (sessionError) {
      console.error('⚠️ Session kaydetme hatası (devam ediliyor):', sessionError);
      // Don't fail registration if session save fails
    }

    res.status(201).json({
      success: true,
      message: 'Kayıt başarılı',
      token,
      user: {
        id: userId,
        name,
        email
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({
      success: false,
      message: 'Kayıt sırasında bir hata oluştu'
    });
  }
});

// Login Endpoint
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({
        success: false,
        message: 'E-posta ve şifre gereklidir'
      });
    }

    // Find user
    const [users] = await pool.execute(
      'SELECT id, name, email, password FROM users WHERE email = ?',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({
        success: false,
        message: 'E-posta veya şifre hatalı'
      });
    }

    const user = users[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password);

    if (!isValidPassword) {
      return res.status(401).json({
        success: false,
        message: 'E-posta veya şifre hatalı'
      });
    }

    // Generate JWT token
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Calculate expiration date (7 days from now)
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);

    // Generate UUID for session
    const sessionId = generateUUID();

    // Save session to database
    try {
      await pool.execute(
        'INSERT INTO sessions (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)',
        [sessionId, user.id, token, expiresAt]
      );
    } catch (sessionError) {
      console.error('Session kaydetme hatası (devam ediliyor):', sessionError);
      // Don't fail login if session save fails
    }

    // Get free_analysis_used and premium status
    const [userData] = await pool.execute(
      'SELECT free_analysis_used, is_premium FROM users WHERE id = ?',
      [user.id]
    );

    res.json({
      success: true,
      message: 'Giriş başarılı',
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        free_analysis_used: userData[0]?.free_analysis_used || false,
        is_premium: userData[0]?.is_premium || false
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({
      success: false,
      message: 'Giriş sırasında bir hata oluştu'
    });
  }
});

// Get Current User (Protected Route)
router.get('/me', async (req, res) => {
  try {
    // This should be protected with authenticateToken middleware
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        message: 'Token bulunamadı'
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    
    const [users] = await pool.execute(
      'SELECT id, name, email, free_analysis_used, is_premium, created_at FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    res.json({
      success: true,
      user: users[0]
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(401).json({
      success: false,
      message: 'Geçersiz token'
    });
  }
});

// Upgrade to Premium Endpoint
router.post('/upgrade-premium', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;

    // Update user to premium
    await pool.execute(
      'UPDATE users SET is_premium = TRUE WHERE id = ?',
      [userId]
    );

    // Get user's IP address
    const [users] = await pool.execute(
      'SELECT ip_address FROM users WHERE id = ?',
      [userId]
    );

    const userIp = users[0]?.ip_address;

    // Remove user's IP from free_analyses table (premium users bypass IP restrictions)
    if (userIp && userIp !== 'unknown') {
      await pool.execute(
        'DELETE FROM free_analyses WHERE ip_address = ?',
        [userIp]
      );
      console.log('✅ Premium kullanıcının IP kayıtları temizlendi:', userIp);
    }

    console.log('✅ Kullanıcı premium olarak güncellendi:', userId);

    res.json({
      success: true,
      message: 'Premium üyeliğe geçiş başarılı'
    });
  } catch (error) {
    console.error('Premium upgrade error:', error);
    res.status(500).json({
      success: false,
      message: 'Premium üyeliğe geçiş sırasında bir hata oluştu'
    });
  }
});

export default router;

