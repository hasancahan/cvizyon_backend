import express from 'express';
import pool from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';
import crypto from 'crypto';

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
  // IP should already be normalized before calling this function
  const hash = crypto.createHash('sha256');
  hash.update(`${ip}-${userAgent || ''}`);
  return hash.digest('hex');
};

// Check if anonymous user can perform free analysis (IP + User-Agent based)
router.post('/check-anonymous', async (req, res) => {
  try {
    const rawIp = req.clientIp || req.ip || 'unknown';
    const ip = normalizeIp(rawIp);
    const userAgent = req.headers['user-agent'] || '';
    const fingerprint = createClientFingerprint(ip, userAgent);
    
    console.log('🔍 Anonymous check:', { rawIp, normalizedIp: ip, fingerprint: fingerprint.substring(0, 16) + '...' });

    // Check if any premium user has this IP (premium users bypass IP restrictions)
    const [premiumUsers] = await pool.execute(
      'SELECT id FROM users WHERE ip_address = ? AND is_premium = TRUE',
      [ip]
    );

    // If a premium user has this IP, allow analysis (they might be using same network)
    if (premiumUsers.length > 0) {
      console.log('✅ Premium kullanıcı IP\'si tespit edildi, analiz izni verildi');
      return res.json({
        success: true,
        canAnalyze: true
      });
    }

    // Check if this fingerprint has already used free analysis
    const [existing] = await pool.execute(
      'SELECT id FROM free_analyses WHERE client_fingerprint = ?',
      [fingerprint]
    );

    if (existing.length > 0) {
      return res.json({
        success: true,
        canAnalyze: false,
        message: 'Ücretsiz analiz hakkınız kullanılmış. Pro versiyona geçin veya giriş yapın.'
      });
    }

    res.json({
      success: true,
      canAnalyze: true
    });
  } catch (error) {
    console.error('Anonymous check error:', error);
    // On error, allow analysis (fail open for better UX)
    res.json({
      success: true,
      canAnalyze: true
    });
  }
});

// Track anonymous free analysis usage
router.post('/track-anonymous', async (req, res) => {
  try {
    const rawIp = req.clientIp || req.ip || 'unknown';
    const ip = normalizeIp(rawIp);
    const userAgent = req.headers['user-agent'] || '';
    const fingerprint = createClientFingerprint(ip, userAgent);
    
    console.log('📝 Tracking anonymous analysis:', { rawIp, normalizedIp: ip, fingerprint: fingerprint.substring(0, 16) + '...' });

    // Generate UUID for free analysis record
    const freeAnalysisId = generateUUID();

    // Insert tracking record
    await pool.execute(
      'INSERT INTO free_analyses (id, client_fingerprint, ip_address, user_agent) VALUES (?, ?, ?, ?)',
      [freeAnalysisId, fingerprint, ip, userAgent]
    );

    res.json({
      success: true,
      message: 'Free analysis tracked'
    });
  } catch (error) {
    console.error('Track anonymous error:', error);
    // Don't fail the request if tracking fails
    res.json({
      success: true,
      message: 'Tracking failed but analysis continues'
    });
  }
});

// Check if user can perform analysis
router.get('/check', authenticateToken, async (req, res) => {
  try {
    // JWT token'da userId olarak kaydediliyor
    const userId = req.user?.userId || req.user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Kullanıcı kimliği bulunamadı'
      });
    }

    const [users] = await pool.execute(
      'SELECT free_analysis_used, is_premium FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    const user = users[0];
    
    // Premium users can always analyze
    if (user.is_premium) {
      return res.json({
        success: true,
        canAnalyze: true,
        freeAnalysisUsed: false,
        isPremium: true
      });
    }
    
    res.json({
      success: true,
      canAnalyze: !user.free_analysis_used,
      freeAnalysisUsed: user.free_analysis_used,
      isPremium: false
    });
  } catch (error) {
    console.error('Analiz kontrol hatası:', error);
    res.status(500).json({
      success: false,
      message: 'Analiz kontrolü yapılırken bir hata oluştu'
    });
  }
});

// Save CV Analysis Endpoint
router.post('/', authenticateToken, async (req, res) => {
  try {
    const { analysisData } = req.body;
    const userId = req.user?.userId || req.user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Kullanıcı kimliği bulunamadı'
      });
    }

    console.log('📝 Analiz kaydetme isteği alındı:', {
      userId,
      hasAnalysisData: !!analysisData,
      overallScore: analysisData?.overallScore
    });

    // Validation
    if (!analysisData) {
      return res.status(400).json({
        success: false,
        message: 'Analiz verisi bulunamadı'
      });
    }

    // Check if user has used free analysis and premium status
    const [users] = await pool.execute(
      'SELECT free_analysis_used, is_premium FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    const user = users[0];
    
    // Premium users don't need to mark free_analysis_used
    // If free analysis is used, mark it (this is called after analysis is done)
    if (!user.is_premium && !user.free_analysis_used) {
      await pool.execute(
        'UPDATE users SET free_analysis_used = TRUE WHERE id = ?',
        [userId]
      );
      console.log('✅ Kullanıcının ücretsiz analiz hakkı kullanıldı olarak işaretlendi');
    }

    // Extract data from analysisData
    const candidateName = analysisData.candidateName || null;
    const overallScore = analysisData.overallScore || null;
    const summary = analysisData.summary || null;

    // Store full analysis data as JSON (limit to reasonable size)
    let analysisDataJson;
    try {
      analysisDataJson = JSON.stringify(analysisData);
      // MySQL JSON column has size limit, truncate if too large (16MB limit)
      if (analysisDataJson.length > 16 * 1024 * 1024) {
        console.warn('⚠️ Analysis data too large, truncating...');
        analysisDataJson = JSON.stringify({
          ...analysisData,
          sections: [],
          actionPlan: []
        });
      }
    } catch (jsonError) {
      console.error('JSON stringify hatası:', jsonError);
      analysisDataJson = JSON.stringify({ error: 'JSON serialization failed' });
    }

    // Generate UUID for analysis
    const analysisId = generateUUID();
    console.log('📝 Creating analysis with UUID:', analysisId);

    // Insert into database with UUID
    await pool.execute(
      `INSERT INTO cv_analyses (id, user_id, candidate_name, overall_score, summary, analysis_data)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [analysisId, userId, candidateName, overallScore, summary, analysisDataJson]
    );

    console.log('✅ Analiz başarıyla kaydedildi, ID:', analysisId);

    res.json({
      success: true,
      message: 'Analiz başarıyla kaydedildi',
      analysisId: analysisId
    });
  } catch (error) {
    console.error('❌ Analiz kaydetme hatası:', error);
    console.error('Hata detayı:', {
      message: error.message,
      code: error.code,
      sqlState: error.sqlState,
      sqlMessage: error.sqlMessage,
      errno: error.errno,
      stack: error.stack?.split('\n').slice(0, 5).join('\n')
    });
    res.status(500).json({
      success: false,
      message: 'Analiz kaydedilirken bir hata oluştu',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get specific analysis by ID (must be before the list route)
router.get('/:id', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 GET /:id route called with ID:', req.params.id);
    const userId = req.user?.userId || req.user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Kullanıcı kimliği bulunamadı'
      });
    }

    const analysisId = req.params.id;
    console.log('🔍 Looking for analysis:', { analysisId, userId, analysisIdType: typeof analysisId, analysisIdLength: analysisId?.length });

    // Validate analysisId
    if (!analysisId || analysisId.trim() === '') {
      console.error('❌ Empty analysis ID provided');
      return res.status(400).json({
        success: false,
        message: 'Analiz ID\'si geçersiz'
      });
    }

    const [analyses] = await pool.execute(
      `SELECT id, candidate_name, overall_score, summary, analysis_data, created_at
       FROM cv_analyses
       WHERE id = ? AND user_id = ?`,
      [analysisId, userId]
    );
    
    console.log('🔍 Query result:', { found: analyses.length, analysisId });

    if (analyses.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Analiz bulunamadı'
      });
    }

    const analysis = analyses[0];
    
    console.log('📋 Analiz bulundu:', {
      id: analysis.id,
      hasAnalysisData: !!analysis.analysis_data,
      analysisDataType: typeof analysis.analysis_data
    });
    
    // Parse JSON data
    let analysisData = null;
    if (analysis.analysis_data) {
      try {
        if (typeof analysis.analysis_data === 'string') {
          analysisData = JSON.parse(analysis.analysis_data);
        } else if (typeof analysis.analysis_data === 'object') {
          // MySQL JSON column already returns as object
          analysisData = analysis.analysis_data;
        }
        console.log('✅ Analysis data parsed successfully');
      } catch (e) {
        console.error('❌ JSON parse hatası:', e);
        console.error('Raw analysis_data:', analysis.analysis_data);
      }
    } else {
      console.warn('⚠️ analysis_data is null or undefined');
    }

    const responseData = {
      success: true,
      analysis: {
        id: analysis.id,
        candidateName: analysis.candidate_name || null,
        overallScore: analysis.overall_score || null,
        summary: analysis.summary || null,
        analysisData: analysisData,
        createdAt: analysis.created_at ? new Date(analysis.created_at).toISOString() : new Date().toISOString()
      }
    };

    console.log('📤 Sending response:', {
      hasAnalysis: !!responseData.analysis,
      hasAnalysisData: !!responseData.analysis.analysisData,
      analysisKeys: Object.keys(responseData.analysis)
    });

    res.json(responseData);
  } catch (error) {
    console.error('Analiz detay hatası:', error);
    res.status(500).json({
      success: false,
      message: 'Analiz detayı alınırken bir hata oluştu'
    });
  }
});

// Get user's analysis history (must be after the :id route)
router.get('/', authenticateToken, async (req, res) => {
  try {
    console.log('🔍 GET / route called (list endpoint)');
    const userId = req.user?.userId || req.user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Kullanıcı kimliği bulunamadı'
      });
    }

    const [analyses] = await pool.execute(
      `SELECT id, candidate_name, overall_score, summary, analysis_data, created_at
       FROM cv_analyses
       WHERE user_id = ?
       ORDER BY created_at DESC
       LIMIT 50`,
      [userId]
    );

    // Map created_at to createdAt for frontend consistency and extract candidate name
    const formattedAnalyses = analyses.map(analysis => {
      // Try to get candidate name from candidate_name field first
      let candidateName = analysis.candidate_name;
      
      // If candidate_name is null, try to extract from analysis_data
      if (!candidateName && analysis.analysis_data) {
        try {
          const analysisData = typeof analysis.analysis_data === 'string' 
            ? JSON.parse(analysis.analysis_data) 
            : analysis.analysis_data;
          candidateName = analysisData?.candidateName || null;
        } catch (e) {
          console.error('Error parsing analysis_data for candidate name:', e);
        }
      }
      
      return {
        id: analysis.id,
        candidateName: candidateName || null,
        overallScore: analysis.overall_score || null,
        summary: analysis.summary || null,
        createdAt: analysis.created_at ? new Date(analysis.created_at).toISOString() : new Date().toISOString()
      };
    });

    res.json({
      success: true,
      analyses: formattedAnalyses
    });
  } catch (error) {
    console.error('Analiz listesi hatası:', error);
    res.status(500).json({
      success: false,
      message: 'Analiz listesi alınırken bir hata oluştu'
    });
  }
});


export default router;

