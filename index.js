import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import authRoutes from './routes/auth.js';
import analysesRoutes from './routes/analyses.js';
import paymentsRoutes from './routes/payments.js';
import appointmentsRoutes from './routes/appointments.js';
import profileRoutes from './routes/profile.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Kök dizindeki .env dosyasını oku
dotenv.config({ path: path.resolve(__dirname, '../.env') });

const app = express();
const PORT = process.env.PORT || 5000;

// Middleware - CORS ayarları
// FRONTEND_URL'i normalize et (sonundaki slash'i kaldır)
const normalizeOrigin = (url) => {
  if (!url) return 'http://localhost:3000';
  return url.replace(/\/$/, ''); // Sonundaki slash'i kaldır
};

const allowedOrigins = [
  normalizeOrigin(process.env.FRONTEND_URL),
  'http://localhost:3000',
  'https://cvizyonai.com',
  'https://www.cvizyonai.com'
];

app.use(cors({
  origin: (origin, callback) => {
    // Origin yoksa (ör: Postman, curl) veya allowedOrigins'de varsa izin ver
    if (!origin || allowedOrigins.includes(origin) || allowedOrigins.some(allowed => origin.startsWith(allowed))) {
      callback(null, true);
    } else {
      // Origin'i normalize et ve tekrar kontrol et
      const normalizedOrigin = normalizeOrigin(origin);
      if (allowedOrigins.includes(normalizedOrigin)) {
        callback(null, true);
      } else {
        callback(new Error('CORS policy: Origin not allowed'));
      }
    }
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Get client IP address middleware
app.use((req, res, next) => {
  // Get real IP from various proxy headers
  let ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 
           req.headers['x-real-ip'] || 
           req.connection?.remoteAddress || 
           req.socket?.remoteAddress ||
           req.ip ||
           'unknown';
  
  // Normalize IP address (convert IPv6 localhost to IPv4)
  if (ip.startsWith('::ffff:')) {
    ip = ip.substring(7);
  } else if (ip === '::1' || ip === 'localhost') {
    ip = '127.0.0.1';
  }
  
  req.clientIp = ip;
  next();
});

// Health check (Railway için)
app.get('/api/health', (req, res) => {
  res.status(200).json({ 
    success: true, 
    message: 'CVizyon AI API is running',
    timestamp: new Date().toISOString(),
    uptime: process.uptime()
  });
});

// Root health check (Railway bazen root path'i kontrol eder)
app.get('/', (req, res) => {
  res.status(200).json({ 
    success: true, 
    message: 'CVizyon AI API is running',
    timestamp: new Date().toISOString()
  });
});

// Routes
app.use('/api/auth', authRoutes);
app.use('/api/analyses', analysesRoutes);
app.use('/api/payments', paymentsRoutes);
app.use('/api/appointments', appointmentsRoutes);
app.use('/api/profile', profileRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({
    success: false,
    message: 'Sunucu hatası oluştu'
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    message: 'Endpoint bulunamadı'
  });
});

const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server ${PORT} portunda çalışıyor`);
  console.log(`📡 API: http://localhost:${PORT}/api`);
});

// Graceful shutdown for Railway
process.on('SIGTERM', () => {
  console.log('SIGTERM signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  console.log('SIGINT signal received: closing HTTP server');
  server.close(() => {
    console.log('HTTP server closed');
    process.exit(0);
  });
});

