import mysql from 'mysql2/promise';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Kök dizindeki .env dosyasını oku
dotenv.config({ path: path.resolve(__dirname, '../../.env') });

// Hostinger MySQL Connection Configuration
const dbConfig = {
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'cv_master',
  port: parseInt(process.env.DB_PORT || '3306'),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  enableKeepAlive: true,
  keepAliveInitialDelay: 0
};

// Debug: Bağlantı bilgilerini logla (şifre hariç)
if (process.env.NODE_ENV !== 'production') {
  console.log('🔍 MySQL Bağlantı Ayarları:');
  console.log('   Host:', dbConfig.host);
  console.log('   User:', dbConfig.user);
  console.log('   Database:', dbConfig.database);
  console.log('   Port:', dbConfig.port);
  console.log('   Password:', dbConfig.password ? '***' : '(boş)');
}

// Create connection pool
const pool = mysql.createPool(dbConfig);

// Test connection (async, don't block server start)
pool.getConnection()
  .then(connection => {
    console.log('✅ MySQL veritabanına başarıyla bağlandı');
    connection.release();
  })
  .catch(err => {
    console.error('❌ MySQL bağlantı hatası:', err.message);
    console.error('Hata kodu:', err.code);
    console.error('Tam hata:', err);
    console.error('\nLütfen .env dosyasındaki veritabanı bilgilerini kontrol edin.');
    console.error('Backend çalışmaya devam ediyor, ancak veritabanı işlemleri çalışmayacak.');
    console.error('\n🔍 Kontrol edilmesi gerekenler:');
    console.error('  1. DB_HOST doğru mu? (Hostinger için genellikle "localhost" veya verilen host)');
    console.error('  2. DB_USER, DB_PASSWORD, DB_NAME doğru mu?');
    console.error('  3. Veritabanı oluşturuldu mu? (server/database/schema.sql dosyasını çalıştırın)');
    console.error('  4. Hostinger\'da MySQL servisi aktif mi?');
    console.error('  5. Şifrede özel karakterler varsa tırnak içine alın: DB_PASSWORD="-23-Hasan008"');
  });

export default pool;

