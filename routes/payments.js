import express from 'express';
import pool from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';
import crypto from 'crypto';
import axios from 'axios';
import nodemailer from 'nodemailer';

const router = express.Router();

// Helper function to generate UUID
const generateUUID = () => {
  return crypto.randomUUID();
};

// PayTR credentials (strip surrounding quotes and trim)
const cleanEnv = (v) =>
  typeof v === 'string' ? v.replace(/^"+|"+$/g, '').replace(/^'+|'+$/g, '').trim() : v;
const PAYTR_MERCHANT_ID = cleanEnv(process.env.PAYTR_MERCHANT_ID) || '648222';
const PAYTR_MERCHANT_KEY = cleanEnv(process.env.PAYTR_MERCHANT_KEY) || 'Fz5DzcPGszXGd6mY';
const PAYTR_MERCHANT_SALT = cleanEnv(process.env.PAYTR_MERCHANT_SALT) || 'UDaAp99Rg8MqheJ4';
const PAYTR_CALLBACK_URL =
  cleanEnv(process.env.PAYTR_CALLBACK_URL) || 'https://cvizyonai.com/api/payments/paytr/callback';
const PAYTR_SUCCESS_URL =
  cleanEnv(process.env.PAYTR_SUCCESS_URL) || cleanEnv(process.env.FRONTEND_URL) || 'http://localhost:3000';
const PAYTR_FAIL_URL = cleanEnv(process.env.PAYTR_FAIL_URL) || PAYTR_SUCCESS_URL;

// Build success return URL with a marker to trigger frontend modal
const buildSuccessReturnUrl = () => {
  try {
    const url = new URL(PAYTR_SUCCESS_URL);
    url.searchParams.set('paytr_return', '1');
    return url.toString();
  } catch (err) {
    return PAYTR_SUCCESS_URL;
  }
};

// Email helper (optional; works when SMTP env vars are set)
const sendPaymentEmail = async ({ to, planName, amount }) => {
  if (!process.env.SMTP_HOST || !process.env.SMTP_USER || !process.env.SMTP_PASS) {
    console.log('ℹ️ SMTP ayarları bulunamadı, e-posta gönderilmedi');
    return;
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: parseInt(process.env.SMTP_PORT || '587', 10),
    secure: process.env.SMTP_SECURE === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  const mailOptions = {
    from: process.env.SMTP_FROM || process.env.SMTP_USER,
    to,
    subject: 'Ödemeniz Başarıyla Alındı',
    text: `Merhaba,\n\n${planName} için ödemeniz başarıyla alındı. Tutar: ${amount} TL\n\nTeşekkürler.`,
    html: `<p>Merhaba,</p><p><strong>${planName}</strong> için ödemeniz başarıyla alındı.</p><p>Tutar: <strong>${amount} TL</strong></p><p>Teşekkürler.</p>`
  };

  await transporter.sendMail(mailOptions);
};

// Save payment record
router.post('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const { plan_type, amount, payment_method, transaction_id } = req.body;

    if (!plan_type || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Plan tipi ve tutar gereklidir'
      });
    }

    // Generate UUID for payment
    const paymentId = generateUUID();

    await pool.execute(
      'INSERT INTO payments (id, user_id, plan_type, amount, status, payment_method, transaction_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [paymentId, userId, plan_type, amount, 'completed', payment_method || 'card', transaction_id || null]
    );

    console.log('✅ Ödeme kaydı oluşturuldu:', paymentId);

    res.json({
      success: true,
      message: 'Ödeme kaydı oluşturuldu',
      paymentId: paymentId
    });
  } catch (error) {
    console.error('Payment save error:', error);
    res.status(500).json({
      success: false,
      message: 'Ödeme kaydı oluşturulurken bir hata oluştu'
    });
  }
});

// Get user's payment history
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;

    const [payments] = await pool.execute(
      'SELECT id, plan_type, amount, status, payment_method, transaction_id, created_at FROM payments WHERE user_id = ? ORDER BY created_at DESC',
      [userId]
    );

    // Convert amount from DECIMAL to number
    const formattedPayments = payments.map(payment => ({
      ...payment,
      amount: parseFloat(payment.amount) || 0
    }));

    res.json({
      success: true,
      payments: formattedPayments
    });
  } catch (error) {
    console.error('Get payments error:', error);
    res.status(500).json({
      success: false,
      message: 'Ödeme kayıtları alınırken bir hata oluştu'
    });
  }
});

// PayTR Link Create Endpoint
router.post('/paytr/create', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const { plan_type, amount } = req.body;

    if (!plan_type || !amount) {
      return res.status(400).json({
        success: false,
        message: 'Plan tipi ve tutar gereklidir'
      });
    }

    // Get user email for callback_id
    const [users] = await pool.execute(
      'SELECT email FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    const userEmail = users[0].email;

    // Plan details
    const planDetails = {
      pro: {
        name: 'CVizyon AI - Profesyonel Plan',
        price: 199
      },
      consulting: {
        name: 'CVizyon AI - Danışmanlık Seansı',
        price: 999
      }
    };

    const plan = planDetails[plan_type];
    if (!plan) {
      return res.status(400).json({
        success: false,
        message: 'Geçersiz plan tipi'
      });
    }

    // Calculate total with KDV (20%)
    const totalAmount = Math.round(amount * 1.20 * 100); // PayTR requires amount in kuruş (multiply by 100)

    // PayTR Link API parameters
    const name = plan.name;
    const price = totalAmount.toString();
    const currency = 'TL';
    const max_installment = '12';
    const link_type = 'product';
    const lang = 'tr';
    const min_count = '1';
    const max_count = '1';
    const debug_on = '1';

    // Callback link: PayTR production ortamında zorunlu. Localhost kabul edilmez.
    // Eğer .env'de geçerli (localhost olmayan) bir URL yoksa callback'i göndermiyoruz.
    const callbackLink =
      PAYTR_CALLBACK_URL && !PAYTR_CALLBACK_URL.includes('localhost') ? PAYTR_CALLBACK_URL : '';

    // callback_link gönderiliyorsa callback_id zorunlu. Alfanumerik olmalı (PayTR şartı).
    const sanitize = (val) => val.replace(/[^a-zA-Z0-9]/g, '');
    const callback_id = callbackLink ? `${sanitize(userId)}${Date.now()}` : '';
    const successReturnUrl = buildSuccessReturnUrl();

    // Required fields for token generation
    const required = name + price + currency + max_installment + link_type + lang + min_count;

    // Generate PayTR token
    const paytr_token = crypto
      .createHmac('sha256', PAYTR_MERCHANT_KEY)
      .update(required + PAYTR_MERCHANT_SALT)
      .digest('base64');

    // Prepare form data
    const formData = new URLSearchParams({
      merchant_id: PAYTR_MERCHANT_ID,
      name: name,
      price: price,
      currency: currency,
      max_installment: max_installment,
      link_type: link_type,
      lang: lang,
      min_count: min_count,
      max_count: max_count,
      debug_on: debug_on,
      paytr_token: paytr_token
    });

    // callback_link sadece localhost olmayan geçerli bir URL ise eklenir
    if (callbackLink) {
      formData.append('callback_link', callbackLink);
      formData.append('callback_id', callback_id);
    }

    // Kullanıcının ödemeden sonra döneceği URL'ler (PayTR destekliyorsa)
    if (PAYTR_SUCCESS_URL) {
      formData.append('callback_url', successReturnUrl);
    }

    // Call PayTR API
    const response = await axios.post(
      'https://www.paytr.com/odeme/api/link/create',
      formData.toString(),
      {
        headers: {
          'Content-Type': 'application/x-www-form-urlencoded'
        }
      }
    );

    const responseData = response.data;

    if (responseData.status === 'success') {
      // Save pending payment record
      const paymentId = generateUUID();
      await pool.execute(
        'INSERT INTO payments (id, user_id, plan_type, amount, status, payment_method, transaction_id) VALUES (?, ?, ?, ?, ?, ?, ?)',
        [paymentId, userId, plan_type, amount, 'pending', 'paytr', callback_id]
      );

      console.log('✅ PayTR link oluşturuldu:', responseData.link);

      res.json({
        success: true,
        payment_link: responseData.link,
        payment_id: paymentId,
        callback_id: callback_id
      });
    } else {
      console.error('PayTR link oluşturma hatası:', responseData);
      res.status(400).json({
        success: false,
        message: responseData.reason || 'PayTR link oluşturulamadı'
      });
    }
  } catch (error) {
    console.error('PayTR create error:', error);
    res.status(500).json({
      success: false,
      message: error.response?.data?.reason || 'PayTR link oluşturulurken bir hata oluştu'
    });
  }
});

// PayTR Callback Endpoint (No authentication required - called by PayTR)
router.post('/paytr/callback', async (req, res) => {
  try {
    const callback = req.body;

    // DEBUG: callback gövdesini logla (hata ayıklama için)
    console.log('🔔 PayTR callback payload:', callback);

    // PayTR Link API formülü (dokümana göre):
    // hash_str = merchant_oid + merchant_salt + status + total_amount
    const oidPart = String(callback.merchant_oid ?? '');
    const statusPart = String(callback.status ?? '');
    const totalPart = String(callback.total_amount ?? '');
    const hashStr = oidPart + PAYTR_MERCHANT_SALT + statusPart + totalPart;
    const computedHash = crypto.createHmac('sha256', PAYTR_MERCHANT_KEY).update(hashStr).digest('base64');

    if (computedHash !== callback.hash) {
      console.error('PayTR callback hash doğrulama hatası', {
        id: callback.id,
        merchant_oid: callback.merchant_oid,
        status: callback.status,
        total_amount: callback.total_amount,
        payment_amount: callback.payment_amount,
        merchant_id: callback.merchant_id,
        callback_id: callback.callback_id,
        computed_hash: computedHash,
        incoming_hash: callback.hash,
        hash_str: hashStr,
        key_length: PAYTR_MERCHANT_KEY?.length || 0,
        salt_length: PAYTR_MERCHANT_SALT?.length || 0
      });
      return res.status(400).send('INVALID_HASH');
    }

    // Extract callback_id and user_id
    const callback_id = callback.callback_id;
    if (!callback_id) {
      console.error('PayTR callback_id bulunamadı');
      return res.status(400).send('INVALID_CALLBACK_ID');
    }

    // Parse callback_id (format: userId_timestamp)
    const parts = callback_id.split('_');
    if (parts.length < 2) {
      console.error('PayTR callback_id formatı geçersiz:', callback_id);
      return res.status(400).send('INVALID_CALLBACK_ID_FORMAT');
    }

    const userId = parts[0];

    if (callback.status === 'success') {
      // Find pending payment by callback_id
      const [payments] = await pool.execute(
        'SELECT id, user_id, plan_type, amount FROM payments WHERE transaction_id = ? AND status = ?',
        [callback_id, 'pending']
      );

      if (payments.length === 0) {
        console.error('PayTR callback için ödeme kaydı bulunamadı:', callback_id);
        return res.status(404).send('PAYMENT_NOT_FOUND');
      }

      const payment = payments[0];

      // Update payment status
      await pool.execute(
        'UPDATE payments SET status = ?, transaction_id = ? WHERE id = ?',
        ['completed', callback.merchant_oid, payment.id]
      );

      // If pro plan, upgrade user to premium
      let userEmailForReceipt = null;
      let userNameForReceipt = null;

      // If pro plan, upgrade user to premium
      if (payment.plan_type === 'pro') {
        await pool.execute(
          'UPDATE users SET is_premium = TRUE WHERE id = ?',
          [userId]
        );

        // Get user's IP address and remove from free_analyses
        const [users] = await pool.execute(
          'SELECT ip_address, email, name FROM users WHERE id = ?',
          [userId]
        );

        const userIp = users[0]?.ip_address;
        userEmailForReceipt = users[0]?.email || null;
        userNameForReceipt = users[0]?.name || null;

        if (userIp && userIp !== 'unknown') {
          await pool.execute(
            'DELETE FROM free_analyses WHERE ip_address = ?',
            [userIp]
          );
        }

        console.log('✅ Kullanıcı premium olarak güncellendi:', userId);
      } else {
        // Non-pro plan için de e-posta adresi alınsın
        const [users] = await pool.execute(
          'SELECT email, name FROM users WHERE id = ?',
          [userId]
        );
        userEmailForReceipt = users[0]?.email || null;
        userNameForReceipt = users[0]?.name || null;
      }

      // Send payment receipt email (if SMTP configured)
      if (userEmailForReceipt) {
        const amountTl = parseFloat(payment.amount || 0);
        const planName =
          payment.plan_type === 'pro'
            ? 'CVizyon AI - Profesyonel Plan'
            : 'CVizyon AI - Danışmanlık Seansı';

        try {
          await sendPaymentEmail({
            to: userEmailForReceipt,
            planName,
            amount: amountTl
          });
        } catch (err) {
          console.error('E-posta gönderilemedi:', err?.message || err);
        }
      }

      console.log('✅ PayTR ödeme başarılı:', {
        merchant_oid: callback.merchant_oid,
        total_amount: callback.total_amount,
        user_id: userId,
        plan_type: payment.plan_type
      });

      res.send('OK');
    } else {
      // Payment failed - update status
      const [payments] = await pool.execute(
        'SELECT id FROM payments WHERE transaction_id = ? AND status = ?',
        [callback_id, 'pending']
      );

      if (payments.length > 0) {
        await pool.execute(
          'UPDATE payments SET status = ? WHERE id = ?',
          ['failed', payments[0].id]
        );
      }

      console.log('❌ PayTR ödeme başarısız:', callback.merchant_oid);
      res.send('OK');
    }
  } catch (error) {
    console.error('PayTR callback error:', error);
    res.status(500).send('ERROR');
  }
});

export default router;

