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
const clean = (v) => (v ? String(v).trim() : '');
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
    const callback_id = callbackLink ? sanitize(`${userId}${Date.now()}`) : '';
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
router.post(
  '/paytr/callback',
  express.urlencoded({ extended: false }),
  async (req, res) => {
    try {
      const merchant_key = PAYTR_MERCHANT_KEY;
      const merchant_salt = PAYTR_MERCHANT_SALT;

      const oid = clean(req.body.merchant_oid);
      const status = clean(req.body.status);
      const total = clean(req.body.total_amount);
      const incoming_hash = clean(req.body.hash);
      const callback_id = clean(req.body.callback_id);

    const hash_str = oid + merchant_salt + status + total;
    const computed_hash = crypto.createHmac('sha256', merchant_key).update(hash_str).digest('base64');
    const test_mode = clean(req.body.test_mode);

    console.log({
      merchant_oid: oid,
      status,
      total_amount: total,
      payment_amount: clean(req.body.payment_amount),
      callback_id,
      merchant_id: clean(req.body.merchant_id),
      test_mode,
      hash_str,
      computed_hash,
      incoming_hash
    });

    // In test mode, allow bypass (PayTR test callback hash eşleşmeyebilir)
    if (test_mode !== '1' && computed_hash !== incoming_hash) {
      return res.status(400).send('INVALID_HASH');
    }

      if (!callback_id) {
        console.error('PayTR callback_id bulunamadı');
        return res.status(400).send('INVALID_CALLBACK_ID');
      }

      const parts = callback_id.split('_');
      if (parts.length < 2) {
        console.error('PayTR callback_id formatı geçersiz:', callback_id);
        return res.status(400).send('INVALID_CALLBACK_ID_FORMAT');
      }

      const userId = parts[0];

      if (status === 'success') {
        const [payments] = await pool.execute(
          'SELECT id, user_id, plan_type, amount FROM payments WHERE transaction_id = ? AND status = ?',
          [callback_id, 'pending']
        );

        if (payments.length === 0) {
          console.error('PayTR callback için ödeme kaydı bulunamadı:', callback_id);
          return res.status(404).send('PAYMENT_NOT_FOUND');
        }

        const payment = payments[0];

        await pool.execute(
          'UPDATE payments SET status = ?, transaction_id = ? WHERE id = ?',
          ['completed', oid, payment.id]
        );

        let userEmailForReceipt = null;
        let userNameForReceipt = null;

        if (payment.plan_type === 'pro') {
          await pool.execute(
            'UPDATE users SET is_premium = TRUE WHERE id = ?',
            [userId]
          );

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
          const [users] = await pool.execute(
            'SELECT email, name FROM users WHERE id = ?',
            [userId]
          );
          userEmailForReceipt = users[0]?.email || null;
          userNameForReceipt = users[0]?.name || null;
        }

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
          merchant_oid: oid,
          total_amount: total,
          user_id: userId,
          plan_type: payment.plan_type
        });

        res.send('OK');
      } else {
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

        console.log('❌ PayTR ödeme başarısız:', oid);
        res.send('OK');
      }
    } catch (error) {
      console.error('PayTR callback error:', error);
      res.status(500).send('ERROR');
    }
  }
);

export default router;

