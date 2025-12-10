import express from 'express';
import pool from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';
import crypto from 'crypto';

const router = express.Router();

// Helper function to generate UUID
const generateUUID = () => {
  return crypto.randomUUID();
};

// Save appointment record
router.post('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const { name, email, phone, appointment_date, appointment_time, message } = req.body;

    if (!name || !email || !appointment_date || !appointment_time) {
      return res.status(400).json({
        success: false,
        message: 'Tüm zorunlu alanları doldurun'
      });
    }

    // Check if user has a pending appointment
    const [pendingAppointments] = await pool.execute(
      'SELECT id FROM appointments WHERE user_id = ? AND status = ?',
      [userId, 'pending']
    );

    if (pendingAppointments.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Bekleyen bir randevunuz bulunmaktadır. Lütfen mevcut randevunuzun onaylanmasını bekleyin veya iptal edin.'
      });
    }

    // Generate UUID for appointment
    const appointmentId = generateUUID();

    await pool.execute(
      'INSERT INTO appointments (id, user_id, name, email, phone, appointment_date, appointment_time, message, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [appointmentId, userId, name, email, phone || null, appointment_date, appointment_time, message || null, 'pending']
    );

    console.log('✅ Randevu kaydı oluşturuldu:', appointmentId);

    res.json({
      success: true,
      message: 'Randevu kaydı oluşturuldu',
      appointmentId: appointmentId
    });
  } catch (error) {
    console.error('Appointment save error:', error);
    res.status(500).json({
      success: false,
      message: 'Randevu kaydı oluşturulurken bir hata oluştu'
    });
  }
});

// Get user's appointment history
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;

    const [appointments] = await pool.execute(
      'SELECT id, name, email, phone, appointment_date, appointment_time, message, status, created_at FROM appointments WHERE user_id = ? ORDER BY appointment_date DESC, appointment_time DESC',
      [userId]
    );

    res.json({
      success: true,
      appointments
    });
  } catch (error) {
    console.error('Get appointments error:', error);
    res.status(500).json({
      success: false,
      message: 'Randevu kayıtları alınırken bir hata oluştu'
    });
  }
});

// Delete appointment
router.delete('/:id', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const appointmentId = req.params.id;

    if (!appointmentId) {
      return res.status(400).json({
        success: false,
        message: 'Randevu ID\'si gerekli'
      });
    }

    // Check if appointment exists and belongs to user
    const [appointments] = await pool.execute(
      'SELECT id FROM appointments WHERE id = ? AND user_id = ?',
      [appointmentId, userId]
    );

    if (appointments.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Randevu bulunamadı veya bu randevuya erişim yetkiniz yok'
      });
    }

    // Delete appointment
    await pool.execute(
      'DELETE FROM appointments WHERE id = ? AND user_id = ?',
      [appointmentId, userId]
    );

    console.log('✅ Randevu silindi:', appointmentId);

    res.json({
      success: true,
      message: 'Randevu başarıyla iptal edildi'
    });
  } catch (error) {
    console.error('Delete appointment error:', error);
    res.status(500).json({
      success: false,
      message: 'Randevu silinirken bir hata oluştu'
    });
  }
});

export default router;

