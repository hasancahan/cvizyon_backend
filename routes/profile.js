import express from 'express';
import bcrypt from 'bcryptjs';
import pool from '../config/database.js';
import { authenticateToken } from '../middleware/auth.js';

const router = express.Router();

// Get user profile
router.get('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Kullanıcı bilgisi bulunamadı'
      });
    }

    const [users] = await pool.execute(
      'SELECT id, name, email, free_analysis_used, is_premium, created_at FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    const user = users[0];

    // Get statistics
    const [analysisCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM cv_analyses WHERE user_id = ?',
      [userId]
    );

    const [paymentCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM payments WHERE user_id = ?',
      [userId]
    );

    const [appointmentCount] = await pool.execute(
      'SELECT COUNT(*) as count FROM appointments WHERE user_id = ?',
      [userId]
    );

    res.json({
      success: true,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        free_analysis_used: user.free_analysis_used || false,
        is_premium: user.is_premium || false,
        created_at: user.created_at
      },
      statistics: {
        total_analyses: analysisCount[0]?.count || 0,
        total_payments: paymentCount[0]?.count || 0,
        total_appointments: appointmentCount[0]?.count || 0
      }
    });
  } catch (error) {
    console.error('Get profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Profil bilgileri alınırken bir hata oluştu'
    });
  }
});

// Update user profile
router.put('/', authenticateToken, async (req, res) => {
  try {
    const userId = req.user?.userId || req.user?.id;
    const { name, email, currentPassword, newPassword } = req.body;

    if (!userId) {
      return res.status(401).json({
        success: false,
        message: 'Kullanıcı bilgisi bulunamadı'
      });
    }

    // Get current user
    const [users] = await pool.execute(
      'SELECT id, name, email, password FROM users WHERE id = ?',
      [userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        success: false,
        message: 'Kullanıcı bulunamadı'
      });
    }

    const currentUser = users[0];
    const updates = [];
    const values = [];

    // Update name
    if (name && name !== currentUser.name) {
      updates.push('name = ?');
      values.push(name);
    }

    // Update email (check if email is already taken)
    if (email && email !== currentUser.email) {
      const [existingUsers] = await pool.execute(
        'SELECT id FROM users WHERE email = ? AND id != ?',
        [email, userId]
      );

      if (existingUsers.length > 0) {
        return res.status(409).json({
          success: false,
          message: 'Bu e-posta adresi zaten kullanılıyor'
        });
      }

      updates.push('email = ?');
      values.push(email);
    }

    // Update password (if provided)
    if (newPassword) {
      if (!currentPassword) {
        return res.status(400).json({
          success: false,
          message: 'Mevcut şifre gereklidir'
        });
      }

      // Verify current password
      const isValidPassword = await bcrypt.compare(currentPassword, currentUser.password);
      if (!isValidPassword) {
        return res.status(401).json({
          success: false,
          message: 'Mevcut şifre hatalı'
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          success: false,
          message: 'Yeni şifre en az 8 karakter olmalıdır'
        });
      }

      const hashedPassword = await bcrypt.hash(newPassword, 10);
      updates.push('password = ?');
      values.push(hashedPassword);
    }

    if (updates.length === 0) {
      return res.status(400).json({
        success: false,
        message: 'Güncellenecek bir alan bulunamadı'
      });
    }

    values.push(userId);

    await pool.execute(
      `UPDATE users SET ${updates.join(', ')} WHERE id = ?`,
      values
    );

    // Get updated user
    const [updatedUsers] = await pool.execute(
      'SELECT id, name, email, free_analysis_used, is_premium FROM users WHERE id = ?',
      [userId]
    );

    res.json({
      success: true,
      message: 'Profil başarıyla güncellendi',
      user: {
        id: updatedUsers[0].id,
        name: updatedUsers[0].name,
        email: updatedUsers[0].email,
        free_analysis_used: updatedUsers[0].free_analysis_used || false,
        is_premium: updatedUsers[0].is_premium || false
      }
    });
  } catch (error) {
    console.error('Update profile error:', error);
    res.status(500).json({
      success: false,
      message: 'Profil güncellenirken bir hata oluştu'
    });
  }
});

export default router;

