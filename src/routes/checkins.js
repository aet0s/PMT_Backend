const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { sanitizePlain } = require('../utils/sanitizer');
const { notify } = require('../services/notify');

const router = express.Router();

// POST /api/checkins/:id/review
router.post(
  '/checkins/:id/review',
  requireAuth,
  requirePermission('checkin.review'),
  async (req, res, next) => {
    const checkinId = Number(req.params.id);
    const { action, note } = req.body;

    if (!['ack', 'question', 'request_evidence'].includes(action)) {
      return res.status(400).json({
        error: { message: "Invalid action. Must be 'ack', 'question', or 'request_evidence'", code: 'BAD_REQUEST' }
      });
    }

    try {
      const [checkin] = await req.db.query(
        `SELECT ci.*, c.title as card_title, l.board_id, b.workspace_id
         FROM check_ins ci
         JOIN cards c ON ci.card_id = c.id
         JOIN lists l ON c.list_id = l.id
         JOIN boards b ON l.board_id = b.id
         WHERE ci.id = ?`,
        [checkinId]
      );

      if (!checkin) {
        return res.status(404).json({ error: { message: 'Check-in not found', code: 'NOT_FOUND' } });
      }

      const cleanNote = note ? sanitizePlain(String(note).trim()) : null;
      const result = await req.db.execute(
        `INSERT INTO check_in_reviews (check_in_id, reviewer_id, action, note, created_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [checkinId, req.user.id, action, cleanNote]
      );

      const [review] = await req.db.query(
        `SELECT r.*, u.name as reviewer_name, u.avatar_url as reviewer_avatar
         FROM check_in_reviews r
         JOIN users u ON r.reviewer_id = u.id
         WHERE r.id = ?`,
        [result.insertId]
      );

      // Notify check-in author
      await notify({
        db: req.db,
        tenantId: req.tenant?.id,
        boardId: checkin.board_id,
        cardId: checkin.card_id,
        eventType: 'checkin.reviewed',
        actorId: req.user.id,
        targetUserId: checkin.user_id,
        data: {
          action,
          note: cleanNote,
          cardTitle: checkin.card_title,
          reviewerName: req.user.name
        }
      });

      return res.status(201).json({ review });
    } catch (err) {
      next(err);
    }
  }
);

// POST /api/checkin-reviews/:id/answer
router.post(
  '/checkin-reviews/:id/answer',
  requireAuth,
  requirePermission('checkin.create'),
  async (req, res, next) => {
    const reviewId = Number(req.params.id);
    const { answer_note, evidence_url, attachment_id } = req.body;

    try {
      const [review] = await req.db.query(
        `SELECT r.*, ci.user_id as checkin_user_id, ci.id as checkin_id
         FROM check_in_reviews r
         JOIN check_ins ci ON r.check_in_id = ci.id
         WHERE r.id = ?`,
        [reviewId]
      );

      if (!review) {
        return res.status(404).json({ error: { message: 'Review not found', code: 'NOT_FOUND' } });
      }

      // Only check-in author can answer
      if (Number(review.checkin_user_id) !== Number(req.user.id)) {
        return res.status(403).json({ error: { message: 'Only check-in author can answer review', code: 'FORBIDDEN' } });
      }

      await req.db.execute(
        'UPDATE check_in_reviews SET answered_at = NOW() WHERE id = ?',
        [reviewId]
      );

      // If evidence supplied, update check_in
      if (evidence_url || attachment_id) {
        await req.db.execute(
          `UPDATE check_ins
           SET evidence_url = COALESCE(?, evidence_url),
               attachment_id = COALESCE(?, attachment_id)
           WHERE id = ?`,
          [evidence_url || null, attachment_id || null, review.checkin_id]
        );
      }

      const [updatedReview] = await req.db.query('SELECT * FROM check_in_reviews WHERE id = ?', [reviewId]);
      return res.json({ review: updatedReview });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
