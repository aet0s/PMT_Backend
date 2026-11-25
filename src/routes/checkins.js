// server/src/routes/checkins.js
// Review & answer endpoints supporting both v3 daily_updates and legacy check_ins.
const express = require('express');
const { requireAuth } = require('../middleware/auth');
const { requirePermission } = require('../middleware/permissions');
const { sanitizePlain } = require('../utils/sanitizer');
const auditService = require('../services/audit');

const router = express.Router();

const VALID_REVIEW_ACTIONS = ['seen', 'ask_proof', 'ack', 'request_evidence', 'question'];

function mapReviewAction(action) {
  if (action === 'seen') return 'ack';
  if (action === 'ask_proof') return 'request_evidence';
  return action;
}

// POST /api/daily-updates/:id/review
router.post(
  '/daily-updates/:id/review',
  requireAuth,
  requirePermission('checkin.review'),
  async (req, res, next) => {
    const dailyUpdateId = Number(req.params.id);
    const { action, note } = req.body;

    if (!VALID_REVIEW_ACTIONS.includes(action)) {
      return res.status(400).json({
        error: { message: "Invalid action. Must be 'ack', 'question', or 'request_evidence'", code: 'BAD_REQUEST' }
      });
    }
    const dbAction = mapReviewAction(action);

    try {
      const [du] = await req.db.query('SELECT * FROM daily_updates WHERE id = ?', [dailyUpdateId]);
      if (!du) {
        return res.status(404).json({ error: { message: 'Daily update not found', code: 'NOT_FOUND' } });
      }

      const cleanNote = note ? sanitizePlain(String(note).trim()).slice(0, 500) : null;
      const result = await req.db.execute(
        `INSERT INTO check_in_reviews (daily_update_id, reviewer_id, action, note, created_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [dailyUpdateId, req.user.id, dbAction, cleanNote]
      );

      const [review] = await req.db.query(
        `SELECT r.*, u.name AS reviewer_name, u.avatar_url AS reviewer_avatar
         FROM check_in_reviews r
         JOIN users u ON r.reviewer_id = u.id
         WHERE r.id = ?`,
        [result.insertId]
      );

      await auditService.record(req.db, {
        userId: req.user.id,
        workspaceId: du.workspace_id,
        category: 'checkin',
        action: 'checkin.reviewed',
        entityType: 'daily_update',
        entityId: dailyUpdateId,
        meta: { target_user_id: du.user_id, review_action: dbAction, review_id: review.id },
        req
      });

      return res.status(201).json({ review });
    } catch (err) {
      next(err);
    }
  }
);

// POST /api/daily-update-reviews/:id/answer
router.post(
  '/daily-update-reviews/:id/answer',
  requireAuth,
  requirePermission('checkin.create'),
  async (req, res, next) => {
    const reviewId = Number(req.params.id);
    const { answer_note, evidence_url } = req.body;

    try {
      const [review] = await req.db.query(
        `SELECT r.*, du.user_id AS du_user_id, du.workspace_id, du.id AS du_id
         FROM check_in_reviews r
         JOIN daily_updates du ON r.daily_update_id = du.id
         WHERE r.id = ?`,
        [reviewId]
      );
      if (!review) {
        return res.status(404).json({ error: { message: 'Review not found', code: 'NOT_FOUND' } });
      }
      if (Number(review.du_user_id) !== Number(req.user.id)) {
        return res.status(403).json({ error: { message: 'Only the daily update author can answer this review', code: 'FORBIDDEN' } });
      }

      const cleanAnswer = answer_note ? sanitizePlain(String(answer_note).trim()).slice(0, 500) : null;
      await req.db.execute(
        'UPDATE check_in_reviews SET answered_at = NOW(), answer_note = ? WHERE id = ?',
        [cleanAnswer, reviewId]
      );

      if (evidence_url) {
        await req.db.execute(
          `UPDATE daily_update_items SET evidence_url = COALESCE(?, evidence_url) WHERE daily_update_id = ? LIMIT 1`,
          [String(evidence_url).trim().slice(0, 1000), review.du_id]
        );
      }

      const [updatedReview] = await req.db.query('SELECT * FROM check_in_reviews WHERE id = ?', [reviewId]);

      await auditService.record(req.db, {
        userId: req.user.id,
        workspaceId: review.workspace_id,
        category: 'checkin',
        action: 'checkin.answered',
        entityType: 'check_in_review',
        entityId: reviewId,
        meta: { daily_update_id: review.du_id, has_evidence: Boolean(evidence_url) },
        req
      });

      return res.json({ review: updatedReview });
    } catch (err) {
      next(err);
    }
  }
);

// Legacy POST /api/checkins/:id/review
router.post(
  '/checkins/:id/review',
  requireAuth,
  requirePermission('checkin.review'),
  async (req, res, next) => {
    const checkinId = Number(req.params.id);
    const { action, note } = req.body;

    if (!VALID_REVIEW_ACTIONS.includes(action)) {
      return res.status(400).json({
        error: { message: "Invalid action. Must be 'seen' or 'ask_proof'", code: 'BAD_REQUEST' }
      });
    }
    const dbAction = mapReviewAction(action);

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

      const cleanNote = note ? sanitizePlain(String(note).trim()).slice(0, 500) : null;
      const result = await req.db.execute(
        `INSERT INTO check_in_reviews (check_in_id, reviewer_id, action, note, created_at)
         VALUES (?, ?, ?, ?, NOW())`,
        [checkinId, req.user.id, dbAction, cleanNote]
      );

      const [review] = await req.db.query(
        `SELECT r.*, u.name as reviewer_name, u.avatar_url as reviewer_avatar
         FROM check_in_reviews r
         JOIN users u ON r.reviewer_id = u.id
         WHERE r.id = ?`,
        [result.insertId]
      );

      await auditService.record(req.db, {
        userId: req.user.id,
        workspaceId: checkin.workspace_id,
        category: 'checkin',
        action: 'checkin.reviewed',
        entityType: 'checkin',
        entityId: checkinId,
        meta: { target_user_id: checkin.user_id, review_action: dbAction, review_id: review.id },
        req
      });

      return res.status(201).json({ review });
    } catch (err) {
      next(err);
    }
  }
);

// Legacy POST /api/checkin-reviews/:id/answer
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

      if (Number(review.checkin_user_id) !== Number(req.user.id)) {
        return res.status(403).json({ error: { message: 'Only check-in author can answer review', code: 'FORBIDDEN' } });
      }

      const cleanAnswer = answer_note ? sanitizePlain(String(answer_note).trim()).slice(0, 500) : null;
      await req.db.execute(
        'UPDATE check_in_reviews SET answered_at = NOW(), answer_note = ? WHERE id = ?',
        [cleanAnswer, reviewId]
      );

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
