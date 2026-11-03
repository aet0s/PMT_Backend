// server/src/middleware/validate.js
// Safe Zod schema validation middleware preventing crashes on malformed inputs

const validate = (schema) => (req, res, next) => {
  try {
    const rawBody = req.body ?? {};
    req.body = schema.parse(rawBody);
    return next();
  } catch (err) {
    if (err && (err.name === 'ZodError' || Array.isArray(err.issues) || Array.isArray(err.errors))) {
      const issues = err.issues || err.errors || [];
      const firstIssue = issues[0];
      const fieldPath = firstIssue && Array.isArray(firstIssue.path) && firstIssue.path.length > 0
        ? `${firstIssue.path.join('.')}: `
        : '';
      const issueMessage = firstIssue?.message || 'Invalid input payload';

      return res.status(400).json({
        error: {
          message: `${fieldPath}${issueMessage}`,
          code: 'VALIDATION_ERROR',
          details: issues.map((i) => ({
            field: Array.isArray(i.path) ? i.path.join('.') : '',
            message: i.message || 'Validation error'
          })),
          requestId: req.id
        }
      });
    }

    // For any unexpected parsing or schema errors, return generic 400 rather than crashing
    return res.status(400).json({
      error: {
        message: 'Malformed or invalid request payload',
        code: 'VALIDATION_ERROR',
        requestId: req.id
      }
    });
  }
};

module.exports = validate;
