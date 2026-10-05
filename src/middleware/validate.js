const validate = (schema) => (req, res, next) => {
  try {
    req.body = schema.parse(req.body);
    next();
  } catch (err) {
    if (err.name === 'ZodError') {
      const firstIssue = err.errors[0];
      return res.status(400).json({
        error: {
          message: `${firstIssue.path.join('.')}: ${firstIssue.message}`,
          code: 'VALIDATION_ERROR',
          details: err.errors
        }
      });
    }
    next(err);
  }
};

module.exports = validate;
