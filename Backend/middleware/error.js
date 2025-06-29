// backend/middleware/error.js
export function errorHandler(err, req, res, next) {
  console.error('❌ Unhandled Error:', err);
  res.status(500).json({
    error: {
      message: 'Internal Server Error',
      code: 'INTERNAL_SERVER_ERROR',
      details: process.env.NODE_ENV === 'development' ? err.message : undefined,
    },
  });
}