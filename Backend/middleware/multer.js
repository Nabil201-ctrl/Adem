// backend/middleware/multer.js
export function handleMulterError(err, req, res, next) {
  if (err instanceof multer.MulterError) {
    return res.status(400).json({ error: { message: err.message, code: 'MULTER_ERROR' } });
  } else if (err) {
    return res.status(400).json({ error: { message: err.message, code: 'FILE_ERROR' } });
  }
  next();
}