import express from 'express';

const router = express.Router();

router.get('/config', (req, res) => {
  res.json({
    clientId: process.env.CLIENT_ID,
    appUrl: process.env.FRONTEND_ORIGIN || 'https://athleta-qr.vercel.app',
    allowedDomain: process.env.ALLOWED_EMAIL_DOMAIN || '@rvu.edu.in'
  });
});

export default router;
