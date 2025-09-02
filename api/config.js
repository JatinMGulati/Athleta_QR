import express from 'express';

const router = express.Router();

router.get('/config', (req, res) => {
  res.json({
    clientId: process.env.CLIENT_ID
  });
});

export default router;
