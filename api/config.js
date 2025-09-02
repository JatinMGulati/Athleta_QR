export default function handler(req, res) {
  res.json({
    clientId: process.env.CLIENT_ID || ''
  });
}
