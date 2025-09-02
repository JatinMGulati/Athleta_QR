import { sql } from '@vercel/postgres';
import { OAuth2Client } from 'google-auth-library';

const client = new OAuth2Client(process.env.CLIENT_ID);

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    res.setHeader('Allow', ['POST']);
    return res.status(405).end(`Method ${req.method} Not Allowed`);
  }

  try {
    const authHeader = req.headers.authorization || '';
    let idToken = '';
    if (authHeader.startsWith('Bearer ')) {
      idToken = authHeader.split(' ')[1];
    } else if (req.body && (req.body.credential || req.body.id_token)) {
      idToken = req.body.credential || req.body.id_token;
    }
    if (!idToken) {
      return res.status(400).json({ success: false, status: 'no_token', message: 'No ID token provided' });
    }

    // Verify Google ID token
    const ticket = await client.verifyIdToken({ idToken, audience: process.env.CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name || '';
    const allowedDomain = process.env.ALLOWED_EMAIL_DOMAIN || '@rvu.edu.in';
    if (!email || !email.endsWith(allowedDomain)) {
      return res.json({ success: false, status: 'invalid_email', message: 'Please use your official RVU email address.' });
    }

    // Device token (from header or cookie)
    const deviceToken = req.headers['x-device-token'] || (req.cookies && req.cookies.device_token);
    // Check if device is already mapped to another email
    if (deviceToken) {
      const deviceRes = await sql`SELECT email FROM devices WHERE token = ${deviceToken}`;
      if (deviceRes.rows.length > 0 && deviceRes.rows[0].email !== email) {
        return res.json({ success: false, status: 'locked_device', message: 'This device is locked to another account.' });
      }
    }

    // Check if already claimed
    const claimRes = await sql`SELECT * FROM claims WHERE email = ${email}`;
    if (claimRes.rows.length > 0) {
      // Block device for future attempts
      if (deviceToken) {
        await sql`INSERT INTO devices (token, email) VALUES (${deviceToken}, ${email}) ON CONFLICT (token) DO UPDATE SET email = EXCLUDED.email`;
      }
      return res.json({ success: false, status: 'already_claimed', message: 'This email has already claimed a jersey.' });
    }

    // Insert claim
    await sql`INSERT INTO claims (email, name) VALUES (${email}, ${name})`;
    // Save device mapping
    let finalDeviceToken = deviceToken;
    if (!finalDeviceToken) {
      finalDeviceToken = Math.random().toString(36).substring(2, 15);
      res.setHeader('Set-Cookie', `device_token=${finalDeviceToken}; Path=/; Max-Age=31536000`);
    }
    await sql`INSERT INTO devices (token, email) VALUES (${finalDeviceToken}, ${email}) ON CONFLICT (token) DO UPDATE SET email = EXCLUDED.email`;
    return res.json({ success: true, status: 'success', message: 'Claim successful. Show this to collect your jersey.' });
  } catch (err) {
    console.error('Error verifying ID token or processing claim:', err);
    return res.status(500).json({ success: false, status: 'server_error', message: 'Authentication failed' });
  }
}
