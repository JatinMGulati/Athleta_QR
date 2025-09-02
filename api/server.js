import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import { OAuth2Client } from "google-auth-library";
import { sql } from '@vercel/postgres';
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// --- Database Setup ---
async function setupDatabase() {
  try {
    await sql`
      CREATE TABLE IF NOT EXISTS claims (
        email TEXT PRIMARY KEY,
        name TEXT,
        claimed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `;
    console.log('Database tables created successfully');
  } catch (error) {
    console.error('Error setting up database:', error);
  }
}

setupDatabase();

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "../public")));

// Google OAuth2 setup
const client = new OAuth2Client(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI
);

app.post('/claim', async (req, res) => {
  try {
    const authHeader = req.headers.authorization || '';
    let idToken = '';
    if (authHeader.startsWith('Bearer ')) {
      idToken = authHeader.split(' ')[1];
    } else if (req.body && (req.body.credential || req.body.id_token)) {
      idToken = req.body.credential || req.body.id_token;
    }

    if (!idToken) {
      return res.status(400).json({ success: false, message: 'No ID token provided' });
    }

    console.log('Verifying ID token on /claim');
    const ticket = await client.verifyIdToken({ idToken, audience: process.env.CLIENT_ID });
    const payload = ticket.getPayload();
    console.log('Payload from ID token:', payload);

    const email = payload.email;
    const name = payload.name || '';

    // Check email domain
    const allowedDomain = process.env.ALLOWED_EMAIL_DOMAIN || '@rvu.edu.in';
    if (!email || !email.endsWith(allowedDomain)) {
      console.warn('Invalid email domain:', email);
      return res.json({ success: false, message: 'Please use your official RVU email address.' });
    }

    // Check if already claimed
    const existingClaim = await sql`
      SELECT * FROM claims WHERE email = ${email}
    `;

    if (existingClaim.rows.length > 0) {
      console.warn('Email already claimed:', email);
      return res.json({ success: false, message: 'This email has already claimed a jersey.' });
    }

    // Insert new claim
    await sql`
      INSERT INTO claims (email, name)
      VALUES (${email}, ${name})
    `;

    console.log('Claim successfully saved for:', email);
    return res.json({ success: true, message: 'Claim successful. Show this to collect your jersey.' });
  } catch (err) {
    console.error('Error verifying ID token or processing claim:', err);
    return res.status(500).json({ success: false, message: 'Authentication failed' });
  }
});

app.get('/admin/claims', async (req, res) => {
  const authHeader = req.headers.authorization;
  const secret = authHeader && authHeader.split(' ')[1];

  if (secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ success: false, message: 'Unauthorized' });
  }

  try {
    const claims = await sql`
      SELECT email, name, claimed_at 
      FROM claims 
      ORDER BY claimed_at DESC
    `;
    res.json({ success: true, claims: claims.rows });
  } catch (err) {
    console.error('Database error:', err);
    res.status(500).json({ success: false, message: 'Error fetching claims' });
  }
});

// Only start the server if running directly (not when imported by Vercel)
if (process.env.NODE_ENV !== 'production') {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

export default app;
