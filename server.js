import express from "express";
import dotenv from "dotenv";
import cors from "cors";
import cookieParser from 'cookie-parser';
import rateLimit from 'express-rate-limit';
import { OAuth2Client } from "google-auth-library";
import sqlite3 from "sqlite3";
import crypto from "crypto";
import path from "path";
import { fileURLToPath } from "url";

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 8080;

// --- Database Setup ---
const db = new sqlite3.Database("./claims.db", (err) => {
  if (err) {
    console.error("Error opening database", err.message);
  } else {
    console.log("Connected to the SQLite database.");
    db.run(`CREATE TABLE IF NOT EXISTS claims (
      email TEXT PRIMARY KEY,
      name TEXT,
      claimed_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);
  }
});

// Create tokens table for short-lived verification tokens (used to prevent screenshot reuse)
db.run(`CREATE TABLE IF NOT EXISTS tokens (
  token TEXT PRIMARY KEY,
  email TEXT,
  expires_at DATETIME
)`);

// Devices table: map a persistent device token (cookie) to the first email that claimed on that device
db.run(`CREATE TABLE IF NOT EXISTS devices (
  token TEXT PRIMARY KEY,
  email TEXT,
  claimed_at DATETIME
)`);

// Ensure devices table has blocked_until column (migration for older DBs)
db.all("PRAGMA table_info(devices)", (err, cols) => {
  if (!err && cols) {
    const names = cols.map(c => c.name);
    if (!names.includes('blocked_until')) {
      console.log('Altering devices table to add blocked_until column');
      db.run("ALTER TABLE devices ADD COLUMN blocked_until DATETIME", (aErr) => {
        if (aErr) console.error('Error adding blocked_until column:', aErr);
      });
    }
  }
});

// Log DB schema and row count at startup for debugging and repair legacy schema
db.serialize(() => {
  db.all("PRAGMA table_info(claims)", (err, cols) => {
    if (err) {
      console.error('Error fetching claims table info:', err);
      return;
    }
    console.log('claims table columns:', cols);
    try {
      const colNames = cols.map(c => c.name);
      if (!colNames.includes('name')) {
        console.log('Detected legacy schema: adding missing `name` column to claims table');
        db.run("ALTER TABLE claims ADD COLUMN name TEXT", (alterErr) => {
          if (alterErr) console.error('Error adding name column:', alterErr);
          else console.log('Added name column to claims table');
        });
      }
      if (!colNames.includes('claimed_at')) {
        console.log('Detected missing claimed_at column (unexpected)');
      }
    } catch (e) {
      console.error('Error while inspecting/altering claims table:', e);
    }
  });

  db.get('SELECT COUNT(*) as cnt FROM claims', (err, row) => {
    if (err) {
      console.error('Error counting claims rows:', err);
    } else {
      console.log('claims row count:', row && row.cnt);
    }
  });
});

app.use(cors());
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

// Simple request logger for debugging (will print method and path)
app.use((req, res, next) => {
  try { console.log('REQ', req.method, req.path); } catch(e) {}
  next();
});

// Helper to extract admin secret from Authorization header (accepts 'Bearer x' or raw secret)
function getAuthSecret(req){
  const ah = req.headers.authorization;
  if(!ah) return null;
  if(typeof ah !== 'string') return null;
  if(ah.startsWith('Bearer ')) return ah.slice(7).trim();
  return ah.trim();
}

// Basic rate limiter for sensitive endpoints
const claimLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 12, // limit each IP to 12 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
});

// Google OAuth2 setup
const client = new OAuth2Client(
  process.env.CLIENT_ID,
  process.env.CLIENT_SECRET,
  process.env.REDIRECT_URI,
  process.env.FRONTEND_ORIGIN,
  process.env.NEXT_PUBLIC_API_URL
);

app.get("/api/auth/callback", async (req, res) => {
  const code = req.query.code;

  if (!code) {
    console.error("No code returned from Google");
    return res.status(400).send("No code returned from Google");
  }

  try {
    console.log("Received code from Google:", code);
    const { tokens } = await client.getToken(code);
    console.log("Received tokens from Google:", tokens);
    client.setCredentials(tokens);

    // Get user info
    const ticket = await client.verifyIdToken({
      idToken: tokens.id_token,
      audience: process.env.CLIENT_ID,
    });

    const payload = ticket.getPayload();
    console.log("User info from Google:", payload);
    const email = payload["email"];
    const name = payload["name"];

    // --- Claim Logic ---
    // 1. Check if it's a valid RVU email
    // TODO: Update with your college's actual email domain
    if (!email || !email.endsWith("@rvei.edu.in")) {
      console.warn("Invalid email domain:", email);
      return res.redirect("/claimed.html?status=invalid_email");
    }

    // Device locking: check device token cookie
    const deviceToken = req.cookies && req.cookies.device_token;
    // Helper to block device for a duration
    function blockDevice(token, lockedEmail, hours = 12){
      if(!token) return;
      const blockedUntil = new Date(Date.now() + hours * 3600 * 1000).toISOString();
      db.run('INSERT OR REPLACE INTO devices (token, email, claimed_at, blocked_until) VALUES (?, ?, datetime("now"), ?)', [token, lockedEmail, blockedUntil], (err) => {
        if(err) console.error('Error blocking device:', err);
      });
    }
    if (deviceToken) {
      db.get('SELECT * FROM devices WHERE token = ?', [deviceToken], (dErr, dRow) => {
        if (dErr) console.error('Error querying devices table:', dErr);
        if (dRow && dRow.email && dRow.email !== email) {
          console.warn('Device locked to another email:', dRow.email, 'current:', email);
          return res.redirect('/claimed.html?status=locked_device');
        }

        // proceed with existing claim flow
        db.get("SELECT * FROM claims WHERE email = ?", [email], (err, row) => {
          if (err) {
            console.error("Database error:", err);
            return res.status(500).send("Server error checking claim.");
          }
          if (row) {
            console.warn("Email already claimed:", email);
            // block this device to prevent further attempts from different accounts
            if (deviceToken) blockDevice(deviceToken, email, 12);
            return res.redirect("/claimed.html?status=already_claimed");
          }

          db.run("INSERT INTO claims (email, name, claimed_at) VALUES (?, ?, datetime('now'))", [email, name], (insertErr) => {
            if (insertErr) {
              console.error("Database insert error:", insertErr);
              if (insertErr.code && insertErr.code === 'SQLITE_CONSTRAINT') {
                console.warn('Constraint error on insert for email (likely duplicate):', email);
                return res.redirect("/claimed.html?status=already_claimed");
              }
              return res.status(500).send("Server error saving claim.");
            }
            console.log("Claim successfully saved for:", email);
            // ensure device mapping
            const deviceTok = deviceToken || crypto.randomBytes(10).toString('base64url');
            db.run('INSERT OR REPLACE INTO devices (token, email, claimed_at) VALUES (?, ?, datetime("now"))', [deviceTok, email], (devErr) => {
              if (devErr) console.error('Error saving device token:', devErr);
              res.cookie('device_token', deviceTok, { httpOnly: false, maxAge: 1000 * 60 * 60 * 24 * 365 });
              // Create a short-lived verification token (server-side) to show on the claimed page
              const token = crypto.randomBytes(12).toString('base64url');
              const ttlSeconds = parseInt(process.env.CLAIM_TOKEN_TTL || '90', 10);
              const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
              db.run("INSERT INTO tokens (token, email, expires_at) VALUES (?, ?, datetime(?))", [token, email, expiresAt], (tErr) => {
                if (tErr) console.error('Error saving token:', tErr);
                res.redirect(`/claimed.html?status=success&token=${encodeURIComponent(token)}`);
              });
            });
          });
        });
      });
      return;
    }

    // No device token: proceed normally and set one after success
    db.get("SELECT * FROM claims WHERE email = ?", [email], (err, row) => {
      if (err) {
        console.error("Database error:", err);
        return res.status(500).send("Server error checking claim.");
      }
      if (row) {
        console.warn("Email already claimed:", email);
        return res.redirect("/claimed.html?status=already_claimed");
      }

      db.run("INSERT INTO claims (email, name, claimed_at) VALUES (?, ?, datetime('now'))", [email, name], (insertErr) => {
        if (insertErr) {
          console.error("Database insert error:", insertErr);
          if (insertErr.code && insertErr.code === 'SQLITE_CONSTRAINT') {
            console.warn('Constraint error on insert for email (likely duplicate):', email);
            return res.redirect("/claimed.html?status=already_claimed");
          }
          return res.status(500).send("Server error saving claim.");
        }
        console.log("Claim successfully saved for:", email);
        const deviceTok = crypto.randomBytes(10).toString('base64url');
        db.run('INSERT OR REPLACE INTO devices (token, email, claimed_at) VALUES (?, ?, datetime("now"))', [deviceTok, email], (devErr) => {
          if (devErr) console.error('Error saving device token:', devErr);
          res.cookie('device_token', deviceTok, { httpOnly: false, maxAge: 1000 * 60 * 60 * 24 * 365 });
          const token = crypto.randomBytes(12).toString('base64url');
          const ttlSeconds = parseInt(process.env.CLAIM_TOKEN_TTL || '90', 10);
          const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
          db.run("INSERT INTO tokens (token, email, expires_at) VALUES (?, ?, datetime(?))", [token, email, expiresAt], (tErr) => {
            if (tErr) console.error('Error saving token:', tErr);
            res.redirect(`/claimed.html?status=success&token=${encodeURIComponent(token)}`);
          });
        });
      });
    });
  } catch (err) {
    console.error("Auth error:", err);
    res.status(500).send("Authentication failed");
  }
});

// New route: accept ID token from Google Identity Services (GSI) on the frontend
app.post('/claim', claimLimiter, async (req, res) => {
  try {
    // Accept token from Authorization header or body (credential/id_token)
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

    // Allowed domain — default to @rvu.edu.in, can be overridden by env
    const allowedDomain = process.env.ALLOWED_EMAIL_DOMAIN || '@rvu.edu.in';
    if (!email || !email.endsWith(allowedDomain)) {
      console.warn('Invalid email domain:', email);
      return res.json({ success: false, status: 'invalid_email', message: 'Please use your official RVU email address.' });
    }

    // Device locking: prefer X-Device-Token header (API clients) or device_token cookie (browsers)
    const deviceToken = req.headers['x-device-token'] || (req.cookies && req.cookies.device_token);

    function proceedInsertWithDevice(deviceTok){
      // Ensure claim not already present
      db.get('SELECT * FROM claims WHERE email = ?', [email], (err, row) => {
        if (err) {
          console.error('Database error:', err);
          return res.status(500).json({ success: false, message: 'Server error checking claim.' });
        }
        if (row) {
          console.warn('Email already claimed:', email);
          // block this device token to prevent further attempts from different accounts
          const dt = deviceTok || (req.cookies && req.cookies.device_token) || crypto.randomBytes(10).toString('base64url');
          const blockedUntil = new Date(Date.now() + 12 * 3600 * 1000).toISOString();
          db.run('INSERT OR REPLACE INTO devices (token, email, claimed_at, blocked_until) VALUES (?, ?, datetime("now"), ?)', [dt, email, blockedUntil], (bErr) => {
            if (bErr) console.error('Error blocking device (api):', bErr);
            try { res.cookie('device_token', dt, { httpOnly: false, maxAge: 1000 * 60 * 60 * 24 * 365 }); } catch(e){}
            return res.json({ success: false, status: 'already_claimed', message: 'This email has already claimed a jersey.' });
          });
          return;
        }

        // Insert claim
        db.run("INSERT INTO claims (email, name, claimed_at) VALUES (?, ?, datetime('now'))", [email, name], function(insertErr) {
          if (insertErr) {
            console.error('Database insert error:', insertErr);
            if (insertErr.code && insertErr.code === 'SQLITE_CONSTRAINT') {
              console.warn('Constraint error on insert for email (likely duplicate):', email);
              return res.json({ success: false, message: 'This email has already claimed a jersey.' });
            }
            return res.status(500).json({ success: false, message: 'Server error saving claim.' });
          }

          // save/ensure device mapping
          const finalDeviceTok = deviceTok || crypto.randomBytes(10).toString('base64url');
          db.run('INSERT OR REPLACE INTO devices (token, email, claimed_at) VALUES (?, ?, datetime("now"))', [finalDeviceTok, email], (devErr) => {
            if (devErr) console.error('Error saving device token:', devErr);
            try { res.cookie('device_token', finalDeviceTok, { httpOnly: false, maxAge: 1000 * 60 * 60 * 24 * 365 }); } catch(e){}

            // create server token and return it to client
            const token = crypto.randomBytes(12).toString('base64url');
            const ttlSeconds = parseInt(process.env.CLAIM_TOKEN_TTL || '90', 10);
            const expiresAt = new Date(Date.now() + ttlSeconds * 1000).toISOString();
            db.run("INSERT INTO tokens (token, email, expires_at) VALUES (?, ?, datetime(?))", [token, email, expiresAt], (tErr) => {
              if (tErr) {
                console.error('Error saving token:', tErr);
                return res.json({ success: true, status: 'success', message: 'Claim successful. Show this to collect your jersey.' });
              }
              return res.json({ success: true, status: 'success', message: 'Claim successful. Show this to collect your jersey.', token, expiresAt });
            });
          });
        });
      });
    }

    if (deviceToken) {
      // check mapping
      db.get('SELECT * FROM devices WHERE token = ?', [deviceToken], (dErr, dRow) => {
        if (dErr) console.error('Error querying devices table:', dErr);
        // if device already mapped to another email, block immediately
        if (dRow && dRow.email && dRow.email !== email) {
          console.warn('Device locked to another email (API):', dRow.email, 'current:', email);
          // refresh block expiry
          const blockedUntil = new Date(Date.now() + 12 * 3600 * 1000).toISOString();
          db.run('UPDATE devices SET blocked_until = ? WHERE token = ?', [blockedUntil, deviceToken], (uErr) => { if (uErr) console.error('Error updating block expiry:', uErr); });
              return res.json({ success: false, status: 'locked_device', message: 'This device is locked to another account.' });
        }
        // allowed, proceed using this device token
        proceedInsertWithDevice(deviceToken);
      });
    } else {
      // no device token supplied, proceed and create one
      proceedInsertWithDevice(null);
    }
  } catch (err) {
    console.error('Error verifying ID token or processing claim:', err);
    return res.status(500).json({ success: false, message: 'Authentication failed' });
  }
});

// Admin endpoints removed per request

// Public helper: return token expiry (no email) so frontend can display countdown.
app.get('/token-info', (req, res) => {
  const token = req.query.token;
  if (!token) return res.status(400).json({ success: false, message: 'No token provided' });
  db.get('SELECT expires_at FROM tokens WHERE token = ?', [token], (err, row) => {
    if (err) return res.status(500).json({ success: false, message: 'DB error' });
    if (!row) return res.json({ success: true, found: false });
    return res.json({ success: true, found: true, expiresAt: row.expires_at });
  });
});

// Serve admin page (registered after admin API routes below)

// Admin endpoints and static admin UI removed per request

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

// Diagnostic: list registered routes (temporary)
app.get('/__routes', (req, res) => {
  const routes = [];
  try {
    if (app._router && Array.isArray(app._router.stack)) {
      routes.push({ stackLength: app._router.stack.length });
      app._router.stack.forEach((m, i) => {
        try {
          const item = { idx: i, name: m && m.name, handleName: m && m.handle && m.handle.name };
          if (m && m.route) {
            item.type = 'route';
            item.path = m.route.path;
            item.methods = Object.keys(m.route.methods).join(',');
          } else if (m && m.name === 'bound dispatch') {
            item.type = 'dispatch';
          } else if (m && m.name === 'serveStatic') {
            item.type = 'static';
            item.regexp = m.regexp && m.regexp.source;
          } else {
            item.type = m && m.name || 'middleware';
            item.regexp = m && m.regexp && m.regexp.source;
          }
          routes.push(item);
        } catch (innerE) {
          routes.push({ idx: i, error: String(innerE) });
        }
      });
    }
  } catch (e) {
    console.error('Error enumerating routes:', e);
  }
  res.json(routes);
});

app.get('/health', (req, res) => res.json({ ok: true }));