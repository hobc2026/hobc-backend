
const express = require('express');
const session = require('express-session');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'hobc.sqlite'));

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    phone TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    membership_plan TEXT DEFAULT 'Premium',
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS referral_partners (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    partner_type TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    first_name TEXT NOT NULL,
    last_name TEXT NOT NULL,
    phone TEXT NOT NULL,
    email TEXT NOT NULL,
    message TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
`);

app.use(cors({ origin: true, credentials: true }));

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AU_PHONE_REGEX = /^(?:\+61|0)(?:2|3|4|7|8)(?:\s?\d){8}$/;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'replace-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,
    maxAge: 1000 * 60 * 60 * 24
  }
}));

app.use(express.static(path.join(__dirname, '..')));

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validAustralianPhone(phone) {
  const normalised = String(phone || '').replace(/\s+/g, '');
  return /^(?:\+61|0)(?:2|3|4|7|8)\d{8}$/.test(normalised);
}

const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);
const transporter = smtpConfigured ? nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: Number(process.env.SMTP_PORT || 587),
  secure: String(process.env.SMTP_SECURE || 'false') === 'true',
  auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
}) : null;

app.post('/api/auth/register', (req, res) => {
  const { firstName, lastName, email, phone, password, confirmPassword } = req.body;
  if (!firstName || !lastName || !email || !phone || !password || !confirmPassword) {
    return res.status(400).json({ message: 'Please fill all required fields.' });
  }
  if (!validEmail(email)) {
    return res.status(400).json({ message: 'Please enter a valid email address.' });
  }
  if (!validAustralianPhone(phone)) {
    return res.status(400).json({ message: 'Please enter a valid Australian phone number.' });
  }
  if (password.length < 6) {
    return res.status(400).json({ message: 'Password must be at least 6 characters.' });
  }
  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());
  if (existing) {
    return res.status(409).json({ message: 'An account with this email already exists.' });
  }

  const hash = bcrypt.hashSync(password, 10);
  const result = db.prepare(`
    INSERT INTO users (first_name, last_name, email, phone, password_hash)
    VALUES (?, ?, ?, ?, ?)
  `).run(firstName, lastName, email.toLowerCase(), phone, hash);

  req.session.user = {
    id: result.lastInsertRowid,
    firstName,
    lastName,
    email: email.toLowerCase(),
    membershipPlan: 'Premium'
  };

  return res.json({ message: 'Registration successful.', user: req.session.user });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: 'Email and password are required.' });
  }

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email.toLowerCase());
  if (!user || !bcrypt.compareSync(password, user.password_hash)) {
    return res.status(401).json({ message: 'Invalid login details.' });
  }

  req.session.user = {
    id: user.id,
    firstName: user.first_name,
    lastName: user.last_name,
    email: user.email,
    membershipPlan: user.membership_plan
  };

  return res.json({ message: 'Login successful.', user: req.session.user });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => {
    res.json({ message: 'Logged out.' });
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ message: 'Not authenticated.' });
  }
  return res.json({ user: req.session.user });
});


app.post('/api/contact', async (req, res) => {
  try {
    const payload = req.body || {};
    const name = String(payload.name || payload.fullName || '').trim();
    const email = String(payload.email || '').trim().toLowerCase();
    const phone = String(payload.phone || payload.number || '').trim();
    const message = String(payload.message || payload.query || '').trim();

    if (!name) {
      return res.status(400).json({ message: 'Name is required.' });
    }
    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({ message: 'Please enter a valid email address.' });
    }
    if (!AU_PHONE_REGEX.test(phone)) {
      return res.status(400).json({ message: 'Please enter a valid Australian phone number.' });
    }
    if (!message) {
      return res.status(400).json({ message: 'Message is required.' });
    }

    try {
      if (typeof db !== 'undefined' && db && db.prepare) {
        db.prepare(`
          CREATE TABLE IF NOT EXISTS contacts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            message TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `).run();

        db.prepare(`
          INSERT INTO contacts (name, email, phone, message)
          VALUES (?, ?, ?, ?)
        `).run(name, email, phone, message);
      }
    } catch (dbErr) {
      console.error('Contact DB save error:', dbErr);
    }

    if (typeof transporter !== 'undefined' && transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: process.env.CONTACT_TO || 'heymittydocs@gmail.com',
        replyTo: email,
        subject: 'New HOBC Contact Enquiry',
        html: `
          <h2>New Contact Enquiry</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Phone:</strong> ${phone}</p>
          <p><strong>Message:</strong><br>${message.replace(/
/g, '<br>')}</p>
        `
      });
    }

    return res.json({
      message: (typeof transporter !== 'undefined' && transporter)
        ? 'Enquiry submitted successfully.'
        : 'Enquiry saved successfully. Add SMTP settings in backend/.env to enable live email delivery.'
    });
  } catch (error) {
    console.error('Contact form error:', error);
    return res.status(500).json({ message: 'Failed to submit enquiry.' });
  }
});


app.get('/api/site-config', (_, res) => {
  const configuredEndAt = process.env.LAUNCH_END_AT;
  let launchEndsAt = configuredEndAt;

  if (!launchEndsAt) {
    const fallback = new Date(Date.now() + (48 * 60 * 60 * 1000));
    launchEndsAt = fallback.toISOString();
  }

  res.json({
    launchEndsAt,
    contactEmail: process.env.CONTACT_TO || 'heymittydocs@gmail.com'
  });
});

app.get('*', (_, res) => {
  res.sendFile(path.join(__dirname, '..', 'index.html'));
});


const __hobc_email_regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const __hobc_au_phone_regex = /^(?:\+61|0)[2-478](?:\s?\d){8}$/;


app.post('/api/referral-partner', async (req, res) => {
  try {
    const payload = req.body || {};
    const name = String(payload.name || '').trim();
    const email = String(payload.email || '').trim().toLowerCase();
    const phone = String(payload.phone || payload.number || '').trim();
    const partnerType = String(payload.partnerType || payload.partner || '').trim();

    if (!name) {
      return res.status(400).json({ message: 'Name is required.' });
    }
    if (!EMAIL_REGEX.test(email)) {
      return res.status(400).json({ message: 'Please enter a valid email address.' });
    }
    if (!AU_PHONE_REGEX.test(phone)) {
      return res.status(400).json({ message: 'Please enter a valid Australian phone number.' });
    }
    if (!partnerType) {
      return res.status(400).json({ message: 'Partner type is required.' });
    }

    try {
      if (typeof db !== 'undefined' && db && db.prepare) {
        db.prepare(`
          CREATE TABLE IF NOT EXISTS referral_partners (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            phone TEXT NOT NULL,
            partner_type TEXT NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
          )
        `).run();

        db.prepare(`
          INSERT INTO referral_partners (name, email, phone, partner_type)
          VALUES (?, ?, ?, ?)
        `).run(name, email, phone, partnerType);
      }
    } catch (dbErr) {
      console.error('Referral DB save error:', dbErr);
    }

    if (typeof transporter !== 'undefined' && transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: process.env.CONTACT_TO || 'heymittydocs@gmail.com',
        replyTo: email,
        subject: 'New HOBC Referral Partner Enquiry',
        html: `
          <h2>New Referral Partner Enquiry</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Phone:</strong> ${phone}</p>
          <p><strong>Become a Partner:</strong> ${partnerType}</p>
        `
      });
    }

    return res.json({
      message: (typeof transporter !== 'undefined' && transporter)
        ? 'Partner enquiry submitted successfully.'
        : 'Partner enquiry saved successfully. Add SMTP settings in backend/.env to enable live email delivery.'
    });
  } catch (error) {
    console.error('Referral partner error:', error);
    return res.status(500).json({ message: 'Failed to submit partner enquiry.' });
  }
});



app.listen(PORT, () => {
  console.log(`HOBC client-ready website running on http://localhost:${PORT}`);
});
