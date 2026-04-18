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

// ================= DATABASE =================
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

// ================= MIDDLEWARE =================
app.use(cors({ origin: true }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET || 'replace-this-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false
  }
}));

app.use(express.static(path.join(__dirname, '..')));

// ================= VALIDATIONS =================
const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const AU_PHONE_REGEX = /^(?:\+61|0)(?:2|3|4|7|8)\d{8}$/;

function validEmail(email) {
  return EMAIL_REGEX.test(email);
}

function validAustralianPhone(phone) {
  const normalised = String(phone || '').replace(/\s+/g, '');
  return AU_PHONE_REGEX.test(normalised);
}

// ================= EMAIL =================
const smtpConfigured = !!(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS);

const transporter = smtpConfigured
  ? nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: Number(process.env.SMTP_PORT || 587),
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    })
  : null;

// ================= AUTH =================
app.post('/api/auth/register', (req, res) => {
  const { firstName, lastName, email, phone, password, confirmPassword } = req.body;

  if (!firstName || !lastName || !email || !phone || !password || !confirmPassword) {
    return res.status(400).json({ message: 'Please fill all required fields.' });
  }

  if (!validEmail(email)) {
    return res.status(400).json({ message: 'Invalid email.' });
  }

  if (!validAustralianPhone(phone)) {
    return res.status(400).json({ message: 'Invalid phone.' });
  }

  if (password !== confirmPassword) {
    return res.status(400).json({ message: 'Passwords do not match.' });
  }

  const existing = db.prepare('SELECT id FROM users WHERE email = ?').get(email.toLowerCase());

  if (existing) {
    return res.status(409).json({ message: 'Email already exists.' });
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
    email
  };

  res.json({ message: 'Registered successfully' });
});

// ================= CONTACT =================
app.post('/api/contact', async (req, res) => {
  try {
    const { name, email, phone, message } = req.body;

    if (!name) return res.status(400).json({ message: 'Name required' });
    if (!validEmail(email)) return res.status(400).json({ message: 'Invalid email' });
    if (!validAustralianPhone(phone)) return res.status(400).json({ message: 'Invalid phone' });
    if (!message) return res.status(400).json({ message: 'Message required' });

    db.prepare(`
      INSERT INTO contacts (first_name, last_name, phone, email, message)
      VALUES (?, ?, ?, ?, ?)
    `).run(name, '', phone, email, message);

    if (transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: process.env.CONTACT_TO,
        subject: 'New Contact Enquiry',
        html: `
          <h2>New Contact Enquiry</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Phone:</strong> ${phone}</p>
          <p><strong>Message:</strong><br>${message.split('\\n').join('<br>')}</p>
        `
      });
    }

    res.json({ message: 'Enquiry submitted successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error submitting enquiry' });
  }
});

// ================= REFERRAL =================
app.post('/api/referral-partner', async (req, res) => {
  try {
    const { name, email, phone, partnerType } = req.body;

    if (!name) return res.status(400).json({ message: 'Name required' });
    if (!validEmail(email)) return res.status(400).json({ message: 'Invalid email' });
    if (!validAustralianPhone(phone)) return res.status(400).json({ message: 'Invalid phone' });

    db.prepare(`
      INSERT INTO referral_partners (name, email, phone, partner_type)
      VALUES (?, ?, ?, ?)
    `).run(name, email, phone, partnerType);

    if (transporter) {
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: process.env.CONTACT_TO,
        subject: 'New Referral Partner',
        html: `
          <h2>New Referral Partner</h2>
          <p><strong>Name:</strong> ${name}</p>
          <p><strong>Email:</strong> ${email}</p>
          <p><strong>Phone:</strong> ${phone}</p>
          <p><strong>Partner Type:</strong> ${partnerType}</p>
        `
      });
    }

    res.json({ message: 'Partner submitted successfully' });

  } catch (err) {
    console.error(err);
    res.status(500).json({ message: 'Error submitting partner' });
  }
});

// ================= COUNTDOWN =================
app.get('/api/site-config', (req, res) => {
  res.json({
    launchEndsAt: process.env.LAUNCH_END_AT || '2026-05-31T23:59:59.000Z',
    contactEmail: process.env.CONTACT_TO || 'heymittydocs@gmail.com'
  });
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
