// ===================================================================
// ONLINE PROPERTY MANAGEMENT SYSTEM - Complete Backend Server
// ===================================================================

const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const path = require('path');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs').promises;
const fsSync = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const axios = require('axios'); // ✅ BREVO

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// ===================================================================
// MIDDLEWARE
// ===================================================================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// ===================================================================
// FILE STORAGE INIT
// ===================================================================

const initDirectories = async () => {
  const dirs = ['data', 'uploads', 'private_uploads'];
  for (const dir of dirs) {
    const dirPath = path.join(__dirname, dir);
    if (!fsSync.existsSync(dirPath)) {
      await fs.mkdir(dirPath, { recursive: true });
    }
  }
};

const initDataFiles = async () => {
  const files = {
    'data/users.json': [],
    'data/properties.json': [],
    'data/messages.json': [],
    'data/otps.json': []
  };

  for (const [file, defaultData] of Object.entries(files)) {
    const filePath = path.join(__dirname, file);
    if (!fsSync.existsSync(filePath)) {
      await fs.writeFile(filePath, JSON.stringify(defaultData, null, 2));
    }
  }
};

initDirectories().then(() => initDataFiles());

// ===================================================================
// JSON HELPERS
// ===================================================================

const readJSON = async (filename) => {
  try {
    const data = await fs.readFile(path.join(__dirname, 'data', filename), 'utf8');
    return JSON.parse(data);
  } catch {
    return [];
  }
};

const writeJSON = async (filename, data) => {
  await fs.writeFile(
    path.join(__dirname, 'data', filename),
    JSON.stringify(data, null, 2)
  );
};

// ===================================================================
// ✅ BREVO OTP EMAIL SYSTEM
// ===================================================================

const generateOTP = () =>
  Math.floor(100000 + Math.random() * 900000).toString();

const sendOTPEmail = async (email, otp, purpose = 'verification') => {
  try {
    const subject =
      purpose === 'reset'
        ? 'Password Reset OTP - Property System'
        : 'Account Verification OTP - Property System';

    const htmlContent = `
      <h2>Online Property Management System</h2>
      <p>Your OTP is:</p>
      <h1 style="letter-spacing:5px;">${otp}</h1>
      <p>This OTP will expire in 10 minutes.</p>
    `;

    await axios.post(
      'https://api.brevo.com/v3/smtp/email',
      {
        sender: { email: process.env.SMTP_EMAIL },
        to: [{ email }],
        subject,
        htmlContent
      },
      {
        headers: {
          'api-key': process.env.BREVO_API_KEY,
          'content-type': 'application/json'
        }
      }
    );

    return true;
  } catch (error) {
    console.error('Brevo Email Error:', error.response?.data || error.message);
    return false;
  }
};

const storeOTP = async (email, otp, purpose = 'verification') => {
  const otps = await readJSON('otps.json');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000);

  const filtered = otps.filter(o => o.email !== email || o.purpose !== purpose);
  filtered.push({ email, otp, purpose, expiresAt: expiresAt.toISOString() });
  await writeJSON('otps.json', filtered);
};

const verifyOTP = async (email, otp, purpose = 'verification') => {
  const otps = await readJSON('otps.json');
  const valid = otps.find(
    o =>
      o.email === email &&
      o.otp === otp &&
      o.purpose === purpose &&
      new Date(o.expiresAt) > new Date()
  );

  if (!valid) return false;
  const filtered = otps.filter(o => o.email !== email || o.purpose !== purpose);
  await writeJSON('otps.json', filtered);
  return true;
};

// ===================================================================
// JWT MIDDLEWARE
// ===================================================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];

  if (!token)
    return res.status(401).json({ success: false, message: 'Token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err)
      return res
        .status(403)
        .json({ success: false, message: 'Invalid token' });
    req.user = user;
    next();
  });
};

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user.role))
    return res.status(403).json({ success: false, message: 'Unauthorized' });
  next();
};

// ===================================================================
// FILE UPLOAD
// ===================================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    if (file.fieldname === 'documents') cb(null, 'private_uploads/');
    else cb(null, 'uploads/');
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname);
  }
});
const upload = multer({ storage });

// ===================================================================
// AUTH ROUTES (SIGNUP OTP ✅)
// ===================================================================

app.post('/api/auth/signup', async (req, res) => {
  const { email, name, role } = req.body;
  const users = await readJSON('users.json');

  if (users.find(u => u.email === email))
    return res.json({ success: false, message: 'Email exists' });

  const otp = generateOTP();
  await storeOTP(email, otp, 'verification');
  await sendOTPEmail(email, otp);

  res.json({ success: true, message: 'OTP sent' });
});

app.post('/api/auth/verify', async (req, res) => {
  const { email, otp, password, name, role } = req.body;
  const valid = await verifyOTP(email, otp);

  if (!valid)
    return res.json({ success: false, message: 'Invalid OTP' });

  const users = await readJSON('users.json');
  const hashed = await bcrypt.hash(password, 10);

  const user = {
    id: Date.now().toString(),
    email,
    name,
    role,
    password: hashed,
    createdAt: new Date().toISOString()
  };

  users.push(user);
  await writeJSON('users.json', users);

  const token = jwt.sign(user, process.env.JWT_SECRET, { expiresIn: '7d' });

  res.json({ success: true, token });
});

// ===================================================================
// START SERVER
// ===================================================================

const PORT = process.env.PORT || 10000;
app.get("/test-brevo", async (req, res) => {
  try {
    const ok = await sendOTPEmail("nadeeshkumar57@gmail.com", "123456", "verification");
    res.json({ success: ok });
  } catch (e) {
    res.json({ success: false, error: e.message });
  }
});

server.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
