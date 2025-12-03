// ===================================================================
// ONLINE PROPERTY MANAGEMENT SYSTEM - Complete Backend Server
// ===================================================================
// Author: Property Management Team
// Description: Express.js server with JWT auth, OTP email, and Socket.io chat
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
const nodemailer = require('nodemailer');
const multer = require('multer');

// Load environment variables
dotenv.config();

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

// ===================================================================
// MIDDLEWARE CONFIGURATION
// ===================================================================

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));
app.use('/uploads', express.static('uploads'));

// ===================================================================
// FILE STORAGE SETUP
// ===================================================================

// Ensure directories exist
const initDirectories = async () => {
  const dirs = ['data', 'uploads', 'private_uploads'];
  for (const dir of dirs) {
    const dirPath = path.join(__dirname, dir);
    if (!fsSync.existsSync(dirPath)) {
      await fs.mkdir(dirPath, { recursive: true });
    }
  }
};

// Initialize JSON data files
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

// Initialize on startup
initDirectories().then(() => initDataFiles());

// ===================================================================
// HELPER FUNCTIONS - DATA OPERATIONS
// ===================================================================

const readJSON = async (filename) => {
  try {
    const data = await fs.readFile(path.join(__dirname, 'data', filename), 'utf8');
    return JSON.parse(data);
  } catch (error) {
    console.error(`Error reading ${filename}:`, error);
    return [];
  }
};

const writeJSON = async (filename, data) => {
  try {
    await fs.writeFile(
      path.join(__dirname, 'data', filename),
      JSON.stringify(data, null, 2)
    );
  } catch (error) {
    console.error(`Error writing ${filename}:`, error);
  }
};

// ===================================================================
// EMAIL CONFIGURATION (NODEMAILER + GMAIL SMTP)
// ===================================================================

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.SMTP_EMAIL,
    pass: process.env.SMTP_PASS
  },
  tls: {
    rejectUnauthorized: false // 🔧 Fix for self-signed certificate issue
  }
});


// Generate 6-digit OTP
const generateOTP = () => {
  return Math.floor(100000 + Math.random() * 900000).toString();
};

// Send OTP email
const sendOTPEmail = async (email, otp, purpose = 'verification') => {
  const subject = purpose === 'reset'
    ? 'Password Reset OTP - Property Management System'
    : 'Account Verification OTP - Property Management System';

  const text = `Your OTP code is: ${otp}\n\nThis code will expire in 10 minutes.\n\nIf you didn't request this, please ignore this email.`;

  const mailOptions = {
    from: process.env.SMTP_EMAIL,
    to: email,
    subject: subject,
    text: text,
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
        <h2 style="color: #1e40af;">Property Management System</h2>
        <p>Your OTP code is:</p>
        <h1 style="background: #1e40af; color: white; padding: 20px; text-align: center; letter-spacing: 5px;">${otp}</h1>
        <p>This code will expire in 10 minutes.</p>
        <p style="color: #666;">If you didn't request this, please ignore this email.</p>
      </div>
    `
  };

  try {
    await transporter.sendMail(mailOptions);
    return true;
  } catch (error) {
    console.error('Email error:', error);
    return false;
  }
};

// Store OTP with expiration
const storeOTP = async (email, otp, purpose = 'verification') => {
  const otps = await readJSON('otps.json');
  const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

  // Remove old OTPs for this email
  const filtered = otps.filter(item => item.email !== email || item.purpose !== purpose);

  filtered.push({
    email,
    otp,
    purpose,
    expiresAt: expiresAt.toISOString(),
    createdAt: new Date().toISOString()
  });

  await writeJSON('otps.json', filtered);
};

// Verify OTP
const verifyOTP = async (email, otp, purpose = 'verification') => {
  const otps = await readJSON('otps.json');
  const otpRecord = otps.find(
    item => item.email === email &&
      item.otp === otp &&
      item.purpose === purpose &&
      new Date(item.expiresAt) > new Date()
  );

  if (otpRecord) {
    // Remove used OTP
    const filtered = otps.filter(item => item.email !== email || item.purpose !== purpose);
    await writeJSON('otps.json', filtered);
    return true;
  }
  return false;
};

// ===================================================================
// JWT AUTHENTICATION MIDDLEWARE
// ===================================================================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ success: false, message: 'Access token required' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ success: false, message: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

// Role-based middleware
const requireRole = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({ success: false, message: 'Insufficient permissions' });
    }
    next();
  };
};

// ===================================================================
// FILE UPLOAD CONFIGURATION (MULTER)  ✅ UPDATED
// ===================================================================

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    // Save documents to a private folder, images remain in public uploads
    if (file.fieldname === 'documents') {
      cb(null, 'private_uploads/');
    } else {
      cb(null, 'uploads/');
    }
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, uniqueSuffix + '-' + file.originalname);
  }
});

const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB limit per file
  fileFilter: (req, file, cb) => {
    // Property images
    if (file.fieldname === 'images') {
      const allowedTypes = /jpeg|jpg|png|gif/;
      const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
      const mimetype = allowedTypes.test(file.mimetype);
      if (mimetype && extname) {
        return cb(null, true);
      } else {
        return cb(new Error('Only image files (jpeg, jpg, png, gif) are allowed for property images!'));
      }
    }

    // ✅ Property documents (now also allow jpg/jpeg/png)
    if (file.fieldname === 'documents') {
      const allowedDocs = /pdf|doc|docx|xls|xlsx|txt|jpeg|jpg|png/;
      const extname = allowedDocs.test(path.extname(file.originalname).toLowerCase());
      const mimetypeOk =
        file.mimetype.startsWith('application/') ||
        file.mimetype.startsWith('image/'); // allow images as scanned docs
      if (extname && mimetypeOk) {
        return cb(null, true);
      } else {
        return cb(
          new Error(
            'Only pdf, doc, docx, xls, xlsx, txt, jpg, jpeg, png are allowed for property documents!'
          )
        );
      }
    }

    // Default allow other fields (if any)
    cb(null, true);
  }
});


// ===================================================================
// AUTHENTICATION ROUTES
// ===================================================================

// Signup - Send OTP
app.post('/api/auth/signup', async (req, res) => {
  try {
    const { email, name, role } = req.body;

    if (!email || !name || !role) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    if (!['owner', 'tenant'].includes(role)) {
      return res.status(400).json({ success: false, message: 'Invalid role' });
    }

    const users = await readJSON('users.json');
    const existingUser = users.find(u => u.email === email);

    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered' });
    }

    // Generate and send OTP
    const otp = generateOTP();
    await storeOTP(email, otp, 'verification');
    await sendOTPEmail(email, otp, 'verification');

    res.json({
      success: true,
      message: 'OTP sent to your email',
      email
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Verify OTP and Complete Registration
app.post('/api/auth/verify', async (req, res) => {
  try {
    const { email, otp, password, name, role } = req.body;

    if (!email || !otp || !password || !name || !role) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    const isValid = await verifyOTP(email, otp, 'verification');
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }

    const users = await readJSON('users.json');
    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
      id: Date.now().toString(),
      email,
      name,
      role,
      password: hashedPassword,
      verified: true,
      createdAt: new Date().toISOString()
    };

    users.push(newUser);
    await writeJSON('users.json', users);

    const token = jwt.sign(
      { id: newUser.id, email: newUser.email, role: newUser.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Registration successful',
      token,
      user: { id: newUser.id, email: newUser.email, name: newUser.name, role: newUser.role }
    });
  } catch (error) {
    console.error('Verify error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ success: false, message: 'Email and password required' });
    }

    const users = await readJSON('users.json');
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { id: user.id, email: user.email, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      message: 'Login successful',
      token,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Forgot Password - Send OTP
app.post('/api/auth/forgot', async (req, res) => {
  try {
    const { email } = req.body;

    const users = await readJSON('users.json');
    const user = users.find(u => u.email === email);

    if (!user) {
      return res.status(400).json({ success: false, message: 'Email not found' });
    }

    const otp = generateOTP();
    await storeOTP(email, otp, 'reset');
    await sendOTPEmail(email, otp, 'reset');

    res.json({ success: true, message: 'OTP sent to your email' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Reset Password
app.post('/api/auth/reset', async (req, res) => {
  try {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
      return res.status(400).json({ success: false, message: 'All fields required' });
    }

    const isValid = await verifyOTP(email, otp, 'reset');
    if (!isValid) {
      return res.status(400).json({ success: false, message: 'Invalid or expired OTP' });
    }

    const users = await readJSON('users.json');
    const userIndex = users.findIndex(u => u.email === email);

    if (userIndex === -1) {
      return res.status(400).json({ success: false, message: 'User not found' });
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);
    users[userIndex].password = hashedPassword;
    await writeJSON('users.json', users);

    res.json({ success: true, message: 'Password reset successful' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get Current User
app.get('/api/auth/me', authenticateToken, async (req, res) => {
  try {
    const users = await readJSON('users.json');
    const user = users.find(u => u.id === req.user.id);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    res.json({
      success: true,
      user: { id: user.id, email: user.email, name: user.name, role: user.role }
    });
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===================================================================
// PROPERTY ROUTES
// ===================================================================

// Add Property (Owner only) ✅ UPDATED
app.post(
  '/api/property/add',
  authenticateToken,
  requireRole('owner'),
  upload.fields([
    { name: 'images', maxCount: 5 },
    { name: 'documents', maxCount: 5 }
  ]),
  async (req, res) => {
    try {
      const { title, description, location, price, propertyType, district, taluka, city } = req.body;

      if (!title || !description || !location || !price || !propertyType) {
        return res.status(400).json({ success: false, message: 'All fields required' });
      }

      const properties = await readJSON('properties.json');

      const images = req.files && req.files.images
        ? req.files.images.map(file => `/uploads/${file.filename}`)
        : [];

      // Store only filenames for documents (kept in private_uploads)
      const documents = req.files && req.files.documents
        ? req.files.documents.map(file => file.filename)
        : [];

      const newProperty = {
        id: Date.now().toString(),
        title,
        description,
        location, // existing logic kept
        district: district || '',
        taluka: taluka || '',
        city: city || '',
        price: parseFloat(price),
        propertyType,
        images,
        documents, // new field
        latitude: req.body.latitude ? parseFloat(req.body.latitude) : null,
        longitude: req.body.longitude ? parseFloat(req.body.longitude) : null,
        ownerId: req.user.id,
        ownerName: req.user.email,
        status: 'pending', // pending, approved, rejected
        // expose only first two images to admin for review
        visibleToAdminPhotos: images.slice(0, 2),
        createdAt: new Date().toISOString()
      };

      properties.push(newProperty);
      await writeJSON('properties.json', properties);

      res.json({ success: true, message: 'Property added successfully. Awaiting admin approval.', property: newProperty });
    } catch (error) {
      console.error('Add property error:', error);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

// Get All Approved Properties (Public)
app.get('/api/property/list', async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    const approved = properties
      .filter(p => p.status === 'approved')
      .map(p => {
        // Do not expose private documents to public
        const { documents, ...rest } = p;
        return rest;
      });

    res.json({ success: true, properties: approved });
  } catch (error) {
    console.error('List properties error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get My Properties (Owner only)
app.get('/api/property/mine', authenticateToken, requireRole('owner'), async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    const myProperties = properties
      .filter(p => p.ownerId === req.user.id)
      .map(p => {
        // Owners should not get access to private documents via this endpoint
        const { documents, ...rest } = p;
        return rest;
      });

    res.json({ success: true, properties: myProperties });
  } catch (error) {
    console.error('Get my properties error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get Property by ID
app.get('/api/property/:id', async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    const property = properties.find(p => p.id === req.params.id);

    if (!property) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }

    // Get owner details
    const users = await readJSON('users.json');
    const owner = users.find(u => u.id === property.ownerId);

    // Determine if requester is admin (optional token)
    let isAdmin = false;
    const authHeader = req.headers['authorization'];
    if (authHeader) {
      const token = authHeader.split(' ')[1];
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        if (decoded && decoded.role === 'admin') isAdmin = true;
      } catch (e) {
        // ignore token errors - treat as non-admin
      }
    }

    const propertyResponse = {
      ...property,
      ownerDetails: owner ? { name: owner.name, email: owner.email } : null
    };

    // Only include private documents for admins
    if (!isAdmin) {
      delete propertyResponse.documents;
    }

    res.json({ success: true, property: propertyResponse });
  } catch (error) {
    console.error('Get property error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Edit Property (Owner only) ✅ UPDATED
app.put(
  '/api/property/edit/:id',
  authenticateToken,
  requireRole('owner'),
  upload.fields([
    { name: 'images', maxCount: 5 },
    { name: 'documents', maxCount: 5 }
  ]),
  async (req, res) => {
    try {
      const { title, description, location, price, propertyType, district, taluka, city } = req.body;
      const properties = await readJSON('properties.json');
      const propertyIndex = properties.findIndex(p => p.id === req.params.id && p.ownerId === req.user.id);

      if (propertyIndex === -1) {
        return res.status(404).json({ success: false, message: 'Property not found or unauthorized' });
      }

      const existing = properties[propertyIndex];

      const updatedProperty = {
        ...existing,
        title: title || existing.title,
        description: description || existing.description,
        location: location || existing.location,
        district: district || existing.district || '',
        taluka: taluka || existing.taluka || '',
        city: city || existing.city || '',
        price: price ? parseFloat(price) : existing.price,
        propertyType: propertyType || existing.propertyType,
        latitude: req.body.latitude ? parseFloat(req.body.latitude) : existing.latitude,
        longitude: req.body.longitude ? parseFloat(req.body.longitude) : existing.longitude,
        status: 'pending', // Reset to pending after edit
        updatedAt: new Date().toISOString()
      };

      // Append new images
      if (req.files && req.files.images && req.files.images.length > 0) {
        const newImages = req.files.images.map(file => `/uploads/${file.filename}`);
        updatedProperty.images = [...(existing.images || []), ...newImages];
      }

      // Append new documents (store filenames only, files are in private_uploads)
      if (req.files && req.files.documents && req.files.documents.length > 0) {
        const newDocs = req.files.documents.map(file => file.filename);
        updatedProperty.documents = [...(existing.documents || []), ...newDocs];
      }

      // Update visible images for admin review (only first two)
      updatedProperty.visibleToAdminPhotos = (updatedProperty.images || []).slice(0, 2);

      properties[propertyIndex] = updatedProperty;
      await writeJSON('properties.json', properties);

      res.json({ success: true, message: 'Property updated successfully', property: updatedProperty });
    } catch (error) {
      console.error('Edit property error:', error);
      res.status(500).json({ success: false, message: 'Server error' });
    }
  }
);

// Delete Property (Owner only)
app.delete('/api/property/delete/:id', authenticateToken, requireRole('owner'), async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    const propertyIndex = properties.findIndex(p => p.id === req.params.id && p.ownerId === req.user.id);

    if (propertyIndex === -1) {
      return res.status(404).json({ success: false, message: 'Property not found or unauthorized' });
    }

    properties.splice(propertyIndex, 1);
    await writeJSON('properties.json', properties);

    res.json({ success: true, message: 'Property deleted successfully' });
  } catch (error) {
    console.error('Delete property error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===================================================================
// ADMIN ROUTES
// ===================================================================

// Create admin account (first time only - remove in production)
app.post('/api/admin/create-admin', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    const users = await readJSON('users.json');
    const adminExists = users.find(u => u.role === 'admin');

    if (adminExists) {
      return res.status(400).json({ success: false, message: 'Admin already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const admin = {
      id: Date.now().toString(),
      email,
      name: name || 'Admin',
      role: 'admin',
      password: hashedPassword,
      verified: true,
      createdAt: new Date().toISOString()
    };

    users.push(admin);
    await writeJSON('users.json', users);

    res.json({ success: true, message: 'Admin account created successfully' });
  } catch (error) {
    console.error('Create admin error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get Pending Properties (Admin only)
app.get('/api/admin/pending', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    const pending = properties.filter(p => p.status === 'pending');
    res.json({ success: true, properties: pending });
  } catch (error) {
    console.error('Get pending properties error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Approve Property (Admin only)
app.put('/api/admin/approve/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    const propertyIndex = properties.findIndex(p => p.id === req.params.id);

    if (propertyIndex === -1) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }

    properties[propertyIndex].status = 'approved';
    properties[propertyIndex].approvedAt = new Date().toISOString();
    await writeJSON('properties.json', properties);

    res.json({ success: true, message: 'Property approved successfully' });
  } catch (error) {
    console.error('Approve property error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Reject Property (Admin only)
app.put('/api/admin/reject/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const { reason } = req.body;
    const properties = await readJSON('properties.json');
    const propertyIndex = properties.findIndex(p => p.id === req.params.id);

    if (propertyIndex === -1) {
      return res.status(404).json({ success: false, message: 'Property not found' });
    }

    properties[propertyIndex].status = 'rejected';
    properties[propertyIndex].rejectionReason = reason || 'Does not meet requirements';
    properties[propertyIndex].rejectedAt = new Date().toISOString();
    await writeJSON('properties.json', properties);

    res.json({ success: true, message: 'Property rejected successfully' });
  } catch (error) {
    console.error('Reject property error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get All Users (Admin only)
app.get('/api/admin/users', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const users = await readJSON('users.json');
    const sanitizedUsers = users.map(({ password, ...user }) => user);
    res.json({ success: true, users: sanitizedUsers });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get All Properties (Admin only)
app.get('/api/admin/properties', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const properties = await readJSON('properties.json');
    res.json({ success: true, properties });
  } catch (error) {
    console.error('Get all properties error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Admin-only document download
app.get('/api/admin/document/:filename', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const filename = req.params.filename;
    // Basic validation to avoid path traversal
    if (!filename || filename.includes('..') || filename.includes('/') || filename.includes('\\')) {
      return res.status(400).json({ success: false, message: 'Invalid filename' });
    }

    const filePath = path.join(__dirname, 'private_uploads', filename);

    if (!fsSync.existsSync(filePath)) {
      return res.status(404).json({ success: false, message: 'File not found' });
    }

    res.sendFile(filePath);
  } catch (error) {
    console.error('Document download error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Delete User (Admin only)
app.delete('/api/admin/user/:id', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const users = await readJSON('users.json');
    const userIndex = users.findIndex(u => u.id === req.params.id);

    if (userIndex === -1) {
      return res.status(404).json({ success: false, message: 'User not found' });
    }

    if (users[userIndex].role === 'admin') {
      return res.status(400).json({ success: false, message: 'Cannot delete admin user' });
    }

    users.splice(userIndex, 1);
    await writeJSON('users.json', users);

    res.json({ success: true, message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// Get Dashboard Stats (Admin only)
app.get('/api/admin/stats', authenticateToken, requireRole('admin'), async (req, res) => {
  try {
    const users = await readJSON('users.json');
    const properties = await readJSON('properties.json');

    const stats = {
      totalUsers: users.length,
      totalOwners: users.filter(u => u.role === 'owner').length,
      totalTenants: users.filter(u => u.role === 'tenant').length,
      totalProperties: properties.length,
      approvedProperties: properties.filter(p => p.status === 'approved').length,
      pendingProperties: properties.filter(p => p.status === 'pending').length,
      rejectedProperties: properties.filter(p => p.status === 'rejected').length
    };

    res.json({ success: true, stats });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===================================================================
// SOCKET.IO - REAL-TIME CHAT (FULLY FIXED)
// ===================================================================

io.on('connection', (socket) => {
  console.log('✅ New client connected:', socket.id);

  // ✅ Join a chat room (normalize IDs so both sides join same room)
  socket.on('join-chat', ({ senderId, receiverId }) => {
    const roomId = [String(senderId), String(receiverId)].sort().join('-');
    socket.join(roomId);
    console.log(`👥 User ${senderId} joined room: ${roomId}`);
  });

  // ✅ Send a message
  socket.on('send-message', async (data) => {
    try {
      const { senderId, receiverId, message, senderName } = data;
      const roomId = [String(senderId), String(receiverId)].sort().join('-');

      const messages = await readJSON('messages.json');
      const users = await readJSON('users.json');

      // Find sender and receiver from users.json
      const senderUser = users.find(u => String(u.id) === String(senderId));
      const receiverUser = users.find(u => String(u.id) === String(receiverId));

      const newMessage = {
        id: Date.now().toString(),
        senderId: String(senderId),
        receiverId: String(receiverId),
        message,
        senderName: senderUser ? senderUser.name : senderName || 'Admin',
        timestamp: new Date().toISOString(),
        // ✅ Add user details for frontend dashboards
        sender: senderUser
          ? { id: senderUser.id, name: senderUser.name, email: senderUser.email, role: senderUser.role }
          : { id: senderId, name: senderName || 'Admin', email: '', role: 'admin' },
        receiver: receiverUser
          ? { id: receiverUser.id, name: receiverUser.name, email: receiverUser.email, role: receiverUser.role }
          : { id: receiverId, name: 'User', email: '', role: 'user' }
      };

      messages.push(newMessage);
      await writeJSON('messages.json', messages);

      // ✅ Emit to both chat participants
      io.to(roomId).emit('receive-message', newMessage);

      // ✅ Broadcast update event for dashboards (owner, tenant, admin)
      io.emit('new-dashboard-message', newMessage);

      console.log(`📨 ${senderId} → ${receiverId}: ${message}`);
    } catch (error) {
      console.error('Send message error:', error);
    }
  });

  // ✅ Load chat history between two users
  socket.on('load-messages', async ({ userId1, userId2 }) => {
    try {
      const messages = await readJSON('messages.json');
      const chatMessages = messages.filter(
        msg =>
          (msg.senderId === String(userId1) && msg.receiverId === String(userId2)) ||
          (msg.senderId === String(userId2) && msg.receiverId === String(userId1))
      );

      socket.emit('messages-loaded', chatMessages);
    } catch (error) {
      console.error('Load messages error:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('❌ Client disconnected:', socket.id);
  });
});

// ===================================================================
// STATIC FILE ROUTES
// ===================================================================

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ===================================================================
// ERROR HANDLING
// ===================================================================

app.use((err, req, res, next) => {
  console.error('Server error:', err.stack);
  res.status(500).json({ success: false, message: 'Something went wrong!' });
});

// ===================================================================
// MESSAGES ROUTE - LOAD ALL USER MESSAGES (FULLY FIXED)
// ===================================================================

app.get('/api/messages', authenticateToken, async (req, res) => {
  try {
    const userId = String(req.user.id);
    const messages = await readJSON('messages.json');
    const users = await readJSON('users.json');

    // ✅ Normalize IDs and collect all messages where user is sender or receiver
    const userMessages = messages.filter(
      msg => String(msg.senderId) === userId || String(msg.receiverId) === userId
    );

    // ✅ Populate sender/receiver data (fallback for admin)
    const populated = userMessages.map(msg => {
      const sender =
        msg.sender ||
        users.find(u => String(u.id) === String(msg.senderId)) || {
          id: msg.senderId,
          name: msg.senderName || 'Admin',
          email: '',
          role: 'admin'
        };

      const receiver =
        msg.receiver ||
        users.find(u => String(u.id) === String(msg.receiverId)) || {
          id: msg.receiverId,
          name: 'User',
          email: '',
          role: 'user'
        };

      return {
        ...msg,
        sender,
        receiver
      };
    });

    // ✅ Sort by most recent first
    populated.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));

    res.json({ success: true, messages: populated });
  } catch (error) {
    console.error('Get messages error:', error);
    res.status(500).json({ success: false, message: 'Server error' });
  }
});

// ===================================================================
// START SERVER
// ===================================================================

const PORT = process.env.PORT || 5000;
server.listen(PORT, () => {
  console.log('═══════════════════════════════════════════════════════');
  console.log('🚀 Property Management System Server Started');
  console.log('═══════════════════════════════════════════════════════');
  console.log(`📡 Server running on: http://localhost:${PORT}`);
  console.log(`📧 Email service: ${process.env.SMTP_EMAIL ? 'Configured' : 'Not configured'}`);
  console.log(`🔐 JWT Secret: ${process.env.JWT_SECRET ? 'Set' : 'Not set'}`);
  console.log('═══════════════════════════════════════════════════════');
});
