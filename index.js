const express = require('express');
const path = require('path');
const multer = require('multer');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const SALT_ROUNDS = 10;
const UPLOAD_DIR = path.join(__dirname, 'uploads');

// Database initialization
const db = new sqlite3.Database('./contacts.db', (err) => {
  if (err) console.error('Database connection error:', err);
  else console.log('Connected to SQLite database');
});

// Create tables
db.serialize(() => {
  // Users table with role-based access
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('user', 'admin')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);

  // Contacts table
  db.run(`CREATE TABLE IF NOT EXISTS contacts (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    email TEXT,
    phone TEXT,
    notes TEXT,
    icon TEXT,
    created_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (created_by) REFERENCES users(id)
  )`);

  // Create default admin if not exists
  db.get('SELECT id FROM users WHERE username = ?', ['admin'], (err, row) => {
    if (!row) {
      bcrypt.hash('admin123', SALT_ROUNDS, (err, hash) => {
        if (err) {
          console.error('Error creating default admin:', err);
          return;
        }
        db.run(
          'INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)',
          [uuidv4(), 'admin', hash, 'admin'],
          (err) => {
            if (err) console.error('Error inserting admin:', err);
            else console.log('Default admin created (username: admin, password: admin123)');
          }
        );
      });
    }
  });
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use('/uploads', express.static(UPLOAD_DIR));
app.use(express.static(path.join(__dirname, 'public')));

// File upload configuration
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => {
    const sanitized = file.originalname.replace(/[^a-zA-Z0-9.-]/g, '_');
    cb(null, `${Date.now()}-${sanitized}`);
  },
});
const upload = multer({
  storage,
  limits: { fileSize: 200000 },
  fileFilter: (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed'));
    }
  }
});

// Ensure upload directory exists
const fs = require('fs');
if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Authentication middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
}

// Admin-only middleware
function requireAdmin(req, res, next) {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// Input validation middleware
function validateContact(req, res, next) {
  const { name, email, phone } = req.body;
  
  if (!name || name.trim().length === 0) {
    return res.status(400).json({ error: 'Name is required' });
  }
  
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  
  if (phone && !/^[\d\s\-\+\(\)]+$/.test(phone)) {
    return res.status(400).json({ error: 'Invalid phone format' });
  }
  
  next();
}

// ==================== AUTH ROUTES ====================

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    bcrypt.compare(password, user.password, (err, match) => {
      if (err) {
        console.error('Password comparison error:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      if (!match) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }

      const token = jwt.sign(
        { id: user.id, username: user.username, role: user.role },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      res.json({
        token,
        user: {
          id: user.id,
          username: user.username,
          role: user.role
        }
      });
    });
  });
});

// Register (admin only)
app.post('/api/auth/register', authenticateToken, requireAdmin, (req, res) => {
  const { username, password, role } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ error: 'Invalid role. Must be "user" or "admin"' });
  }

  if (username.length < 3 || password.length < 6) {
    return res.status(400).json({
      error: 'Username must be at least 3 characters, password at least 6 characters'
    });
  }

  bcrypt.hash(password, SALT_ROUNDS, (err, hash) => {
    if (err) {
      console.error('Hashing error:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    const userId = uuidv4();
    db.run(
      'INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)',
      [userId, username, hash, role],
      function(err) {
        if (err) {
          if (err.message.includes('UNIQUE')) {
            return res.status(409).json({ error: 'Username already exists' });
          }
          console.error('Registration error:', err);
          return res.status(500).json({ error: 'Internal server error' });
        }

        res.status(201).json({
          message: 'User created successfully',
          user: { id: userId, username, role }
        });
      }
    );
  });
});

// Verify token
app.get('/api/auth/verify', authenticateToken, (req, res) => {
  res.json({ user: req.user });
});

// List users (admin only)
app.get('/api/users', authenticateToken, requireAdmin, (req, res) => {
  db.all('SELECT id, username, role, created_at FROM users', [], (err, users) => {
    if (err) {
      console.error('Error fetching users:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(users);
  });
});

// Delete user (admin only, cannot delete self)
app.delete('/api/users/:id', authenticateToken, requireAdmin, (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own account' });
  }

  db.run('DELETE FROM users WHERE id = ?', [req.params.id], function(err) {
    if (err) {
      console.error('Error deleting user:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json({ success: true, message: 'User deleted' });
  });
});

// ==================== CONTACT ROUTES ====================

// List contacts with search
app.get('/api/contacts', authenticateToken, (req, res) => {
  const search = req.query.search || '';
  const query = search
    ? 'SELECT * FROM contacts WHERE name LIKE ? ORDER BY created_at DESC'
    : 'SELECT * FROM contacts ORDER BY created_at DESC';
  const params = search ? [`%${search}%`] : [];

  db.all(query, params, (err, contacts) => {
    if (err) {
      console.error('Error fetching contacts:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }
    res.json(contacts);
  });
});

// Get single contact
app.get('/api/contacts/:id', authenticateToken, (req, res) => {
  db.get('SELECT * FROM contacts WHERE id = ?', [req.params.id], (err, contact) => {
    if (err) {
      console.error('Error fetching contact:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!contact) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    res.json(contact);
  });
});

// Create contact
app.post('/api/contacts', authenticateToken, upload.single('icon'), validateContact, (req, res) => {
  const { name, email, phone, notes } = req.body;
  const contactId = uuidv4();
  const icon = req.file ? `/uploads/${path.basename(req.file.path)}` : null;

  db.run(
    `INSERT INTO contacts (id, name, email, phone, notes, icon, created_by)
     VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [contactId, name.trim(), email || null, phone || null, notes || null, icon, req.user.id],
    function(err) {
      if (err) {
        console.error('Error creating contact:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      db.get('SELECT * FROM contacts WHERE id = ?', [contactId], (err, contact) => {
        if (err) {
          console.error('Error fetching created contact:', err);
          return res.status(500).json({ error: 'Contact created but fetch failed' });
        }
        res.status(201).json(contact);
      });
    }
  );
});

// Update contact
app.put('/api/contacts/:id', authenticateToken, upload.single('icon'), validateContact, (req, res) => {
  const { name, email, phone, notes } = req.body;
  const icon = req.file ? `/uploads/${path.basename(req.file.path)}` : undefined;

  const updates = [name.trim(), email || null, phone || null, notes || null];
  let query = `UPDATE contacts SET name = ?, email = ?, phone = ?, notes = ?, updated_at = CURRENT_TIMESTAMP`;

  if (icon !== undefined) {
    query += `, icon = ?`;
    updates.push(icon);
  }

  query += ` WHERE id = ?`;
  updates.push(req.params.id);

  db.run(query, updates, function(err) {
    if (err) {
      console.error('Error updating contact:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (this.changes === 0) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    db.get('SELECT * FROM contacts WHERE id = ?', [req.params.id], (err, contact) => {
      if (err) {
        console.error('Error fetching updated contact:', err);
        return res.status(500).json({ error: 'Contact updated but fetch failed' });
      }
      res.json(contact);
    });
  });
});

// Delete contact
app.delete('/api/contacts/:id', authenticateToken, (req, res) => {
  // Get contact first to delete associated file
  db.get('SELECT icon FROM contacts WHERE id = ?', [req.params.id], (err, contact) => {
    if (err) {
      console.error('Error fetching contact for deletion:', err);
      return res.status(500).json({ error: 'Internal server error' });
    }

    if (!contact) {
      return res.status(404).json({ error: 'Contact not found' });
    }

    db.run('DELETE FROM contacts WHERE id = ?', [req.params.id], function(err) {
      if (err) {
        console.error('Error deleting contact:', err);
        return res.status(500).json({ error: 'Internal server error' });
      }

      // Delete associated file if exists
      if (contact.icon) {
        const filePath = path.join(__dirname, 'public', contact.icon);
        fs.unlink(filePath, (err) => {
          if (err) console.error('Error deleting file:', err);
        });
      }

      res.json({ success: true, message: 'Contact deleted' });
    });
  });
});

// Fallback to index.html for SPA
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: err.message || 'Internal server error' });
});

// Graceful shutdown
process.on('SIGINT', () => {
  db.close((err) => {
    if (err) console.error('Error closing database:', err);
    else console.log('Database connection closed');
    process.exit(0);
  });
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log('Default admin credentials: username=admin, password=admin123');
});