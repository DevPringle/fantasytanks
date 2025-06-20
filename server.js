const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors({
  origin: ['https://devpringle.github.io', 'http://localhost:3000', 'https://localhost:3000'],
  credentials: true
}));
app.use(express.json());
app.use(express.static('.'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET environment variable is not set');
  console.error('Please set JWT_SECRET in your Railway environment variables');
  process.exit(1);
}

const createEmailTransporter = () => {
  const emailConfig = {
    host: process.env.SMTP_HOST || 'smtp.zoho.com',
    port: parseInt(process.env.SMTP_PORT) || 465,
    secure: process.env.SMTP_SECURE === 'true' || true,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD
    }
  };

  if (!process.env.SMTP_USER || !process.env.SMTP_PASSWORD) {
    console.log('No SMTP credentials provided. Email functionality disabled.');
    return null;
  }

  return nodemailer.createTransporter(emailConfig);
};

const emailTransporter = createEmailTransporter();

if (emailTransporter) {
  emailTransporter.verify((error, success) => {
    if (error) {
      console.log('Email transporter verification failed:', error);
    } else {
      console.log('Email server is ready to send messages');
    }
  });
}

const generateEmailVerificationEmail = (username, verificationToken, baseUrl) => {
  const verifyUrl = `${baseUrl}/verify-email.html?token=${verificationToken}`;
  
  return {
    subject: 'Verify Your Email - WoT Fantasy',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #1a2332; color: white; padding: 20px; border-radius: 10px;">
        <h2 style="color: #00d4ff; text-align: center;">Verify Your Email Address</h2>
        <p>Hello <strong>${username}</strong>,</p>
        <p>Welcome to WoT Fantasy! To complete your registration and start playing, please verify your email address.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${verifyUrl}" style="background: linear-gradient(135deg, #00d4ff, #00b8e6); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Verify Email Address</a>
        </div>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="background: rgba(255,255,255,0.1); padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace;">${verifyUrl}</p>
        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 0; font-size: 0.9rem;"><strong>📧 Important:</strong></p>
          <ul style="margin: 10px 0; font-size: 0.9rem;">
            <li>You must verify your email to login</li>
            <li>This link expires in 24 hours</li>
            <li>If you didn't create this account, ignore this email</li>
          </ul>
        </div>
        <p style="font-size: 0.8rem; color: rgba(255,255,255,0.6); text-align: center; margin-top: 30px;">
          This is an automated message from WoTFantasy. Please do not reply.
        </p>
      </div>
    `,
    text: `Verify Your Email - WoTFantasy\n\nHello ${username},\n\nTo complete registration, verify your email: ${verifyUrl}\n\nThis link expires in 24 hours.\n\nYou must verify your email to login.`
  };
};

const generatePasswordResetEmail = (username, resetToken, baseUrl) => {
  const resetUrl = `${baseUrl}/reset-password.html?token=${resetToken}`;
  
  return {
    subject: 'Password Reset - WoT Fantasy',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #1a2332; color: white; padding: 20px; border-radius: 10px;">
        <h2 style="color: #00d4ff; text-align: center;">Password Reset Request</h2>
        <p>Hello <strong>${username}</strong>,</p>
        <p>We received a request to reset your password for your WoTFantasy account.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${resetUrl}" style="background: linear-gradient(135deg, #00d4ff, #00b8e6); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Reset Your Password</a>
        </div>
        <p>If the button doesn't work, copy and paste this link into your browser:</p>
        <p style="background: rgba(255,255,255,0.1); padding: 10px; border-radius: 5px; word-break: break-all; font-family: monospace;">${resetUrl}</p>
        <div style="background: rgba(255,255,255,0.05); padding: 15px; border-radius: 8px; margin: 20px 0;">
          <p style="margin: 0; font-size: 0.9rem;"><strong>🔒 Security Info:</strong></p>
          <ul style="margin: 10px 0; font-size: 0.9rem;">
            <li>This link expires in 1 hour</li>
            <li>If you didn't request this, ignore this email</li>
            <li>Never share this link with anyone</li>
          </ul>
        </div>
        <p style="font-size: 0.8rem; color: rgba(255,255,255,0.6); text-align: center; margin-top: 30px;">
          This is an automated message from WoTFantasy. Please do not reply.
        </p>
      </div>
    `,
    text: `Password Reset - WoTFantasy\n\nHello ${username},\n\nTo reset your password, visit: ${resetUrl}\n\nThis link expires in 1 hour.\n\nIf you didn't request this, ignore this email.`
  };
};

const generateWelcomeEmail = (username, baseUrl) => {
  return {
    subject: 'Welcome to WoT Fantasy - Email Verified!',
    html: `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; background: #1a2332; color: white; padding: 20px; border-radius: 10px;">
        <h2 style="color: #00d4ff; text-align: center;">Welcome to WoTFantasy!</h2>
        <p>Hello <strong>${username}</strong>,</p>
        <p>🎉 <strong>Your email has been verified!</strong> Your WoTFantasy account is now fully activated and ready to use.</p>
        <div style="text-align: center; margin: 30px 0;">
          <a href="${baseUrl}/tournaments.html" style="background: linear-gradient(135deg, #00d4ff, #00b8e6); color: white; padding: 15px 30px; text-decoration: none; border-radius: 8px; font-weight: bold; display: inline-block;">Start Playing Now</a>
        </div>
        <p>With WoTFantasy, you can:</p>
        <ul>
          <li>Pick players from active tournaments</li>
          <li>Earn points based on their live performance</li>
          <li>Compete against other fantasy teams</li>
          <li>Climb the leaderboards and prove your skills</li>
        </ul>
        <div style="background: rgba(0, 212, 255, 0.1); padding: 15px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #00d4ff;">
          <p style="margin: 0; font-size: 0.9rem;"><strong>🚀 Quick Start:</strong></p>
          <p style="margin: 5px 0 0 0; font-size: 0.9rem;">Ready to build your first roster? Head to the tournaments section and start drafting your team of players!</p>
        </div>
        <p style="font-size: 0.8rem; color: rgba(255,255,255,0.6); text-align: center; margin-top: 30px;">
          Welcome to the WoTFantasy community!
        </p>
      </div>
    `,
    text: `Welcome to WoTFantasy!\n\nHello ${username},\n\nYour email has been verified! Your account is now fully activated.\n\nStart playing: ${baseUrl}/tournaments.html\n\nWelcome to the WoTFantasy community!`
  };
};

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

async function initializeTables() {
  try {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        email_verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS email_verifications (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        verified BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS password_resets (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS rosters (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES users(id),
        tournament_id VARCHAR(100) NOT NULL,
        roster JSONB NOT NULL,
        match_day INTEGER DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(user_id, tournament_id, match_day)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS player_scores (
        id SERIAL PRIMARY KEY,
        player_name VARCHAR(100) NOT NULL,
        tournament_id VARCHAR(100) NOT NULL,
        match_day INTEGER NOT NULL,
        points DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(player_name, tournament_id, match_day)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS player_match_performance (
        id SERIAL PRIMARY KEY,
        player_name VARCHAR(100) NOT NULL,
        tournament_id VARCHAR(100) NOT NULL,
        match_day INTEGER NOT NULL,
        points DECIMAL(10,2) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(player_name, tournament_id, match_day)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS tournaments (
        tournament_id VARCHAR(100) PRIMARY KEY,
        tournament_name VARCHAR(255) NOT NULL,
        region VARCHAR(50) NOT NULL,
        start_date DATE,
        end_date DATE,
        status VARCHAR(20) DEFAULT 'upcoming',
        max_roster_size INTEGER DEFAULT 10,
        total_fantasy_teams INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS teams (
        team_name VARCHAR(100) NOT NULL,
        team_code VARCHAR(10) NOT NULL,
        tournament_id VARCHAR(100) NOT NULL,
        region VARCHAR(50),
        UNIQUE(tournament_id, team_code)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS players (
        player_name VARCHAR(100) NOT NULL,
        tournament_id VARCHAR(100) NOT NULL,
        team_code VARCHAR(10) NOT NULL,
        battles_played VARCHAR(10) DEFAULT '0%',
        total_points DECIMAL(10,2) DEFAULT 0.00,
        average_points DECIMAL(10,2) DEFAULT 0.00,
        picked_percentage VARCHAR(10) DEFAULT '0%',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(tournament_id, player_name)
      )
    `);

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database tables:', error);
  }
}

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'WoTFantasy API is running' });
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, email_verified) VALUES ($1, $2, $3, $4) RETURNING id, username, email',
      [username, email, passwordHash, false]
    );

    const user = result.rows[0];

    if (emailTransporter) {
      try {
        const verificationToken = crypto.randomBytes(32).toString('hex');
        const expiresAt = new Date(Date.now() + 86400000);

        await pool.query(
          'INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)',
          [user.id, verificationToken, expiresAt]
        );

        const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
        const verificationEmail = generateEmailVerificationEmail(username, verificationToken, baseUrl);
        
        await emailTransporter.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: email,
          subject: verificationEmail.subject,
          html: verificationEmail.html,
          text: verificationEmail.text
        });

        console.log('Verification email sent to:', email);

        res.status(201).json({
          message: 'Account created successfully! Please check your email to verify your account before logging in.',
          requiresVerification: true,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            email_verified: false
          }
        });

      } catch (emailError) {
        console.error('Failed to send verification email:', emailError);
        
        await pool.query('UPDATE users SET email_verified = true WHERE id = $1', [user.id]);
        
        const token = jwt.sign(
          { userId: user.id, username: user.username },
          JWT_SECRET,
          { expiresIn: '7d' }
        );

        res.status(201).json({
          message: 'Account created successfully! (Email verification temporarily unavailable)',
          token,
          user: {
            id: user.id,
            username: user.username,
            email: user.email,
            email_verified: true
          }
        });
      }
    } else {
      await pool.query('UPDATE users SET email_verified = true WHERE id = $1', [user.id]);
      
      const token = jwt.sign(
        { userId: user.id, username: user.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.status(201).json({
        message: 'Account created successfully!',
        token,
        user: {
          id: user.id,
          username: user.username,
          email: user.email,
          email_verified: true
        }
      });
    }

  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/verify-email/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(`
      SELECT ev.id, ev.user_id, ev.expires_at, ev.verified, u.username, u.email
      FROM email_verifications ev
      JOIN users u ON ev.user_id = u.id
      WHERE ev.token = $1
    `, [token]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid verification token' });
    }

    const verificationRecord = result.rows[0];

    if (verificationRecord.verified) {
      return res.status(400).json({ error: 'Email has already been verified' });
    }

    if (new Date() > new Date(verificationRecord.expires_at)) {
      return res.status(400).json({ error: 'Verification token has expired' });
    }

    await pool.query('BEGIN');
    
    try {
      await pool.query(
        'UPDATE users SET email_verified = true WHERE id = $1',
        [verificationRecord.user_id]
      );

      await pool.query(
        'UPDATE email_verifications SET verified = true WHERE id = $1',
        [verificationRecord.id]
      );

      await pool.query('COMMIT');

      if (emailTransporter) {
        try {
          const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
          const welcomeEmail = generateWelcomeEmail(verificationRecord.username, baseUrl);
          
          await emailTransporter.sendMail({
            from: process.env.SMTP_FROM || process.env.SMTP_USER,
            to: verificationRecord.email,
            subject: welcomeEmail.subject,
            html: welcomeEmail.html,
            text: welcomeEmail.text
          });

          console.log('Welcome email sent to:', verificationRecord.email);
        } catch (emailError) {
          console.error('Failed to send welcome email:', emailError);
        }
      }

      const authToken = jwt.sign(
        { userId: verificationRecord.user_id, username: verificationRecord.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        message: 'Email verified successfully! You can now login.',
        token: authToken,
        user: {
          id: verificationRecord.user_id,
          username: verificationRecord.username,
          email: verificationRecord.email,
          email_verified: true
        }
      });

    } catch (error) {
      await pool.query('ROLLBACK');
      throw error;
    }

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/resend-verification', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (!emailTransporter) {
      return res.status(503).json({ error: 'Email service not configured' });
    }

    const result = await pool.query(
      'SELECT id, username, email, email_verified FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({ message: 'If an unverified account with that email exists, a verification email has been sent.' });
    }

    const user = result.rows[0];

    if (user.email_verified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 86400000);

    await pool.query('DELETE FROM email_verifications WHERE user_id = $1', [user.id]);
    await pool.query(
      'INSERT INTO email_verifications (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, verificationToken, expiresAt]
    );

    try {
      const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
      const verificationEmail = generateEmailVerificationEmail(user.username, verificationToken, baseUrl);
      
      await emailTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: verificationEmail.subject,
        html: verificationEmail.html,
        text: verificationEmail.text
      });

      console.log('New verification email sent to:', user.email);
      res.json({ message: 'A new verification email has been sent.' });

    } catch (emailError) {
      console.error('Failed to send verification email:', emailError);
      res.status(500).json({ error: 'Failed to send verification email' });
    }

  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    const result = await pool.query(
      'SELECT id, username, email, password_hash, email_verified FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    if (!user.email_verified) {
      return res.status(403).json({ 
        error: 'Please verify your email address before logging in',
        requiresVerification: true,
        email: user.email
      });
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      message: 'Login successful',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
        email_verified: user.email_verified
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    if (!emailTransporter) {
      return res.status(503).json({ error: 'Email service not configured' });
    }

    const result = await pool.query(
      'SELECT id, username, email, email_verified FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const user = result.rows[0];

    if (!user.email_verified) {
      return res.status(403).json({ error: 'Please verify your email address first before resetting your password' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 3600000);

    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES ($1, $2, $3)',
      [user.id, resetToken, expiresAt]
    );

    try {
      const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
      const resetEmail = generatePasswordResetEmail(user.username, resetToken, baseUrl);
      
      await emailTransporter.sendMail({
        from: process.env.SMTP_FROM || process.env.SMTP_USER,
        to: user.email,
        subject: resetEmail.subject,
        html: resetEmail.html,
        text: resetEmail.text
      });

      console.log('Password reset email sent to:', user.email);
      res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });

    } catch (emailError) {
      console.error('Failed to send password reset email:', emailError);
      res.status(500).json({ error: 'Failed to send password reset email' });
    }

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/auth/verify-reset-token/:token', async (req, res) => {
  try {
    const { token } = req.params;

    const result = await pool.query(`
      SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.username 
      FROM password_resets pr
      JOIN users u ON pr.user_id = u.id
      WHERE pr.token = $1
    `, [token]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const resetRecord = result.rows[0];

    if (resetRecord.used) {
      return res.status(400).json({ error: 'Reset token has already been used' });
    }

    if (new Date() > new Date(resetRecord.expires_at)) {
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    res.json({ 
      valid: true, 
      username: resetRecord.username,
      message: 'Reset token is valid' 
    });

  } catch (error) {
    console.error('Verify reset token error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ error: 'Token and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const result = await pool.query(`
      SELECT pr.id, pr.user_id, pr.expires_at, pr.used, u.username, u.email
      FROM password_resets pr
      JOIN users u ON pr.user_id = u.id
      WHERE pr.token = $1
    `, [token]);

    if (result.rows.length === 0) {
      return res.status(400).json({ error: 'Invalid reset token' });
    }

    const resetRecord = result.rows[0];

    if (resetRecord.used) {
      return res.status(400).json({ error: 'Reset token has already been used' });
    }

    if (new Date() > new Date(resetRecord.expires_at)) {
      return res.status(400).json({ error: 'Reset token has expired' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    await pool.query('BEGIN');
    
    try {
      await pool.query(
        'UPDATE users SET password_hash = $1 WHERE id = $2',
        [passwordHash, resetRecord.user_id]
      );

      await pool.query(
        'UPDATE password_resets SET used = true WHERE id = $1',
        [resetRecord.id]
      );

      await pool.query('COMMIT');

      const authToken = jwt.sign(
        { userId: resetRecord.user_id, username: resetRecord.username },
        JWT_SECRET,
        { expiresIn: '7d' }
      );

      res.json({
        message: 'Password reset successful',
        token: authToken,
        user: {
          id: resetRecord.user_id,
          username: resetRecord.username,
          email: resetRecord.email
        }
      });

    } catch (error) {
      await pool.query('ROLLBACK');
      throw error;
    }

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/leaderboard/:tournamentId', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { matchDay, minRosterSize = 10, limit, offset = 0 } = req.query;

    let query = `
      WITH user_scores AS (
        SELECT 
          u.id as user_id,
          u.username,
          r.match_day,
          SUM(COALESCE(pmp.points, 0)) as match_day_points,
          COUNT(CASE WHEN r.roster ? pmp.player_name THEN 1 END) as players_with_scores,
          jsonb_array_length(r.roster) as roster_size
        FROM users u
        JOIN rosters r ON u.id = r.user_id
        LEFT JOIN player_match_performance pmp ON 
          pmp.tournament_id = r.tournament_id 
          AND pmp.match_day = r.match_day
          AND r.roster ? pmp.player_name
        WHERE r.tournament_id = $1
          AND jsonb_array_length(r.roster) >= $2
    `;

    let queryParams = [tournamentId, minRosterSize];
    let paramCount = 2;

    if (matchDay) {
      paramCount++;
      query += ` AND r.match_day = ${paramCount}`;
      queryParams.push(matchDay);
    }

    query += `
        GROUP BY u.id, u.username, r.match_day, r.roster
      ),
      aggregated_scores AS (
        SELECT 
          user_id,
          username,
          SUM(match_day_points) as total_points,
          AVG(match_day_points) as avg_points,
          COUNT(DISTINCT match_day) as match_days_played,
          MAX(match_day_points) as best_day_score
        FROM user_scores
        GROUP BY user_id, username
      )
      SELECT 
        ROW_NUMBER() OVER (ORDER BY total_points DESC, avg_points DESC, username ASC) as rank,
        username,
        ROUND(total_points, 2) as total_points,
        ROUND(avg_points, 2) as avg_points,
        match_days_played,
        ROUND(best_day_score, 2) as best_day_score
      FROM aggregated_scores
      ORDER BY total_points DESC, avg_points DESC, username ASC
    `;

    if (limit) {
      paramCount++;
      query += ` LIMIT ${paramCount}`;
      queryParams.push(limit);
    }

    if (offset > 0) {
      paramCount++;
      query += ` OFFSET ${paramCount}`;
      queryParams.push(offset);
    }

    const result = await pool.query(query, queryParams);

    const metadataQuery = `
      SELECT 
        COUNT(DISTINCT u.id) as total_participants,
        COUNT(DISTINCT CASE WHEN jsonb_array_length(r.roster) >= $2 THEN u.id END) as complete_rosters,
        COUNT(DISTINCT r.match_day) as total_match_days
      FROM users u
      JOIN rosters r ON u.id = r.user_id
      WHERE r.tournament_id = $1
    `;

    const metadataResult = await pool.query(metadataQuery, [tournamentId, minRosterSize]);

    res.json({
      leaderboard: result.rows,
      metadata: {
        total_participants: parseInt(metadataResult.rows[0].total_participants),
        complete_rosters: parseInt(metadataResult.rows[0].complete_rosters),
        total_match_days: parseInt(metadataResult.rows[0].total_match_days),
        showing_results_for: matchDay ? `Match Day ${matchDay}` : 'Overall Tournament',
        min_roster_size: parseInt(minRosterSize)
      }
    });

  } catch (error) {
    console.error('Leaderboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/leaderboard/:tournamentId/user/:userId', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, userId } = req.params;
    const { matchDay } = req.query;

    if (req.user.userId !== parseInt(userId)) {
      return res.status(403).json({ error: 'Access denied' });
    }

    let query = `
      WITH user_scores AS (
        SELECT 
          u.id as user_id,
          u.username,
          r.match_day,
          SUM(COALESCE(pmp.points, 0)) as match_day_points,
          jsonb_array_length(r.roster) as roster_size
        FROM users u
        JOIN rosters r ON u.id = r.user_id
        LEFT JOIN player_match_performance pmp ON 
          pmp.tournament_id = r.tournament_id 
          AND pmp.match_day = r.match_day
          AND r.roster ? pmp.player_name
        WHERE r.tournament_id = $1 AND u.id = $2
    `;

    let queryParams = [tournamentId, userId];

    if (matchDay) {
      query += ` AND r.match_day = $3`;
      queryParams.push(matchDay);
    }

    query += `
        GROUP BY u.id, u.username, r.match_day, r.roster
      ),
      aggregated_scores AS (
        SELECT 
          user_id,
          username,
          SUM(match_day_points) as total_points,
          AVG(match_day_points) as avg_points,
          COUNT(DISTINCT match_day) as match_days_played
        FROM user_scores
        GROUP BY user_id, username
      )
      SELECT 
        username,
        ROUND(total_points, 2) as total_points,
        ROUND(avg_points, 2) as avg_points,
        match_days_played
      FROM aggregated_scores
    `;

    const result = await pool.query(query, queryParams);

    if (result.rows.length === 0) {
      return res.json({ 
        user_ranking: null, 
        message: 'No roster data found for this user' 
      });
    }

    res.json({ user_ranking: result.rows[0] });

  } catch (error) {
    console.error('User ranking error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/tournaments', async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM tournaments ORDER BY created_at DESC'
    );
    
    res.json({ tournaments: result.rows });
  } catch (error) {
    console.error('Get tournaments error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/tournaments/:tournamentId/players', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    
    const result = await pool.query(`
      SELECT 
        p.player_name,
        p.team_code,
        p.battles_played,
        p.total_points,
        p.average_points,
        p.picked_percentage
      FROM players p
      WHERE p.tournament_id = $1
      ORDER BY p.total_points DESC
    `, [tournamentId]);
    
    res.json({ players: result.rows });
  } catch (error) {
    console.error('Get players error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/roster', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, matchDay = 1 } = req.query;
    const userId = req.user.userId;

    if (!tournamentId) {
      return res.status(400).json({ error: 'Tournament ID is required' });
    }

    const result = await pool.query(
      'SELECT roster FROM rosters WHERE user_id = $1 AND tournament_id = $2 AND match_day = $3',
      [userId, tournamentId, matchDay]
    );

    if (result.rows.length === 0) {
      return res.json({ roster: [] });
    }

    res.json({ roster: result.rows[0].roster });

  } catch (error) {
    console.error('Get roster error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/roster', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, roster, matchDay = 1 } = req.body;
    const userId = req.user.userId;

    if (!tournamentId || !roster) {
      return res.status(400).json({ error: 'Tournament ID and roster are required' });
    }

    await pool.query(`
      INSERT INTO rosters (user_id, tournament_id, roster, match_day, updated_at)
      VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)
      ON CONFLICT (user_id, tournament_id, match_day)
      DO UPDATE SET 
        roster = EXCLUDED.roster,
        updated_at = CURRENT_TIMESTAMP
    `, [userId, tournamentId, JSON.stringify(roster), matchDay]);

    res.json({ message: 'Roster saved successfully' });

  } catch (error) {
    console.error('Save roster error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, async () => {
  console.log(`Server running on port ${port}`);
  await initializeTables();
});