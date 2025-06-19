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

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET;

// Security check - fail fast if JWT_SECRET is not set
if (!JWT_SECRET) {
  console.error('FATAL ERROR: JWT_SECRET environment variable is not set');
  console.error('Please set JWT_SECRET in your Railway environment variables');
  process.exit(1);
}

// Email configuration
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
    console.log('No SMTP credentials provided. Email functionality disabled for development.');
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

const generatePasswordResetEmail = (username, resetToken, baseUrl) => {
  const resetUrl = `${baseUrl}/reset-password.html?token=${resetToken}`;
  
  return {
    subject: 'Password Reset - WoT Fantasy',
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Password Reset</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1a2332 100%);
            color: #ffffff; margin: 0; padding: 40px 20px; min-height: 100vh;
          }
          .email-container {
            max-width: 600px; margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px; overflow: hidden;
            backdrop-filter: blur(20px);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
          }
          .email-header {
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.15), rgba(26, 35, 50, 0.2));
            padding: 40px 40px 30px; text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
          }
          .email-title {
            font-size: 1.8rem; font-weight: 700; margin-bottom: 10px;
            background: linear-gradient(135deg, #00d4ff 0%, #00b8e6 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
          }
          .email-subtitle { color: rgba(255, 255, 255, 0.7); font-size: 1rem; }
          .email-body { padding: 40px; }
          .greeting { font-size: 1.1rem; color: rgba(255, 255, 255, 0.9); margin-bottom: 20px; }
          .message {
            color: rgba(255, 255, 255, 0.8); line-height: 1.6;
            margin-bottom: 30px; font-size: 1rem;
          }
          .reset-button {
            display: inline-block; padding: 16px 32px;
            background: linear-gradient(135deg, #00d4ff, #00b8e6);
            color: white; text-decoration: none; border-radius: 12px;
            font-weight: 600; font-size: 1rem; text-align: center;
            margin: 20px 0; box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
          }
          .button-container { text-align: center; margin: 30px 0; }
          .security-note {
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 10px; padding: 20px; margin: 30px 0;
          }
          .security-title {
            color: #00d4ff; font-weight: 600; margin-bottom: 10px;
          }
          .security-text { color: rgba(255, 255, 255, 0.7); font-size: 0.9rem; line-height: 1.5; }
          .email-footer {
            background: rgba(255, 255, 255, 0.03); padding: 30px 40px;
            border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center;
          }
          .footer-text { color: rgba(255, 255, 255, 0.5); font-size: 0.85rem; line-height: 1.5; }
          .footer-link { color: #00d4ff; text-decoration: none; }
          .token-display {
            background: rgba(255, 255, 255, 0.1);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 8px; padding: 15px;
            font-family: 'Courier New', monospace; font-size: 0.9rem;
            color: #00d4ff; word-break: break-all; margin: 20px 0;
          }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="email-header">
            <div class="email-title">Password Reset Request</div>
            <div class="email-subtitle">Secure your Fantasy Tanks account</div>
          </div>
          <div class="email-body">
            <div class="greeting">Hello ${username},</div>
            <div class="message">
              We received a request to reset your password for your Fantasy Tanks account. 
              If you requested this password reset, click the button below to create a new password.
            </div>
            <div class="button-container">
              <a href="${resetUrl}" class="reset-button">Reset Your Password</a>
            </div>
            <div class="message">
              If the button above doesn't work, you can copy and paste the following link into your browser:
            </div>
            <div class="token-display">${resetUrl}</div>
            <div class="security-note">
              <div class="security-title">🔒 Security Information</div>
              <div class="security-text">
                • This password reset link will expire in 1 hour for security reasons<br>
                • If you didn't request this reset, you can safely ignore this email<br>
                • Never share this link with anyone else<br>
                • We will never ask for your password via email
              </div>
            </div>
            <div class="message">
              If you're having trouble with the reset process or didn't request this change, 
              please contact our support team immediately.
            </div>
          </div>
          <div class="email-footer">
            <div class="footer-text">
              This email was sent from Fantasy Tanks<br>
              <a href="#" class="footer-link">Contact Support</a> • 
              <a href="#" class="footer-link">Privacy Policy</a><br><br>
              This is an automated message. Please do not reply to this email.
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
Password Reset Request - Fantasy Tanks

Hello ${username},

We received a request to reset your password for your Fantasy Tanks account.

To reset your password, please visit: ${resetUrl}

This link will expire in 1 hour for security reasons.

If you didn't request this password reset, you can safely ignore this email.

Never share this link with anyone else, and we will never ask for your password via email.

If you're having trouble, please contact our support team.

---
Fantasy Tanks
This is an automated message. Please do not reply to this email.
    `
  };
};

const generateWelcomeEmail = (username, baseUrl) => {
  return {
    subject: 'Welcome to WoT Fantasy!',
    html: `
      <!DOCTYPE html>
      <html lang="en">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Welcome to WoT Fantasy</title>
        <style>
          * { margin: 0; padding: 0; box-sizing: border-box; }
          body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
            background: linear-gradient(135deg, #0f1419 0%, #1a2332 100%);
            color: #ffffff; margin: 0; padding: 40px 20px; min-height: 100vh;
          }
          .email-container {
            max-width: 600px; margin: 0 auto;
            background: rgba(255, 255, 255, 0.05);
            border: 1px solid rgba(255, 255, 255, 0.1);
            border-radius: 20px; overflow: hidden;
            backdrop-filter: blur(20px);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
          }
          .email-header {
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.15), rgba(26, 35, 50, 0.2));
            padding: 40px 40px 30px; text-align: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
          }
          .email-title {
            font-size: 1.8rem; font-weight: 700; margin-bottom: 10px;
            background: linear-gradient(135deg, #00d4ff 0%, #00b8e6 100%);
            -webkit-background-clip: text; -webkit-text-fill-color: transparent;
            background-clip: text;
          }
          .email-subtitle { color: rgba(255, 255, 255, 0.7); font-size: 1rem; }
          .email-body { padding: 40px; }
          .greeting { font-size: 1.1rem; color: rgba(255, 255, 255, 0.9); margin-bottom: 20px; }
          .message {
            color: rgba(255, 255, 255, 0.8); line-height: 1.6;
            margin-bottom: 20px; font-size: 1rem;
          }
          .cta-button {
            display: inline-block; padding: 16px 32px;
            background: linear-gradient(135deg, #00d4ff, #00b8e6);
            color: white; text-decoration: none; border-radius: 12px;
            font-weight: 600; font-size: 1rem; text-align: center;
            margin: 20px 0; box-shadow: 0 4px 15px rgba(0, 212, 255, 0.3);
          }
          .button-container { text-align: center; margin: 30px 0; }
          .email-footer {
            background: rgba(255, 255, 255, 0.03); padding: 30px 40px;
            border-top: 1px solid rgba(255, 255, 255, 0.1); text-align: center;
          }
          .footer-text { color: rgba(255, 255, 255, 0.5); font-size: 0.85rem; line-height: 1.5; }
          .footer-link { color: #00d4ff; text-decoration: none; }
        </style>
      </head>
      <body>
        <div class="email-container">
          <div class="email-header">
            <div class="email-title">Welcome to Fantasy Tanks!</div>
            <div class="email-subtitle">Your account has been created successfully</div>
          </div>
          <div class="email-body">
            <div class="greeting">Welcome ${username}!</div>
            <div class="message">
              Thank you for joining Fantasy Tanks! Your account has been successfully created and you're ready to start building your ultimate fantasy lineup.
            </div>
            <div class="message">
              With Fantasy Tanks, you can:
              • Draft pro players from real tournaments<br>
              • Earn points based on their live performance<br>
              • Compete against other fantasy managers<br>
              • Climb the leaderboards and prove your strategic skills
            </div>
            <div class="button-container">
              <a href="${baseUrl}/tournaments.html" class="cta-button">Start Playing Now</a>
            </div>
            <div class="message">
              Ready to build your first roster? Head over to the tournaments section and start drafting your team of pro players.
            </div>
            <div class="message">
              If you have any questions or need help getting started, don't hesitate to reach out to our support team.
            </div>
          </div>
          <div class="email-footer">
            <div class="footer-text">
              Welcome to the Fantasy Tanks community!<br>
              <a href="#" class="footer-link">Get Help</a> • 
              <a href="#" class="footer-link">Community Guidelines</a><br><br>
              This is an automated welcome message.
            </div>
          </div>
        </div>
      </body>
      </html>
    `,
    text: `
Welcome to Fantasy Tanks!

Hello ${username},

Thank you for joining Fantasy Tanks! Your account has been successfully created.

With Fantasy Tanks, you can draft pro players from real tournaments, earn points based on their performance, and compete against other fantasy managers.

Visit ${baseUrl}/tournaments.html to start building your first roster.

If you have any questions, please contact our support team.

Welcome to the Fantasy Tanks community!
    `
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
        FOREIGN KEY (tournament_id) REFERENCES tournaments(tournament_id),
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
        FOREIGN KEY (tournament_id) REFERENCES tournaments(tournament_id),
        UNIQUE(tournament_id, player_name)
      )
    `);

    await pool.query(`
      CREATE TABLE IF NOT EXISTS player_pick_stats (
        id SERIAL PRIMARY KEY,
        tournament_id VARCHAR(100) NOT NULL,
        match_day INTEGER NOT NULL,
        player_name VARCHAR(100) NOT NULL,
        times_picked INTEGER DEFAULT 0,
        total_rosters INTEGER DEFAULT 0,
        pick_percentage DECIMAL(5,2) DEFAULT 0,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        UNIQUE(tournament_id, match_day, player_name)
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
  res.json({ status: 'OK', message: 'Fantasy Tanks API is running' });
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
      [username, email, passwordHash, !emailTransporter]
    );

    const user = result.rows[0];

    if (emailTransporter) {
      try {
        const baseUrl = process.env.BASE_URL || 'http://localhost:3000';
        const welcomeEmail = generateWelcomeEmail(username, baseUrl);
        await emailTransporter.sendMail({
          from: process.env.SMTP_FROM || process.env.SMTP_USER,
          to: email,
          subject: welcomeEmail.subject,
          html: welcomeEmail.html,
          text: welcomeEmail.text
        });
        console.log('Welcome email sent to:', email);
      } catch (emailError) {
        console.error('Failed to send welcome email:', emailError);
      }
    }

    const token = jwt.sign(
      { userId: user.id, username: user.username },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.status(201).json({
      message: 'User created successfully',
      token,
      user: {
        id: user.id,
        username: user.username,
        email: user.email
      }
    });

  } catch (error) {
    console.error('Registration error:', error);
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
      'SELECT id, username, email, password_hash FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(currentPassword, user.password_hash);
    if (!isValidPassword) {
      return res.status(400).json({ error: 'Current password is incorrect' });
    }

    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(newPassword, saltRounds);

    await pool.query(
      'UPDATE users SET password_hash = $1 WHERE id = $2',
      [passwordHash, userId]
    );

    res.json({ message: 'Password changed successfully' });

  } catch (error) {
    console.error('Change password error:', error);
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

app.get('/api/tournaments/:tournamentId', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    
    const result = await pool.query(
      'SELECT * FROM tournaments WHERE tournament_id = $1',
      [tournamentId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Tournament not found' });
    }
    
    res.json({ tournament: result.rows[0] });
  } catch (error) {
    console.error('Get tournament error:', error);
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

app.get('/api/tournaments/:tournamentId/teams', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    
    const result = await pool.query(
      'SELECT team_name, team_code, region FROM teams WHERE tournament_id = $1 ORDER BY team_name',
      [tournamentId]
    );
    
    res.json({ teams: result.rows });
  } catch (error) {
    console.error('Get teams error:', error);
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

app.get('/api/roster/all/:tournamentId', authenticateToken, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const userId = req.user.userId;

    const result = await pool.query(
      'SELECT match_day, roster FROM rosters WHERE user_id = $1 AND tournament_id = $2 ORDER BY match_day',
      [userId, tournamentId]
    );

    const rosters = {};
    result.rows.forEach(row => {
      rosters[row.match_day] = row.roster;
    });

    res.json({ rosters });

  } catch (error) {
    console.error('Get all rosters error:', error);
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

    await updatePickStats(tournamentId, matchDay);

    res.json({ message: 'Roster saved successfully' });

  } catch (error) {
    console.error('Save roster error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

async function updatePickStats(tournamentId, matchDay) {
  try {
    const totalRosters = await pool.query(
      'SELECT COUNT(*) as total FROM rosters WHERE tournament_id = $1 AND match_day = $2',
      [tournamentId, matchDay]
    );
    
    const total = parseInt(totalRosters.rows[0].total) || 1;
    
    const players = await pool.query(
      'SELECT player_name FROM players WHERE tournament_id = $1',
      [tournamentId]
    );
    
    for (const player of players.rows) {
      const pickCount = await pool.query(`
        SELECT COUNT(*) as picks 
        FROM rosters 
        WHERE tournament_id = $1 AND match_day = $2
        AND roster ? $3
      `, [tournamentId, matchDay, player.player_name]);
      
      const picks = parseInt(pickCount.rows[0].picks) || 0;
      const percentage = ((picks / total) * 100);
      
      await pool.query(`
        INSERT INTO player_pick_stats (tournament_id, match_day, player_name, times_picked, total_rosters, pick_percentage)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (tournament_id, match_day, player_name)
        DO UPDATE SET 
          times_picked = EXCLUDED.times_picked,
          total_rosters = EXCLUDED.total_rosters,
          pick_percentage = EXCLUDED.pick_percentage,
          updated_at = CURRENT_TIMESTAMP
      `, [tournamentId, matchDay, player.player_name, picks, total, percentage]);
    }
    
  } catch (error) {
    console.error('Error updating pick stats:', error);
  }
}

app.get('/api/leaderboard/:tournamentId', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { matchDay, minRosterSize = 10 } = req.query;

    if (!tournamentId) {
      return res.status(400).json({ error: 'Tournament ID is required' });
    }

    let query, params;

    if (matchDay) {
      query = `
        WITH roster_stats AS (
          SELECT 
            r.user_id,
            r.match_day,
            r.roster,
            jsonb_array_length(r.roster) as roster_size,
            u.username
          FROM rosters r
          JOIN users u ON r.user_id = u.id
          WHERE r.tournament_id = $1 AND r.match_day = $2
        ),
        player_points AS (
          SELECT 
            rs.user_id,
            rs.username,
            rs.match_day,
            rs.roster,
            rs.roster_size,
            COALESCE(SUM(ps.points), 0) as total_points,
            COALESCE(AVG(ps.points), 0) as avg_points
          FROM roster_stats rs
          LEFT JOIN player_scores ps ON ps.tournament_id = $1
            AND ps.match_day = $2
            AND ps.player_name = ANY(SELECT jsonb_array_elements_text(rs.roster))
          WHERE rs.roster_size >= $3
          GROUP BY rs.user_id, rs.username, rs.match_day, rs.roster, rs.roster_size
        )
        SELECT 
          username,
          match_day,
          total_points,
          avg_points,
          roster,
          roster_size,
          1 as match_days_played
        FROM player_points
        ORDER BY total_points DESC, username ASC
      `;
      params = [tournamentId, matchDay, minRosterSize];
    } else {
      query = `
        WITH roster_stats AS (
          SELECT 
            r.user_id,
            r.match_day,
            r.roster,
            jsonb_array_length(r.roster) as roster_size,
            u.username
          FROM rosters r
          JOIN users u ON r.user_id = u.id
          WHERE r.tournament_id = $1
        ),
        valid_rosters AS (
          SELECT *
          FROM roster_stats
          WHERE roster_size >= $2
        ),
        user_points AS (
          SELECT 
            vr.user_id,
            vr.username,
            vr.match_day,
            vr.roster,
            COALESCE(SUM(ps.points), 0) as match_day_points
          FROM valid_rosters vr
          LEFT JOIN player_scores ps ON ps.tournament_id = $1 
            AND ps.match_day = vr.match_day
            AND ps.player_name = ANY(SELECT jsonb_array_elements_text(vr.roster))
          GROUP BY vr.user_id, vr.username, vr.match_day, vr.roster
        ),
        user_totals AS (
          SELECT 
            user_id,
            username,
            SUM(match_day_points) as total_points,
            AVG(match_day_points) as avg_points,
            COUNT(DISTINCT match_day) as match_days_played,
            ARRAY_AGG(DISTINCT match_day ORDER BY match_day) as participated_days
          FROM user_points
          GROUP BY user_id, username
          HAVING COUNT(DISTINCT match_day) > 0
        )
        SELECT 
          username,
          total_points,
          avg_points,
          match_days_played,
          participated_days
        FROM user_totals
        ORDER BY total_points DESC, avg_points DESC, username ASC
      `;
      params = [tournamentId, minRosterSize];
    }

    const result = await pool.query(query, params);
    
    const totalRosters = await pool.query(
      'SELECT COUNT(DISTINCT user_id) as total FROM rosters WHERE tournament_id = $1',
      [tournamentId]
    );

    const completeRosters = await pool.query(`
      SELECT COUNT(DISTINCT user_id) as complete 
      FROM rosters 
      WHERE tournament_id = $1 AND jsonb_array_length(roster) >= $2
    `, [tournamentId, minRosterSize]);

    res.json({ 
      leaderboard: result.rows,
      metadata: {
        total_participants: parseInt(totalRosters.rows[0]?.total || 0),
        complete_rosters: parseInt(completeRosters.rows[0]?.complete || 0),
        match_day_filter: matchDay || null,
        min_roster_size: minRosterSize,
        generated_at: new Date().toISOString()
      }
    });

  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    const result = await pool.query(
      'SELECT id, username, email FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    
    if (user.id !== 1 && user.username !== 'admin') {
      return res.status(403).json({ error: 'Admin access required' });
    }

    req.user = user;
    next();
  } catch (error) {
    console.error('Admin authentication error:', error);
    return res.status(403).json({ error: 'Invalid token' });
  }
};

app.get('/admin', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

app.post('/api/admin/scores', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId, matchDay, playerScores, playerData } = req.body;

    if (!tournamentId || !matchDay) {
      return res.status(400).json({ error: 'Tournament ID and match day are required' });
    }

    if (playerData) {
      for (const [playerName, data] of Object.entries(playerData)) {
        await pool.query(`
          INSERT INTO player_scores (player_name, tournament_id, match_day, points)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (player_name, tournament_id, match_day)
          DO UPDATE SET points = EXCLUDED.points
        `, [playerName, tournamentId, matchDay, data.points]);

        if (data.battlesPlayed !== undefined && data.totalBattles !== undefined) {
          const battlePercentage = `${Math.round((data.battlesPlayed / data.totalBattles) * 100)}%`;
          await pool.query(`
            UPDATE players 
            SET battles_played = $1 
            WHERE player_name = $2 AND tournament_id = $3
          `, [battlePercentage, playerName, tournamentId]);
        }
      }
    } else if (playerScores) {
      for (const [playerName, points] of Object.entries(playerScores)) {
        await pool.query(`
          INSERT INTO player_scores (player_name, tournament_id, match_day, points)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (player_name, tournament_id, match_day)
          DO UPDATE SET points = EXCLUDED.points
        `, [playerName, tournamentId, matchDay, points]);
      }
    } else {
      return res.status(400).json({ error: 'Either playerScores or playerData is required' });
    }

    res.json({ message: 'Scores updated successfully' });

  } catch (error) {
    console.error('Update scores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.get('/api/admin/scores/:tournamentId/:matchDay', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId, matchDay } = req.params;
    
    const result = await pool.query(`
      SELECT 
        ps.player_name,
        ps.points,
        p.team_code,
        p.battles_played,
        p.picked_percentage
      FROM player_scores ps
      LEFT JOIN players p ON ps.player_name = p.player_name AND ps.tournament_id = p.tournament_id
      WHERE ps.tournament_id = $1 AND ps.match_day = $2
      ORDER BY ps.points DESC
    `, [tournamentId, matchDay]);
    
    res.json({ players: result.rows });
  } catch (error) {
    console.error('Get admin scores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/calculate-picks', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.body;
    
    const totalRosters = await pool.query(
      'SELECT COUNT(DISTINCT user_id) as total FROM rosters WHERE tournament_id = $1',
      [tournamentId]
    );
    
    const total = totalRosters.rows[0].total || 1;
    
    const players = await pool.query(
      'SELECT player_name FROM players WHERE tournament_id = $1',
      [tournamentId]
    );
    
    for (const player of players.rows) {
      const pickCount = await pool.query(`
        SELECT COUNT(*) as picks 
        FROM rosters 
        WHERE tournament_id = $1 
        AND roster ? $2
      `, [tournamentId, player.player_name]);
      
      const picks = pickCount.rows[0].picks || 0;
      const percentage = ((picks / total) * 100).toFixed(2) + '%';
      
      await pool.query(`
        UPDATE players 
        SET picked_percentage = $1 
        WHERE player_name = $2 AND tournament_id = $3
      `, [percentage, player.player_name, tournamentId]);
    }
    
    res.json({ message: 'Pick percentages calculated successfully' });
    
  } catch (error) {
    console.error('Calculate picks error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.post('/api/admin/reset', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.body;
    
    await pool.query('DELETE FROM player_scores WHERE tournament_id = $1', [tournamentId]);
    
    await pool.query(`
      UPDATE players 
      SET total_points = 0, average_points = 0, battles_played = '0%'
      WHERE tournament_id = $1
    `, [tournamentId]);
    
    res.json({ message: 'Tournament reset successfully' });
    
  } catch (error) {
    console.error('Reset tournament error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

app.listen(port, async () => {
  console.log(`Server running on port ${port}`);
  await initializeTables();
}); === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
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
        email: user.email
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
      'SELECT id, username, email FROM users WHERE email = $1',
      [email]
    );

    if (result.rows.length === 0) {
      return res.json({ message: 'If an account with that email exists, a password reset link has been sent.' });
    }

    const user = result.rows[0];

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

app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const userId = req.user.userId;

    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'Current password and new password are required' });
    }

    if (newPassword.length < 6) {
      return res.status(400).json({ error: 'New password must be at least 6 characters' });
    }

    const result = await pool.query(
      'SELECT password_hash FROM users WHERE id = $1',
      [userId]
    );

    if (result.rows.length