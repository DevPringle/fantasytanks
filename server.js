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

  if (!emailConfig.auth.user || !emailConfig.auth.pass) {
    console.warn('SMTP_USER or SMTP_PASSWORD not set. Email features will be disabled.');
    return null;
  }
  return nodemailer.createTransport(emailConfig);
};

// Middleware to authenticate JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token expired', expired: true });
      }
      return res.status(403).json({ error: 'Invalid token' });
    }
    req.user = user;
    next();
  });
};

// --- AUTHENTICATION ROUTES ---

// User registration
app.post('/api/auth/register', async (req, res) => {
  const { username, email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const verificationToken = crypto.randomBytes(32).toString('hex'); // Generate verification token

    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash, email_verified, verification_token) VALUES ($1, $2, $3, FALSE, $4) RETURNING id, username, email, email_verified',
      [username, email, hashedPassword, verificationToken]
    );
    const user = result.rows[0];

    const transporter = createEmailTransporter();
    if (transporter) {
      const verificationLink = `${process.env.FRONTEND_URL || req.protocol + '://' + req.get('host')}/verify-email.html?token=${verificationToken}`;
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: 'Verify Your Email for WoT Fantasy Account',
        html: `<p>Please verify your email by clicking <a href="${verificationLink}">this link</a>.</p>`
      });
      res.status(201).json({ message: 'User registered. Please verify your email.', requiresVerification: true, email: user.email });
    } else {
      // If no transporter, user is registered but email verification is skipped/not possible
      const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
      res.status(201).json({ message: 'User registered successfully (email verification skipped).', token, user: { id: user.id, username: user.username, email: user.email, email_verified: user.email_verified } });
    }

  } catch (error) {
    console.error('Registration error:', error);
    if (error.code === '23505') { // Duplicate username/email
      return res.status(400).json({ error: 'Username or email already exists' });
    }
    res.status(500).json({ error: 'Internal server error during registration' });
  }
});

// User login
app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    if (!user.email_verified) {
      // Re-send verification email if not verified and transporter is available
      const transporter = createEmailTransporter();
      if (transporter) {
        const verificationLink = `${process.env.FRONTEND_URL || req.protocol + '://' + req.get('host')}/verify-email.html?token=${user.verification_token}`;
        await transporter.sendMail({
          from: process.env.SMTP_USER,
          to: user.email,
          subject: 'Verify Your Email for WoT Fantasy Account',
          html: `<p>Please verify your email by clicking <a href="${verificationLink}">this link</a>.</p>`
        });
        return res.status(403).json({ error: 'Email not verified. A new verification email has been sent.', requiresVerification: true, email: user.email });
      } else {
        return res.status(403).json({ error: 'Email not verified. Please contact support.', requiresVerification: true, email: user.email });
      }
    }

    const token = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Login successful', token, user: { id: user.id, username: user.username, email: user.email, email_verified: user.email_verified } });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Internal server error during login' });
  }
});

// Verify email token
app.get('/api/auth/verify-email/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query('UPDATE users SET email_verified = TRUE, verification_token = NULL WHERE verification_token = $1 RETURNING id, username, email, email_verified', [token]);
    const user = result.rows[0];

    if (!user) {
      return res.status(400).json({ error: 'Invalid or expired verification token' });
    }

    const authToken = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Email verified successfully', token: authToken, user: { id: user.id, username: user.username, email: user.email, email_verified: user.email_verified } });

  } catch (error) {
    console.error('Email verification error:', error);
    res.status(500).json({ error: 'Internal server error during email verification' });
  }
});

// Resend verification email
app.post('/api/auth/resend-verification', async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT id, username, email, email_verified, verification_token FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }
    if (user.email_verified) {
      return res.status(400).json({ error: 'Email is already verified' });
    }

    const transporter = createEmailTransporter();
    if (transporter) {
      const verificationLink = `${process.env.FRONTEND_URL || req.protocol + '://' + req.get('host')}/verify-email.html?token=${user.verification_token}`;
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: 'Verify Your Email for WoT Fantasy Account',
        html: `<p>Please verify your email by clicking <a href="${verificationLink}">this link</a>.</p>`
      });
      res.json({ message: 'Verification email re-sent successfully.' });
    } else {
      res.status(500).json({ error: 'Email sending service not configured.' });
    }
  } catch (error) {
    console.error('Resend verification error:', error);
    res.status(500).json({ error: 'Internal server error during resending verification email' });
  }
});

// Forgot password
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;
  try {
    const result = await pool.query('SELECT id, username, email FROM users WHERE email = $1', [email]);
    const user = result.rows[0];

    if (!user) {
      return res.status(404).json({ error: 'User with this email not found' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now

    await pool.query('UPDATE users SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3', [resetToken, new Date(resetTokenExpiry), user.id]);

    const transporter = createEmailTransporter();
    if (transporter) {
      const resetLink = `${process.env.FRONTEND_URL || req.protocol + '://' + req.get('host')}/reset-password.html?token=${resetToken}`;
      await transporter.sendMail({
        from: process.env.SMTP_USER,
        to: email,
        subject: 'Password Reset for WoT Fantasy Account',
        html: `<p>You requested a password reset. Click <a href="${resetLink}">this link</a> to reset your password. This link is valid for 1 hour.</p>`
      });
      res.json({ message: 'Password reset link sent to your email.' });
    } else {
      res.status(500).json({ error: 'Email sending service not configured.' });
    }
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Internal server error during forgot password' });
  }
});

// Verify reset token
app.get('/api/auth/verify-reset-token/:token', async (req, res) => {
  const { token } = req.params;
  try {
    const result = await pool.query('SELECT id, username, reset_token_expiry FROM users WHERE reset_token = $1', [token]);
    const user = result.rows[0];

    if (!user || user.reset_token_expiry < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }
    res.json({ message: 'Reset token is valid', username: user.username });
  } catch (error) {
    console.error('Verify reset token error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset password
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, password } = req.body;
  try {
    const result = await pool.query('SELECT id, username, email, reset_token_expiry FROM users WHERE reset_token = $1', [token]);
    const user = result.rows[0];

    if (!user || user.reset_token_expiry < new Date()) {
      return res.status(400).json({ error: 'Invalid or expired reset token' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    await pool.query('UPDATE users SET password_hash = $1, reset_token = NULL, reset_token_expiry = NULL WHERE id = $2', [hashedPassword, user.id]);

    const authToken = jwt.sign({ userId: user.id, username: user.username, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ message: 'Password reset successful', token: authToken, user: { id: user.id, username: user.username, email: user.email, email_verified: true } });

  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Change password (requires authentication)
app.post('/api/auth/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  try {
    const result = await pool.query('SELECT id, password_hash FROM users WHERE id = $1', [req.user.userId]);
    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(currentPassword, user.password_hash))) {
      return res.status(401).json({ error: 'Invalid current password' });
    }

    const hashedNewPassword = await bcrypt.hash(newPassword, 10);
    await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hashedNewPassword, req.user.userId]);

    res.json({ message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ROSTER ROUTES ---

// Get user's roster for a specific tournament and match day
app.get('/api/roster', authenticateToken, async (req, res) => {
  const { tournamentId, matchDay } = req.query;
  try {
    const result = await pool.query(
      'SELECT roster FROM rosters WHERE user_id = $1 AND tournament_id = $2 AND match_day = $3',
      [req.user.userId, tournamentId, parseInt(matchDay)]
    );
    res.json(result.rows[0] || { roster: [] });
  } catch (error) {
    console.error('Get roster error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get all of user's rosters for a tournament (by match day)
app.get('/api/roster/all/:tournamentId', authenticateToken, async (req, res) => {
  const { tournamentId } = req.params;
  try {
    const result = await pool.query(
      'SELECT match_day, roster FROM rosters WHERE user_id = $1 AND tournament_id = $2 ORDER BY match_day',
      [req.user.userId, tournamentId]
    );
    const rostersByDay = result.rows.reduce((acc, curr) => {
      acc[curr.match_day] = curr.roster;
      return acc;
    }, {});
    res.json({ rosters: rostersByDay });
  } catch (error) {
    console.error('Get all rosters error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Save user's roster for a specific tournament and match day
app.post('/api/roster', authenticateToken, async (req, res) => {
  const { tournamentId, roster, matchDay } = req.body;
  if (!roster || !Array.isArray(roster) || roster.length === 0) {
    return res.status(400).json({ error: 'Roster cannot be empty' });
  }
  if (roster.length > 10) { // Assuming max 10 players per roster
    return res.status(400).json({ error: 'Roster cannot exceed 10 players' });
  }

  try {
    await pool.query(
      `INSERT INTO rosters (user_id, tournament_id, match_day, roster)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (user_id, tournament_id, match_day)
       DO UPDATE SET roster = $4, updated_at = CURRENT_TIMESTAMP`,
      [req.user.userId, tournamentId, parseInt(matchDay), JSON.stringify(roster)]
    );
    res.status(201).json({ message: 'Roster saved successfully' });
  } catch (error) {
    console.error('Save roster error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- LEADERBOARD ROUTES ---

// Get leaderboard for a tournament
app.get('/api/leaderboard/:tournamentId', authenticateToken, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { matchDay, minRosterSize = 10, limit, offset = 0 } = req.query;

    let query;
    let queryParams = [tournamentId, parseInt(minRosterSize)];
    let selectColumns;
    let groupBy = `u.username, u.id`; // Group by user ID for uniqueness
    let joinConditions = `
        JOIN users u ON r.user_id = u.id
        JOIN roster_players rp ON r.id = rp.roster_id
        JOIN player_match_performance pmp ON rp.player_name = pmp.player_name AND pmp.tournament_id = r.tournament_id
    `;
    let orderBy = `total_fantasy_points DESC`; // Default for total

    if (matchDay && matchDay !== 'total') {
        // Logic for a specific match day
        const selectedMatchDayNum = parseInt(matchDay);
        if (isNaN(selectedMatchDayNum)) {
            return res.status(400).json({ error: 'Invalid matchDay parameter.' });
        }

        selectColumns = `
            u.id AS user_id,
            u.username,
            SUM(pmp.match_points) AS match_day_fantasy_points,
            CAST(COUNT(DISTINCT rp.player_name) AS INTEGER) AS roster_size_for_day
        `;
        // Filter `rosters` and `player_match_performance` by the specific matchDay
        joinConditions = `
            JOIN users u ON r.user_id = u.id
            JOIN roster_players rp ON r.id = rp.roster_id
            JOIN player_match_performance pmp ON rp.player_name = pmp.player_name
                                                AND pmp.tournament_id = r.tournament_id
                                                AND pmp.match_day = r.match_day -- Ensure performance is for the same match_day as roster
            WHERE r.tournament_id = $1 AND r.match_day = $3
        `;
        queryParams.push(selectedMatchDayNum); // Add matchDay to params

        orderBy = `match_day_fantasy_points DESC`;

        query = `
            SELECT
                ${selectColumns}
            FROM
                rosters r
            ${joinConditions}
            GROUP BY ${groupBy}
            HAVING COUNT(DISTINCT rp.player_name) >= $2
            ORDER BY ${orderBy}
            ${limit ? `LIMIT ${parseInt(limit)}` : ''} OFFSET ${parseInt(offset)};
        `;
    } else {
        // Original logic for total standings
        selectColumns = `
            u.id AS user_id,
            u.username,
            SUM(pmp.match_points) AS total_fantasy_points,
            CAST(COUNT(DISTINCT r.match_day) AS INTEGER) AS roster_days_submitted,
            (SUM(pmp.match_points) / NULLIF(COUNT(DISTINCT r.match_day), 0)) AS average_fantasy_points
        `;
        joinConditions = `
            JOIN users u ON r.user_id = u.id
            JOIN roster_players rp ON r.id = rp.roster_id
            JOIN player_match_performance pmp ON rp.player_name = pmp.player_name AND pmp.tournament_id = r.tournament_id AND pmp.match_day = r.match_day
            WHERE r.tournament_id = $1
        `;

        query = `
            SELECT
                ${selectColumns}
            FROM
                rosters r
            ${joinConditions}
            GROUP BY ${groupBy}
            HAVING COUNT(DISTINCT rp.player_name) >= $2
            ORDER BY ${orderBy}
            ${limit ? `LIMIT ${parseInt(limit)}` : ''} OFFSET ${parseInt(offset)};
        `;
    }

    const result = await pool.query(query, queryParams);

    res.json({ leaderboard: result.rows });

  } catch (error) {
    console.error('Error fetching leaderboard:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Get leaderboard stats (total users, average score, etc.)
app.get('/api/leaderboard/:tournamentId/stats', authenticateToken, async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const statsResult = await pool.query(
      `SELECT
        COUNT(DISTINCT r.user_id) AS total_users,
        AVG(total_points.sum_points) AS average_user_score
      FROM rosters r
      JOIN (
        SELECT user_id, SUM(pmp.match_points) AS sum_points
        FROM rosters r_sub
        JOIN roster_players rp ON r_sub.id = rp.roster_id
        JOIN player_match_performance pmp ON rp.player_name = pmp.player_name AND pmp.tournament_id = r_sub.tournament_id AND pmp.match_day = r_sub.match_day
        WHERE r_sub.tournament_id = $1
        GROUP BY user_id
      ) AS total_points ON r.user_id = total_points.user_id
      WHERE r.tournament_id = $1;
      `, [tournamentId]);

    const stats = statsResult.rows[0] || {};
    res.json({
      totalUsers: parseInt(stats.total_users || 0),
      averageUserScore: parseFloat(stats.average_user_score || 0).toFixed(2)
    });
  } catch (error) {
    console.error('Error fetching leaderboard stats:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Get specific user's ranking
app.get('/api/leaderboard/:tournamentId/user/:userId', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, userId } = req.params;
    const { matchDay } = req.query; // Allow filtering by matchDay for user ranking

    let userRankingQuery;
    let queryParams = [tournamentId, userId];

    if (matchDay && matchDay !== 'total') {
        // Ranking for a specific match day
        const selectedMatchDayNum = parseInt(matchDay);
        if (isNaN(selectedMatchDayNum)) {
            return res.status(400).json({ error: 'Invalid matchDay parameter.' });
        }
        queryParams.push(selectedMatchDayNum);

        userRankingQuery = `
            WITH MatchDayLeaderboard AS (
                SELECT
                    u.id AS user_id,
                    u.username,
                    SUM(pmp.match_points) AS match_day_fantasy_points,
                    RANK() OVER (ORDER BY SUM(pmp.match_points) DESC) AS rank
                FROM
                    rosters r
                JOIN users u ON r.user_id = u.id
                JOIN roster_players rp ON r.id = rp.roster_id
                JOIN player_match_performance pmp ON rp.player_name = pmp.player_name
                                                    AND pmp.tournament_id = r.tournament_id
                                                    AND pmp.match_day = r.match_day
                WHERE r.tournament_id = $1 AND r.match_day = $3
                GROUP BY u.id, u.username
                HAVING COUNT(DISTINCT rp.player_name) >= 10 -- Assuming min 10 players for ranking
            )
            SELECT
                user_id,
                username,
                match_day_fantasy_points AS total_fantasy_points, -- Use same column name for client consistency
                rank
            FROM MatchDayLeaderboard
            WHERE user_id = $2;
        `;
    } else {
        // Ranking for total fantasy points (original logic)
        userRankingQuery = `
            WITH OverallLeaderboard AS (
                SELECT
                    u.id AS user_id,
                    u.username,
                    SUM(pmp.match_points) AS total_fantasy_points,
                    RANK() OVER (ORDER BY SUM(pmp.match_points) DESC) AS rank
                FROM
                    rosters r
                JOIN users u ON r.user_id = u.id
                JOIN roster_players rp ON r.id = rp.roster_id
                JOIN player_match_performance pmp ON rp.player_name = pmp.player_name AND pmp.tournament_id = r.tournament_id AND pmp.match_day = r.match_day
                WHERE r.tournament_id = $1
                GROUP BY u.id, u.username
                HAVING COUNT(DISTINCT rp.player_name) >= 10 -- Assuming min 10 players for ranking
            )
            SELECT
                user_id,
                username,
                total_fantasy_points,
                rank
            FROM OverallLeaderboard
            WHERE user_id = $2;
        `;
    }

    const result = await pool.query(userRankingQuery, queryParams);
    res.json(result.rows[0] || { rank: null, total_fantasy_points: 0 });

  } catch (error) {
    console.error('Error fetching user ranking:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// --- PLAYER ROUTES ---

// Get players for a specific tournament
app.get('/api/tournaments/:tournamentId/players', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const result = await pool.query('SELECT * FROM players WHERE tournament_id = $1 ORDER BY player_name', [tournamentId]);
    res.json({ players: result.rows });
  } catch (error) {
    console.error('Get players error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get teams for a specific tournament
app.get('/api/tournaments/:tournamentId/teams', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const result = await pool.query('SELECT DISTINCT team_code FROM players WHERE tournament_id = $1 ORDER BY team_code', [tournamentId]);
    res.json({ teams: result.rows.map(row => row.team_code) });
  } catch (error) {
    console.error('Get teams error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// --- TOURNAMENT ROUTES ---

// Get all tournaments
app.get('/api/tournaments', async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM tournaments ORDER BY start_date DESC');
    res.json({ tournaments: result.rows });
  } catch (error) {
    console.error('Get tournaments error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get a single tournament by ID
app.get('/api/tournaments/:tournamentId', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const result = await pool.query('SELECT * FROM tournaments WHERE id = $1', [tournamentId]);
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Tournament not found' });
    }
    res.json({ tournament: result.rows[0] });
  } catch (error) {
    console.error('Get tournament by ID error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// --- ADMIN ROUTES (Requires authentication and possibly admin role check) ---

// Update player scores and battles for a specific match day
app.post('/api/admin/scores', authenticateToken, async (req, res) => {
  // IMPORTANT: Implement isAdmin middleware here for production
  try {
    const { tournamentId, matchDay, playerScores, playerData } = req.body; // playerScores is old format, playerData is new
    if (!tournamentId || !matchDay || (!playerScores && !playerData)) {
      return res.status(400).json({ error: 'Tournament ID, Match Day, and player data are required.' });
    }

    await pool.query('BEGIN');

    if (playerData) { // New format: { playerName: { points, battlesPlayed, totalBattles } }
      for (const playerName in playerData) {
        const data = playerData[playerName];
        await pool.query(`
          INSERT INTO player_match_performance (player_name, tournament_id, match_day, match_points, battles_played, total_battles)
          VALUES ($1, $2, $3, $4, $5, $6)
          ON CONFLICT (player_name, tournament_id, match_day) DO UPDATE SET
            match_points = EXCLUDED.match_points,
            battles_played = EXCLUDED.battles_played,
            total_battles = EXCLUDED.total_battles,
            updated_at = CURRENT_TIMESTAMP
        `, [playerName, tournamentId, matchDay, data.points || 0, data.battlesPlayed || 0, data.totalBattles || 0]);
      }
    } else if (playerScores) { // Old format: [{ player_name, points }]
      for (const score of playerScores) {
        await pool.query(`
          INSERT INTO player_match_performance (player_name, tournament_id, match_day, match_points)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (player_name, tournament_id, match_day) DO UPDATE SET
            match_points = EXCLUDED.match_points,
            updated_at = CURRENT_TIMESTAMP
        `, [score.player_name, tournamentId, matchDay, score.points]);
      }
    }

    await pool.query('COMMIT');
    res.json({ message: 'Player match performance updated successfully' });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Update scores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Get player scores for a specific match day (for admin)
app.get('/api/admin/scores/:tournamentId/:matchDay', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, matchDay } = req.params;

    const result = await pool.query(`
      SELECT
        player_name,
        match_points,
        battles_played,
        total_battles,
        updated_at
      FROM player_match_performance
      WHERE tournament_id = $1 AND match_day = $2
      ORDER BY match_points DESC
    `, [tournamentId, matchDay]);

    res.json({
      tournament_id: tournamentId,
      match_day: parseInt(matchDay),
      player_scores: result.rows
    });

  } catch (error) {
    console.error('Get admin scores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Calculate pick percentages (might be an expensive operation)
app.post('/api/admin/calculate-picks', authenticateToken, async (req, res) => {
  // IMPORTANT: Implement isAdmin middleware here for production
  try {
    const { tournamentId } = req.body;
    if (!tournamentId) {
      return res.status(400).json({ error: 'Tournament ID is required.' });
    }

    await pool.query('BEGIN');

    // Step 1: Get total number of rosters submitted for the tournament
    const totalRostersResult = await pool.query(
      'SELECT COUNT(DISTINCT id) AS total_rosters FROM rosters WHERE tournament_id = $1',
      [tournamentId]
    );
    const totalRosters = parseInt(totalRostersResult.rows[0].total_rosters);

    if (totalRosters === 0) {
      await pool.query('COMMIT');
      return res.json({ message: 'No rosters submitted yet. Pick percentages not calculated.' });
    }

    // Step 2: Calculate how many times each player was picked across all rosters for this tournament
    const playerPickCountsResult = await pool.query(
      `SELECT
          rp.player_name,
          COUNT(rp.player_name) AS pick_count
      FROM roster_players rp
      JOIN rosters r ON rp.roster_id = r.id
      WHERE r.tournament_id = $1
      GROUP BY rp.player_name`,
      [tournamentId]
    );

    // Step 3: Update pick_percentage in the players table
    for (const row of playerPickCountsResult.rows) {
      const pickPercentage = (row.pick_count / totalRosters) * 100;
      await pool.query(
        `UPDATE players SET pick_percentage = $1 WHERE player_name = $2 AND tournament_id = $3`,
        [pickPercentage.toFixed(2), row.player_name, tournamentId]
      );
    }

    await pool.query('COMMIT');
    res.json({ message: 'Pick percentages calculated and updated successfully' });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Calculate pick percentages error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Reset tournament data (for admin)
app.post('/api/admin/reset', authenticateToken, async (req, res) => {
  // IMPORTANT: Implement isAdmin middleware here for production
  try {
    const { tournamentId } = req.body;
    if (!tournamentId) {
      return res.status(400).json({ error: 'Tournament ID is required.' });
    }

    await pool.query('BEGIN');

    // Delete related roster players first
    await pool.query(`
      DELETE FROM roster_players
      WHERE roster_id IN (SELECT id FROM rosters WHERE tournament_id = $1);
    `, [tournamentId]);

    // Then delete rosters
    await pool.query(`
      DELETE FROM rosters WHERE tournament_id = $1;
    `, [tournamentId]);

    // Delete player match performance data
    await pool.query(`
      DELETE FROM player_match_performance WHERE tournament_id = $1;
    `, [tournamentId]);

    // Reset pick percentages for players in this tournament
    await pool.query(`
      UPDATE players SET pick_percentage = 0 WHERE tournament_id = $1;
    `, [tournamentId]);

    await pool.query('COMMIT');
    res.json({ message: `Tournament ${tournamentId} data reset successfully.` });

  } catch (error) {
    await pool.query('ROLLBACK');
    console.error('Reset tournament error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});


// Health check endpoint
app.get('/api/health', (req, res) => {
  res.status(200).json({ status: 'OK', message: 'Fantasy Tanks API is running.' });
});

// Start the server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
