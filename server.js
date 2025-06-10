const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('.')); // Serve static files from root directory

// Database connection
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

// Middleware to verify JWT token
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

// Initialize database tables
async function initializeTables() {
  try {
    // Users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Rosters table
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

    // Player scores table (for tracking individual player performance)
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

    // Tournaments table
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

    // Teams table
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

    // Players table
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

    console.log('Database tables initialized successfully');
  } catch (error) {
    console.error('Error initializing database tables:', error);
  }
}

// Routes

// Serve main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'OK', message: 'Fantasy Tanks API is running' });
});

// Registration endpoint
app.post('/api/auth/register', async (req, res) => {
  try {
    const { username, email, password } = req.body;

    // Validate input
    if (!username || !email || !password) {
      return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    if (password.length < 6) {
      return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: 'Username or email already exists' });
    }

    // Hash password
    const saltRounds = 10;
    const passwordHash = await bcrypt.hash(password, saltRounds);

    // Create user
    const result = await pool.query(
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );

    const user = result.rows[0];

    // Generate JWT token
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

// Login endpoint
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!username || !password) {
      return res.status(400).json({ error: 'Username and password are required' });
    }

    // Find user by username or email
    const result = await pool.query(
      'SELECT id, username, email, password_hash FROM users WHERE username = $1 OR email = $1',
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = result.rows[0];

    // Verify password
    const isValidPassword = await bcrypt.compare(password, user.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
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

// Get all tournaments
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

// Get tournament details
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

// Get players for a tournament
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

// Get teams for a tournament
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

// Get user's roster for a tournament
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

// Save user's roster for a tournament
app.post('/api/roster', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, roster, matchDay = 1 } = req.body;
    const userId = req.user.userId;

    if (!tournamentId || !roster) {
      return res.status(400).json({ error: 'Tournament ID and roster are required' });
    }

    // Upsert roster (update if exists, insert if not)
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

// Get leaderboard for a tournament
app.get('/api/leaderboard/:tournamentId', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { matchDay } = req.query;

    if (!tournamentId) {
      return res.status(400).json({ error: 'Tournament ID is required' });
    }

    let query, params;

    if (matchDay) {
      // Get leaderboard for specific match day
      query = `
        SELECT 
          u.username,
          r.match_day,
          COALESCE(SUM(ps.points), 0) as total_points,
          COALESCE(AVG(ps.points), 0) as avg_points,
          r.roster
        FROM rosters r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN player_scores ps ON ps.tournament_id = r.tournament_id 
          AND ps.match_day = r.match_day
          AND ps.player_name = ANY(SELECT jsonb_array_elements_text(r.roster))
        WHERE r.tournament_id = $1 AND r.match_day = $2
        GROUP BY u.username, r.match_day, r.roster
        ORDER BY total_points DESC
      `;
      params = [tournamentId, matchDay];
    } else {
      // Get overall leaderboard (all match days combined)
      query = `
        SELECT 
          u.username,
          COALESCE(SUM(ps.points), 0) as total_points,
          COALESCE(AVG(ps.points), 0) as avg_points,
          COUNT(DISTINCT r.match_day) as match_days_played
        FROM rosters r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN player_scores ps ON ps.tournament_id = r.tournament_id 
          AND ps.player_name = ANY(SELECT jsonb_array_elements_text(r.roster))
        WHERE r.tournament_id = $1
        GROUP BY u.username
        ORDER BY total_points DESC
      `;
      params = [tournamentId];
    }

    const result = await pool.query(query, params);
    res.json({ leaderboard: result.rows });

  } catch (error) {
    console.error('Get leaderboard error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Admin endpoint to update player scores
app.post('/api/admin/scores', async (req, res) => {
  try {
    const { tournamentId, matchDay, playerScores } = req.body;

    if (!tournamentId || !matchDay || !playerScores) {
      return res.status(400).json({ error: 'Tournament ID, match day, and player scores are required' });
    }

    // Update player scores
    for (const [playerName, points] of Object.entries(playerScores)) {
      await pool.query(`
        INSERT INTO player_scores (player_name, tournament_id, match_day, points)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (player_name, tournament_id, match_day)
        DO UPDATE SET points = EXCLUDED.points
      `, [playerName, tournamentId, matchDay, points]);
    }

    res.json({ message: 'Player scores updated successfully' });

  } catch (error) {
    console.error('Update scores error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Serve login page
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'login.html'));
});

// Serve main pages
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Admin middleware - check if user is admin
const authenticateAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({ error: 'Access token required' });
    }

    const decoded = jwt.verify(token, JWT_SECRET);
    
    // Check if user exists and is admin
    const result = await pool.query(
      'SELECT id, username, email FROM users WHERE id = $1',
      [decoded.userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ error: 'User not found' });
    }

    const user = result.rows[0];
    
    // For now, make the first user admin, or you can add an is_admin column
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

// Serve admin page (protected)
app.get('/admin', authenticateAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

// Admin API endpoints
app.post('/api/admin/scores', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId, matchDay, playerScores, playerData } = req.body;

    if (!tournamentId || !matchDay) {
      return res.status(400).json({ error: 'Tournament ID and match day are required' });
    }

    if (playerData) {
      // Full data mode: update both scores and battle info
      for (const [playerName, data] of Object.entries(playerData)) {
        // Update player_scores table
        await pool.query(`
          INSERT INTO player_scores (player_name, tournament_id, match_day, points)
          VALUES ($1, $2, $3, $4)
          ON CONFLICT (player_name, tournament_id, match_day)
          DO UPDATE SET points = EXCLUDED.points
        `, [playerName, tournamentId, matchDay, data.points]);

        // Update players table with battle info
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
      // Scores only mode
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

// Get current scores for admin view
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

// Calculate pick percentages
app.post('/api/admin/calculate-picks', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.body;
    
    // Get total number of rosters
    const totalRosters = await pool.query(
      'SELECT COUNT(DISTINCT user_id) as total FROM rosters WHERE tournament_id = $1',
      [tournamentId]
    );
    
    const total = totalRosters.rows[0].total || 1;
    
    // Get all players
    const players = await pool.query(
      'SELECT player_name FROM players WHERE tournament_id = $1',
      [tournamentId]
    );
    
    // Calculate pick percentage for each player
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

// Reset tournament scores
app.post('/api/admin/reset', authenticateAdmin, async (req, res) => {
  try {
    const { tournamentId } = req.body;
    
    // Delete all player scores
    await pool.query('DELETE FROM player_scores WHERE tournament_id = $1', [tournamentId]);
    
    // Reset player stats
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

// Start server
app.listen(port, async () => {
  console.log(`Server running on port ${port}`);
  await initializeTables();
});