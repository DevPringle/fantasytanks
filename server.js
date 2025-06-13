const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');

const app = express();
const port = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static('.'));

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-this-in-production';

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
      'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
      [username, email, passwordHash]
    );

    const user = result.rows[0];

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

// Enhanced Leaderboard API Endpoint
app.get('/api/leaderboard/:tournamentId', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    const { matchDay, minRosterSize = 10 } = req.query;

    if (!tournamentId) {
      return res.status(400).json({ error: 'Tournament ID is required' });
    }

    let query, params;

    if (matchDay) {
      // Single match day leaderboard
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
      // Overall tournament leaderboard
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
    
    // Add metadata to the response
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

// Additional endpoint to get leaderboard statistics
app.get('/api/leaderboard/:tournamentId/stats', async (req, res) => {
  try {
    const { tournamentId } = req.params;
    
    // Get roster completion statistics
    const rosterStats = await pool.query(`
      SELECT 
        match_day,
        COUNT(*) as total_rosters,
        COUNT(CASE WHEN jsonb_array_length(roster) >= 10 THEN 1 END) as complete_rosters,
        COUNT(CASE WHEN jsonb_array_length(roster) < 10 THEN 1 END) as incomplete_rosters
      FROM rosters 
      WHERE tournament_id = $1
      GROUP BY match_day
      ORDER BY match_day
    `, [tournamentId]);

    // Get overall tournament stats
    const overallStats = await pool.query(`
      SELECT 
        COUNT(DISTINCT user_id) as unique_participants,
        COUNT(*) as total_roster_submissions,
        AVG(jsonb_array_length(roster)) as avg_roster_size,
        COUNT(CASE WHEN jsonb_array_length(roster) >= 10 THEN 1 END) as complete_roster_submissions
      FROM rosters 
      WHERE tournament_id = $1
    `, [tournamentId]);

    // Get top performers
    const topPerformers = await pool.query(`
      WITH user_points AS (
        SELECT 
          u.username,
          SUM(ps.points) as total_points,
          COUNT(DISTINCT ps.match_day) as active_days
        FROM rosters r
        JOIN users u ON r.user_id = u.id
        LEFT JOIN player_scores ps ON ps.tournament_id = r.tournament_id 
          AND ps.match_day = r.match_day
          AND ps.player_name = ANY(SELECT jsonb_array_elements_text(r.roster))
        WHERE r.tournament_id = $1 AND jsonb_array_length(r.roster) >= 10
        GROUP BY u.username
        HAVING COUNT(DISTINCT ps.match_day) > 0
      )
      SELECT username, total_points, active_days
      FROM user_points
      ORDER BY total_points DESC
      LIMIT 5
    `, [tournamentId]);

    res.json({
      roster_stats_by_day: rosterStats.rows,
      overall_stats: overallStats.rows[0],
      top_performers: topPerformers.rows
    });

  } catch (error) {
    console.error('Get leaderboard stats error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// Endpoint to get user's ranking and position
app.get('/api/leaderboard/:tournamentId/user/:userId', authenticateToken, async (req, res) => {
  try {
    const { tournamentId, userId } = req.params;
    const { matchDay } = req.query;
    
    // Verify user can access this data (either their own or admin)
    if (req.user.userId !== parseInt(userId) && req.user.userId !== 1) {
      return res.status(403).json({ error: 'Access denied' });
    }

    let query, params;

    if (matchDay) {
      query = `
        WITH leaderboard AS (
          SELECT 
            u.username,
            u.id as user_id,
            COALESCE(SUM(ps.points), 0) as total_points,
            ROW_NUMBER() OVER (ORDER BY COALESCE(SUM(ps.points), 0) DESC) as rank
          FROM rosters r
          JOIN users u ON r.user_id = u.id
          LEFT JOIN player_scores ps ON ps.tournament_id = r.tournament_id 
            AND ps.match_day = r.match_day
            AND ps.player_name = ANY(SELECT jsonb_array_elements_text(r.roster))
          WHERE r.tournament_id = $1 AND r.match_day = $2 AND jsonb_array_length(r.roster) >= 10
          GROUP BY u.username, u.id
        )
        SELECT * FROM leaderboard WHERE user_id = $3
      `;
      params = [tournamentId, matchDay, userId];
    } else {
      query = `
        WITH leaderboard AS (
          SELECT 
            u.username,
            u.id as user_id,
            COALESCE(SUM(ps.points), 0) as total_points,
            COUNT(DISTINCT r.match_day) as match_days_played,
            ROW_NUMBER() OVER (ORDER BY COALESCE(SUM(ps.points), 0) DESC) as rank
          FROM rosters r
          JOIN users u ON r.user_id = u.id
          LEFT JOIN player_scores ps ON ps.tournament_id = r.tournament_id 
            AND ps.match_day = r.match_day
            AND ps.player_name = ANY(SELECT jsonb_array_elements_text(r.roster))
          WHERE r.tournament_id = $1 AND jsonb_array_length(r.roster) >= 10
          GROUP BY u.username, u.id
          HAVING COUNT(DISTINCT r.match_day) > 0
        )
        SELECT * FROM leaderboard WHERE user_id = $2
      `;
      params = [tournamentId, userId];
    }

    const result = await pool.query(query, params);
    
    if (result.rows.length === 0) {
      return res.json({ 
        rank: null, 
        message: 'User not found in leaderboard (may not have complete rosters)' 
      });
    }

    res.json(result.rows[0]);

  } catch (error) {
    console.error('Get user ranking error:', error);
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
});
