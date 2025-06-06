// backend/server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 3001;

// Database connection
const pool = new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    database: process.env.DB_NAME || 'fantasy_tanks',
    user: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
});

// Middleware
app.use(cors({
    origin: process.env.FRONTEND_URL || 'http://localhost:3000',
    credentials: true
}));
app.use(express.json());

// Rate limiting
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100 // limit each IP to 100 requests per windowMs
});
app.use('/api/', limiter);

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production';

// Authentication middleware
const authenticateToken = async (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ error: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        
        // Verify session exists and hasn't expired
        const sessionResult = await pool.query(
            'SELECT user_id FROM user_sessions WHERE session_token = $1 AND expires_at > NOW()',
            [token]
        );

        if (sessionResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid or expired session' });
        }

        req.user = { id: decoded.userId };
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token' });
    }
};

// === AUTHENTICATION ROUTES ===

// Register new user
app.post('/api/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;

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
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const saltRounds = 12;
        const hashedPassword = await bcrypt.hash(password, saltRounds);

        // Create user
        const result = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, hashedPassword]
        );

        const user = result.rows[0];

        // Create session
        const sessionToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        await pool.query(
            'INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)',
            [user.id, sessionToken, expiresAt]
        );

        res.status(201).json({
            user: { id: user.id, username: user.username, email: user.email },
            token: sessionToken
        });
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Login user
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Username and password are required' });
        }

        // Find user
        const userResult = await pool.query(
            'SELECT id, username, email, password_hash FROM users WHERE username = $1 OR email = $1',
            [username]
        );

        if (userResult.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = userResult.rows[0];

        // Verify password
        const validPassword = await bcrypt.compare(password, user.password_hash);
        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Create session
        const sessionToken = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        await pool.query(
            'INSERT INTO user_sessions (user_id, session_token, expires_at) VALUES ($1, $2, $3)',
            [user.id, sessionToken, expiresAt]
        );

        res.json({
            user: { id: user.id, username: user.username, email: user.email },
            token: sessionToken
        });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Logout user
app.post('/api/auth/logout', authenticateToken, async (req, res) => {
    try {
        const authHeader = req.headers['authorization'];
        const token = authHeader && authHeader.split(' ')[1];

        // Delete session
        await pool.query('DELETE FROM user_sessions WHERE session_token = $1', [token]);

        res.json({ message: 'Logged out successfully' });
    } catch (error) {
        console.error('Logout error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get current user
app.get('/api/auth/me', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT id, username, email FROM users WHERE id = $1',
            [req.user.id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({ user: result.rows[0] });
    } catch (error) {
        console.error('Get user error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// === TOURNAMENT ROUTES ===

// Get all tournaments
app.get('/api/tournaments', async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT t.*, 
                   COUNT(DISTINCT ur.user_id) as fantasy_teams_count,
                   COUNT(DISTINCT p.id) as players_count,
                   COUNT(DISTINCT teams.id) as teams_count
            FROM tournaments t
            LEFT JOIN user_rosters ur ON t.id = ur.tournament_id
            LEFT JOIN players p ON t.id = p.tournament_id
            LEFT JOIN teams ON t.id = teams.tournament_id
            GROUP BY t.id
            ORDER BY t.start_date DESC
        `);

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

        const result = await pool.query(`
            SELECT t.*, 
                   COUNT(DISTINCT ur.user_id) as fantasy_teams_count,
                   COUNT(DISTINCT p.id) as players_count,
                   COUNT(DISTINCT teams.id) as teams_count
            FROM tournaments t
            LEFT JOIN user_rosters ur ON t.id = ur.tournament_id
            LEFT JOIN players p ON t.id = p.tournament_id
            LEFT JOIN teams ON t.id = teams.tournament_id
            WHERE t.id = $1
            GROUP BY t.id
        `, [tournamentId]);

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Tournament not found' });
        }

        res.json({ tournament: result.rows[0] });
    } catch (error) {
        console.error('Get tournament error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get tournament players
app.get('/api/tournaments/:tournamentId/players', async (req, res) => {
    try {
        const { tournamentId } = req.params;
        const { team } = req.query;

        let query = `
            SELECT p.*, teams.name as team_name, teams.abbreviation as team_abbreviation,
                   ROUND((p.battles_played::decimal / NULLIF(p.total_battles, 0) * 100), 0) as battles_percentage,
                   ROUND((p.times_picked::decimal / NULLIF((SELECT COUNT(DISTINCT user_id) FROM user_rosters WHERE tournament_id = $1), 0) * 100), 2) as picked_percentage
            FROM players p
            JOIN teams ON p.team_id = teams.id
            WHERE p.tournament_id = $1
        `;

        const params = [tournamentId];

        if (team) {
            query += ' AND teams.abbreviation = $2';
            params.push(team);
        }

        query += ' ORDER BY p.fantasy_points DESC';

        const result = await pool.query(query, params);

        res.json({ players: result.rows });
    } catch (error) {
        console.error('Get players error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Get tournament teams
app.get('/api/tournaments/:tournamentId/teams', async (req, res) => {
    try {
        const { tournamentId } = req.params;

        const result = await pool.query(`
            SELECT teams.*, COUNT(p.id) as player_count,
                   AVG(p.fantasy_points) as avg_team_points
            FROM teams
            LEFT JOIN players p ON teams.id = p.team_id
            WHERE teams.tournament_id = $1
            GROUP BY teams.id
            ORDER BY teams.name
        `, [tournamentId]);

        res.json({ teams: result.rows });
    } catch (error) {
        console.error('Get teams error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// === ROSTER ROUTES ===

// Get user's roster for a tournament
app.get('/api/roster', authenticateToken, async (req, res) => {
    try {
        const { tournamentId } = req.query;

        if (!tournamentId) {
            return res.status(400).json({ error: 'Tournament ID is required' });
        }

        const result = await pool.query(`
            SELECT ur.position, p.name, p.fantasy_points, p.average_points,
                   teams.abbreviation as team_abbreviation
            FROM user_rosters ur
            JOIN players p ON ur.player_id = p.id
            JOIN teams ON p.team_id = teams.id
            WHERE ur.user_id = $1 AND ur.tournament_id = $2
            ORDER BY ur.position
        `, [req.user.id, tournamentId]);

        res.json({ roster: result.rows });
    } catch (error) {
        console.error('Get roster error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Save user's roster
app.post('/api/roster', authenticateToken, async (req, res) => {
    const client = await pool.connect();
    
    try {
        const { tournamentId, roster } = req.body;

        if (!tournamentId || !Array.isArray(roster)) {
            return res.status(400).json({ error: 'Tournament ID and roster array are required' });
        }

        // Check if rosters are open for this tournament
        const tournamentResult = await client.query(
            'SELECT rosters_open, max_roster_size FROM tournaments WHERE id = $1',
            [tournamentId]
        );

        if (tournamentResult.rows.length === 0) {
            return res.status(404).json({ error: 'Tournament not found' });
        }

        const tournament = tournamentResult.rows[0];
        if (!tournament.rosters_open) {
            return res.status(403).json({ error: 'Rosters are closed for this tournament' });
        }

        if (roster.length > tournament.max_roster_size) {
            return res.status(400).json({ 
                error: `Roster cannot exceed ${tournament.max_roster_size} players` 
            });
        }

        await client.query('BEGIN');

        // Remove existing roster
        await client.query(
            'DELETE FROM user_rosters WHERE user_id = $1 AND tournament_id = $2',
            [req.user.id, tournamentId]
        );

        // Add new roster
        for (let i = 0; i < roster.length; i++) {
            const playerName = roster[i];
            
            // Get player ID
            const playerResult = await client.query(
                'SELECT id FROM players WHERE tournament_id = $1 AND name = $2',
                [tournamentId, playerName]
            );

            if (playerResult.rows.length === 0) {
                await client.query('ROLLBACK');
                return res.status(400).json({ error: `Player ${playerName} not found` });
            }

            const playerId = playerResult.rows[0].id;

            await client.query(
                'INSERT INTO user_rosters (user_id, tournament_id, player_id, position) VALUES ($1, $2, $3, $4)',
                [req.user.id, tournamentId, playerId, i + 1]
            );
        }

        // Update player pick counts
        await client.query(`
            UPDATE players 
            SET times_picked = (
                SELECT COUNT(DISTINCT ur.user_id) 
                FROM user_rosters ur 
                WHERE ur.player_id = players.id
            )
            WHERE tournament_id = $1
        `, [tournamentId]);

        await client.query('COMMIT');

        res.json({ message: 'Roster saved successfully' });
    } catch (error) {
        await client.query('ROLLBACK');
        console.error('Save roster error:', error);
        res.status(500).json({ error: 'Internal server error' });
    } finally {
        client.release();
    }
});

// Get leaderboard for a tournament
app.get('/api/tournaments/:tournamentId/leaderboard', async (req, res) => {
    try {
        const { tournamentId } = req.params;

        const result = await pool.query(`
            SELECT u.username,
                   COUNT(ur.player_id) as players_count,
                   COALESCE(SUM(p.fantasy_points), 0) as total_points,
                   COALESCE(AVG(p.fantasy_points), 0) as average_points
            FROM users u
            JOIN user_rosters ur ON u.id = ur.user_id
            LEFT JOIN players p ON ur.player_id = p.id
            WHERE ur.tournament_id = $1
            GROUP BY u.id, u.username
            HAVING COUNT(ur.player_id) > 0
            ORDER BY total_points DESC
            LIMIT 100
        `, [tournamentId]);

        res.json({ leaderboard: result.rows });
    } catch (error) {
        console.error('Get leaderboard error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// === ADMIN ROUTES (for updating player stats) ===

// Update player stats (admin only - you'd add admin middleware)
app.put('/api/admin/players/:playerId/stats', async (req, res) => {
    try {
        const { playerId } = req.params;
        const { fantasyPoints, battlesPlayed, totalBattles } = req.body;

        const averagePoints = battlesPlayed > 0 ? fantasyPoints / battlesPlayed : 0;

        await pool.query(`
            UPDATE players 
            SET fantasy_points = $1, battles_played = $2, total_battles = $3, 
                average_points = $4, updated_at = CURRENT_TIMESTAMP
            WHERE id = $5
        `, [fantasyPoints, battlesPlayed, totalBattles, averagePoints, playerId]);

        res.json({ message: 'Player stats updated successfully' });
    } catch (error) {
        console.error('Update player stats error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Toggle tournament roster status (admin only)
app.put('/api/admin/tournaments/:tournamentId/rosters', async (req, res) => {
    try {
        const { tournamentId } = req.params;
        const { rostersOpen } = req.body;

        await pool.query(
            'UPDATE tournaments SET rosters_open = $1, updated_at = CURRENT_TIMESTAMP WHERE id = $2',
            [rostersOpen, tournamentId]
        );

        res.json({ message: 'Tournament roster status updated successfully' });
    } catch (error) {
        console.error('Update tournament status error:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Health check
app.get('/api/health', (req, res) => {
    res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// Error handling middleware
app.use((error, req, res, next) => {
    console.error('Unhandled error:', error);
    res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
    console.log(`Fantasy Tanks API server running on port ${port}`);
});
