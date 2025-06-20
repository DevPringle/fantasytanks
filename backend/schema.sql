-- Database schema for fantasy roster system

-- Users table for authentication
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Tournaments table
CREATE TABLE tournaments (
    id VARCHAR(50) PRIMARY KEY, -- e.g., 'na-15v15-summer-series'
    name VARCHAR(200) NOT NULL,
    region VARCHAR(10) NOT NULL,
    status VARCHAR(20) DEFAULT 'upcoming', -- upcoming, active, finished
    rosters_open BOOLEAN DEFAULT false,
    max_roster_size INTEGER DEFAULT 10,
    start_date TIMESTAMP,
    end_date TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Teams participating in tournaments
CREATE TABLE teams (
    id SERIAL PRIMARY KEY,
    tournament_id VARCHAR(50) REFERENCES tournaments(id),
    name VARCHAR(100) NOT NULL,
    abbreviation VARCHAR(10) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Players in tournaments
CREATE TABLE players (
    id SERIAL PRIMARY KEY,
    tournament_id VARCHAR(50) REFERENCES tournaments(id),
    team_id INTEGER REFERENCES teams(id),
    name VARCHAR(100) NOT NULL,
    battles_played INTEGER DEFAULT 0,
    total_battles INTEGER DEFAULT 0,
    fantasy_points DECIMAL(10,2) DEFAULT 0.00,
    average_points DECIMAL(6,2) DEFAULT 0.00,
    times_picked INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(tournament_id, name)
);

-- User rosters for each tournament
CREATE TABLE user_rosters (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    tournament_id VARCHAR(50) REFERENCES tournaments(id),
    player_id INTEGER REFERENCES players(id),
    position INTEGER, -- roster position 1-10
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, tournament_id, player_id),
    UNIQUE(user_id, tournament_id, position)
);

-- User sessions for authentication
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Match results for updating player stats
CREATE TABLE matches (
    id SERIAL PRIMARY KEY,
    tournament_id VARCHAR(50) REFERENCES tournaments(id),
    match_date TIMESTAMP NOT NULL,
    team1_id INTEGER REFERENCES teams(id),
    team2_id INTEGER REFERENCES teams(id),
    winner_team_id INTEGER REFERENCES teams(id),
    status VARCHAR(20) DEFAULT 'scheduled', -- scheduled, in_progress, finished
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Player performance in specific matches
CREATE TABLE player_match_stats (
    id SERIAL PRIMARY KEY,
    match_id INTEGER REFERENCES matches(id),
    player_id INTEGER REFERENCES players(id),
    eliminations INTEGER DEFAULT 0,
    damage_dealt INTEGER DEFAULT 0,
    objectives_captured INTEGER DEFAULT 0,
    survival_time INTEGER DEFAULT 0, -- in seconds
    fantasy_points DECIMAL(6,2) DEFAULT 0.00,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(match_id, player_id)
);

-- Indexes for better performance
CREATE INDEX idx_user_rosters_user_tournament ON user_rosters(user_id, tournament_id);
CREATE INDEX idx_players_tournament ON players(tournament_id);
CREATE INDEX idx_user_sessions_token ON user_sessions(session_token);
CREATE INDEX idx_user_sessions_expires ON user_sessions(expires_at);
CREATE INDEX idx_players_points ON players(fantasy_points DESC);

-- Insert sample tournament data
INSERT INTO tournaments (id, name, region, status, rosters_open, max_roster_size, start_date, end_date) 
VALUES (
    'na-15v15-summer-series',
    'NA 15v15 Summer Series',
    'NA',
    'active',
    true,
    10,
    '2025-06-01 00:00:00',
    '2025-06-30 23:59:59'
);

-- Insert sample teams
INSERT INTO teams (tournament_id, name, abbreviation) VALUES
    ('na-15v15-summer-series', 'Lightning Hawks Gaming', 'LHG'),
    ('na-15v15-summer-series', '25 Percent', '25%'),
    ('na-15v15-summer-series', 'Tank Team 6', 'TT6'),
    ('na-15v15-summer-series', 'Warriors', 'WAR'),
    ('na-15v15-summer-series', 'Steel Battalion', 'SB');

-- Insert sample players ( team IDs)
INSERT INTO players (tournament_id, team_id, name, battles_played, total_battles, fantasy_points, average_points, times_picked) VALUES
    ('na-15v15-summer-series', 1, 'muscles1', 15, 15, 5714.7, 53.9, 47),
    ('na-15v15-summer-series', 2, 'notch123', 14, 15, 5550.5, 48.7, 54),
    ('na-15v15-summer-series', 3, 'TheLoveHitman', 16, 16, 5298.5, 49.5, 51),
    ('na-15v15-summer-series', 2, 'JxMAN20', 13, 15, 4868.7, 46.4, 11),
    ('na-15v15-summer-series', 3, 'Vyraall', 14, 15, 4781.3, 45.8, 28),
    ('na-15v15-summer-series', 2, 'CommanderHalesBrother', 12, 15, 4567.0, 43.9, 17),
    ('na-15v15-summer-series', 2, 'Major_Kenway', 10, 15, 4513.9, 49.1, 10),
    ('na-15v15-summer-series', 3, '_BlitzWolf', 11, 15, 4492.0, 52.8, 7),
    ('na-15v15-summer-series', 4, 'Accretia', 16, 16, 4461.1, 44.6, 31),
    ('na-15v15-summer-series', 5, '_bloop', 14, 15, 4395.0, 48.3, 60),
    ('na-15v15-summer-series', 1, 'SgtRumsey', 11, 15, 4339.6, 49.1, 24),
    ('na-15v15-summer-series', 3, 'iWrangleEmus', 13, 15, 4268.6, 47.8, 17),
    ('na-15v15-summer-series', 4, 'ShiraiKan_ExcalibuR', 12, 15, 4036.9, 44.2, 21),
    ('na-15v15-summer-series', 4, 'Mlopesz', 15, 15, 4029.7, 40.3, 15),
    ('na-15v15-summer-series', 5, 'SlyGuy_2', 14, 15, 3998.4, 45.7, 29),
    ('na-15v15-summer-series', 5, 'Captian_Jack9', 11, 15, 3967.1, 48.9, 27),
    ('na-15v15-summer-series', 4, 'Starick', 12, 15, 3895.5, 46.9, 18),
    ('na-15v15-summer-series', 5, 'RM_xD', 15, 15, 3659.2, 36.6, 8);
