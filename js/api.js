class FantasyAPI {
    constructor() {
        this.baseURL = 'https://fantasytanks-production.up.railway.app/api';
        
        this.token = localStorage.getItem('authToken');
    }

    async request(endpoint, options = {}) {
        const url = `${this.baseURL}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        if (this.token) {
            config.headers.Authorization = `Bearer ${this.token}`;
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'API request failed');
            }

            return data;
        } catch (error) {
            console.error('API request error:', error);
            throw error;
        }
    }

    async login(username, password) {
        try {
            const response = await this.request('/auth/login', {
                method: 'POST',
                body: JSON.stringify({ username, password })
            });

            if (response.token) {
                this.token = response.token;
                localStorage.setItem('authToken', this.token);
                localStorage.setItem('user', JSON.stringify(response.user));
                return response;
            } else {
                throw new Error('No token received from server');
            }
        } catch (error) {
            throw new Error(error.message || 'Login failed');
        }
    }

    async register(username, email, password) {
        try {
            const response = await this.request('/auth/register', {
                method: 'POST',
                body: JSON.stringify({ username, email, password })
            });

            // If registration requires verification, don't store token yet
            if (response.requiresVerification) {
                return response;
            }

            // If auto-verified (no email service), store token
            if (response.token) {
                this.token = response.token;
                localStorage.setItem('authToken', this.token);
                localStorage.setItem('user', JSON.stringify(response.user));
                return response;
            } else {
                throw new Error('No token received from server');
            }
        } catch (error) {
            throw new Error(error.message || 'Registration failed');
        }
    }

    async verifyEmail(token) {
        try {
            const response = await this.request(`/auth/verify-email/${token}`);
            
            // If verification successful and we get a token, store it
            if (response.token) {
                this.token = response.token;
                localStorage.setItem('authToken', this.token);
                localStorage.setItem('user', JSON.stringify(response.user));
            }
            
            return response;
        } catch (error) {
            throw new Error(error.message || 'Email verification failed');
        }
    }

    async resendVerification(email) {
        try {
            const response = await this.request('/auth/resend-verification', {
                method: 'POST',
                body: JSON.stringify({ email })
            });
            return response;
        } catch (error) {
            throw new Error(error.message || 'Failed to resend verification email');
        }
    }

    // Password reset functionality
    async forgotPassword(email) {
        try {
            const response = await this.request('/auth/forgot-password', {
                method: 'POST',
                body: JSON.stringify({ email })
            });
            return response;
        } catch (error) {
            throw new Error(error.message || 'Failed to send password reset email');
        }
    }

    async verifyResetToken(token) {
        try {
            const response = await this.request(`/auth/verify-reset-token/${token}`);
            return response;
        } catch (error) {
            throw new Error(error.message || 'Invalid or expired reset token');
        }
    }

    async resetPassword(token, newPassword) {
        try {
            const response = await this.request('/auth/reset-password', {
                method: 'POST',
                body: JSON.stringify({ token, password: newPassword })
            });

            if (response.token) {
                this.token = response.token;
                localStorage.setItem('authToken', this.token);
                localStorage.setItem('user', JSON.stringify(response.user));
                return response;
            } else {
                throw new Error('Password reset successful but no token received');
            }
        } catch (error) {
            throw new Error(error.message || 'Password reset failed');
        }
    }

    async changePassword(currentPassword, newPassword) {
        try {
            const response = await this.request('/auth/change-password', {
                method: 'POST',
                body: JSON.stringify({ currentPassword, newPassword })
            });
            return response;
        } catch (error) {
            throw new Error(error.message || 'Password change failed');
        }
    }

    logout() {
        this.token = null;
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        window.location.href = 'index.html';
    }

    isAuthenticated() {
        return !!this.token;
    }

    getCurrentUser() {
        const userStr = localStorage.getItem('user');
        if (!userStr) return null;
        try {
            const user = JSON.parse(userStr);
            if (this.token) {
                const payload = JSON.parse(atob(this.token.split('.')[1]));
                return { ...user, username: payload.username, id: payload.userId };
            }
            return user;
        } catch (error) {
            return null;
        }
    }

    async getRoster(tournamentId, matchDay = 1) {
        return await this.request(`/roster?tournamentId=${tournamentId}&matchDay=${matchDay}`);
    }

    async getAllRosters(tournamentId) {
        return await this.request(`/roster/all/${tournamentId}`);
    }

    async saveRoster(tournamentId, roster, matchDay = 1) {
        return await this.request('/roster', {
            method: 'POST',
            body: JSON.stringify({ tournamentId, roster, matchDay })
        });
    }

    async getLeaderboard(tournamentId, matchDay = null, minRosterSize = 10) {
        let endpoint = `/leaderboard/${tournamentId}?minRosterSize=${minRosterSize}`;
        if (matchDay) {
            endpoint += `&matchDay=${matchDay}`;
        }
        return await this.request(endpoint);
    }

    async getLeaderboardStats(tournamentId) {
        return await this.request(`/leaderboard/${tournamentId}/stats`);
    }

    async getUserRanking(tournamentId, userId, matchDay = null) {
        let endpoint = `/leaderboard/${tournamentId}/user/${userId}`;
        if (matchDay) {
            endpoint += `?matchDay=${matchDay}`;
        }
        return await this.request(endpoint);
    }

    async getPlayers(tournamentId) {
        return await this.request(`/tournaments/${tournamentId}/players`);
    }
    
    async getTeams(tournamentId) {
        return await this.request(`/tournaments/${tournamentId}/teams`);
    }
    
    async getTournament(tournamentId) {
        return await this.request(`/tournaments/${tournamentId}`);
    }

    async getTournaments() {
        return await this.request('/tournaments');
    }

    // Admin endpoints
    async updatePlayerScores(tournamentId, matchDay, playerScores, playerData = null) {
        const body = { tournamentId, matchDay };
        if (playerData) {
            body.playerData = playerData;
        } else {
            body.playerScores = playerScores;
        }
        
        return await this.request('/admin/scores', {
            method: 'POST',
            body: JSON.stringify(body)
        });
    }

    async getAdminScores(tournamentId, matchDay) {
        return await this.request(`/admin/scores/${tournamentId}/${matchDay}`);
    }

    async calculatePickPercentages(tournamentId) {
        return await this.request('/admin/calculate-picks', {
            method: 'POST',
            body: JSON.stringify({ tournamentId })
        });
    }

    async resetTournament(tournamentId) {
        return await this.request('/admin/reset', {
            method: 'POST',
            body: JSON.stringify({ tournamentId })
        });
    }

    // Utility methods for fantasy standings
    async getCurrentUserStanding(tournamentId, matchDay = null) {
        if (!this.isAuthenticated()) return null;
        
        try {
            const user = this.getCurrentUser();
            if (!user) return null;
            
            return await this.getUserRanking(tournamentId, user.id, matchDay);
        } catch (error) {
            console.error('Error getting current user standing:', error);
            return null;
        }
    }

    // Leaderboard with filtering options
    async getFilteredLeaderboard(tournamentId, options = {}) {
        const {
            matchDay = null,
            minRosterSize = 10,
            limit = null,
            offset = 0
        } = options;

        let endpoint = `/leaderboard/${tournamentId}?minRosterSize=${minRosterSize}&offset=${offset}`;
        
        if (matchDay) {
            endpoint += `&matchDay=${matchDay}`;
        }
        
        if (limit) {
            endpoint += `&limit=${limit}`;
        }

        return await this.request(endpoint);
    }

    // Batch operations for admin
    async batchUpdateScores(tournamentId, matchDay, playersData) {
        const promises = [];
        const batchSize = 50; // Process in batches to avoid overwhelming the server
        
        for (let i = 0; i < playersData.length; i += batchSize) {
            const batch = playersData.slice(i, i + batchSize);
            const batchData = {};
            
            batch.forEach(player => {
                batchData[player.name] = {
                    points: player.points,
                    battlesPlayed: player.battlesPlayed,
                    totalBattles: player.totalBattles
                };
            });
            
            promises.push(this.updatePlayerScores(tournamentId, matchDay, null, batchData));
        }
        
        return await Promise.all(promises);
    }

    // Health check
    async healthCheck() {
        try {
            return await this.request('/health');
        } catch (error) {
            console.error('Health check failed:', error);
            return { status: 'ERROR', message: error.message };
        }
    }

    // Get API status and user info
    getStatus() {
        return {
            authenticated: this.isAuthenticated(),
            user: this.getCurrentUser(),
            baseURL: this.baseURL,
            hasToken: !!this.token
        };
    }

    // Clear all local data (useful for debugging)
    clearLocalData() {
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        
        // Clear roster data
        const keys = Object.keys(localStorage);
        keys.forEach(key => {
            if (key.startsWith('roster_')) {
                localStorage.removeItem(key);
            }
        });
        
        this.token = null;
    }

    // Validate roster before submission
    validateRoster(roster, maxSize = 10) {
        if (!Array.isArray(roster)) {
            return { valid: false, error: 'Roster must be an array' };
        }
        
        if (roster.length === 0) {
            return { valid: false, error: 'Roster cannot be empty' };
        }
        
        if (roster.length > maxSize) {
            return { valid: false, error: `Roster cannot exceed ${maxSize} players` };
        }
        
        // Check for duplicates
        const uniquePlayers = [...new Set(roster)];
        if (uniquePlayers.length !== roster.length) {
            return { valid: false, error: 'Roster cannot contain duplicate players' };
        }
        
        // Check for empty or invalid player names
        for (const player of roster) {
            if (!player || typeof player !== 'string' || player.trim().length === 0) {
                return { valid: false, error: 'All players must have valid names' };
            }
        }
        
        return { valid: true };
    }

    // Get roster completion status
    async getRosterCompletionStatus(tournamentId, totalMatchDays = 7) {
        if (!this.isAuthenticated()) {
            return { authenticated: false };
        }

        try {
            const response = await this.getAllRosters(tournamentId);
            const rosters = response.rosters || {};
            
            const status = {
                authenticated: true,
                totalMatchDays,
                completedDays: 0,
                incompleteDays: 0,
                emptyDays: 0,
                details: {}
            };

            for (let day = 1; day <= totalMatchDays; day++) {
                const roster = rosters[day] || [];
                const rosterSize = roster.length;
                
                if (rosterSize === 0) {
                    status.emptyDays++;
                    status.details[day] = { status: 'empty', size: 0 };
                } else if (rosterSize < 10) {
                    status.incompleteDays++;
                    status.details[day] = { status: 'incomplete', size: rosterSize };
                } else {
                    status.completedDays++;
                    status.details[day] = { status: 'complete', size: rosterSize };
                }
            }

            return status;
        } catch (error) {
            console.error('Error getting roster completion status:', error);
            return { authenticated: true, error: error.message };
        }
    }

    // Password validation utility
    validatePassword(password) {
        const errors = [];
        
        if (!password) {
            errors.push('Password is required');
            return { valid: false, errors };
        }
        
        if (password.length < 6) {
            errors.push('Password must be at least 6 characters long');
        }
        
        if (!/[A-Za-z]/.test(password)) {
            errors.push('Password must contain at least one letter');
        }
        
        if (!/\d/.test(password)) {
            errors.push('Password should contain at least one number for better security');
        }
        
        return {
            valid: errors.length === 0,
            errors,
            strength: this.getPasswordStrength(password)
        };
    }

    // Password strength calculator
    getPasswordStrength(password) {
        let score = 0;
        
        if (password.length >= 8) score += 1;
        if (password.length >= 12) score += 1;
        if (/[a-z]/.test(password)) score += 1;
        if (/[A-Z]/.test(password)) score += 1;
        if (/\d/.test(password)) score += 1;
        if (/[^A-Za-z0-9]/.test(password)) score += 1;
        
        if (score < 3) return 'weak';
        if (score < 5) return 'medium';
        return 'strong';
    }

    // Email validation utility
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    }

    // Username validation utility
    validateUsername(username) {
        const usernameRegex = /^[a-zA-Z0-9_]{3,20}$/;
        return {
            valid: usernameRegex.test(username),
            message: 'Username must be 3-20 characters and contain only letters, numbers, and underscores'
        };
    }

    
    // Check if current user needs email verification
    needsEmailVerification() {
        const user = this.getCurrentUser();
        return user && !user.email_verified;
    }

    // Get user's email for verification purposes
    getUserEmail() {
        const user = this.getCurrentUser();
        return user ? user.email : null;
    }

    // Handle login responses that require verification
    handleLoginResponse(response) {
        if (response.requiresVerification) {
            return {
                success: false,
                requiresVerification: true,
                email: response.email,
                message: response.error || 'Please verify your email address before logging in'
            };
        }

        if (response.token) {
            this.token = response.token;
            localStorage.setItem('authToken', this.token);
            localStorage.setItem('user', JSON.stringify(response.user));
            return {
                success: true,
                user: response.user,
                message: response.message || 'Login successful'
            };
        }

        return {
            success: false,
            message: 'Login failed'
        };
    }

    // Handle registration responses that may require verification
    handleRegistrationResponse(response) {
        if (response.requiresVerification) {
            return {
                success: true,
                requiresVerification: true,
                message: response.message || 'Please check your email to verify your account'
            };
        }

        if (response.token) {
            this.token = response.token;
            localStorage.setItem('authToken', this.token);
            localStorage.setItem('user', JSON.stringify(response.user));
            return {
                success: true,
                user: response.user,
                message: response.message || 'Account created successfully'
            };
        }

        return {
            success: false,
            message: 'Registration failed'
        };
    }
}

// Create a global instance
const api = new FantasyAPI();

// Export for use in other files
if (typeof module !== 'undefined' && module.exports) {
    module.exports = FantasyAPI;
}
