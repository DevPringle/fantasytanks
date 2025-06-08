// API client for Fantasy Tanks
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

    logout() {
        this.token = null;
        localStorage.removeItem('authToken');
        localStorage.removeItem('user');
        // Redirect to home page
        window.location.href = 'index.html';
    }

    isAuthenticated() {
        return !!this.token;
    }

    getCurrentUser() {
        const userStr = localStorage.getItem('user');
        return userStr ? JSON.parse(userStr) : null;
    }

    async getRoster(tournamentId) {
        return await this.request(`/roster?tournamentId=${tournamentId}`);
    }

    async saveRoster(tournamentId, roster) {
        return await this.request('/roster', {
            method: 'POST',
            body: JSON.stringify({ tournamentId, roster })
        });
    }

    async getLeaderboard(tournamentId, matchDay = null) {
        let endpoint = `/leaderboard/${tournamentId}`;
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
}

// Create global instance
const api = new FantasyAPI();