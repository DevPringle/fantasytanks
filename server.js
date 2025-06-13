// Updated loadFantasyLeaderboard function for your tournament page
// Replace the existing function in your HTML with this one

async function loadFantasyLeaderboard() {
    const loadingState = document.getElementById('standingsLoadingState');
    const errorState = document.getElementById('standingsErrorState');
    const emptyState = document.getElementById('standingsEmptyState');
    const standingsTable = document.getElementById('fantasyStandingsTable');

    if (!loadingState) return;

    // Show loading state
    loadingState.style.display = 'block';
    if (errorState) errorState.style.display = 'none';
    if (emptyState) emptyState.style.display = 'none';
    standingsTable.style.display = 'none';

    try {
        // Get filter values
        const matchDayFilter = document.getElementById('standingsMatchDayFilter')?.value || '';
        
        // Call your existing API method
        const response = await api.getLeaderboard('na-15v15-summer-series', matchDayFilter || null, 10);

        loadingState.style.display = 'none';

        // Check if we have data
        if (!response.leaderboard || response.leaderboard.length === 0) {
            if (emptyState) emptyState.style.display = 'block';
            updateFantasyStandingsInfo(0, response.metadata);
            return;
        }

        // Show the table and populate it
        standingsTable.style.display = 'table';
        populateFantasyStandingsTable(response.leaderboard, !!matchDayFilter);
        updateFantasyStandingsInfo(response.leaderboard.length, response.metadata);

    } catch (error) {
        console.error('Error loading fantasy leaderboard:', error);
        loadingState.style.display = 'none';
        if (errorState) {
            errorState.style.display = 'block';
        } else {
            // Fallback error display
            const tbody = document.getElementById('fantasyStandingsTableBody');
            if (tbody) {
                tbody.innerHTML = `
                    <tr>
                        <td colspan="5" style="text-align: center; padding: 2rem; color: #ef4444;">
                            <div style="font-size: 1.1rem; margin-bottom: 0.5rem;">❌ Error Loading Standings</div>
                            <div style="font-size: 0.9rem; opacity: 0.8;">${error.message}</div>
                        </td>
                    </tr>
                `;
                standingsTable.style.display = 'table';
            }
        }
    }
}

function populateFantasyStandingsTable(leaderboard, isMatchDaySpecific) {
    const tbody = document.getElementById('fantasyStandingsTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';

    leaderboard.forEach((entry, index) => {
        const rank = index + 1;
        const row = document.createElement('tr');

        // Calculate average points based on data structure
        let avgPoints = 0;
        if (isMatchDaySpecific) {
            avgPoints = parseFloat(entry.total_points) || 0;
        } else {
            avgPoints = parseFloat(entry.avg_points) || 0;
        }

        // Check if this is the current user
        const currentUser = api.getCurrentUser();
        const isCurrentUser = currentUser && currentUser.username === entry.username;
        const rowClass = isCurrentUser ? 'current-user-row' : '';

        row.className = rowClass;
        row.innerHTML = `
            <td class="rank-cell ${rank <= 3 ? `top3 rank-${rank}` : ''}">
                ${rank}
                ${isCurrentUser ? '<span class="current-user-indicator">👤</span>' : ''}
            </td>
            <td class="username-cell">
                ${entry.username}
                ${isCurrentUser ? '<span class="you-label">(You)</span>' : ''}
            </td>
            <td class="score-cell">${parseFloat(entry.total_points || 0).toLocaleString(undefined, {maximumFractionDigits: 1})}</td>
            <td class="avg-cell">${avgPoints.toLocaleString(undefined, {maximumFractionDigits: 1})}</td>
            <td class="days-cell">${isMatchDaySpecific ? '1' : (entry.match_days_played || 0)}</td>
        `;

        tbody.appendChild(row);
    });
}

function updateFantasyStandingsInfo(totalParticipants, metadata = null) {
    const participantsElement = document.getElementById('standingsTotalParticipants');
    const lastUpdatedElement = document.getElementById('standingsLastUpdated');
    
    if (participantsElement) {
        if (metadata && metadata.complete_rosters !== undefined) {
            participantsElement.innerHTML = `
                <span>${totalParticipants} qualified teams</span>
                <span style="margin-left: 1rem; font-size: 0.8rem; opacity: 0.7;">
                    (${metadata.total_participants} total participants)
                </span>
            `;
        } else {
            participantsElement.textContent = `${totalParticipants} qualified fantasy teams`;
        }
    }
    
    if (lastUpdatedElement) {
        const updateTime = metadata?.generated_at 
            ? new Date(metadata.generated_at).toLocaleString()
            : new Date().toLocaleString();
        lastUpdatedElement.textContent = `Last updated: ${updateTime}`;
    }
}

// Initialize standings filters
function initializeFantasyStandingsFilters() {
    const bracketFilter = document.getElementById('standingsBracketFilter');
    const matchDayFilter = document.getElementById('standingsMatchDayFilter');

    if (bracketFilter) {
        bracketFilter.addEventListener('change', () => {
            loadFantasyLeaderboard();
        });
    }

    if (matchDayFilter) {
        matchDayFilter.addEventListener('change', () => {
            loadFantasyLeaderboard();
        });
    }
}

// Add this to your DOMContentLoaded event listener
document.addEventListener('DOMContentLoaded', () => {
    // ... your existing initialization code ...
    
    // Initialize standings functionality
    initializeFantasyStandingsFilters();
    
    // Load standings when the standings tab becomes active
    const standingsTab = document.querySelector('[data-tab="standings"]');
    if (standingsTab) {
        standingsTab.addEventListener('click', () => {
            setTimeout(() => {
                loadFantasyLeaderboard();
            }, 100);
        });
    }
});

// Test function you can run in console
window.testLeaderboard = async function() {
    console.log('Testing leaderboard API...');
    try {
        const response = await api.getLeaderboard('na-15v15-summer-series');
        console.log('Leaderboard response:', response);
        return response;
    } catch (error) {
        console.error('Leaderboard test error:', error);
        return error;
    }
};