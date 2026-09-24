/**
 * Dashboard JavaScript for AI-Powered Threat Detection System
 * 
 * Handles real-time updates, data visualization, and user interactions.
 */

// Configuration
const REFRESH_INTERVAL = 3000; // 3 seconds
let refreshTimer = null;
let lastUpdateTime = null;
let lastSeenFlowId = 0; // Track the last flow we've seen
let feedPaused = false; // Track if live feed is paused
let previousFlows = []; // Store previous flows to detect new ones

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', function() {
    console.log('Dashboard initialized');
    
    // Initial data load
    loadDashboardData();
    
    // Start auto-refresh
    startAutoRefresh();
    
    // Setup event listeners
    setupEventListeners();
    
    // Setup live feed controls
    setupLiveFeedControls();
});

/**
 * Start automatic dashboard refresh
 */
function startAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
    }
    
    refreshTimer = setInterval(function() {
        loadDashboardData();
    }, REFRESH_INTERVAL);
    
    console.log(`Auto-refresh started (${REFRESH_INTERVAL}ms interval)`);
}

/**
 * Stop automatic dashboard refresh
 */
function stopAutoRefresh() {
    if (refreshTimer) {
        clearInterval(refreshTimer);
        refreshTimer = null;
        console.log('Auto-refresh stopped');
    }
}

/**
 * Load all dashboard data
 */
async function loadDashboardData() {
    try {
        await Promise.all([
            loadStats(),
            loadAlerts(),
            loadHistory()
        ]);
        
        updateLastRefreshTime();
        updateConnectionStatus(true);
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        updateConnectionStatus(false);
    }
}

/**
 * Load and render statistics
 */
async function loadStats() {
    try {
        const response = await fetch('/api/stats');
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const stats = await response.json();
        renderStats(stats);
        
    } catch (error) {
        console.error('Error loading stats:', error);
        throw error;
    }
}

/**
 * Load and render alerts
 */
async function loadAlerts() {
    try {
        const response = await fetch('/api/alerts');
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const alerts = await response.json();
        renderAlerts(alerts);
        
        // Update live feed if not paused
        if (!feedPaused) {
            updateLiveFeed(alerts);
        }
        
    } catch (error) {
        console.error('Error loading alerts:', error);
        throw error;
    }
}

/**
 * Load and render history
 */
async function loadHistory() {
    try {
        const response = await fetch('/api/history');
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }
        
        const history = await response.json();
        renderHistory(history);
        
    } catch (error) {
        console.error('Error loading history:', error);
        throw error;
    }
}

/**
 * Render statistics cards
 */
function renderStats(stats) {
    document.getElementById('stat-packets').textContent = 
        formatNumber(stats.packets_analyzed);
    
    document.getElementById('stat-threats').textContent = 
        formatNumber(stats.active_threats);
    
    document.getElementById('stat-traffic').textContent = 
        formatBytes(stats.traffic_volume);
    
    document.getElementById('stat-blocked').textContent = 
        formatNumber(stats.blocked_ips);
}

/**
 * Render alerts table
 */
function renderAlerts(alerts) {
    const tbody = document.getElementById('alerts-tbody');
    
    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="' + 
            (window.USER_IS_ADMIN ? '7' : '6') + 
            '" class="no-data">No network activity detected yet</td></tr>';
        return;
    }
    
    tbody.innerHTML = alerts.map(alert => {
        const time = formatFullTimestamp(alert.timestamp); // Use full timestamp with date
        const destination = `${alert.destination_ip}:${alert.destination_port}`;
        const confidence = Math.round(alert.score * 100);
        const statusClass = getStatusClass(alert.status);
        
        // Better classification labels
        let classification = alert.attack_type;
        if (alert.status === 'Low' || alert.prediction === 'BENIGN') {
            classification = 'Normal Traffic';
        }
        
        let row = `
            <tr class="flow-row flow-${statusClass}">
                <td>${time}</td>
                <td class="mono">${escapeHtml(alert.source_ip)}</td>
                <td class="mono">${escapeHtml(destination)}</td>
                <td>${escapeHtml(classification)}</td>
                <td>
                    <span class="confidence confidence-${statusClass}">${confidence}%</span>
                </td>
                <td>
                    <span class="badge badge-${statusClass}">${alert.status}</span>
                </td>
        `;
        
        if (window.USER_IS_ADMIN) {
            if (alert.status === 'Blocked') {
                row += `
                    <td>
                        <button 
                            class="btn btn-sm btn-unblock" 
                            onclick="handleUnblock('${escapeHtml(alert.source_ip)}')">
                            Unblock
                        </button>
                    </td>
                `;
            } else {
                row += '<td>-</td>';
            }
        }
        
        row += '</tr>';
        return row;
    }).join('');
}

/**
 * Render history table
 */
function renderHistory(history) {
    const tbody = document.getElementById('history-tbody');
    
    if (!history || history.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="no-data">No history available</td></tr>';
        return;
    }
    
    tbody.innerHTML = history.map(entry => {
        const time = formatTimestamp(entry.timestamp);
        const actionClass = getActionClass(entry.action);
        
        return `
            <tr>
                <td>${time}</td>
                <td>
                    <span class="badge badge-${actionClass}">${escapeHtml(entry.action)}</span>
                </td>
                <td class="mono">${escapeHtml(entry.ip)}</td>
                <td>${escapeHtml(entry.actor)}</td>
                <td>${escapeHtml(entry.reason)}</td>
            </tr>
        `;
    }).join('');
}

/**
 * Handle unblock IP action
 */
async function handleUnblock(ip) {
    if (!window.USER_IS_ADMIN) {
        alert('Administrator privileges required');
        return;
    }
    
    if (!confirm(`Are you sure you want to unblock IP ${ip}?`)) {
        return;
    }
    
    const button = event.target;
    button.disabled = true;
    button.textContent = 'Processing...';
    
    try {
        const response = await fetch(`/api/unblock/${encodeURIComponent(ip)}`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-CSRFToken': window.CSRF_TOKEN
            }
        });
        
        const result = await response.json();
        
        if (response.ok && result.success) {
            alert(`Success: ${result.message}`);
            
            // Refresh all dashboard data
            await loadDashboardData();
        } else {
            alert(`Error: ${result.message}`);
            button.disabled = false;
            button.textContent = 'Unblock';
        }
        
    } catch (error) {
        console.error('Error unblocking IP:', error);
        alert('Failed to unblock IP. Please try again.');
        button.disabled = false;
        button.textContent = 'Unblock';
    }
}

/**
 * Update last refresh time display
 */
function updateLastRefreshTime() {
    const now = new Date();
    lastUpdateTime = now;
    
    const timeString = now.toLocaleTimeString('en-US', {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false
    });
    
    document.getElementById('last-updated').textContent = timeString;
}

/**
 * Update connection status indicator
 */
function updateConnectionStatus(connected) {
    const statusEl = document.getElementById('connection-status');
    
    if (connected) {
        statusEl.textContent = '● Connected to detection engine';
        statusEl.className = 'status-ok';
    } else {
        statusEl.textContent = '● Connection to detection engine unavailable';
        statusEl.className = 'status-error';
    }
}

/**
 * Setup event listeners
 */
function setupEventListeners() {
    // Handle visibility change (pause refresh when tab is hidden)
    document.addEventListener('visibilitychange', function() {
        if (document.hidden) {
            stopAutoRefresh();
        } else {
            loadDashboardData();
            startAutoRefresh();
        }
    });
    
    // Handle page unload
    window.addEventListener('beforeunload', function() {
        stopAutoRefresh();
    });
}

// ==================== UTILITY FUNCTIONS ====================

/**
 * Format number with thousands separators
 */
function formatNumber(num) {
    if (num === null || num === undefined) return '0';
    return num.toLocaleString('en-US');
}

/**
 * Format bytes to human-readable string
 */
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

/**
 * Format ISO timestamp to readable string (time only)
 */
function formatTimestamp(isoString) {
    if (!isoString) return 'N/A';
    
    try {
        // Ensure UTC timestamp is properly parsed
        // If no 'Z' suffix, add it to indicate UTC
        let timestamp = isoString;
        if (!timestamp.endsWith('Z') && !timestamp.includes('+')) {
            timestamp = timestamp + 'Z';
        }
        
        const date = new Date(timestamp);
        
        // Format: HH:MM:SS in local timezone
        return date.toLocaleTimeString('en-US', {
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    } catch (error) {
        console.error('Error formatting timestamp:', error);
        return 'Invalid';
    }
}

/**
 * Format ISO timestamp to full date and time
 */
function formatFullTimestamp(isoString) {
    if (!isoString) return 'N/A';
    
    try {
        // Ensure UTC timestamp is properly parsed
        let timestamp = isoString;
        if (!timestamp.endsWith('Z') && !timestamp.includes('+')) {
            timestamp = timestamp + 'Z';
        }
        
        const date = new Date(timestamp);
        
        // Format: YYYY-MM-DD HH:MM:SS in local timezone
        return date.toLocaleString('en-US', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false
        });
    } catch (error) {
        console.error('Error formatting full timestamp:', error);
        return 'Invalid';
    }
}

/**
 * Get CSS class for status badge
 */
function getStatusClass(status) {
    const statusMap = {
        'Blocked': 'danger',
        'Critical': 'danger',
        'Logged': 'warning',
        'Low': 'success'  // Changed from 'info' to 'success' for benign traffic
    };
    
    return statusMap[status] || 'secondary';
}

/**
 * Get CSS class for action badge
 */
function getActionClass(action) {
    const actionMap = {
        'BLOCK': 'danger',
        'UNBLOCK': 'success',
        'BLOCK_DENIED': 'warning',
        'ALERT_SENT': 'info'
    };
    
    return actionMap[action] || 'secondary';
}

/**
 * Escape HTML to prevent XSS
 */
function escapeHtml(text) {
    if (!text) return '';
    
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#039;'
    };
    
    return String(text).replace(/[&<>"']/g, function(m) {
        return map[m];
    });
}

/**
 * Log dashboard errors to console
 */
window.addEventListener('error', function(event) {
    console.error('Dashboard error:', event.error);
});

/**
 * Log unhandled promise rejections
 */
window.addEventListener('unhandledrejection', function(event) {
    console.error('Unhandled promise rejection:', event.reason);
});


/**
 * Update live network feed with new flows
 */
function updateLiveFeed(alerts) {
    const liveFeed = document.getElementById('live-feed');
    if (!liveFeed) return;
    
    // Get new flows (flows we haven't seen before)
    const newFlows = alerts.filter((alert, index) => {
        const flowKey = `${alert.timestamp}-${alert.source_ip}-${alert.destination_ip}-${alert.destination_port}`;
        return !previousFlows.includes(flowKey);
    });
    
    if (newFlows.length === 0) {
        return; // No new flows
    }
    
    // Update previous flows tracker (keep last 100)
    const currentFlows = alerts.map(alert => 
        `${alert.timestamp}-${alert.source_ip}-${alert.destination_ip}-${alert.destination_port}`
    );
    previousFlows = currentFlows.slice(0, 100);
    
    // Remove loading message if present
    const loadingMsg = liveFeed.querySelector('.loading');
    if (loadingMsg) {
        loadingMsg.remove();
    }
    
    // Add new flows to the top
    newFlows.reverse().forEach(flow => {
        const feedItem = createLiveFeedItem(flow);
        liveFeed.insertBefore(feedItem, liveFeed.firstChild);
        
        // Highlight as new
        setTimeout(() => {
            feedItem.classList.add('new');
        }, 10);
        
        // Remove highlight after animation
        setTimeout(() => {
            feedItem.classList.remove('new');
        }, 2000);
    });
    
    // Keep only last 50 items in feed
    while (liveFeed.children.length > 50) {
        liveFeed.removeChild(liveFeed.lastChild);
    }
    
    // Auto-scroll to top to show new flows
    liveFeed.scrollTop = 0;
}

/**
 * Create a live feed item element
 */
function createLiveFeedItem(flow) {
    const item = document.createElement('div');
    item.className = 'live-feed-item';
    
    // Ensure UTC timestamp is properly parsed
    let timestamp = flow.timestamp;
    if (!timestamp.endsWith('Z') && !timestamp.includes('+')) {
        timestamp = timestamp + 'Z';
    }
    
    const time = new Date(timestamp).toLocaleTimeString('en-US', {
        hour12: false,
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
    });
    
    // Determine score class
    const score = flow.score;
    let scoreClass = 'benign';
    let scoreLabel = 'BENIGN';
    
    if (score >= 0.85) {
        scoreClass = 'malicious';
        scoreLabel = 'MALICIOUS';
    } else if (score >= 0.50) {
        scoreClass = 'suspicious';
        scoreLabel = 'SUSPICIOUS';
    }
    
    const scorePercent = Math.round(score * 100);
    
    item.innerHTML = `
        <span class="feed-time">${time}</span>
        <span class="mono">${escapeHtml(flow.source_ip)}</span>
        <span class="feed-arrow">→</span>
        <span class="mono">${escapeHtml(flow.destination_ip)}:${flow.destination_port}</span>
        <span class="feed-protocol">${escapeHtml(flow.protocol || 'TCP')}</span>
        <span class="feed-score ${scoreClass}">${scoreLabel} ${scorePercent}%</span>
    `;
    
    return item;
}

/**
 * Setup live feed controls (pause/clear)
 */
function setupLiveFeedControls() {
    const pauseBtn = document.getElementById('pause-feed');
    const clearBtn = document.getElementById('clear-feed');
    const pauseIcon = document.getElementById('pause-icon');
    
    if (pauseBtn) {
        pauseBtn.addEventListener('click', () => {
            feedPaused = !feedPaused;
            
            if (feedPaused) {
                pauseBtn.innerHTML = '<span id="pause-icon">▶️</span> Resume';
                pauseBtn.classList.add('btn-primary');
                pauseBtn.classList.remove('btn-secondary');
            } else {
                pauseBtn.innerHTML = '<span id="pause-icon">⏸️</span> Pause';
                pauseBtn.classList.add('btn-secondary');
                pauseBtn.classList.remove('btn-primary');
            }
        });
    }
    
    if (clearBtn) {
        clearBtn.addEventListener('click', () => {
            const liveFeed = document.getElementById('live-feed');
            if (liveFeed) {
                liveFeed.innerHTML = '<div class="live-feed-item loading"><span>Feed cleared. Waiting for new data...</span></div>';
                previousFlows = [];
            }
        });
    }
}
