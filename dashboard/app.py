"""
Main Flask application for AI-Powered Threat Detection Dashboard.

Provides web interface for monitoring threats, viewing statistics,
and managing blocked IPs.
"""

import logging
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash, session
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from flask_wtf.csrf import CSRFProtect
from werkzeug.exceptions import HTTPException

from dashboard.config import DashboardConfig
from dashboard.auth import AuthManager, ROLE_ADMIN, ROLE_ANALYST
from dashboard.api import DashboardAPI


# Initialize Flask application
app = Flask(__name__, 
            template_folder='templates',
            static_folder='static')

# Load configuration
try:
    DashboardConfig.validate()
    app.config.update(DashboardConfig.get_flask_config())
except ValueError as e:
    print(f"Configuration error: {e}")
    exit(1)

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access the dashboard.'

# Initialize auth manager and API
auth_manager = AuthManager()
api = DashboardAPI()


@login_manager.user_loader
def load_user(user_id):
    """
    Load user by ID for Flask-Login.
    
    Args:
        user_id: User ID as string
        
    Returns:
        User object or None
    """
    try:
        return auth_manager.get_user_by_id(int(user_id))
    except (ValueError, TypeError):
        return None


def admin_required(f):
    """
    Decorator to require administrator role.
    
    Args:
        f: View function to decorate
        
    Returns:
        Decorated function that checks for admin role
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return jsonify({'success': False, 'message': 'Authentication required'}), 401
        
        if not current_user.is_admin():
            logger.warning(
                f"Unauthorized access attempt by {current_user.username} "
                f"(role: {current_user.role}) to admin endpoint"
            )
            return jsonify({
                'success': False,
                'message': 'Administrator privileges required'
            }), 403
        
        return f(*args, **kwargs)
    
    return decorated_function


# ==================== AUTHENTICATION ROUTES ====================

@app.route('/login', methods=['GET', 'POST'])
@csrf.exempt
def login():
    """
    Handle user login.
    
    GET: Display login form
    POST: Process login credentials
    """
    # Redirect if already logged in
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        if not username or not password:
            flash('Username and password are required', 'error')
            return render_template('login.html')
        
        # Authenticate user
        user = auth_manager.authenticate(username, password)
        
        if user:
            login_user(user, remember=False)
            logger.info(f"User logged in: {username} ({user.role})")
            
            # Redirect to next page or dashboard
            next_page = request.args.get('next')
            if next_page and next_page.startswith('/'):
                return redirect(next_page)
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'error')
            logger.warning(f"Failed login attempt for username: {username}")
    
    return render_template('login.html')


@app.route('/logout', methods=['POST'])
@login_required
def logout():
    """Handle user logout."""
    username = current_user.username
    logout_user()
    logger.info(f"User logged out: {username}")
    flash('You have been logged out successfully', 'success')
    return redirect(url_for('login'))


# ==================== DASHBOARD ROUTES ====================

@app.route('/')
@login_required
def index():
    """Redirect root to dashboard."""
    return redirect(url_for('dashboard'))


@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main dashboard view.
    
    Renders the dashboard template with user information.
    """
    return render_template(
        'dashboard.html',
        username=current_user.username,
        role=current_user.role,
        is_admin=current_user.is_admin()
    )


# ==================== API ROUTES ====================

@app.route('/api/stats')
@login_required
def api_stats():
    """
    Get dashboard statistics.
    
    Returns:
        JSON with packets_analyzed, active_threats, traffic_volume, blocked_ips
    """
    try:
        stats = api.get_statistics()
        return jsonify(stats), 200
    except Exception as e:
        logger.error(f"Error in /api/stats: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve statistics'}), 500


@app.route('/api/alerts')
@login_required
def api_alerts():
    """
    Get recent threat alerts.
    
    Returns:
        JSON array of recent alerts/flows
    """
    try:
        limit = min(
            int(request.args.get('limit', DashboardConfig.API_ALERTS_LIMIT)),
            DashboardConfig.API_ALERTS_LIMIT
        )
        
        alerts = api.get_recent_alerts(limit=limit)
        return jsonify(alerts), 200
    except Exception as e:
        logger.error(f"Error in /api/alerts: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve alerts'}), 500


@app.route('/api/history')
@login_required
def api_history():
    """
    Get audit log history.
    
    Returns:
        JSON array of audit log entries
    """
    try:
        limit = min(
            int(request.args.get('limit', DashboardConfig.API_HISTORY_LIMIT)),
            DashboardConfig.API_HISTORY_LIMIT
        )
        
        history = api.get_audit_history(limit=limit)
        return jsonify(history), 200
    except Exception as e:
        logger.error(f"Error in /api/history: {e}", exc_info=True)
        return jsonify({'error': 'Failed to retrieve history'}), 500


@app.route('/api/unblock/<ip>', methods=['POST'])
@login_required
@admin_required
def api_unblock(ip):
    """
    Unblock an IP address (Administrator only).
    
    Args:
        ip: IP address to unblock
        
    Returns:
        JSON with success status and message
    """
    try:
        logger.info(
            f"Unblock request received: IP={ip}, User={current_user.username}, "
            f"Role={current_user.role}"
        )
        
        # Call backend unblock function
        result = api.unblock_ip_address(ip, actor=current_user.username)
        
        if result['success']:
            return jsonify(result), 200
        else:
            return jsonify(result), 400
        
    except Exception as e:
        logger.error(f"Error in /api/unblock/{ip}: {e}", exc_info=True)
        return jsonify({
            'success': False,
            'message': 'Internal server error'
        }), 500


# ==================== ERROR HANDLERS ====================

@app.errorhandler(401)
def unauthorized(error):
    """Handle unauthorized access."""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Authentication required'}), 401
    return redirect(url_for('login', next=request.path))


@app.errorhandler(403)
def forbidden(error):
    """Handle forbidden access."""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Forbidden'}), 403
    flash('You do not have permission to access this resource', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(404)
def not_found(error):
    """Handle not found errors."""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Not found'}), 404
    return render_template('login.html'), 404


@app.errorhandler(500)
def internal_error(error):
    """Handle internal server errors."""
    logger.error(f"Internal server error: {error}", exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    flash('An internal error occurred. Please try again.', 'error')
    return redirect(url_for('dashboard'))


@app.errorhandler(Exception)
def handle_exception(e):
    """Handle all unhandled exceptions."""
    if isinstance(e, HTTPException):
        return e
    
    logger.error(f"Unhandled exception: {e}", exc_info=True)
    
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    
    flash('An unexpected error occurred. Please try again.', 'error')
    return redirect(url_for('dashboard'))


# ==================== MAIN ====================

def main():
    """
    Main entry point for running the dashboard.
    
    Uses Waitress WSGI server for Windows compatibility.
    """
    print("=" * 60)
    print("AI-Powered Threat Detection & Response System - Dashboard")
    print("Debre Berhan University - Department of IT")
    print("=" * 60)
    print(f"Starting dashboard server on http://{DashboardConfig.HOST}:{DashboardConfig.PORT}")
    print("Press Ctrl+C to stop")
    print("=" * 60)
    
    if DashboardConfig.DEBUG:
        # Development mode - use Flask's built-in server
        logger.warning("Running in DEBUG mode - DO NOT use in production!")
        app.run(
            host=DashboardConfig.HOST,
            port=DashboardConfig.PORT,
            debug=True
        )
    else:
        # Production mode - use Waitress
        from waitress import serve
        serve(
            app,
            host=DashboardConfig.HOST,
            port=DashboardConfig.PORT,
            threads=4
        )


if __name__ == '__main__':
    main()
