"""WebSec Scanner - Web Security Assessment Tool"""

from flask import Flask, render_template, request, jsonify, send_file, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import json
import threading
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List

# Import scanner modules with proper path handling
import sys
import os
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

from src.scanners.crawler import get_forms
from src.scanners.xss_scanner import XSSScanner
from src.scanners.sqli_scanner import SQLIScanner
from src.scanners.csrf_scanner import CSRFScanner
from src.core.utils import SecurityUtils
from src.core.database import DatabaseManager
from src.core.logger import setup_logging, get_logger

from dotenv import load_dotenv
from werkzeug.security import check_password_hash, generate_password_hash
from flask_wtf.csrf import CSRFProtect
from urllib.parse import urlparse
import re

# Load environment variables
load_dotenv()

# Setup logging
setup_logging()
logger = get_logger(__name__)

app = Flask(__name__, 
            template_folder='src/web/templates',
            static_folder='src/web/static')
app.secret_key = os.getenv('FLASK_SECRET_KEY')
if not app.secret_key:
    if os.getenv('FLASK_ENV') == 'production':
        raise ValueError("No FLASK_SECRET_KEY set for production configuration")
    app.secret_key = 'default-dev-key-do-not-use-in-prod'

# Configure secure cookies
app.config.update(
    SESSION_COOKIE_SECURE=True if os.getenv('FLASK_ENV') == 'production' else False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=3600  # 1 hour
)

# Setup CSRF Protection
csrf = CSRFProtect(app)

# Setup Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User Class
class User(UserMixin):
    def __init__(self, user_data):
        self.id = user_data['user_id']
        self.email = user_data['email']
        self.name = user_data['name']
        self.created_at = user_data.get('created_at')

@login_manager.user_loader
def load_user(user_id):
    user_data = db.get_user_by_id(user_id)
    if user_data:
        return User(user_data)
    return None

# Initialize Database Manager
db = DatabaseManager()

CONFIG = {
    "scanning": {
        "capabilities": {
            "xss": {
                "name": "Cross-Site Scripting (XSS)",
                "description": "Detect reflected, stored, and DOM-based XSS vulnerabilities",
                "level": "Critical",
                "features": ["Reflected XSS", "Stored XSS", "DOM-based XSS", "Context Analysis"]
            },
            "sqli": {
                "name": "SQL Injection",
                "description": "Identify SQL injection vulnerabilities in database queries",
                "level": "Critical",
                "features": ["Error-based SQLi", "Union-based SQLi", "Blind SQLi", "Time-based SQLi"]
            },
            "csrf": {
                "name": "CSRF Protection",
                "description": "Validate Cross-Site Request Forgery protection mechanisms",
                "level": "High",
                "features": ["Token Validation", "SameSite Cookies", "Origin Verification", "Referer Checking"]
            }
        }
    }
}


# Routes
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not name or not email or not password:
            return render_template('signup.html', error='All fields are required')
            
        # Check if user exists
        if db.get_user_by_email(email):
            return render_template('signup.html', error='Email already registered')
            
        # Create user
        password_hash = generate_password_hash(password)
        if db.create_user(email, password_hash, name):
            # Auto login
            user = User(db.get_user_by_email(email))
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('signup.html', error='Registration failed')
            
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        user_data = db.get_user_by_email(email)
        
        if user_data and check_password_hash(user_data['password_hash'], password):
            user = User(user_data)
            login_user(user)
            return redirect(url_for('index'))
        else:
            return render_template('login.html', error='Invalid email or password')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    message = None
    error = None
    
    if request.method == 'POST':
        # Handle password change or name update
        new_password = request.form.get('new_password')
        current_password = request.form.get('current_password')
        
        if new_password:
            user_data = db.get_user_by_id(current_user.id)
            if check_password_hash(user_data['password_hash'], current_password):
                db.update_user_password(current_user.id, generate_password_hash(new_password))
                message = "Password updated successfully"
            else:
                error = "Incorrect current password"
    
    # Get stats for profile
    user_scans = db.get_all_scans(user_id=current_user.id)
    scan_count = len(user_scans)
    
    return render_template('profile.html', user=current_user, scan_count=scan_count, message=message, error=error)



@app.route('/')
@login_required
def index():
    """Main dashboard with professional capability descriptions"""
    capabilities = CONFIG.get("scanning", {}).get("capabilities", {})
    crawl_options = CONFIG.get("scanning", {}).get("crawl_depth", {})
    assessment_modes = CONFIG.get("scanning", {}).get("assessment_modes", {})
    
    # Get recent scan statistics from database (Filtered by User)
    recent_scans = db.get_recent_scans(limit=5, user_id=current_user.id)
    
    # Calculate stats (Filtered by User)
    all_scans = db.get_all_scans(user_id=current_user.id)
    scan_stats = {
        'total_scans': len(all_scans),
        'high_risk_scans': sum(1 for s in all_scans if s.get('risk_level') in ['High', 'Critical']),
        'vulnerabilities_found': sum(s.get('vulnerabilities_count', 0) for s in all_scans)
    }
    
    return render_template('index.html', 
                         capabilities=capabilities,
                         crawl_options=crawl_options,
                         assessment_modes=assessment_modes,
                         recent_scans=recent_scans,
                         scan_stats=scan_stats,
                         user=current_user)



def validate_url(url: str) -> tuple[bool, str]:
    """
    Validate URL format and accessibility
    
    Returns:
        tuple: (is_valid, error_message)
    """
    try:
        # Check if URL is not empty
        if not url or not url.strip():
            return False, "URL cannot be empty"
        
        # Parse URL
        parsed = urlparse(url)
        
        # Check if has scheme (http/https)
        if not parsed.scheme:
            return False, "URL must include http:// or https://"
        
        # Only allow http and https
        if parsed.scheme not in ['http', 'https']:
            return False, "Only HTTP and HTTPS protocols are supported"
        
        # Check if has domain
        if not parsed.netloc:
            return False, "Invalid URL format - missing domain"
        
        # Check for valid domain format (basic check)
        domain_pattern = re.compile(
            r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^localhost$|^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        )
        if not domain_pattern.match(parsed.netloc.split(':')[0]):
            return False, "Invalid domain format"
        
        # Check URL length
        if len(url) > 2048:
            return False, "URL is too long (max 2048 characters)"
        
        return True, ""
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"


@app.route('/scan', methods=['POST'])
@login_required
def start_scan():
    """Initialize and start security assessment"""
    try:
        # Extract form data
        target_url = request.form.get('url', '').strip()
        scan_types = request.form.getlist('scan_types')
        crawl_depth = int(request.form.get('crawl_depth', 2))
        scan_intensity = request.form.get('scan_intensity', 'normal')
        
        # Validation
        if not target_url:
            return jsonify({'error': 'Target URL is required'}), 400
        
        # Validate URL format and accessibility
        is_valid, error_msg = validate_url(target_url)
        if not is_valid:
            logger.warning(f"Invalid URL submitted: {target_url} - {error_msg}")
            return jsonify({'error': error_msg}), 400
            
        if not scan_types:
            scan_types = ['xss', 'sqli', 'csrf']

        
        # Generate scan ID and initialize tracking
        scan_id = str(uuid.uuid4())
        
        # Create scan record in database
        if not db.create_scan(scan_id, target_url, scan_types, user_id=current_user.id):
            return jsonify({'error': 'Failed to initialize scan in database'}), 500
        
        # Start assessment in background thread
        def run_assessment():
            try:
                execute_security_assessment(scan_id, target_url, scan_types, 
                                          crawl_depth, scan_intensity)
            except Exception as e:
                logger.error(f"Scan execution failed for {scan_id}: {e}")
                db.fail_scan(scan_id, str(e))
        
        thread = threading.Thread(target=run_assessment, daemon=True)
        thread.start()
        
        return jsonify({
            'success': True,
            'scan_id': scan_id,
            'message': 'Security assessment initiated successfully'
        })
    
    except ValueError as e:
        logger.error(f"Invalid input data: {e}")
        return jsonify({'error': f'Invalid input: {str(e)}'}), 400
    except KeyError as e:
        logger.error(f"Missing required field: {e}")
        return jsonify({'error': f'Missing required field: {str(e)}'}), 400
    except Exception as e:
        logger.error(f"Unexpected error in start_scan: {e}", exc_info=True)
        return jsonify({'error': f'Assessment initialization failed: {str(e)}'}), 500


import io

def execute_security_assessment(scan_id: str, target_url: str, scan_types: List[str], 
                               crawl_depth: int, scan_intensity: str):
    """Execute comprehensive security assessment"""
    start_time = time.time()
    all_vulnerabilities = []
    current_test_count = 0
    total_estimated_tests = 230
    
    try:
        # Update status to running
        db.update_scan_progress(scan_id, 5, 'running', 'Analyzing target structure...')
        
        # 1. Discovery Crawl for Estimation
        from src.scanners.crawler import get_forms
        forms = get_forms(target_url)
        num_forms = len(forms)
        
        # 2. Determine Payload Count
        payload_count = 75 # Default normal
        if scan_intensity == 'basic': payload_count = 25
        elif scan_intensity == 'high': payload_count = 150
        elif scan_intensity == 'brutal': payload_count = 550 # Actual count (approx)
        
        # 3. Calculate Estimate
        # (Forms * Payloads * ScanTypes) + Overhead
        num_scan_types = len(scan_types)
        
        # Measure actual response time for a single request
        try:
            import requests
            start_check = time.time()
            requests.get(target_url, timeout=5)
            response_time = time.time() - start_check
        except requests.exceptions.Timeout:
            logger.warning(f"Target URL {target_url} timed out, using default response time")
            response_time = 0.5
        except requests.exceptions.ConnectionError:
            logger.error(f"Cannot connect to {target_url}")
            response_time = 0.5
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error for {target_url}: {e}")
            response_time = 0.5
            
        # Add slight buffer for processing overhead
        avg_request_time = response_time + 0.1
        
        total_requests = num_forms * payload_count * num_scan_types
        if total_requests == 0: total_requests = 50 # Baseline
        
        estimated_seconds = total_requests * avg_request_time
        
        # Format time
        if estimated_seconds < 60:
            est_str = f"{int(estimated_seconds)}s"
        else:
            est_str = f"{int(estimated_seconds // 60)}m {int(estimated_seconds % 60)}s"
            
        db.update_scan_progress(scan_id, 10, 'running', f'Estimated time: {est_str}', estimated_time=est_str)
        
        # Progress Callback
        def progress_callback(increment=1):
            nonlocal current_test_count
            current_test_count += increment
            # Update DB every 5 tests to reduce load
            if current_test_count % 5 == 0:
                db.update_scan_progress(scan_id, 
                                      min(90, 10 + int((current_test_count / total_requests) * 80)), 
                                      'running', 
                                      f'Testing payloads ({current_test_count} tests)...')

        # XSS Assessment
        if 'xss' in scan_types:
            db.update_scan_progress(scan_id, 15, 'running', 'Running XSS Assessment...')
            xss_scanner = XSSScanner({'scan_intensity': scan_intensity})
            xss_vulns = xss_scanner.scan(target_url, progress_callback=progress_callback)
            all_vulnerabilities.extend(xss_vulns)
            
        # SQLi Assessment
        if 'sqli' in scan_types:
            db.update_scan_progress(scan_id, 45, 'running', 'Running SQL Injection Assessment...')
            sqli_scanner = SQLIScanner({'scan_intensity': scan_intensity})
            sqli_vulns = sqli_scanner.scan(target_url, progress_callback=progress_callback)
            all_vulnerabilities.extend(sqli_vulns)
            
            current_test_count += 126
            db.update_scan_progress(scan_id, 70, 'running', 'SQL Injection Scan Complete', len(all_vulnerabilities))
        
        # CSRF Assessment
        if 'csrf' in scan_types:
            db.update_scan_progress(scan_id, 75, 'running', 'CSRF Protection Assessment')
            
            time.sleep(1)
            scanner = CSRFScanner(config={'scan_intensity': scan_intensity})
            csrf_vulns = scanner.scan(target_url)
            all_vulnerabilities.extend(csrf_vulns)
            
            current_test_count += 24
            db.update_scan_progress(scan_id, 90, 'running', 'CSRF Scan Complete', len(all_vulnerabilities))
        
        # Finalize assessment
        db.update_scan_progress(scan_id, 95, 'running', 'Generating professional security report...')
        
        # Generate reports
        utils = SecurityUtils()
        risk_score = utils.calculate_risk_score(all_vulnerabilities)
        
        # Create scan data object
        scan_data = {
            'scan_id': scan_id,
            'target_url': target_url,
            'scan_time': datetime.now().isoformat(),
            'vulnerabilities': all_vulnerabilities,
            'total_vulns': len(all_vulnerabilities),
            'risk_score': risk_score,
            'scan_duration': time.time() - start_time,
            'scan_types': scan_types,
            'crawl_depth': crawl_depth,
            'scan_intensity': scan_intensity
        }
        
        # Save full results to Database
        db.complete_scan(scan_id, scan_data)
        
    except Exception as e:
        db.fail_scan(scan_id, str(e))


@app.route('/status/<scan_id>')
@login_required
def get_scan_status(scan_id: str):
    """Get real-time scan progress and status"""
    scan_data = db.get_scan(scan_id)
    if not scan_data:
        return jsonify({'error': 'Scan not found'}), 404
    
    # Check ownership
    if scan_data.get('user_id') != current_user.id:
        return jsonify({'error': 'Unauthorized access to scan status'}), 403
    
    # Add estimated remaining time logic if needed, or keep it simple
    return jsonify(scan_data)


@app.route('/history')
@login_required
def scan_history():
    """Display scan history page"""
    try:
        scan_history_list = db.get_all_scans(user_id=current_user.id)
        return render_template('history.html', scans=scan_history_list)
    except Exception as e:
        return render_template('error.html', error=f'Error loading scan history: {e}'), 500


@app.route('/reports')
@login_required
def reports():
    """Professional reports overview page"""
    try:
        # Reuse history logic but maybe filter for completed scans only?
        # For now, showing all scans is fine as per original logic
        report_files = db.get_all_scans(user_id=current_user.id)
        return render_template('reports.html', reports=report_files)
    except Exception as e:
        return render_template('error.html', error=f'Error loading reports: {e}'), 500


@app.route('/results/<scan_id>')
@login_required
def view_results(scan_id):
    """View detailed results for a specific scan"""
    try:
        scan_data = db.get_scan(scan_id)
        if not scan_data:
            return render_template('error.html', error=f'Scan not found for ID: {scan_id}'), 404
            
        # Check ownership
        if scan_data.get('user_id') != current_user.id:
            return render_template('error.html', error='Unauthorized access to scan results'), 403
            
        # If scan_data has 'scan_data' field (new format), use it. 
        # Otherwise use the top-level object (or fallback for old scans if needed)
        results = scan_data.get('scan_data', scan_data)
        
        # If results is still missing vulnerabilities (e.g. old scan without full data), 
        # we might need to handle that. But for now assuming new scans.
        
        return render_template('results.html', results=results)
        
    except Exception as e:
        return render_template('error.html', error=f'Error loading scan results: {e}'), 500


@app.route('/download/<scan_id>')
@login_required
def download_report(scan_id):
    """Download scan report (supports html, json, pdf via format query param)"""
    try:
        fmt = request.args.get('format', 'html').lower()
        
        # Fetch scan data from DB
        scan_record = db.get_scan(scan_id)
        if not scan_record:
            return render_template('error.html', error=f'Scan not found for ID: {scan_id}'), 404
            
        # Check ownership
        if scan_record.get('user_id') != current_user.id:
            return render_template('error.html', error='Unauthorized access to scan report'), 403
            
        # Extract full scan details
        scan_data = scan_record.get('scan_data', scan_record)
        utils = SecurityUtils()

        if fmt == 'pdf':
            # Generate PDF in memory
            pdf_buffer = io.BytesIO()
            utils.generate_pdf_report(scan_data, pdf_buffer)
            pdf_buffer.seek(0)
            
            return send_file(
                pdf_buffer, 
                as_attachment=True, 
                download_name=f"security_report_{scan_id}.pdf", 
                mimetype='application/pdf'
            )

        if fmt == 'json':
            # Generate JSON in memory
            json_str = json.dumps(scan_data, indent=2, default=str)
            json_buffer = io.BytesIO(json_str.encode('utf-8'))
            
            return send_file(
                json_buffer, 
                as_attachment=True, 
                download_name=f"security_report_{scan_id}.json", 
                mimetype='application/json'
            )

        # Default HTML
        html_content = utils.generate_html_report(scan_data)
        html_buffer = io.BytesIO(html_content.encode('utf-8'))
        
        return send_file(
            html_buffer, 
            as_attachment=True, 
            download_name=f"security_report_{scan_id}.html", 
            mimetype='text/html'
        )

    except Exception as e:
        return render_template('error.html', error=f'Error downloading report: {e}'), 500


if __name__ == '__main__':
    logger.info("WebSec Scanner v2.1.0")
    logger.info("Starting server...")
    
    # Production: Use Gunicorn
    # Development: python app.py
    debug_mode = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(host='0.0.0.0', port=5001, debug=debug_mode)