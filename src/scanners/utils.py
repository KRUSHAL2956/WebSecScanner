"""
scanner/utils.py

PURPOSE:
Helper functions for the scanner.
Includes report generation, logging, and utility functions.

WHAT TO IMPLEMENT:
1. generate_html_report(findings) - Create HTML report
2. calculate_risk_score(vulnerabilities) - Assign severity ratings
3. save_scan_results(data) - Save results to file/database
4. format_vulnerability(vuln) - Format vulnerability for display
5. logging functions - Track scan progress
"""

import json
import datetime
from pathlib import Path


def get_timestamp():
    """
    Get current timestamp as string
    
    Returns:
        str: Current timestamp in format YYYY-MM-DD_HH-MM-SS
    """
    return datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def calculate_risk_score(vulnerabilities):
    """
    Calculate overall risk score based on vulnerabilities
    
    IMPLEMENT:
    1. Count vulnerabilities by severity
    2. Assign points: CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1
    3. Calculate total score
    4. Return score and risk level
    
    Args:
        vulnerabilities (list): List of vulnerability dicts
        
    Returns:
        dict: {
            'score': int,
            'level': str (CRITICAL/HIGH/MEDIUM/LOW),
            'breakdown': dict
        }
        
    Example:
        score = calculate_risk_score(vulnerabilities)
        print(f"Risk Level: {score['level']}")
    """
    severity_points = {
        'CRITICAL': 10,
        'HIGH': 7,
        'MEDIUM': 4,
        'LOW': 1
    }
    
    # Count vulnerabilities by severity
    breakdown = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'total': 0
    }
    
    total_score = 0
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'LOW').upper()
        if severity in breakdown:
            breakdown[severity] += 1
            breakdown['total'] += 1
            total_score += severity_points.get(severity, 1)
    
    # Determine overall risk level
    if total_score >= 30 or breakdown['CRITICAL'] > 0:
        risk_level = 'CRITICAL'
    elif total_score >= 15 or breakdown['HIGH'] > 0:
        risk_level = 'HIGH'
    elif total_score >= 5 or breakdown['MEDIUM'] > 0:
        risk_level = 'MEDIUM'
    elif total_score > 0:
        risk_level = 'LOW'
    else:
        risk_level = 'SAFE'
    
    return {
        'score': total_score,
        'level': risk_level,
        'breakdown': breakdown
    }


def format_vulnerability(vuln):
    """
    Format vulnerability data for display
    
    IMPLEMENT:
    1. Take vulnerability dict
    2. Format into readable string or HTML
    3. Include all relevant details
    
    Args:
        vuln (dict): Vulnerability information
        
    Returns:
        str: Formatted vulnerability description
    """
    severity = vuln.get('severity', 'UNKNOWN')
    vuln_type = vuln.get('type', 'Unknown Vulnerability')
    url = vuln.get('url', 'N/A')
    description = vuln.get('description', 'No description available')
    
    # Create formatted string
    formatted = f"\n[{severity}] {vuln_type}\n"
    formatted += f"URL: {url}\n"
    formatted += f"Description: {description}\n"
    
    # Add specific details based on vulnerability type
    if 'payload' in vuln:
        formatted += f"Payload: {vuln['payload']}\n"
    
    if 'evidence' in vuln:
        formatted += f"Evidence: {vuln['evidence']}\n"
    
    if 'form_action' in vuln:
        formatted += f"Form Action: {vuln['form_action']}\n"
    
    if 'form_method' in vuln:
        formatted += f"Form Method: {vuln['form_method']}\n"
    
    if 'parameter' in vuln:
        formatted += f"Parameter: {vuln['parameter']}\n"
    
    if 'inputs_tested' in vuln and vuln['inputs_tested']:
        formatted += f"Inputs Tested: {', '.join(vuln['inputs_tested'])}\n"
    
    formatted += "-" * 50
    
    return formatted


def save_scan_results(scan_data, filename=None):
    """
    Save scan results to JSON file
    
    IMPLEMENT:
    1. Create reports directory if not exists
    2. Generate filename if not provided
    3. Save data as JSON
    4. Return filepath
    
    Args:
        scan_data (dict): Complete scan results
        filename (str, optional): Custom filename
        
    Returns:
        str: Path to saved file
        
    Example:
        filepath = save_scan_results(results)
        print(f"Results saved to {filepath}")
    """
    try:
        if not filename:
            # Generate filename based on target URL and timestamp
            target = scan_data.get('target_url', 'unknown')
            # Clean URL for filename
            clean_target = target.replace('http://', '').replace('https://', '')
            clean_target = clean_target.replace('/', '_').replace(':', '_')
            filename = f"scan_{clean_target}_{get_timestamp()}.json"
        
        # Ensure filename ends with .json
        if not filename.endswith('.json'):
            filename += '.json'
        
        # Create reports directory
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        # Save scan data
        filepath = reports_dir / filename
        with open(filepath, 'w') as f:
            json.dump(scan_data, f, indent=4, default=str)
        
        return str(filepath)
    
    except Exception as e:
        print(f"Error saving scan results: {e}")
        return None


def generate_html_report(scan_data):
    """
    Generate HTML report from scan results
    
    IMPLEMENT:
    1. Create HTML template
    2. Include scan summary
    3. List all vulnerabilities with details
    4. Add severity color coding
    5. Include remediation suggestions
    6. Save as HTML file
    
    Args:
        scan_data (dict): Complete scan results including:
            - target_url
            - scan_time
            - vulnerabilities
            - risk_score
            
    Returns:
        str: Path to HTML report file
        
    Example:
        report_path = generate_html_report(results)
        print(f"Report generated: {report_path}")
    """
    try:
        target_url = scan_data.get('target_url', 'Unknown')
        scan_time = scan_data.get('scan_time', 'Unknown')
        vulnerabilities = scan_data.get('vulnerabilities', [])
        risk_score = scan_data.get('risk_score', {})
        
        # Generate vulnerability HTML
        vulnerabilities_html = ""
        vulnerability_types = {}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'LOW')
            vuln_type = vuln.get('type', 'Unknown')
            
            # Count vulnerability types
            if vuln_type not in vulnerability_types:
                vulnerability_types[vuln_type] = 0
            vulnerability_types[vuln_type] += 1
            
            # Create vulnerability HTML block
            vuln_html = f"""
            <div class="vulnerability {severity.lower()}">
                <h4>[{severity}] {vuln_type}</h4>
                <p><strong>URL:</strong> {vuln.get('url', 'N/A')}</p>
                <p><strong>Description:</strong> {vuln.get('description', 'No description')}</p>
            """
            
            if 'payload' in vuln:
                vuln_html += f"<p><strong>Payload:</strong> <code>{vuln['payload']}</code></p>"
            
            if 'evidence' in vuln:
                vuln_html += f"<p><strong>Evidence:</strong> {vuln['evidence']}</p>"
            
            if 'form_action' in vuln:
                vuln_html += f"<p><strong>Form Action:</strong> {vuln['form_action']}</p>"
            
            vuln_html += "</div>\n"
            vulnerabilities_html += vuln_html
        
        # Generate remediation advice
        remediation_html = ""
        for vuln_type in vulnerability_types.keys():
            advice = get_remediation_advice(vuln_type)
            remediation_html += f"<h4>{vuln_type}</h4><pre>{advice}</pre>"
        
        # Complete HTML template
        html_content = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Web Vulnerability Scan Report</title>
    <meta charset="utf-8">
    <style>
        body {{ 
            font-family: 'Arial', sans-serif; 
            margin: 20px; 
            background-color: #f5f5f5;
            color: #333;
        }}
        .container {{ 
            max-width: 1200px; 
            margin: 0 auto; 
            background-color: white; 
            padding: 20px; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        h1 {{ 
            color: #2c3e50; 
            text-align: center; 
            margin-bottom: 30px;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{ 
            color: #34495e; 
            margin-top: 30px;
            border-left: 4px solid #3498db;
            padding-left: 15px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 15px 0;
        }}
        .vulnerability {{ 
            border: 1px solid #ddd; 
            margin: 10px 0; 
            padding: 15px; 
            border-radius: 5px;
            background-color: #fafafa;
        }}
        .critical {{ 
            border-left: 5px solid #e74c3c; 
            background-color: #fdf2f2;
        }}
        .high {{ 
            border-left: 5px solid #f39c12; 
            background-color: #fef9e7;
        }}
        .medium {{ 
            border-left: 5px solid #f1c40f; 
            background-color: #fffbea;
        }}
        .low {{ 
            border-left: 5px solid #27ae60; 
            background-color: #eafaf1;
        }}
        code {{ 
            background-color: #2c3e50; 
            color: #ecf0f1; 
            padding: 2px 6px; 
            border-radius: 3px; 
            font-family: 'Courier New', monospace;
        }}
        pre {{ 
            background-color: #2c3e50; 
            color: #ecf0f1; 
            padding: 15px; 
            border-radius: 5px; 
            overflow-x: auto;
            font-size: 14px;
        }}
        .risk-score {{
            font-size: 24px;
            font-weight: bold;
            text-align: center;
            padding: 20px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .risk-critical {{ background-color: #e74c3c; color: white; }}
        .risk-high {{ background-color: #f39c12; color: white; }}
        .risk-medium {{ background-color: #f1c40f; color: #333; }}
        .risk-low {{ background-color: #27ae60; color: white; }}
        .risk-safe {{ background-color: #2ecc71; color: white; }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Web Vulnerability Scan Report</h1>

        <div class="summary">
            <h2>Scan Summary</h2>
            <p><strong>Target URL:</strong> {target_url}</p>
            <p><strong>Scan Time:</strong> {scan_time}</p>
            <p><strong>Total Vulnerabilities:</strong> {len(vulnerabilities)}</p>
            <p><strong>Vulnerability Types:</strong> {len(vulnerability_types)}</p>
        </div>
        
        <div class="risk-score risk-{risk_score.get('level', 'safe').lower()}">
            Risk Level: {risk_score.get('level', 'SAFE')} (Score: {risk_score.get('score', 0)})
        </div>
        
        <h2>Vulnerabilities Found</h2>
        {'<p>No vulnerabilities found.</p>' if not vulnerabilities else vulnerabilities_html}

        <h2>Remediation Recommendations</h2>
        {'<p>No specific recommendations - site appears secure.</p>' if not vulnerability_types else remediation_html}

        <div class="summary">
            <h2>Vulnerability Breakdown</h2>
            <ul>
                <li>Critical: {risk_score.get('breakdown', {}).get('CRITICAL', 0)}</li>
                <li>High: {risk_score.get('breakdown', {}).get('HIGH', 0)}</li>
                <li>Medium: {risk_score.get('breakdown', {}).get('MEDIUM', 0)}</li>
                <li>Low: {risk_score.get('breakdown', {}).get('LOW', 0)}</li>
            </ul>
        </div>
        
        <footer style="text-align: center; margin-top: 50px; padding: 20px; background-color: #ecf0f1; border-radius: 5px;">
            <p><em>Report generated by Web Vulnerability Scanner v1.0</em></p>
            <p>Generated on: {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        </footer>
    </div>
</body>
</html>
"""
        
        # Save HTML report
        target_clean = target_url.replace('http://', '').replace('https://', '')
        target_clean = target_clean.replace('/', '_').replace(':', '_')
        filename = f"report_{target_clean}_{get_timestamp()}.html"
        
        reports_dir = Path("reports")
        reports_dir.mkdir(exist_ok=True)
        
        filepath = reports_dir / filename
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        return str(filepath)
    
    except Exception as e:
        print(f"Error generating HTML report: {e}")
        return None


def get_remediation_advice(vuln_type):
    """
    Get remediation advice for vulnerability type
    
    IMPLEMENT:
    Return fix recommendations based on vulnerability
    
    Args:
        vuln_type (str): Type of vulnerability (XSS, SQLi, CSRF)
        
    Returns:
        str: Remediation advice
    """

    remediation = {
        'XSS': """
        - Sanitize all user input
        - Use Content Security Policy (CSP)
        - Encode output before displaying
        - Use frameworks with auto-escaping
        """,
        'SQL Injection': """
        - Use parameterized queries (prepared statements)
        - Never concatenate user input in SQL
        - Use ORM frameworks
        - Implement least privilege for database accounts
        """,
        'CSRF': """
        - Implement CSRF tokens in all forms
        - Use SameSite cookie attribute
        - Validate Origin/Referer headers
        - Require re-authentication for sensitive actions
        """
    }
    return remediation.get(vuln_type, "Consult security documentation")


def print_banner():
    """
    Print tool banner/logo
    
    IMPLEMENT:
    Create ASCII art banner for the tool
    """
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   WEB VULNERABILITY SCANNER v1.0 - Professional Edition       ║
║                                                               ║
║   Automated security testing for web applications            ║
║   Detects: XSS, SQLi, CSRF and related issues                ║
║                                                               ║
║   [NOTICE] FOR AUTHORIZED TESTING ONLY                        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def print_scan_summary(vulnerabilities):
    """
    Print colored summary of scan results
    
    IMPLEMENT:
    1. Count vulnerabilities by type and severity
    2. Print formatted summary
    3. Use colors for severity levels
    
    Args:
        vulnerabilities (list): List of found vulnerabilities
    """
    try:
        from colorama import init, Fore, Style
        init()  # Initialize colorama
    except ImportError:
        # Fallback if colorama not available
        class Fore:
            RED = YELLOW = GREEN = BLUE = CYAN = MAGENTA = WHITE = ''
        class Style:
            BRIGHT = RESET_ALL = ''
    
    risk_score = calculate_risk_score(vulnerabilities)
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}SCAN SUMMARY{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    # Overall risk level with colors
    risk_level = risk_score['level']
    if risk_level == 'CRITICAL':
        color = Fore.RED
        icon = "[CRITICAL]"
    elif risk_level == 'HIGH':
        color = Fore.YELLOW
        icon = "[HIGH]"
    elif risk_level == 'MEDIUM':
        color = Fore.YELLOW
        icon = "[MEDIUM]"
    elif risk_level == 'LOW':
        color = Fore.GREEN
        icon = "[LOW]"
    else:
        color = Fore.GREEN
        icon = "[SAFE]"

    print(f"\n{color}{Style.BRIGHT}{icon} RISK LEVEL: {risk_level} (Score: {risk_score['score']}){Style.RESET_ALL}")
    
    # Vulnerability breakdown
    breakdown = risk_score['breakdown']
    print(f"\n{Fore.WHITE}{Style.BRIGHT}Vulnerability Breakdown:{Style.RESET_ALL}")
    print(f"   {Fore.RED}Critical: {breakdown['CRITICAL']}{Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}High:     {breakdown['HIGH']}{Style.RESET_ALL}")
    print(f"   {Fore.YELLOW}Medium:   {breakdown['MEDIUM']}{Style.RESET_ALL}")
    print(f"   {Fore.GREEN}Low:      {breakdown['LOW']}{Style.RESET_ALL}")
    print(f"   {Fore.CYAN}Total:    {breakdown['total']}{Style.RESET_ALL}")
    
    # Vulnerability types
    vuln_types = {}
    for vuln in vulnerabilities:
        vuln_type = vuln.get('type', 'Unknown')
        if vuln_type not in vuln_types:
            vuln_types[vuln_type] = 0
        vuln_types[vuln_type] += 1
    
    if vuln_types:
        print(f"\n{Fore.WHITE}{Style.BRIGHT}Vulnerability Types:{Style.RESET_ALL}")
        for vuln_type, count in vuln_types.items():
            print(f"   {Fore.MAGENTA}{vuln_type}: {count}{Style.RESET_ALL}")
    
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    
    if vulnerabilities:
        print(f"{Fore.YELLOW}Run with --verbose to see detailed vulnerability information{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}No vulnerabilities found. The target appears to be secure.{Style.RESET_ALL}")
    
    print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}\n")


def validate_url(url):
    """
    Check if URL is valid and reachable
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid and reachable, False otherwise
    """
    try:
        from urllib.parse import urlparse
        import requests
        
        # Parse URL
        parsed = urlparse(url)
        
        # Check if has scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Check if reachable (quick HEAD request)
        response = requests.head(url, timeout=10)
        return response.status_code < 400
    
    except:
        return False


def get_domain(url):
    """
    Extract domain from URL
    
    Args:
        url (str): Full URL
        
    Returns:
        str: Domain name
    """
    try:
        from urllib.parse import urlparse
        parsed = urlparse(url)
        return parsed.netloc
    except:
        return url


def sanitize_filename(name):
    """
    Clean filename for saving (remove invalid characters)
    
    Args:
        name (str): Original filename
        
    Returns:
        str: Sanitized filename
    """
    import re
    # Remove invalid filename characters
    sanitized = re.sub(r'[<>:"/\\|?*]', '_', name)
    # Remove multiple underscores
    sanitized = re.sub(r'_+', '_', sanitized)
    # Limit length
    return sanitized[:100] if len(sanitized) > 100 else sanitized


def load_payloads_from_file(filepath):
    """
    Read payloads from text file
    
    Args:
        filepath (str): Path to payload file
        
    Returns:
        list: List of payloads
    """
    payloads = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    payloads.append(line)
    except FileNotFoundError:
        print(f"Payload file not found: {filepath}")
    except Exception as e:
        print(f"Error reading payload file: {e}")
    
    return payloads


def create_scan_session():
    """
    Create a requests session with appropriate headers and settings
    
    Returns:
        requests.Session: Configured session object
    """
    import requests
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    })
    session.timeout = 10
    return session
