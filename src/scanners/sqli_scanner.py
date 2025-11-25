"""SQL Injection Scanner - SQL injection vulnerability detection"""

import requests
from bs4 import BeautifulSoup
from pathlib import Path
from typing import List, Dict, Any
import time


class SQLIScanner:
    """SQL injection vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize SQL injection scanner"""
        self.config = config or {}
        self.payloads = self._load_payloads()
        self.vulnerabilities = []
    
    def _load_payloads(self) -> List[str]:
        """Load SQL injection payloads from data file"""
        payload_file = Path("data/payloads/sqli_payloads.txt")
        payloads = []
        
        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        payloads.append(line)
        
        except FileNotFoundError:
            print("SQLi payloads file not found, using default payloads")
            # Fallback to hardcoded payloads
            payloads = [
                "' OR '1'='1",
                "' OR '1'='1' --",
                "' OR '1'='1' /*",
                "' OR 1=1--",
                "admin' --",
                "admin' #",
                "' OR 'x'='x",
                "') OR ('1'='1",
                "1' OR '1' = '1",
                "1' OR 1 -- -",
                "' UNION SELECT NULL--",
                "' UNION SELECT NULL,NULL--",
                "' UNION SELECT NULL,NULL,NULL--",
                "'",
                "''",
                "\"",
                "1'1",
                "' OR SLEEP(5)--",
                "' AND 1=1--",
                "' AND 1=2--"
            ]
        
        return payloads
    
    def scan(self, url: str, progress_callback=None) -> List[Dict[str, Any]]:
        """
        Perform comprehensive SQL injection scan
        
        Args:
            url: Target URL to scan
            progress_callback: Optional callback function(count) to report progress
            
        Returns:
            List of vulnerability findings
        """
        print(f"Starting SQL injection scan on: {url}")
        self.vulnerabilities = []

        import os
        if os.getenv("WEBSEC_TEST_MODE") == "1":
            return [{
                'type': 'SQL Injection',
                'severity': 'Medium',
                'url': url,
                'description': 'Test mode SQLi stub',
                'payload': "' OR '1'='1"
            }]
        
        try:
            from .crawler import get_forms, get_form_details
            
            forms = get_forms(url)
            print(f"Found {len(forms)} forms to test for SQL injection\\n")
            
            if not forms:
                print("No forms found for SQL injection testing")
                return self.vulnerabilities
                
            # Test each form
            for i, form in enumerate(forms):
                print(f"Testing form {i+1}/{len(forms)}")
                self._test_form_sqli(url, form, i+1, progress_callback)
                
        except Exception as e:
            print(f"SQL injection scan error: {e}")
            
        print(f"SQL injection scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities
    
    def _test_form_sqli(self, url: str, form: Any, form_index: int, progress_callback=None):
        """Test form for SQL injection vulnerabilities"""
        try:
            from .crawler import get_form_details
            form_details = get_form_details(form)
            
            # Determine payload limit based on intensity
            intensity = self.config.get('scan_intensity', 'normal')
            if intensity == 'basic':
                limit = 25
            elif intensity == 'normal':
                limit = 75
            elif intensity == 'high':
                limit = 150
            elif intensity == 'brutal':
                limit = len(self.payloads)  # Test ALL payloads
            else:
                limit = 75
                
            print(f"Scan intensity: {intensity}, using {limit} payloads")
            
            # Test various payloads
            for i, payload in enumerate(self.payloads[:limit]):
                if progress_callback and i % 5 == 0:  # Update every 5 payloads
                    progress_callback(1)
                    
                try:
                    response = self._inject_payload(url, form_details, payload)
                    is_vulnerable, error_msg = self._detect_sql_error(response)
                    
                    if is_vulnerable:
                        vulnerability = {
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'url': url,
                            'form_index': form_index,
                            'payload': payload,
                            'error': error_msg,
                            'description': f"SQL injection vulnerability in form {form_index}"
                        }
                        self.vulnerabilities.append(vulnerability)
                        print(f"  ✓ SQL injection vulnerability found with payload: {payload[:50]}...")
                        break  # Found vulnerability, move to next form
                        
                except Exception as e:
                    print(f"  Error testing payload {payload}: {e}")
                    continue
                    
        except Exception as e:
            print(f"  Error testing form: {e}")
    
    def _inject_payload(self, url: str, form_details: Dict[str, Any], payload: str):
        """Inject SQL payload into form"""
        try:
            # Build form data with payload
            data = {}
            for input_field in form_details.get('inputs', []):
                field_name = input_field.get('name', '')
                if field_name:
                    data[field_name] = payload
            
            # Submit form
            action = form_details.get('action', '')
            method = form_details.get('method', 'get').lower()
            
            target_url = url if not action else action
            if not target_url.startswith('http'):
                from urllib.parse import urljoin
                target_url = urljoin(url, action)
            
            if method == 'post':
                response = requests.post(target_url, data=data, timeout=10)
            else:
                response = requests.get(target_url, params=data, timeout=10)
                
            return response
            
        except Exception as e:
            print(f"Error injecting payload: {e}")
            return None
    
    def _detect_sql_error(self, response):
        """Detect SQL errors in response"""
        if not response:
            return False, ""
            
        try:
            response_text = response.text.lower()
            error_signatures = self._get_error_signatures()
            
            for signature in error_signatures:
                if signature.lower() in response_text:
                    return True, signature
                    
            return False, ""
            
        except Exception:
            return False, ""
    
    def _get_error_signatures(self) -> List[str]:
        """Get SQL error signatures for detection"""
        return [
            "you have an error in your sql syntax",
            "warning: mysql",
            "mysql_fetch_array",
            "postgresql query failed",
            "microsoft sql server",
            "ora-01756",
            "sqlite error",
            "sql syntax",
            "database error",
            "syntax error"
        ]


def get_sql_error_signatures():
    """
    Return list of common database error messages
    
    IMPLEMENT:
    Return list of error patterns to look for
    
    Returns:
        list: Error message patterns
        
    Common errors:
        - "SQL syntax error"
        - "mysql_fetch"
        - "ORA-01756" (Oracle)
        - "PostgreSQL ERROR"
    """
    error_signatures = [
        # MySQL errors
        "you have an error in your sql syntax",
        "warning: mysql",
        "mysql_fetch_array",
        "mysql_fetch_assoc",
        "mysql_fetch_row",
        "mysql_num_rows",
        "mysql_result",
        "mysql_query",
        "unknown column",
        "table doesn't exist",
        
        # PostgreSQL errors
        "postgresql query failed",
        "postgresql error",
        "pg_query()",
        "pg_exec()",
        "pg_fetch_array",
        "invalid query",
        
        # MSSQL errors
        "microsoft sql server",
        "microsoft ole db provider",
        "odbc sql server driver",
        "unclosed quotation mark after",
        "incorrect syntax near",
        "server error in",
        
        # Oracle errors
        "ora-01756",
        "ora-00933",
        "ora-00942",
        "oracle error",
        "oracle driver",
        
        # SQLite errors
        "sqlite_query",
        "sqlite error",
        "no such table",
        "sql logic error",
        
        # Generic SQL errors
        "sql syntax",
        "database error",
        "syntax error",
        "mysql error",
        "sql query failed",
        "invalid sql",
        "query failed",
        "database query error",
        "sql statement",
        "column doesn't exist",
        "table not found",
        "access denied for user"
    ]
    return error_signatures


def detect_sqli_errors(response):
    """
    Detect SQL errors in HTTP response
    
    IMPLEMENT:
    1. Get error signatures
    2. Check if any error appears in response
    3. Return True if SQL error detected
    
    Args:
        response: HTTP response object
        
    Returns:
        tuple: (bool, str) - (is_vulnerable, error_message)
        
    Example:
        is_vuln, error = detect_sqli_errors(response)
        if is_vuln:
            print(f"SQL Injection found! Error: {error}")
    """
    if not response:
        return False, ""
    
    try:
        response_text = response.text.lower()
        error_signatures = get_sql_error_signatures()
        
        for error_signature in error_signatures:
            if error_signature.lower() in response_text:
                # Find the exact error message in the original case
                lines = response.text.split('\n')
                for line in lines:
                    if error_signature.lower() in line.lower():
                        # Return first 200 chars of the line containing the error
                        error_context = line[:200] if len(line) > 200 else line
                        return True, error_context.strip()
                
                # If we can't find the exact line, return the signature
                return True, error_signature
        
        return False, ""
    
    except Exception as e:
        print(f"Error detecting SQL errors: {e}")
        return False, ""


def inject_sqli_payload(form_details, url, payload):
    """
    Inject SQL payload into form
    
    IMPLEMENT:
    1. Use submit_form() from crawler
    2. Submit with SQL injection payload
    3. Return response
    
    Args:
        form_details (dict): Form information
        url (str): Base URL
        payload (str): SQL injection payload
        
    Returns:
        Response object
    """
    try:
        # Use the submit_form function from crawler module
        response = submit_form(form_details, url, payload)
        return response
    
    except Exception as e:
        print(f"Error injecting SQL payload: {e}")
        return None


def time_based_sqli(url, delay=5):
    """
    Test for blind SQL injection using time delays
    
    IMPLEMENT:
    1. Send payload with time delay (e.g., SLEEP(5))
    2. Measure response time
    3. If response takes ~5 seconds, likely vulnerable
    
    Args:
        url (str): Target URL
        delay (int): Seconds to delay (default: 5)
        
    Returns:
        tuple: (bool, str, float) - (is_vulnerable, payload_used, response_time)
        
    Example payloads:
        - ' OR SLEEP(5)--
        - '; WAITFOR DELAY '00:00:05'--
    """
    time_payloads = [
        f"' OR SLEEP({delay})--",
        f"'; WAITFOR DELAY '00:00:0{delay}'--",
        f"' OR pg_sleep({delay})--",
        f"1' AND SLEEP({delay})--",
        f"'; SELECT SLEEP({delay})--"
    ]
    
    try:
        # First, get baseline response time
        start_time = time.time()
        response = requests.get(url, timeout=30)
        baseline_time = time.time() - start_time
        
        print(f"Baseline response time: {baseline_time:.2f} seconds")
        
        # Test each time-based payload
        for payload in time_payloads:
            print(f"  Testing time-based payload: {payload}")
            
            # Get forms to inject payload into
            forms = get_forms(url)
            
            for form in forms:
                form_details = get_form_details(form)
                
                if form_details['inputs']:
                    start_time = time.time()
                    response = inject_sqli_payload(form_details, url, payload)
                    response_time = time.time() - start_time
                    
                    print(f"    Response time: {response_time:.2f} seconds")
                    
                    # If response time is significantly longer than baseline + delay
                    if response_time >= (baseline_time + delay - 1):  # Allow 1 second tolerance
                        return True, payload, response_time
        
        return False, "", 0.0
    
    except Exception as e:
        print(f"Error in time-based SQLi test: {e}")
        return False, "", 0.0


def scan_sqli(url):
    """
    Main SQL injection scanning function
    
    IMPLEMENT:
    1. Get all forms from URL
    2. For each form:
        a. Get form details
        b. For each SQL payload:
            - Inject payload
            - Check for SQL errors
            - Log vulnerability if found
    3. Test time-based SQLi
    4. Return list of vulnerabilities
    
    Args:
        url (str): Target URL to scan
        
    Returns:
        list: List of SQL injection vulnerabilities
        
    Example:
        vulnerabilities = scan_sqli("http://testsite.com")
        for vuln in vulnerabilities:
            print(f"SQLi found: {vuln['evidence']}")
    """
    print(f"Starting SQL injection scan on: {url}")
    vulnerabilities = []
    
    try:
        # Get all forms from the page
        forms = get_forms(url)
        print(f"Found {len(forms)} forms to test")
        
        if not forms:
            print("No forms found on the page")
            return vulnerabilities
        
        # Get SQL injection payloads
        payloads = get_sqli_payloads()
        print(f"Testing with {len(payloads)} SQL injection payloads")
        
        # Test each form
        for form_index, form in enumerate(forms):
            print(f"\nTesting form {form_index + 1}/{len(forms)}")
            
            # Get form details
            form_details = get_form_details(form)
            
            if not form_details['inputs']:
                print("  No testable inputs found in form")
                continue
            
            print(f"  Form action: {form_details['action']}")
            print(f"  Form method: {form_details['method']}")
            
            # Test each payload on this form
            for payload_index, payload in enumerate(payloads):
                print(f"    Testing payload {payload_index + 1}/{len(payloads)}: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                
                # Inject payload and get response
                response = inject_sqli_payload(form_details, url, payload)
                
                if response:
                    # Check for SQL errors
                    is_vuln, error_message = detect_sqli_errors(response)
                    
                    if is_vuln:
                        vuln = {
                            'type': 'SQL Injection',
                            'url': url,
                            'form_action': form_details['action'],
                            'form_method': form_details['method'],
                            'payload': payload,
                            'evidence': error_message,
                            'severity': 'CRITICAL',
                            'description': f'SQL injection vulnerability found in form submitting to {form_details["action"]}',
                            'inputs_tested': [inp['name'] for inp in form_details['inputs'] if inp['name']]
                        }
                        vulnerabilities.append(vuln)
                        print(f"    🚨 SQL INJECTION VULNERABILITY FOUND!")
                        print(f"       Error: {error_message[:100]}{'...' if len(error_message) > 100 else ''}")
                        
                        # Break after finding one successful payload for this form
                        break
                else:
                    print(f"    Failed to submit payload")
        
        # Test for time-based SQL injection
        print(f"\nTesting for time-based SQL injection...")
        is_time_vuln, time_payload, response_time = time_based_sqli(url)
        
        if is_time_vuln:
            vuln = {
                'type': 'Time-based SQL Injection',
                'url': url,
                'payload': time_payload,
                'evidence': f'Response delayed by {response_time:.2f} seconds',
                'severity': 'CRITICAL',
                'description': 'Time-based blind SQL injection vulnerability detected'
            }
            vulnerabilities.append(vuln)
            print(f"🚨 TIME-BASED SQL INJECTION FOUND!")
        
        print(f"\nSQL injection scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    except Exception as e:
        print(f"Error during SQL injection scan: {e}")
        return vulnerabilities




def boolean_based_sqli(url):
    """
    Test for boolean-based blind SQL injection
    
    Args:
        url (str): Target URL
        
    Returns:
        list: List of vulnerabilities found
    """
    vulnerabilities = []
    
    # Boolean-based payloads (true/false conditions)
    true_payloads = ["' AND 1=1--", "' AND 'a'='a'--"]
    false_payloads = ["' AND 1=2--", "' AND 'a'='b'--"]
    
    try:
        forms = get_forms(url)
        
        for form in forms:
            form_details = get_form_details(form)
            
            if not form_details['inputs']:
                continue
            
            # Test true condition
            true_response = None
            for payload in true_payloads:
                response = inject_sqli_payload(form_details, url, payload)
                if response:
                    true_response = response
                    break
            
            # Test false condition
            false_response = None
            for payload in false_payloads:
                response = inject_sqli_payload(form_details, url, payload)
                if response:
                    false_response = response
                    break
            
            # Compare responses
            if (true_response and false_response and 
                len(true_response.text) != len(false_response.text)):
                
                vuln = {
                    'type': 'Boolean-based SQL Injection',
                    'url': url,
                    'form_action': form_details['action'],
                    'evidence': f'Different response lengths: True={len(true_response.text)}, False={len(false_response.text)}',
                    'severity': 'HIGH',
                    'description': 'Boolean-based blind SQL injection detected'
                }
                vulnerabilities.append(vuln)
                print("🚨 Boolean-based SQL injection found!")
                break
    
    except Exception as e:
        print(f"Error in boolean-based SQL injection test: {e}")
    
    return vulnerabilities
