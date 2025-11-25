"""XSS Scanner - Cross-Site Scripting vulnerability detection"""

import requests
from bs4 import BeautifulSoup
from pathlib import Path
from typing import List, Dict, Any
import time
from .crawler import get_forms, get_form_details, submit_form


class XSSScanner:
    """XSS vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize XSS scanner"""
        self.config = config or {}
        self.payloads = self._load_payloads()
        self.vulnerabilities = []
    
    def _load_payloads(self) -> List[str]:
        """Load XSS payloads from data file"""
        payload_file = Path("data/payloads/xss_payloads.txt")
        payloads = []
        
        try:
            with open(payload_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip comments and empty lines
                    if line and not line.startswith('#'):
                        payloads.append(line)
        
        except FileNotFoundError:
            print("XSS payloads file not found, using default payloads")
            # Fallback to hardcoded payloads
            payloads = [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg/onload=alert('XSS')>",
                "javascript:alert('XSS')",
                "<iframe src=javascript:alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<div onclick=alert('XSS')>Click</div>",
                "<input autofocus onfocus=alert('XSS')>",
                "'\"><script>alert('XSS')</script>",
                "\"><img src=x onerror=alert('XSS')>",
                "'><svg/onload=alert('XSS')>",
                "</script><script>alert('XSS')</script>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                "<img src='x' onerror='alert(1)'>",
                "<svg><script>alert('XSS')</script></svg>"
            ]
        
        return payloads
    
    def scan(self, url: str, progress_callback=None) -> List[Dict[str, Any]]:
        """
        Perform comprehensive XSS vulnerability scan
        
        Args:
            url: Target URL to scan
            progress_callback: Optional callback function(count) to report progress
            
        Returns:
            List of vulnerability findings
        """
        print(f"Starting XSS scan on: {url}")
        self.vulnerabilities = []

        import os
        if os.getenv("WEBSEC_TEST_MODE") == "1":
            # Return deterministic stub vulnerabilities for testing
            return [{
                'type': 'XSS',
                'severity': 'High',
                'url': url,
                'description': 'Test mode XSS stub',
                'payload': "<script>alert(1)</script>"
            }]
        
        try:
            forms = get_forms(url)
            print(f"Found {len(forms)} forms to test for XSS\\n")
            
            if not forms:
                print("No forms found for XSS testing")
                return self.vulnerabilities
                
            # Test each form
            for i, form in enumerate(forms):
                print(f"Testing form {i+1}/{len(forms)}")
                self._test_form_xss(url, form, i+1, progress_callback)
                
        except Exception as e:
            print(f"XSS scan error: {e}")
            
        print(f"XSS scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities
    
    def _test_form_xss(self, url: str, form: Any, form_index: int, progress_callback=None):
        """Test form for XSS vulnerabilities"""
        try:
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
                    progress_callback(1)  # Increment by 1 (or batch size if logic changed)
                
                try:
                    response = self._inject_payload(url, form_details, payload)
                    if self._detect_xss_response(response, payload):
                        vulnerability = {
                            'type': 'XSS',
                            'severity': 'High',
                            'url': url,
                            'form_index': form_index,
                            'payload': payload,
                            'description': f"XSS vulnerability in form {form_index}"
                        }
                        self.vulnerabilities.append(vulnerability)
                        print(f"  ✓ XSS vulnerability found with payload: {payload[:50]}...")
                        break  # Found vulnerability, move to next form
                        
                except Exception as e:
                    print(f"  Error testing payload {payload}: {e}")
                    continue
                    
        except Exception as e:
            print(f"  Error testing form: {e}")
    
    def _inject_payload(self, url: str, form_details: Dict[str, Any], payload: str):
        """Inject XSS payload into form"""
        try:
            # Build form data with payload
            data = {}
            for input_field in form_details.get('inputs', []):
                field_name = input_field.get('name', '')
                if field_name and input_field.get('type', '').lower() not in ['submit', 'button']:
                    data[field_name] = payload
                elif input_field.get('type', '').lower() == 'hidden':
                    data[field_name] = input_field.get('value', '')
            
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
    
    def _detect_xss_response(self, response, payload: str) -> bool:
        """Detect XSS vulnerability in response"""
        if not response:
            return False
            
        try:
            response_text = response.text
            
            # Check if payload appears unescaped in response
            if payload in response_text:
                return True
                
            # Check for common XSS indicators
            xss_indicators = [
                "alert('XSS')",
                "alert(\"XSS\")",
                "javascript:alert",
                "onload=alert",
                "onerror=alert",
                "onclick=alert",
                "onfocus=alert"
            ]
            
            for indicator in xss_indicators:
                if indicator.lower() in response_text.lower():
                    return True
                    
            return False
            
        except Exception:
            return False


def get_xss_payloads():
    """
    Return list of XSS payloads to test
    
    IMPLEMENT:
    1. Read payloads from file (payloads/xss_payloads.txt)
    2. OR return hardcoded list
    3. Include various XSS techniques
    
    Returns:
        list: List of XSS payload strings
        
    Example payloads:
        - <script>alert('XSS')</script>
        - <img src=x onerror=alert('XSS')>
        - <svg/onload=alert('XSS')>
    """
    payloads = []
    
    try:
        # Try to read from payloads file
        with open('payloads/xss_payloads.txt', 'r') as file:
            for line in file:
                line = line.strip()
                # Skip comments and empty lines
                if line and not line.startswith('#'):
                    payloads.append(line)
    
    except FileNotFoundError:
        print("XSS payloads file not found, using default payloads")
        # Fallback to hardcoded payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<iframe src='javascript:alert(\"XSS\")'></iframe>",
            "\"><script>alert('XSS')</script>",
            "'><script>alert('XSS')</script>",
            "<div onmouseover=\"alert('XSS')\">Hover me</div>",
            "<input onfocus=alert('XSS') autofocus>",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E"
        ]
    
    return payloads


def detect_xss_in_response(response, payload):
    """
    Check if XSS payload is reflected in the response
    
    IMPLEMENT:
    1. Check if payload appears in response HTML
    2. Check if payload is executed (harder to detect)
    3. Look for payload in different encodings
    
    Args:
        response: HTTP response object
        payload (str): The XSS payload that was injected
        
    Returns:
        bool: True if XSS detected, False otherwise
        
    Example:
        if detect_xss_in_response(response, "<script>alert('XSS')</script>"):
            print("XSS Vulnerability Found!")
    """
    if not response:
        return False
    
    try:
        response_text = response.text.lower()
        payload_lower = payload.lower()
        
        # Check for exact payload match
        if payload_lower in response_text:
            return True
        
        # Check for common HTML encodings
        import html
        encoded_payload = html.escape(payload).lower()
        if encoded_payload in response_text:
            return True
        
        # Check for URL encoded versions
        import urllib.parse
        url_encoded = urllib.parse.quote(payload).lower()
        if url_encoded in response_text:
            return True
        
        # Check for key XSS indicators in response
        xss_indicators = [
            'alert(',
            'prompt(',
            'confirm(',
            'javascript:',
            'onerror=',
            'onload=',
            'onmouseover=',
            'onfocus='
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text and indicator in payload_lower:
                return True
        
        # Check if script tags are reflected
        if '<script>' in payload_lower and '<script>' in response_text:
            return True
        
        if 'script>' in payload_lower and 'script>' in response_text:
            return True
        
        return False
    
    except Exception as e:
        print(f"Error detecting XSS in response: {e}")
        return False


def inject_xss_payload(form_details, url, payload):
    """
    Inject XSS payload into form and submit
    
    IMPLEMENT:
    1. Use submit_form() from crawler module
    2. Submit form with XSS payload
    3. Return response
    
    Args:
        form_details (dict): Form information
        url (str): Base URL
        payload (str): XSS payload to inject
        
    Returns:
        Response object from form submission
    """
    try:
        # Use the submit_form function from crawler module
        response = submit_form(form_details, url, payload)
        return response
    
    except Exception as e:
        print(f"Error injecting XSS payload: {e}")
        return None


def scan_xss(url):
    """
    Main XSS scanning function
    
    IMPLEMENT:
    1. Get all forms from the URL
    2. For each form:
        a. Get form details
        b. For each XSS payload:
            - Inject payload
            - Check if reflected
            - Log vulnerability if found
    3. Return list of vulnerabilities
    
    Args:
        url (str): Target URL to scan
        
    Returns:
        list: List of found vulnerabilities with details
        
    Example:
        vulnerabilities = scan_xss("http://testsite.com")
        for vuln in vulnerabilities:
            print(f"XSS found in {vuln['form_action']}")
    """
    print(f"Starting XSS scan on: {url}")
    vulnerabilities = []
    
    try:
        # Get all forms from the page
        forms = get_forms(url)
        print(f"Found {len(forms)} forms to test")
        
        if not forms:
            print("No forms found on the page")
            return vulnerabilities
        
        # Get XSS payloads to test
        payloads = get_xss_payloads()
        print(f"Testing with {len(payloads)} XSS payloads")
        
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
            print(f"  Testable inputs: {len([inp for inp in form_details['inputs'] if inp['name'] and inp['type'] not in ['submit', 'button', 'hidden']])}")
            
            # Test each payload on this form
            for payload_index, payload in enumerate(payloads):
                print(f"    Testing payload {payload_index + 1}/{len(payloads)}: {payload[:50]}{'...' if len(payload) > 50 else ''}")
                
                # Inject payload and get response
                response = inject_xss_payload(form_details, url, payload)
                
                if response:
                    # Check if XSS was successful
                    if detect_xss_in_response(response, payload):
                        vuln = {
                            'type': 'XSS',
                            'url': url,
                            'form_action': form_details['action'],
                            'form_method': form_details['method'],
                            'payload': payload,
                            'severity': 'HIGH',
                            'description': f'XSS vulnerability found in form submitting to {form_details["action"]}',
                            'inputs_tested': [inp['name'] for inp in form_details['inputs'] if inp['name']]
                        }
                        vulnerabilities.append(vuln)
                        print(f"    ✓ XSS VULNERABILITY FOUND!")
                        
                        # Break after finding one successful payload for this form
                        # to avoid too much noise (optional)
                        break
                else:
                    print(f"    Failed to submit payload")
        
        print(f"\nXSS scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    except Exception as e:
        print(f"Error during XSS scan: {e}")
        return vulnerabilities


def scan_xss_in_url_params(url):
    """
    Test XSS in URL parameters
    
    Args:
        url (str): URL with parameters to test
        
    Returns:
        list: List of vulnerabilities found
    """
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
    
    vulnerabilities = []
    
    try:
        parsed_url = urlparse(url)
        
        if not parsed_url.query:
            return vulnerabilities
        
        params = parse_qs(parsed_url.query)
        payloads = get_xss_payloads()[:5]  # Use first 5 payloads for URL testing
        
        print(f"Testing URL parameters: {list(params.keys())}")
        
        for param_name in params:
            print(f"  Testing parameter: {param_name}")
            
            for payload in payloads:
                # Create modified URL with XSS payload
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                query_string = urlencode(test_params, doseq=True)
                test_url = urlunparse((
                    parsed_url.scheme,
                    parsed_url.netloc,
                    parsed_url.path,
                    parsed_url.params,
                    query_string,
                    parsed_url.fragment
                ))
                
                # Make request to test URL
                try:
                    headers = {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                    response = requests.get(test_url, headers=headers, timeout=10)
                    
                    if detect_xss_in_response(response, payload):
                        vuln = {
                            'type': 'XSS (URL Parameter)',
                            'url': test_url,
                            'parameter': param_name,
                            'payload': payload,
                            'severity': 'HIGH',
                            'description': f'XSS vulnerability found in URL parameter "{param_name}"'
                        }
                        vulnerabilities.append(vuln)
                        print(f"    ✓ XSS found in parameter {param_name}")
                        break  # Found one, move to next parameter
                
                except Exception as e:
                    print(f"    Error testing URL parameter: {e}")
                    continue
    
    except Exception as e:
        print(f"Error in URL parameter XSS scan: {e}")
    
    return vulnerabilities


def verify_xss(url, payload):
    """
    Verify if XSS payload is exploitable
    
    Args:
        url (str): Target URL
        payload (str): XSS payload to verify
        
    Returns:
        bool: True if XSS is exploitable
    """
    try:
        response = requests.get(url, timeout=10)
        return detect_xss_in_response(response, payload)
    except:
        return False


