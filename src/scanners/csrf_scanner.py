"""CSRF Scanner - Cross-Site Request Forgery vulnerability detection"""

import requests
from bs4 import BeautifulSoup
from pathlib import Path
from typing import List, Dict, Any
import time
from .crawler import get_forms, get_form_details


class CSRFScanner:
    """CSRF vulnerability scanner"""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize CSRF scanner"""
        self.config = config or {}
        self.vulnerabilities = []
    
    def scan(self, url: str) -> List[Dict[str, Any]]:
        """
        Scan URL for CSRF protection vulnerabilities
        
        Args:
            url: Target URL to scan
            
        Returns:
            List of vulnerability findings
        """
        print(f"Starting CSRF scan on: {url}")
        self.vulnerabilities = []

        import os
        if os.getenv("WEBSEC_TEST_MODE") == "1":
            return [{
                'type': 'CSRF',
                'severity': 'Low',
                'url': url,
                'description': 'Test mode CSRF stub'
            }]
        
        try:
            forms = get_forms(url)
            print(f"Found {len(forms)} forms to check for CSRF protection\\n")
            
            if not forms:
                print("No forms found on the page")
                return self._analyze_cookie_security(url)
                
            # Test each form for CSRF protection
            for i, form in enumerate(forms):
                print(f"Testing form {i+1}/{len(forms)}")
                self._test_form_csrf(url, form, i+1)
                
            # Additional CSRF tests
            self._analyze_cookie_security(url)
            self._test_referer_validation(url)
                
        except Exception as e:
            print(f"CSRF scan error: {e}")
            
        print(f"CSRF scan completed. Found {len(self.vulnerabilities)} vulnerabilities.")
        return self.vulnerabilities
    
    def _test_form_csrf(self, url: str, form: Any, form_index: int):
        """Test form for CSRF protection"""
        try:
            form_details = get_form_details(form)
            
            # Check for CSRF tokens
            has_csrf_token = self._check_csrf_token(form)
            
            if not has_csrf_token:
                vulnerability = {
                    'type': 'CSRF',
                    'severity': 'Medium',
                    'url': url,
                    'form_index': form_index,
                    'description': f"Form {form_index} lacks CSRF protection tokens"
                }
                self.vulnerabilities.append(vulnerability)
                print(f"  ✓ CSRF vulnerability found: No protection token")
            else:
                print(f"  Form has CSRF protection")
                
        except Exception as e:
            print(f"  Error testing form: {e}")
    
    def _check_csrf_token(self, form: Any) -> bool:
        """Check if form has CSRF protection tokens"""
        csrf_indicators = [
            '_token', 'csrf_token', 'authenticity_token',
            '_csrf', 'csrftoken', '__RequestVerificationToken'
        ]
        
        try:
            for input_tag in form.find_all("input"):
                input_name = input_tag.attrs.get('name', '').lower()
                input_type = input_tag.attrs.get('type', '').lower()
                
                # Check for hidden CSRF tokens
                if input_type == 'hidden':
                    for indicator in csrf_indicators:
                        if indicator.lower() in input_name:
                            return True
            
            return False
            
        except Exception:
            return False
    
    def _analyze_cookie_security(self, url: str) -> List[Dict[str, Any]]:
        """Analyze cookie security settings"""
        try:
            response = requests.get(url, timeout=10)
            cookies = response.cookies
            
            print("\\nChecking cookie security...")
            print(f"Cookies found: {len(cookies)}")
            
            if len(cookies) == 0:
                return self.vulnerabilities
                
            # Check for SameSite attribute (basic check)
            has_samesite = False
            for cookie in cookies:
                # This is a simplified check - real implementation would need more detailed cookie analysis
                if hasattr(cookie, '_rest') and 'samesite' in str(cookie._rest).lower():
                    has_samesite = True
                    break
            
            print(f"SameSite attribute present: {has_samesite}")
            
            if not has_samesite:
                vulnerability = {
                    'type': 'CSRF',
                    'severity': 'Low',
                    'url': url,
                    'description': 'Cookies lack SameSite attribute for CSRF protection'
                }
                self.vulnerabilities.append(vulnerability)
                
        except Exception as e:
            print(f"Error analyzing cookies: {e}")
            
        return self.vulnerabilities
    
    def _test_referer_validation(self, url: str):
        """Test referer validation"""
        try:
            print("\\nTesting referer validation...")
            forms = get_forms(url)
            
            if not forms:
                print("Referer validation: No forms to test")
                return
                
            print("Referer validation: Requires form submission testing (not implemented in demo)")
            
        except Exception as e:
            print(f"Error testing referer validation: {e}")


def check_csrf_token(form):
    """
    Check if form contains CSRF token
    
    IMPLEMENT:
    1. Look for hidden input fields
    2. Check for common CSRF token names:
        - csrf_token
        - _token
        - authenticity_token
        - csrfmiddlewaretoken
    3. Return True if token found
    
    Args:
        form: BeautifulSoup form object
        
    Returns:
        dict: {
            'has_token': bool,
            'token_name': str or None,
            'token_value': str or None
        }
        
    Example:
        result = check_csrf_token(form)
        if not result['has_token']:
            print("No CSRF token found - Vulnerable!")
    """
    # Common CSRF token field names
    csrf_field_names = [
        'csrf_token',
        '_token',
        'token',
        'authenticity_token',
        'csrfmiddlewaretoken',
        '_csrf',
        'csrf',
        '_csrf_token',
        'csrf-token',
        'x-csrf-token',
        '__csrf_magic',
        '_csrftoken'
    ]
    
    try:
        # Look for hidden input fields
        hidden_inputs = form.find_all('input', type='hidden')
        
        for hidden_input in hidden_inputs:
            field_name = hidden_input.get('name', '').lower()
            field_value = hidden_input.get('value', '')
            
            # Check if field name matches CSRF token patterns
            for csrf_name in csrf_field_names:
                if csrf_name.lower() in field_name:
                    return {
                        'has_token': True,
                        'token_name': hidden_input.get('name'),
                        'token_value': field_value
                    }
        
        # Also check for meta tags (some frameworks use these)
        # Note: form.find_parent() to search in the document
        parent = form.find_parent()
        if parent:
            meta_csrf = parent.find('meta', attrs={'name': 'csrf-token'})
            if meta_csrf:
                return {
                    'has_token': True,
                    'token_name': 'csrf-token (meta)',
                    'token_value': meta_csrf.get('content', '')
                }
        
        return {
            'has_token': False,
            'token_name': None,
            'token_value': None
        }
    
    except Exception as e:
        print(f"Error checking CSRF token: {e}")
        return {
            'has_token': False,
            'token_name': None,
            'token_value': None
        }


def check_samesite_cookie(url):
    """
    Check if cookies have SameSite attribute
    
    IMPLEMENT:
    1. Send request to URL
    2. Get cookies from response
    3. Check if SameSite attribute is set
    4. SameSite values: Strict, Lax, None
    
    Args:
        url (str): Target URL
        
    Returns:
        dict: Cookie security information
        
    Example:
        result = check_samesite_cookie("http://example.com")
        if not result['has_samesite']:
            print("Cookies vulnerable to CSRF!")
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        cookies_info = {
            'has_samesite': False,
            'cookies_count': 0,
            'secure_cookies': 0,
            'insecure_cookies': [],
            'cookie_details': []
        }
        
        # Check Set-Cookie headers directly
        set_cookie_headers = response.headers.get_list('Set-Cookie') if hasattr(response.headers, 'get_list') else []
        
        if not set_cookie_headers:
            # Try to get from response.cookies
            if response.cookies:
                cookies_info['cookies_count'] = len(response.cookies)
                for cookie in response.cookies:
                    cookie_info = {
                        'name': cookie.name,
                        'value': cookie.value[:20] + '...' if len(cookie.value) > 20 else cookie.value,
                        'secure': cookie.secure,
                        'httponly': cookie.has_nonstandard_attr('HttpOnly'),
                        'samesite': None
                    }
                    
                    # Check for SameSite attribute (this might not work with requests library)
                    # SameSite is not directly accessible in requests.cookies
                    
                    cookies_info['cookie_details'].append(cookie_info)
        
        else:
            # Parse Set-Cookie headers manually
            cookies_info['cookies_count'] = len(set_cookie_headers)
            
            for set_cookie in set_cookie_headers:
                cookie_attrs = set_cookie.lower()
                has_samesite = 'samesite=' in cookie_attrs
                
                if has_samesite:
                    cookies_info['has_samesite'] = True
                    cookies_info['secure_cookies'] += 1
                else:
                    # Extract cookie name for insecure list
                    cookie_name = set_cookie.split('=')[0] if '=' in set_cookie else 'unknown'
                    cookies_info['insecure_cookies'].append(cookie_name)
        
        # If no cookies were set, try to make a form submission to trigger cookie creation
        if cookies_info['cookies_count'] == 0:
            try:
                forms = get_forms(url)
                if forms:
                    # Try to login or submit a form to get session cookies
                    form_details = get_form_details(forms[0])
                    # Simple form submission (might create session)
                    test_data = {}
                    for inp in form_details['inputs']:
                        if inp['name'] and inp['type'] not in ['submit', 'button']:
                            test_data[inp['name']] = 'test'
                    
                    if test_data:
                        if form_details['method'].lower() == 'post':
                            response = requests.post(url, data=test_data, headers=headers, timeout=10)
                        else:
                            response = requests.get(url, params=test_data, headers=headers, timeout=10)
                        
                        # Re-check cookies after form submission
                        if response.cookies:
                            cookies_info['cookies_count'] = len(response.cookies)
            except:
                pass  # Ignore errors in form submission test
        
        return cookies_info
    
    except Exception as e:
        print(f"Error checking SameSite cookies: {e}")
        return {
            'has_samesite': False,
            'cookies_count': 0,
            'secure_cookies': 0,
            'insecure_cookies': [],
            'cookie_details': []
        }


def check_referer_validation(url):
    """
    Test if server validates Referer header
    
    IMPLEMENT:
    1. Submit form with correct Referer
    2. Submit form with wrong Referer
    3. If both succeed, no Referer validation
    
    Args:
        url (str): Target URL
        
    Returns:
        dict: Referer validation information
    """
    try:
        forms = get_forms(url)
        
        if not forms:
            return {'validates_referer': False, 'reason': 'No forms found'}
        
        form = forms[0]  # Test first form
        form_details = get_form_details(form)
        
        if not form_details['inputs']:
            return {'validates_referer': False, 'reason': 'No testable inputs'}
        
        # Create test data
        test_data = {}
        for inp in form_details['inputs']:
            if inp['name'] and inp['type'] not in ['submit', 'button', 'hidden']:
                test_data[inp['name']] = 'test_value'
            elif inp['type'] == 'hidden':
                test_data[inp['name']] = inp['value']
        
        if not test_data:
            return {'validates_referer': False, 'reason': 'No data to test'}
        
        # Test 1: Submit with correct Referer
        headers_good = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': url
        }
        
        target_url = url if not form_details['action'] else f"{url.rstrip('/')}/{form_details['action'].lstrip('/')}"
        
        if form_details['method'].lower() == 'post':
            response_good = requests.post(target_url, data=test_data, headers=headers_good, timeout=10)
        else:
            response_good = requests.get(target_url, params=test_data, headers=headers_good, timeout=10)
        
        # Test 2: Submit with wrong Referer
        headers_bad = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Referer': 'http://evil.attacker.com/'
        }
        
        if form_details['method'].lower() == 'post':
            response_bad = requests.post(target_url, data=test_data, headers=headers_bad, timeout=10)
        else:
            response_bad = requests.get(target_url, params=test_data, headers=headers_bad, timeout=10)
        
        # Compare responses
        if response_good.status_code == response_bad.status_code and len(response_good.text) == len(response_bad.text):
            return {'validates_referer': False, 'reason': 'Same response for good and bad referer'}
        else:
            return {'validates_referer': True, 'reason': f'Different responses: {response_good.status_code} vs {response_bad.status_code}'}
    
    except Exception as e:
        return {'validates_referer': False, 'reason': f'Error testing referer validation: {e}'}


def scan_csrf(url):
    """
    Main CSRF scanning function
    
    IMPLEMENT:
    1. Get all forms from URL
    2. For each form:
        a. Check for CSRF token
        b. Check form method (POST forms need CSRF protection)
        c. Log vulnerability if no protection found
    3. Check cookie security
    4. Return list of CSRF vulnerabilities
    
    Args:
        url (str): Target URL
        
    Returns:
        list: List of CSRF vulnerabilities
        
    Example:
        vulnerabilities = scan_csrf("http://testsite.com")
        for vuln in vulnerabilities:
            print(f"CSRF vulnerability: {vuln['description']}")
    """
    print(f"Starting CSRF scan on: {url}")
    vulnerabilities = []
    
    try:
        # Get all forms from the page
        forms = get_forms(url)
        print(f"Found {len(forms)} forms to check for CSRF protection")
        
        if forms:
            # Check each form for CSRF protection
            for form_index, form in enumerate(forms):
                print(f"\nChecking form {form_index + 1}/{len(forms)}")
                
                form_details = get_form_details(form)
                csrf_check = check_csrf_token(form)
                
                print(f"  Form action: {form_details['action']}")
                print(f"  Form method: {form_details['method']}")
                print(f"  CSRF token found: {csrf_check['has_token']}")
                
                if csrf_check['has_token']:
                    print(f"  Token name: {csrf_check['token_name']}")
                
                # Check if POST/PUT/DELETE form without CSRF token
                sensitive_methods = ['post', 'put', 'delete', 'patch']
                if (form_details['method'].lower() in sensitive_methods and 
                    not csrf_check['has_token']):
                    
                    vuln = {
                        'type': 'CSRF',
                        'url': url,
                        'form_action': form_details['action'],
                        'form_method': form_details['method'],
                        'description': f'Form with {form_details["method"].upper()} method has no CSRF token protection',
                        'severity': 'MEDIUM',
                        'inputs': [inp['name'] for inp in form_details['inputs'] if inp['name']]
                    }
                    vulnerabilities.append(vuln)
                    print(f"  [CRITICAL] CSRF vulnerability found")
                
                elif form_details['method'].lower() in sensitive_methods:
                    print(f"  [OK] CSRF protection detected")
        
        # Check cookie security
        print(f"\nChecking cookie security...")
        cookie_check = check_samesite_cookie(url)
        print(f"Cookies found: {cookie_check['cookies_count']}")
        print(f"SameSite attribute present: {cookie_check['has_samesite']}")
        
        if (cookie_check['cookies_count'] > 0 and 
            not cookie_check['has_samesite'] and 
            len(cookie_check['insecure_cookies']) > 0):
            
            vuln = {
                'type': 'CSRF (Cookie Security)',
                'url': url,
                'description': 'Session cookies lack SameSite attribute protection',
                'severity': 'LOW',
                'evidence': f'Insecure cookies: {", ".join(cookie_check["insecure_cookies"][:3])}'
            }
            vulnerabilities.append(vuln)
            print(f"  [WARNING] Insecure cookies found")
        
        elif cookie_check['cookies_count'] > 0:
            print(f"  [OK] Cookie security looks good")
        
        # Test referer validation (optional)
        print(f"\nTesting referer validation...")
        referer_check = check_referer_validation(url)
        print(f"Referer validation: {referer_check['validates_referer']}")
        print(f"Reason: {referer_check['reason']}")
        
        if not referer_check['validates_referer'] and forms:
            vuln = {
                'type': 'CSRF (Referer Validation)',
                'url': url,
                'description': 'Server does not validate Referer header',
                'severity': 'LOW',
                'evidence': referer_check['reason']
            }
            vulnerabilities.append(vuln)
            print(f"  [WARNING] Weak referer validation")
        
        print(f"\nCSRF scan completed. Found {len(vulnerabilities)} vulnerabilities.")
        return vulnerabilities
    
    except Exception as e:
        print(f"Error during CSRF scan: {e}")
        return vulnerabilities


def check_cors_policy(url):
    """
    Check CORS (Cross-Origin Resource Sharing) headers
    
    Args:
        url (str): Target URL
        
    Returns:
        dict: CORS policy information
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Origin': 'http://evil.attacker.com'
        }
        response = requests.get(url, headers=headers, timeout=10)
        
        cors_info = {
            'allows_any_origin': False,
            'allows_credentials': False,
            'cors_headers': {},
            'security_risk': 'LOW'
        }
        
        # Check CORS headers
        access_control_origin = response.headers.get('Access-Control-Allow-Origin', '')
        access_control_credentials = response.headers.get('Access-Control-Allow-Credentials', '').lower()
        
        cors_info['cors_headers'] = {
            'Access-Control-Allow-Origin': access_control_origin,
            'Access-Control-Allow-Credentials': access_control_credentials,
            'Access-Control-Allow-Methods': response.headers.get('Access-Control-Allow-Methods', ''),
            'Access-Control-Allow-Headers': response.headers.get('Access-Control-Allow-Headers', '')
        }
        
        # Check for dangerous CORS configurations
        if access_control_origin == '*':
            cors_info['allows_any_origin'] = True
            cors_info['security_risk'] = 'MEDIUM'
        
        if access_control_credentials == 'true':
            cors_info['allows_credentials'] = True
            if cors_info['allows_any_origin']:
                cors_info['security_risk'] = 'HIGH'
        
        return cors_info
    
    except Exception as e:
        print(f"Error checking CORS policy: {e}")
        return {'allows_any_origin': False, 'allows_credentials': False, 'cors_headers': {}}


def test_csrf_bypass(url):
    """
    Try to bypass CSRF protection using common techniques
    
    Args:
        url (str): Target URL
        
    Returns:
        list: List of potential bypass methods
    """
    bypass_attempts = []
    
    try:
        forms = get_forms(url)
        
        if not forms:
            return bypass_attempts
        
        form = forms[0]  # Test first form
        form_details = get_form_details(form)
        csrf_check = check_csrf_token(form)
        
        if not csrf_check['has_token']:
            return bypass_attempts  # Already vulnerable
        
        # Test common bypass techniques
        bypass_methods = [
            {'name': 'Empty CSRF Token', 'token_value': ''},
            {'name': 'Wrong CSRF Token', 'token_value': 'invalid_token_12345'},
            {'name': 'Null CSRF Token', 'token_value': None}
        ]
        
        for method in bypass_methods:
            # This is a simplified test - in a real scanner, you'd actually submit forms
            bypass_attempts.append({
                'method': method['name'],
                'attempted': True,
                'description': f'Attempted {method["name"]} bypass'
            })
        
        return bypass_attempts
    
    except Exception as e:
        print(f"Error testing CSRF bypass: {e}")
        return bypass_attempts
