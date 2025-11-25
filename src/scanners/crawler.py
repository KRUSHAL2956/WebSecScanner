"""
scanner/crawler.py

PURPOSE:
This module crawls websites and finds all forms and input fields.
It's like a robot that explores a website and maps out all the places 
where users can input data.

WHAT TO IMPLEMENT:
1. get_forms(url) - Find all forms on a webpage
2. get_form_details(form) - Extract form attributes (action, method, inputs)
3. submit_form(form_details, url, value) - Submit form with test data
4. crawl_links(url, max_depth) - Discover all pages on website

LIBRARIES NEEDED:
- requests (for making HTTP requests)
- BeautifulSoup (for parsing HTML)
- urllib.parse (for handling URLs)
"""

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse


def get_forms(url):
    """
    Find all HTML forms on a given URL
    
    IMPLEMENT:
    1. Send GET request to the URL
    2. Parse HTML with BeautifulSoup
    3. Find all <form> tags
    4. Return list of forms
    
    Args:
        url (str): The target URL to scan
        
    Returns:
        list: List of BeautifulSoup form objects
        
    Example:
        forms = get_forms("http://example.com")
        print(f"Found {len(forms)} forms")
    """
    try:
        # Send GET request with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Parse HTML content
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # Find all form tags
        forms = soup.find_all('form')
        
        return forms
    
    except requests.exceptions.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return []
    except Exception as e:
        print(f"Error parsing forms from {url}: {e}")
        return []


def get_form_details(form):
    """
    Extract all details from a form element
    
    IMPLEMENT:
    1. Get form action (where form submits to)
    2. Get form method (GET or POST)
    3. Find all input fields in the form
    4. Extract input names, types, and values
    5. Return organized dictionary
    
    Args:
        form: BeautifulSoup form object
        
    Returns:
        dict: Dictionary containing:
            - action: URL where form submits
            - method: GET or POST
            - inputs: List of all input fields
            
    Example:
        details = get_form_details(form)
        print(details['action'])  # /login
        print(details['method'])  # POST
    """
    try:
        # Extract form attributes
        action = form.get('action', '')
        method = form.get('method', 'get').lower()
        
        # Find all input elements
        inputs = []
        
        # Get regular input fields
        for input_tag in form.find_all('input'):
            input_details = {
                'name': input_tag.get('name', ''),
                'type': input_tag.get('type', 'text'),
                'value': input_tag.get('value', ''),
                'placeholder': input_tag.get('placeholder', ''),
                'required': input_tag.has_attr('required')
            }
            inputs.append(input_details)
        
        # Get textarea fields
        for textarea in form.find_all('textarea'):
            input_details = {
                'name': textarea.get('name', ''),
                'type': 'textarea',
                'value': textarea.get_text(),
                'placeholder': textarea.get('placeholder', ''),
                'required': textarea.has_attr('required')
            }
            inputs.append(input_details)
        
        # Get select fields
        for select in form.find_all('select'):
            # Find selected option or first option
            selected_option = select.find('option', selected=True)
            if not selected_option:
                selected_option = select.find('option')
            
            value = selected_option.get('value', '') if selected_option else ''
            
            input_details = {
                'name': select.get('name', ''),
                'type': 'select',
                'value': value,
                'placeholder': '',
                'required': select.has_attr('required')
            }
            inputs.append(input_details)
        
        return {
            'action': action,
            'method': method,
            'inputs': inputs
        }
    
    except Exception as e:
        print(f"Error extracting form details: {e}")
        return {
            'action': '',
            'method': 'get',
            'inputs': []
        }


def submit_form(form_details, url, value):
    """
    Submit a form with test/payload data
    
    IMPLEMENT:
    1. Build data dictionary from form inputs
    2. Fill each input with the test value (payload)
    3. Determine target URL (form action)
    4. Submit form using appropriate method (GET/POST)
    5. Return response
    
    Args:
        form_details (dict): Form details from get_form_details()
        url (str): Base URL of the page
        value (str): Test value/payload to inject
        
    Returns:
        requests.Response: Response from form submission
        
    Example:
        response = submit_form(form_details, url, "<script>alert('XSS')</script>")
    """
    try:
        # Build form data dictionary
        data = {}
        
        for input_field in form_details['inputs']:
            input_name = input_field['name']
            input_type = input_field['type']
            
            # Skip submit buttons, reset buttons, and empty names
            if not input_name or input_type in ['submit', 'button', 'reset', 'image']:
                continue
            
            # For password fields and hidden fields, use existing value if available
            if input_type == 'password' and input_field['value']:
                data[input_name] = input_field['value']
            elif input_type == 'hidden':
                data[input_name] = input_field['value']
            elif input_type == 'checkbox' or input_type == 'radio':
                # For checkboxes and radio buttons, use original value or 'on'
                data[input_name] = input_field['value'] or 'on'
            else:
                # For text inputs, inject our test value/payload
                data[input_name] = value
        
        # Determine target URL
        target_url = urljoin(url, form_details['action']) if form_details['action'] else url
        
        # Set headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        
        # Submit form based on method
        if form_details['method'].lower() == 'post':
            response = requests.post(target_url, data=data, headers=headers, timeout=10, allow_redirects=True)
        else:
            response = requests.get(target_url, params=data, headers=headers, timeout=10, allow_redirects=True)
        
        return response
    
    except requests.exceptions.RequestException as e:
        print(f"Error submitting form to {target_url}: {e}")
        return None
    except Exception as e:
        print(f"Error processing form submission: {e}")
        return None


def crawl_links(url, max_depth=2):
    """
    Discover all links on a website (recursive crawling)
    
    IMPLEMENT:
    1. Visit the URL
    2. Find all links (<a> tags)
    3. Follow links up to max_depth
    4. Avoid visiting same URL twice
    5. Return list of all discovered URLs
    
    Args:
        url (str): Starting URL
        max_depth (int): How deep to crawl (default: 2)
        
    Returns:
        set: Set of all discovered URLs
        
    Example:
        urls = crawl_links("http://example.com", max_depth=2)
        print(f"Found {len(urls)} pages")
    """
    visited_urls = set()
    to_visit = [(url, 0)]  # (url, depth)
    base_domain = urlparse(url).netloc
    
    def get_all_links(page_url):
        """Helper function to extract all links from a page"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(page_url, headers=headers, timeout=10)
            response.raise_for_status()
            
            soup = BeautifulSoup(response.content, 'html.parser')
            links = set()
            
            # Find all anchor tags with href attributes
            for link in soup.find_all('a', href=True):
                href = link['href']
                
                # Convert relative URLs to absolute
                full_url = urljoin(page_url, href)
                
                # Only include HTTP/HTTPS URLs from the same domain
                parsed_url = urlparse(full_url)
                if (parsed_url.scheme in ['http', 'https'] and 
                    parsed_url.netloc == base_domain):
                    
                    # Remove fragment identifiers (#section)
                    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if parsed_url.query:
                        clean_url += f"?{parsed_url.query}"
                    
                    links.add(clean_url)
            
            return links
        
        except Exception as e:
            print(f"Error crawling {page_url}: {e}")
            return set()
    
    # Breadth-first crawling
    while to_visit:
        current_url, depth = to_visit.pop(0)
        
        # Skip if already visited or max depth exceeded
        if current_url in visited_urls or depth > max_depth:
            continue
        
        visited_urls.add(current_url)
        print(f"Crawling: {current_url} (depth: {depth})")
        
        # Get all links from current page
        if depth < max_depth:
            links = get_all_links(current_url)
            
            # Add new links to visit queue
            for link in links:
                if link not in visited_urls:
                    to_visit.append((link, depth + 1))
    
    return visited_urls


# Helper function - Already implemented as example
def is_valid_url(url):
    """
    Check if URL is valid
    
    Args:
        url (str): URL to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    parsed = urlparse(url)
    return bool(parsed.netloc) and bool(parsed.scheme)


def get_all_links(url):
    """
    Get all links from a single page
    
    Args:
        url (str): URL to extract links from
        
    Returns:
        set: Set of all links found on the page
    """
    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        soup = BeautifulSoup(response.content, 'html.parser')
        links = set()
        
        for link in soup.find_all('a', href=True):
            href = link['href']
            full_url = urljoin(url, href)
            if is_valid_url(full_url):
                links.add(full_url)
        
        return links
    
    except Exception as e:
        print(f"Error getting links from {url}: {e}")
        return set()


def is_same_domain(url1, url2):
    """
    Check if two URLs are from the same domain
    
    Args:
        url1 (str): First URL
        url2 (str): Second URL
        
    Returns:
        bool: True if same domain, False otherwise
    """
    try:
        domain1 = urlparse(url1).netloc
        domain2 = urlparse(url2).netloc
        return domain1 == domain2
    except:
        return False


def clean_url(url):
    """
    Remove fragments and normalize URL
    
    Args:
        url (str): URL to clean
        
    Returns:
        str: Cleaned URL
    """
    try:
        parsed = urlparse(url)
        clean = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        if parsed.query:
            clean += f"?{parsed.query}"
        return clean
    except:
        return url
