# WebSec Scanner Professional v2.1.0

**Professional Web Application Security Assessment Platform**

A comprehensive, enterprise-grade vulnerability scanner designed for professional security assessments. Features advanced detection capabilities, real-time progress tracking, and professional reporting.

## Key Features

### Security Assessment Capabilities

- **Cross-Site Scripting (XSS)** - Advanced Level
  - 80+ specialized payloads including filter bypasses and WAF evasion
  - Context-aware detection for reflected, stored, and DOM-based XSS
  - Modern browser bypass techniques

- **SQL Injection** - Enterprise Level  
  - 126+ injection patterns covering multiple database types
  - Error-based, boolean-based, and time-based detection
  - NoSQL injection testing capabilities

- **CSRF Protection Analysis** - Professional Level
  - Token validation analysis and cookie security assessment
  - CORS policy evaluation and referer validation testing
  - Session security analysis

### Professional Interface

- **Real-Time Progress Tracking** with live timing estimates
- **Professional Reporting** in JSON and HTML formats
- **Risk Scoring** with comprehensive vulnerability analysis
- **Assessment History** with searchable scan records

## Project Structure

```
WebSecScanner/
├── app.py                 # Main application entry point
├── config/               # Configuration files
│   └── settings.json    # Application settings
├── src/                 # Source code
│   ├── core/           # Core utilities
│   │   └── utils.py    # Security utilities and helpers
│   ├── scanners/       # Vulnerability scanners
│   │   ├── xss_scanner.py     # XSS detection engine
│   │   ├── sqli_scanner.py    # SQL injection scanner
│   │   ├── csrf_scanner.py    # CSRF analysis module
│   │   └── crawler.py         # Web crawling utilities
│   └── web/            # Web interface
│       ├── app.py      # Flask application (legacy)
│       ├── static/     # CSS, JS assets
│       └── templates/  # HTML templates
├── data/               # Application data
│   └── payloads/      # Security test payloads
│       ├── xss_payloads.txt   # XSS attack vectors
│       └── sqli_payloads.txt  # SQL injection payloads
├── output/            # Generated reports
│   └── reports/       # JSON and HTML reports
├── tests/             # Test suite
├── docs/              # Documentation
└── requirements.txt   # Python dependencies
```

## Quick Start

### Prerequisites

- Python 3.8+ 
- Virtual environment support

### Installation

1. **Clone and Navigate**
   ```bash
   git clone https://github.com/KRUSHAL2956/Cyber-Security.git
   cd WebSecScanner
   ```

2. **Setup Environment**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # Linux/Mac
   # OR
   .venv\Scripts\activate     # Windows
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**

**Crucial Step**: You must activate the virtual environment first!

```bash
# Linux/MacOS
source .venv/bin/activate

# Windows
.venv\Scripts\activate
```

Once activated (you'll see `(.venv)` in your terminal), run:

```bash
python app.py
```

5. **Access Interface**
   - Open: http://localhost:5000
   - Professional security assessment interface

### Environment Configuration
**Important**: You must set the following environment variables in a `.env` file or your shell:

```bash
MONGO_URI="mongodb+srv://your_user:your_password@cluster.mongodb.net/"
FLASK_SECRET_KEY="your_secure_random_key"
```

## Configuration Options

### Crawl Depth
- **Surface (1)**: Basic page scanning
- **Standard (2)**: Moderate depth analysis  
- **Deep (5)**: Comprehensive crawling

### Assessment Modes
- **Quick**: Basic vulnerability detection (10 payloads/module)
- **Standard**: Comprehensive analysis (50 payloads/module)
- **Thorough**: Deep investigation (100+ payloads/module)

## Assessment Capabilities

| Module | Level | Payloads | Detection Types |
|--------|-------|----------|----------------|
| XSS | Advanced | 80+ | Reflected, Stored, DOM-based |
| SQL Injection | Enterprise | 126+ | Error-based, Boolean, Time-based |
| CSRF | Professional | 24+ | Token, Cookie, CORS Analysis |

## Professional Features

### Real-Time Monitoring
- Live progress tracking with timing estimates
- Connection status monitoring with retry logic
- Detailed test execution visibility

### Professional Reporting
- Comprehensive HTML reports with risk scoring
- Machine-readable JSON output for integration
- Vulnerability categorization and severity scoring

### Enterprise Integration
- RESTful API for status monitoring
- Configurable assessment parameters
- Extensible scanner architecture

## Security Assessment Process

1. **Target Configuration**: Enter application URL and select modules
2. **Assessment Execution**: Real-time scanning with progress tracking  
3. **Vulnerability Analysis**: Professional risk scoring and categorization
4. **Report Generation**: Comprehensive findings with remediation guidance

## API Reference

### Scan Management
- `POST /scan` - Initialize security assessment
- `GET /status/<scan_id>` - Real-time progress monitoring
- `GET /reports` - Assessment history overview

### Data Formats
- **Input**: Form-based configuration with JSON API support  
- **Output**: Professional HTML reports + JSON data export

## Testing & Quality

### Test Coverage
- 230+ total security tests across all modules
- Comprehensive payload coverage for major vulnerability types
- Real-world attack simulation capabilities

### Quality Assurance
- Professional code structure with type hints
- Comprehensive error handling and logging
- Responsive UI with real-time feedback

## Professional Use Cases

- **Security Audits**: Comprehensive vulnerability assessments
- **Penetration Testing**: Professional security evaluation
- **Compliance Scanning**: Regular security monitoring
- **Development Integration**: CI/CD security validation

## Support & Documentation

- **Version**: 2.1.0 Professional Edition
- **Platform**: Cross-platform (Windows, Linux, macOS)  
- **License**: Professional Security Assessment Platform
- **Author**: KRUSHAL2956 Security Team

## Legal Notice

**IMPORTANT**: This tool is designed for authorized security testing only. Users must ensure they have proper authorization before scanning any applications. Unauthorized scanning may violate laws and regulations.

---

**© 2025 Professional Web Application Security Assessment Platform**