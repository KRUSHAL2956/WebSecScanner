"""
Security Utilities - Professional Helper Functions

Core utility functions for security assessment, reporting, and data processing.
"""

import json
import html
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Tuple


class SecurityUtils:
    """Professional security assessment utilities"""
    
    def __init__(self):
        self.output_dir = Path("output/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def calculate_risk_score(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate comprehensive risk score based on vulnerabilities
        
        Args:
            vulnerabilities: List of vulnerability findings
            
        Returns:
            Risk score data with level and score
        """
        if not vulnerabilities:
            return {
                'score': 0,
                'level': 'Safe',
                'color': 'green',
                'description': 'No vulnerabilities detected'
            }
        
        # Vulnerability severity scoring
        severity_scores = {
            'Critical': 10,
            'High': 7,
            'Medium': 4,
            'Low': 2,
            'Info': 1
        }
        
        total_score = 0
        vuln_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0, 'Info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.get('severity', 'Low')
            score = severity_scores.get(severity, 2)
            total_score += score
            vuln_counts[severity] = vuln_counts.get(severity, 0) + 1
        
        # Determine risk level based on Highest Severity Rule
        if vuln_counts['Critical'] > 0:
            risk_level = 'Critical'
            color = 'red'
        elif vuln_counts['High'] > 0:
            risk_level = 'High'
            color = 'orange'
        elif vuln_counts['Medium'] > 0:
            risk_level = 'Medium'
            color = 'yellow'
        elif vuln_counts['Low'] > 0:
            risk_level = 'Low'
            color = 'blue'
        else:
            risk_level = 'Info'
            color = 'gray'
            
        # Upgrade risk based on total score (Volume based upgrade)
        if total_score >= 100 and risk_level not in ['Critical', 'High']:
            risk_level = 'High'
            color = 'orange'
        elif total_score >= 50 and risk_level not in ['Critical', 'High', 'Medium']:
            risk_level = 'Medium'
            color = 'yellow'
        
        # Generate description
        total_vulns = len(vulnerabilities)
        high_risk = vuln_counts['Critical'] + vuln_counts['High']
        
        if high_risk > 0:
            description = f"{total_vulns} vulnerabilities found including {high_risk} high-risk issues"
        else:
            description = f"{total_vulns} vulnerabilities found, mostly low-risk"
        
        # Uppercase breakdown for templates expecting CRITICAL/HIGH/... keys
        breakdown = {
            'CRITICAL': vuln_counts.get('Critical', 0),
            'HIGH': vuln_counts.get('High', 0),
            'MEDIUM': vuln_counts.get('Medium', 0),
            'LOW': vuln_counts.get('Low', 0),
            'INFO': vuln_counts.get('Info', 0),
        }

        return {
            'score': float(total_score),
            'level': risk_level,
            'color': color,
            'description': description,
            'vulnerability_counts': vuln_counts,
            'breakdown': breakdown,
            'total_vulnerabilities': total_vulns
        }
    
    def save_scan_results(self, scan_data: Dict[str, Any], scan_id: str) -> Tuple[str, str, str]:
        """Save scan results in JSON, HTML and PDF formats"""
        json_path = self.output_dir / f"scan_{scan_id}.json"
        with open(json_path, 'w') as f:
            json.dump(scan_data, f, indent=2, default=str)
        html_path = self.output_dir / f"report_{scan_id}.html"
        html_content = self.generate_html_report(scan_data)
        with open(html_path, 'w') as f:
            f.write(html_content)
        # PDF report (best-effort; skip if dependency missing)
        pdf_path = self.output_dir / f"report_{scan_id}.pdf"
        try:
            self.generate_pdf_report(scan_data, pdf_path)
        except Exception:
            pdf_path = None
        return str(json_path), str(html_path), (str(pdf_path) if pdf_path else "")
    
    def generate_report(self, target_url: str, vulnerabilities: List[Dict[str, Any]], scan_status: Dict[str, str] = None) -> str:
        """
        Generate comprehensive scan report
        
        Args:
            target_url: Target URL that was scanned
            vulnerabilities: List of found vulnerabilities
            scan_status: Status of each scan module
            
        Returns:
            Formatted report as string
        """
        from datetime import datetime
        
        risk_data = self.calculate_risk_score(vulnerabilities)
        scan_time = datetime.now().isoformat()
        
        # Create scan data dictionary
        scan_data = {
            'target_url': target_url,
            'scan_time': scan_time,
            'vulnerabilities': vulnerabilities,
            'risk_score': risk_data,
            'total_vulns': len(vulnerabilities),
            'scan_status': scan_status or {}
        }
        
        # Generate JSON report
        import json
        return json.dumps(scan_data, indent=2, default=str)
    
    def generate_html_report(self, scan_data: Dict[str, Any]) -> str:
        """Generate professional HTML security report"""
        
        vulnerabilities = scan_data.get('vulnerabilities', [])
        risk_score = scan_data.get('risk_score', {})
        target_url = scan_data.get('target_url', 'Unknown')
        scan_time = scan_data.get('scan_time', 'Unknown')
        scan_duration = scan_data.get('scan_duration', 0)
        
        # HTML template
        html_template = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>WebSec Security Assessment Report</title>
    <style>
        body {{
            font-family: 'Segoe UI', sans-serif;
            margin: 0;
            padding: 20px;
            background: #f5f5f5;
            color: #333;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        .header {{
            border-bottom: 3px solid #000;
            padding-bottom: 20px;
            margin-bottom: 30px;
        }}
        .header h1 {{
            margin: 0;
            color: #000;
            font-size: 2.5rem;
        }}
        .header p {{
            margin: 5px 0 0 0;
            color: #666;
            font-size: 1.1rem;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            padding: 20px;
            border-radius: 6px;
            border-left: 4px solid #000;
        }}
        .summary-card h3 {{
            margin: 0 0 10px 0;
            font-size: 0.9rem;
            text-transform: uppercase;
            color: #666;
        }}
        .summary-card .value {{
            font-size: 2rem;
            font-weight: bold;
            color: #000;
        }}
        .risk-{risk_score.get('color', 'gray')} {{
            border-left-color: {self._get_color_code(risk_score.get('color', 'gray'))};
        }}
        .vulnerability {{
            background: #f9f9f9;
            border: 1px solid #ddd;
            border-radius: 6px;
            padding: 20px;
            margin-bottom: 20px;
        }}
        .vulnerability h3 {{
            margin: 0 0 10px 0;
            color: #000;
        }}
        .severity {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            color: white;
            font-size: 0.8rem;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-critical {{ background: #dc2626; }}
        .severity-high {{ background: #ea580c; }}
        .severity-medium {{ background: #ca8a04; }}
        .severity-low {{ background: #2563eb; }}
        .severity-info {{ background: #6b7280; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>WEBSEC SECURITY ASSESSMENT</h1>
            <p>Professional Web Application Security Report</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>Target URL</h3>
                <div class="value" style="font-size: 1.2rem;">{html.escape(target_url)}</div>
            </div>
            <div class="summary-card">
                <h3>Scan Date</h3>
                <div class="value" style="font-size: 1.2rem;">{scan_time}</div>
            </div>
            <div class="summary-card">
                <h3>Duration</h3>
                <div class="value">{self._format_duration(scan_duration)}</div>
            </div>
            <div class="summary-card">
                <h3>Vulnerabilities</h3>
                <div class="value">{len(vulnerabilities)}</div>
            </div>
            <div class="summary-card risk-{risk_score.get('color', 'gray')}">
                <h3>Risk Level</h3>
                <div class="value">{risk_score.get('level', 'Unknown')}</div>
            </div>
        </div>
        
        <h2>Vulnerability Details</h2>
        """
        
        if vulnerabilities:
            for i, vuln in enumerate(vulnerabilities, 1):
                severity = vuln.get('severity', 'Low').lower()
                html_template += f"""
        <div class="vulnerability">
            <h3>#{i}: {html.escape(vuln.get('type', 'Unknown'))} Vulnerability</h3>
            <span class="severity severity-{severity}">{vuln.get('severity', 'Low')}</span>
            <p><strong>URL:</strong> {html.escape(vuln.get('url', 'Unknown'))}</p>
            <p><strong>Description:</strong> {html.escape(vuln.get('description', 'No description'))}</p>
            {f'<p><strong>Payload:</strong> <code>{html.escape(vuln.get("payload", ""))}</code></p>' if vuln.get('payload') else ''}
        </div>
                """
        else:
            html_template += """
        <div class="vulnerability" style="background: #f0f9ff; border-color: #0284c7;">
            <h3>✓ No Vulnerabilities Detected</h3>
            <p>The security assessment completed successfully with no vulnerabilities found.</p>
        </div>
            """
        
        html_template += """
        <div style="margin-top: 40px; padding-top: 20px; border-top: 1px solid #ddd; color: #666; font-size: 0.9rem;">
            <p>Report generated by WebSec Scanner Professional v2.1.0</p>
            <p>© 2025 Professional Web Application Security Assessment Platform</p>
        </div>
    </div>
</body>
</html>
        """
        
        return html_template

    def generate_pdf_report(self, scan_data: Dict[str, Any], output_file: Any):
        """
        Generate a professional, detailed PDF report using reportlab Platypus
        
        Args:
            scan_data: Dictionary containing scan results
            output_file: File path (str/Path) or file-like object (BytesIO) to write PDF to
        """
        from reportlab.lib.pagesizes import A4
        from reportlab.lib import colors
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
        from reportlab.lib.enums import TA_CENTER, TA_LEFT

        # If output_file is a string or Path, convert to str
        target = str(output_file) if isinstance(output_file, (str, Path)) else output_file

        doc = SimpleDocTemplate(
            target,
            pagesize=A4,
            rightMargin=40, leftMargin=40,
            topMargin=40, bottomMargin=40
        )

        styles = getSampleStyleSheet()
        story = []

        # Custom Styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            spaceAfter=30,
            alignment=TA_CENTER,
            textColor=colors.HexColor('#000000')
        )
        
        subtitle_style = ParagraphStyle(
            'CustomSubtitle',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=10,
            textColor=colors.HexColor('#333333')
        )

        normal_style = styles['Normal']
        normal_style.fontSize = 10
        normal_style.leading = 14

        code_style = ParagraphStyle(
            'Code',
            parent=styles['Code'],
            fontSize=8,
            leading=10,
            fontName='Courier',
            textColor=colors.HexColor('#333333'),
            backColor=colors.HexColor('#f5f5f5'),
            borderPadding=5
        )

        # Title Page
        story.append(Paragraph("WebSec Professional", title_style))
        story.append(Paragraph("Security Assessment Report", subtitle_style))
        story.append(Spacer(1, 40))

        # Scan Details Table
        data = [
            ["Target URL", scan_data.get('target_url', 'Unknown')],
            ["Scan Date", scan_data.get('scan_time', 'Unknown')],
            ["Scan Duration", self._format_duration(scan_data.get('scan_duration', 0))],
            ["Risk Level", scan_data.get('risk_score', {}).get('level', 'Unknown')],
            ["Total Issues", str(scan_data.get('total_vulns', 0))]
        ]

        t = Table(data, colWidths=[120, 350])
        t.setStyle(TableStyle([
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('TEXTCOLOR', (0, 0), (0, -1), colors.HexColor('#333333')),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#e5e7eb')),
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f9fafb')),
        ]))
        story.append(t)
        story.append(Spacer(1, 40))

        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        risk_level = scan_data.get('risk_score', {}).get('level', 'Low')
        summary_text = f"A security assessment was conducted on {scan_data.get('target_url')}. " \
                       f"The scan identified {scan_data.get('total_vulns', 0)} potential vulnerabilities. " \
                       f"The overall risk level is assessed as <b>{risk_level}</b>."
        story.append(Paragraph(summary_text, normal_style))
        story.append(Spacer(1, 20))

        # Vulnerabilities Section
        story.append(PageBreak())
        story.append(Paragraph("Detailed Findings", styles['Heading1']))
        story.append(Spacer(1, 20))

        vulns = scan_data.get('vulnerabilities', [])
        if not vulns:
            story.append(Paragraph("No vulnerabilities were detected during this scan.", normal_style))
        else:
            for i, v in enumerate(vulns, 1):
                # Vulnerability Header
                severity = v.get('severity', 'Low')
                color = colors.HexColor(self._get_color_code(severity.lower()))
                
                # Title
                story.append(Paragraph(f"{i}. {v.get('type', 'Unknown Vulnerability')}", styles['Heading3']))
                
                # Metadata
                meta_data = [
                    [Paragraph(f"<b>Severity:</b> <font color='{color}'>{severity}</font>", normal_style)],
                    [Paragraph(f"<b>Location:</b> {v.get('url', 'Unknown')}", normal_style)]
                ]
                t_meta = Table(meta_data, colWidths=[450])
                t_meta.setStyle(TableStyle([
                    ('LEFTPADDING', (0,0), (-1,-1), 0),
                    ('BOTTOMPADDING', (0,0), (-1,-1), 6),
                ]))
                story.append(t_meta)
                story.append(Spacer(1, 10))

                # Description
                story.append(Paragraph("<b>Description:</b>", normal_style))
                story.append(Paragraph(v.get('description', 'No description provided.'), normal_style))
                story.append(Spacer(1, 10))

                # Payload
                payload = v.get('payload')
                if payload:
                    story.append(Paragraph("<b>Payload Used:</b>", normal_style))
                    # Escape XML characters in payload for Paragraph
                    from xml.sax.saxutils import escape
                    safe_payload = escape(payload)
                    story.append(Paragraph(safe_payload, code_style))
                    story.append(Spacer(1, 10))
                
                # Remediation (Generic based on type)
                story.append(Paragraph("<b>Remediation Recommendation:</b>", normal_style))
                remediation = "Validate and sanitize all user inputs. Use parameterized queries for SQL injection protection. Encode output to prevent XSS."
                if 'SQL' in v.get('type', ''):
                    remediation = "Use prepared statements (parameterized queries). Avoid constructing SQL queries with string concatenation. Validate all inputs."
                elif 'XSS' in v.get('type', ''):
                    remediation = "Implement Content Security Policy (CSP). Contextually encode all user-supplied data before rendering it in the browser."
                elif 'CSRF' in v.get('type', ''):
                    remediation = "Implement anti-CSRF tokens in all state-changing forms. Ensure SameSite cookie attributes are set to Strict or Lax."
                
                story.append(Paragraph(remediation, normal_style))
                
                # Separator
                story.append(Spacer(1, 20))
                story.append(Paragraph("<hr/>", normal_style))
                story.append(Spacer(1, 20))

        # Footer
        story.append(Spacer(1, 40))
        story.append(Paragraph("End of Report", ParagraphStyle('Footer', parent=normal_style, alignment=TA_CENTER, textColor=colors.gray)))

        doc.build(story)
    
    def _get_color_code(self, color: str) -> str:
        """Get hex color code for risk level colors"""
        color_map = {
            'red': '#dc2626',
            'orange': '#ea580c', 
            'yellow': '#d97706',
            'blue': '#2563eb',
            'gray': '#6b7280'
        }
        return color_map.get(color, '#6b7280')
    
    def _get_color_code(self, color: str) -> str:
        """Get hex color code for risk level"""
        colors = {
            'red': '#dc2626',
            'orange': '#ea580c', 
            'yellow': '#ca8a04',
            'blue': '#2563eb',
            'gray': '#6b7280',
            'green': '#16a34a'
        }
        return colors.get(color, '#6b7280')
    
    def _format_duration(self, duration_seconds: float) -> str:
        """Format duration in human-readable format"""
        if duration_seconds < 60:
            return f"{duration_seconds:.1f}s"
        elif duration_seconds < 3600:
            minutes = duration_seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = duration_seconds / 3600
            return f"{hours:.1f}h"
    
    def validate_url(self, url: str) -> bool:
        """Validate target URL format"""
        try:
            from urllib.parse import urlparse
            result = urlparse(url)
            return all([result.scheme, result.netloc])
        except Exception:
            return False