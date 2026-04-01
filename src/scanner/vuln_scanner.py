import socket
import ssl
import logging
import requests
from datetime import datetime
from typing import List, Dict, Optional
from urllib.parse import urlparse


logger = logging.getLogger("scanline.vuln")


class VulnScanner:
    def __init__(self, config: Dict, db):
        self.config = config
        self.db = db
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "ScanLine-Security-Scanner/1.0 (OSINT Research)"
        })

    def check_ssl_certificate(self, domain: str) -> List[Dict]:
        findings = []
        
        logger.info(f"Checking SSL certificate for: {domain}")
        
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    import datetime as dt
                    not_after = dt.datetime.strptime(
                        cert["notAfter"], 
                        "%b %d %H:%M:%S %Y %Z"
                    )
                    
                    days_until_expiry = (not_after - dt.datetime.utcnow()).days
                    
                    if days_until_expiry < 0:
                        finding = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "source": "ssl_scanner",
                            "category": "ssl_tls",
                            "severity": "critical",
                            "title": f"[SSL] Expired Certificate: {domain}",
                            "description": f"SSL certificate for {domain} expired {abs(days_until_expiry)} days ago",
                            "url": f"https://{domain}",
                            "raw_data": {
                                "domain": domain,
                                "expiry_date": cert["notAfter"],
                                "days_expired": abs(days_until_expiry)
                            }
                        }
                        finding_id = self.db.insert_finding(finding)
                        finding["id"] = finding_id
                        findings.append(finding)
                        
                    elif days_until_expiry < 30:
                        severity = "high" if days_until_expiry < 14 else "medium"
                        finding = {
                            "timestamp": datetime.utcnow().isoformat(),
                            "source": "ssl_scanner",
                            "category": "ssl_tls",
                            "severity": severity,
                            "title": f"[SSL] Certificate Expiring Soon: {domain}",
                            "description": f"SSL certificate for {domain} expires in {days_until_expiry} days",
                            "url": f"https://{domain}",
                            "raw_data": {
                                "domain": domain,
                                "expiry_date": cert["notAfter"],
                                "days_remaining": days_until_expiry
                            }
                        }
                        finding_id = self.db.insert_finding(finding)
                        finding["id"] = finding_id
                        findings.append(finding)
                        
        except ssl.SSLCertVerificationError as e:
            finding = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "ssl_scanner",
                "category": "ssl_tls",
                "severity": "high",
                "title": f"[SSL] Certificate Verification Failed: {domain}",
                "description": f"SSL certificate verification failed for {domain}: {str(e)}",
                "url": f"https://{domain}",
                "raw_data": {"domain": domain, "error": str(e)}
            }
            finding_id = self.db.insert_finding(finding)
            finding["id"] = finding_id
            findings.append(finding)
            
        except Exception as e:
            logger.error(f"SSL check failed for {domain}: {e}")
        
        return findings

    def check_security_headers(self, url: str) -> List[Dict]:
        findings = []
        
        logger.info(f"Checking security headers for: {url}")
        
        required_headers = {
            "Strict-Transport-Security": {
                "severity": "high",
                "description": "HSTS header missing - vulnerable to protocol downgrade attacks"
            },
            "X-Content-Type-Options": {
                "severity": "medium",
                "description": "X-Content-Type-Options missing - vulnerable to MIME sniffing"
            },
            "X-Frame-Options": {
                "severity": "medium",
                "description": "X-Frame-Options missing - vulnerable to clickjacking"
            },
            "Content-Security-Policy": {
                "severity": "medium",
                "description": "CSP header missing - increased XSS risk"
            },
            "Referrer-Policy": {
                "severity": "low",
                "description": "Referrer-Policy missing - may leak sensitive URL data"
            },
            "Permissions-Policy": {
                "severity": "low",
                "description": "Permissions-Policy missing - no feature policy set"
            }
        }
        
        try:
            response = self.session.get(url, timeout=15, verify=True)
            
            for header_name, header_info in required_headers.items():
                if header_name.lower() not in {k.lower() for k in response.headers.keys()}:
                    finding = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "source": "header_scanner",
                        "category": "security_headers",
                        "severity": header_info["severity"],
                        "title": f"[Headers] Missing {header_name}: {urlparse(url).netloc}",
                        "description": f"{header_info['description']}\nURL: {url}",
                        "url": url,
                        "raw_data": {
                            "missing_header": header_name,
                            "url": url,
                            "status_code": response.status_code
                        }
                    }
                    finding_id = self.db.insert_finding(finding)
                    finding["id"] = finding_id
                    findings.append(finding)
            
            server_header = response.headers.get("Server", "")
            if server_header and any(indicator in server_header.lower() for indicator in 
                                      ["apache/", "nginx/", "iis/", "php/", "express/"]):
                finding = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "source": "header_scanner",
                    "category": "information_disclosure",
                    "severity": "low",
                    "title": f"[Headers] Server Version Disclosure: {urlparse(url).netloc}",
                    "description": f"Server header reveals version information: {server_header}",
                    "url": url,
                    "raw_data": {"server_header": server_header, "url": url}
                }
                finding_id = self.db.insert_finding(finding)
                finding["id"] = finding_id
                findings.append(finding)
                
        except requests.exceptions.SSLError:
            finding = {
                "timestamp": datetime.utcnow().isoformat(),
                "source": "header_scanner",
                "category": "ssl_tls",
                "severity": "high",
                "title": f"[SSL] SSL Error: {urlparse(url).netloc}",
                "description": f"SSL connection failed for {url}",
                "url": url,
                "raw_data": {"url": url, "error": "SSL_ERROR"}
            }
            self.db.insert_finding(finding)
            findings.append(finding)
            
        except Exception as e:
            logger.error(f"Header check failed for {url}: {e}")
        
        return findings

    def check_exposed_files(self, base_url: str) -> List[Dict]:
        findings = []
        
        logger.info(f"Checking for exposed sensitive files: {base_url}")
        
        sensitive_paths = [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.env.backup",
            "/config.yml",
            "/config.yaml",
            "/config.json",
            "/.git/config",
            "/.git/HEAD",
            "/wp-config.php",
            "/web.config",
            "/app.config",
            "/settings.py",
            "/secrets.yml",
            "/database.yml",
            "/credentials.json",
            "/.aws/credentials",
            "/backup.sql",
            "/dump.sql",
            "/database.sql",
            "/id_rsa",
            "/id_rsa.pub",
            "/.ssh/id_rsa",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/.htpasswd",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/.DS_Store",
            "/Thumbs.db"
        ]
        
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        
        for path in sensitive_paths:
            try:
                url = base + path
                response = self.session.get(url, timeout=5, allow_redirects=False)
                
                if response.status_code == 200 and len(response.content) > 0:
                    severity = "critical" if any(p in path for p in [".env", "id_rsa", "credentials", ".aws", "backup.sql"]) else \
                               "high" if any(p in path for p in [".git", "config", "wp-config", "secrets"]) else \
                               "medium" if any(p in path for p in ["phpinfo", ".htpasswd", "dump.sql"]) else "low"
                    
                    finding = {
                        "timestamp": datetime.utcnow().isoformat(),
                        "source": "file_scanner",
                        "category": "exposed_files",
                        "severity": severity,
                        "title": f"[Files] Exposed Sensitive File: {path}",
                        "description": (
                            f"Sensitive file accessible at: {url}\n"
                            f"Status: {response.status_code}\n"
                            f"Size: {len(response.content)} bytes"
                        ),
                        "url": url,
                        "raw_data": {
                            "path": path,
                            "status_code": response.status_code,
                            "content_length": len(response.content),
                            "content_type": response.headers.get("Content-Type", "")
                        }
                    }
                    
                    finding_id = self.db.insert_finding(finding)
                    finding["id"] = finding_id
                    findings.append(finding)
                    
                    logger.warning(f"[EXPOSED FILE] {severity.upper()} - {url}")
                    
            except Exception:
                continue
        
        logger.info(f"File exposure check complete. Found {len(findings)} issues.")
        return findings