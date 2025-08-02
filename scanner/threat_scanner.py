from typing import Dict, Any, Optional, Tuple
from urllib.parse import urlparse
import asyncio
import time
import re
from datetime import datetime

from config import config
from utils.ssl_check import async_ssl_check
from utils.analysis_helpers import is_high_entropy
from logger import logger

class ThreatScanner:
    def __init__(self, url: str):
        self.url = url.strip()
        self.parsed_url = urlparse(self.url)
        self.domain = self.parsed_url.netloc.lower()
        self.path = self.parsed_url.path.lower()
        self.results = {}
        
    async def scan_with_virustotal(self) -> Tuple[str, str, Dict[str, Any]]:
        """Scan URL with VirusTotal API"""
        if not config.VT_API_KEY and not config.VIRUSTOTAL_API_KEY:
            return "unknown", "VirusTotal API key not configured", {}
            
        try:
            return await query_virustotal_async(self.url)
        except Exception as e:
            logger.error(f"VirusTotal scan failed for {self.url}: {e}")
            return "error", f"VirusTotal scan failed: {str(e)}", {}

    async def check_ssl(self) -> Tuple[bool, list[str]]:
        """Check SSL certificate validity"""
        if self.parsed_url.scheme != 'https':
            return True, ["HTTP URL - SSL check skipped"]
            
        try:
            return await async_ssl_check(self.domain)
        except Exception as e:
            logger.error(f"SSL check failed for {self.domain}: {e}")
            return False, [f"SSL check error: {str(e)}"]

    def check_url_patterns(self) -> tuple[str, str]:
        """Check for suspicious URL patterns"""
        # Check for suspicious patterns
        suspicious_patterns = [
            r'[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}',  # IP addresses
            r'[a-z0-9]{20,}',  # Long random strings
            r'bit\.ly|tinyurl|short|t\.co',  # URL shorteners
            r'%[0-9a-f]{2}',  # URL encoding
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, self.url, re.IGNORECASE):
                return "suspicious", f"Suspicious pattern detected: {pattern}"
        
        # Check path length
        if len(self.path) > config.MAX_PATH_LENGTH:
            return "suspicious", f"URL path too long ({len(self.path)} chars)"
            
        # Check entropy
        if is_high_entropy(self.path, config.ENTROPY_THRESHOLD):
            return "suspicious", "High entropy in URL path detected"
            
        return "clean", "No suspicious patterns detected"

    async def run_comprehensive_scan(self) -> Dict[str, Any]:
        """Run all available scans and return comprehensive results"""
        start_time = time.time()
        
        # Initialize results
        scan_results = {
            "url": self.url,
            "timestamp": datetime.utcnow().isoformat(),
            "scans": {},
            "final_verdict": "unknown",
            "confidence": 0.0,
            "details": [],
            "scan_duration_ms": 0
        }
        
        try:
            # Run pattern analysis (synchronous)
            pattern_status, pattern_detail = self.check_url_patterns()
            scan_results["scans"]["pattern_analysis"] = {
                "status": pattern_status,
                "details": pattern_detail
            }
            
            # Run async scans concurrently
            vt_task = self.scan_with_virustotal()
            ssl_task = self.check_ssl()
            
            # Wait for all async tasks
            vt_status, vt_details, vt_vendors = await vt_task
            ssl_ok, ssl_issues = await ssl_task
            
            # Store individual scan results
            scan_results["scans"]["virustotal"] = {
                "status": vt_status,
                "details": vt_details,
                "vendors": vt_vendors
            }
            
            scan_results["scans"]["ssl_check"] = {
                "status": "clean" if ssl_ok else "suspicious",
                "details": "SSL certificate valid" if ssl_ok else "; ".join(ssl_issues)
            }
            
            # Determine final verdict
            all_statuses = [vt_status, pattern_status, "clean" if ssl_ok else "suspicious"]
            
            if "malicious" in all_statuses:
                final_verdict = "malicious"
                confidence = 0.9
            elif "suspicious" in all_statuses:
                final_verdict = "suspicious" 
                confidence = 0.7
            elif "clean" in all_statuses:
                final_verdict = "clean"
                confidence = 0.8
            else:
                final_verdict = "unknown"
                confidence = 0.1
                
            scan_results["final_verdict"] = final_verdict
            scan_results["confidence"] = confidence
            
            # Compile details
            details = []
            if vt_details and vt_details != "No threats found by VirusTotal.":
                details.append(f"VT: {vt_details}")
            if pattern_detail and pattern_status != "clean":
                details.append(f"Pattern: {pattern_detail}")
            if not ssl_ok:
                details.append(f"SSL: {'; '.join(ssl_issues)}")
                
            scan_results["details"] = details if details else ["No threats detected"]
            
        except Exception as e:
            logger.error(f"Comprehensive scan failed for {self.url}: {e}")
            scan_results["final_verdict"] = "error"
            scan_results["details"] = [f"Scan error: {str(e)}"]
            
        finally:
            scan_results["scan_duration_ms"] = round((time.time() - start_time) * 1000, 2)
            
        return scan_results
