# threatpeek/utils/ssl_check.py
import ssl
import socket
import certifi
from datetime import datetime, timezone
import asyncio
from logger import logger  # ✅ Add this at the top

async def async_ssl_check(hostname: str, port: int = 443) -> tuple[bool, list[str]]:
    loop = asyncio.get_running_loop()

    def check():
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    not_after = cert.get('notAfter')
                    if not_after:
                        exp_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                        if exp_date < datetime.now(timezone.utc):
                            return False, ["SSL certificate expired."]
                    return True, []
        except ssl.SSLError as e:
            return False, [f"SSL check failed: {str(e)}"]
        except socket.gaierror as e:
            logger.warning(f"DNS resolution failed for domain: {hostname}")  # ✅ Add this log
            return False, [f"SSL check failed: {str(e)}"]
        except Exception as e:
            return False, [f"SSL check failed: {str(e)}"]

    return await loop.run_in_executor(None, check)
