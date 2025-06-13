import logging

# Set up a logger
logger = logging.getLogger("threatpeek")
logger.setLevel(logging.DEBUG)

# Console output handler
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG)

# Formatter
formatter = logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s", datefmt='%Y-%m-%d %H:%M:%S')
console_handler.setFormatter(formatter)

# Attach handler to logger
if not logger.handlers:
    logger.addHandler(console_handler)

# Optional: Shortcut for logging a scanned URL
def log_request(url: str, status: str, detail: str):
    logger.info(f"Scanned URL: {url}")
    logger.info(f"Status: {status}")
    logger.info(f"Details: {detail}")
