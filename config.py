import os
from dotenv import load_dotenv

load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
PHISHTANK_API_KEY = os.getenv("PHISHTANK_API_KEY")
