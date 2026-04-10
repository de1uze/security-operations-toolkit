import os
from dotenv import load_dotenv

# Explicitly point to the .env file in the same folder as config.py
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))

VIRUSTOTAL_API_KEY = os.getenv("38091f5ec7f00e1f72d17998506ba33bc9e08e59801cce574b953166ef1c6fe7")
ABUSEIPDB_API_KEY  = os.getenv("d4fa7148cf54ceb7515892ead42a723f3f1ae7bfa10780f4ead65fe74790fa223e88f25914d14daf")

VT_BASE = "https://www.virustotal.com/api/v3"
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"