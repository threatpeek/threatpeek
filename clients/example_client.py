import requests

API_URL = "http://127.0.0.1:8000/api/scan_url"

payload = {
    "url": "https://safe.com"
}

response = requests.post(API_URL, json=payload)

if response.status_code == 200:
    data = response.json()
    print(f"URL: {data['url']}")
    print(f"Status: {data['status']}")
    print(f"Details: {data['details']}")
else:
    print(f"Request failed with status: {response.status_code}")
