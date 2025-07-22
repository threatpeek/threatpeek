# utils/virustotal.py

import httpx
import base64
import asyncio
import os

VT_API_KEY = os.getenv("VT_API_KEY")

headers = {
    "x-apikey": VT_API_KEY,
    "Content-Type": "application/x-www-form-urlencoded"
}

async def submit_url_to_vt(url: str) -> str:
    async with httpx.AsyncClient() as client:
        response = await client.post("https://www.virustotal.com/api/v3/urls", headers=headers, data=f"url={url}")
        response.raise_for_status()
        return response.json()["data"]["id"]

async def get_vt_report(vt_id: str) -> dict:
    async with httpx.AsyncClient() as client:
        response = await client.get(f"https://www.virustotal.com/api/v3/urls/{vt_id}", headers=headers)
        response.raise_for_status()
        return response.json()