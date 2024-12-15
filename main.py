import requests
import json
from fastapi import FastAPI, HTTPException, Request
from typing import List

app = FastAPI()

# store a list of allowed IP prefixes
allowed_ips: List[str] = []
# URL to download AWS IP ranges
URL_OF_AWS_IP_RANGES = "https://ip-ranges.amazonaws.com/ip-ranges.json"

def get_aws_ip_ranges() -> List[str]:
    try:
        response = requests.get(URL_OF_AWS_IP_RANGES)
        response.raise_for_status()
        data = response.json()
        return [
            prefix['ip_prefix']
            for prefix in data.get('prefixes', [])
            if prefix['region'] == 'eu-west-1' and prefix['service'] == 'EC2'
        ]
    except (requests.RequestException, KeyError, json.JSONDecodeError) as e:
        print(f"Error while downloading data of IP: {e}")
        return []


def is_ip_allowed(client_ip: str, allowed_ranges: List[str]) -> bool:
    from ipaddress import ip_address, ip_network

    try:
        client_ip_obj = ip_address(client_ip)
        for ip_range in allowed_ranges:
            if client_ip_obj in ip_network(ip_range):
                return True
    except ValueError as e:
        print(f"Invalid IP address: {client_ip} ({e})")

    return False


@app.on_event("startup")
def init_allowed_ips():
    global allowed_ips
    allowed_ips = get_aws_ip_ranges()
    print(f"Loaded {len(allowed_ips)} IP ranges.")


@app.post("/verify")
async def verify_request(request: Request):
    client_ip = request.client.host  # <- Downloading IP of the client

    if is_ip_allowed(client_ip, allowed_ips):
        return {"status": "200 OK", "message": "Access granted"}

    raise HTTPException(status_code=401, detail="Unauthorized")


@app.get("/refresh")
def refresh_ip_ranges():
    global allowed_ips
    allowed_ips = get_aws_ip_ranges()
    return {"status": "IPs refreshed", "count": len(allowed_ips)}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)