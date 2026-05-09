import urllib.request
import json
import time

API_URL = "http://localhost:8080"

def make_request(path, method="GET", data=None):
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}
    req_data = json.dumps(data).encode("utf-8") if data else None
    
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    with urllib.request.urlopen(req) as res:
        return json.loads(res.read().decode("utf-8")), res.status

def test_block_google():
    print("1. Resetting live state...")
    make_request("/api/reset", method="POST")
    
    print("2. Blocking domain 'google.com'...")
    make_request("/api/rules/block", method="POST", data={"domain": "google.com"})
    
    print("3. Waiting 20 seconds for www.google.com traffic...")
    time.sleep(20)
    
    print("4. Fetching report...")
    report, _ = make_request("/api/report")
    
    flows = report.get("flows", [])
    google_flows = [f for f in flows if "google.com" in f["sni"]]
    
    print("\nFlows detail:")
    for f in flows:
        print(f"  ID: {f['flow_id']} | DST: {f['dst_ip']} | SNI: '{f['sni']}' | App: {f['app_name']} | Status: {f['status']}")

if __name__ == "__main__":
    test_block_google()
