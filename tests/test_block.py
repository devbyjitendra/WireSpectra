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

def test_block():
    print("1. Resetting live state...")
    make_request("/api/reset", method="POST")
    
    print("2. Blocking domains 'youtube.com' and 'facebook.com'...")
    make_request("/api/rules/block", method="POST", data={"domain": "youtube.com"})
    make_request("/api/rules/block", method="POST", data={"domain": "facebook.com"})
    
    print("3. Waiting 18 seconds for traffic to generate...")
    time.sleep(18)
    
    print("4. Fetching report...")
    report, _ = make_request("/api/report")
    
    print("\nSummary status counts:")
    flows = report.get("flows", [])
    
    blocked_flows = [f for f in flows if f["status"] == "BLOCKED"]
    youtube_flows = [f for f in flows if "youtube.com" in f["sni"]]
    
    print(f"Total flows: {len(flows)}")
    print(f"YouTube flows: {len(youtube_flows)}")
    print(f"Blocked flows: {len(blocked_flows)}")
    
    print("\nFlows detail:")
    for f in flows:
        print(f"  ID: {f['flow_id']} | DST: {f['dst_ip']} | SNI: '{f['sni']}' | App: {f['app_name']} | Status: {f['status']}")
            
if __name__ == "__main__":
    test_block()
