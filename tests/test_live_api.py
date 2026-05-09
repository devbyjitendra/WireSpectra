import urllib.request
import urllib.error
import json
import time

API_URL = "http://localhost:8080"

def make_request(path, method="GET", data=None):
    url = f"{API_URL}{path}"
    headers = {"Content-Type": "application/json"}
    req_data = json.dumps(data).encode("utf-8") if data else None
    
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as res:
            return json.loads(res.read().decode("utf-8")), res.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read().decode("utf-8")), e.code

def test_api():
    print("1. Checking rules list...")
    rules, code = make_request("/api/rules")
    print(f"Response (code {code}):", rules)
    assert code == 200
    
    print("\n2. Blocking domain 'youtube.com'...")
    res, code = make_request("/api/rules/block", method="POST", data={"domain": "youtube.com"})
    print(f"Response (code {code}):", res)
    assert code == 200
    assert res["blocked"] == "youtube.com"
    
    print("\n3. Verifying updated rules list...")
    rules, code = make_request("/api/rules")
    print(f"Response (code {code}):", rules)
    assert "youtube.com" in rules["blocked_domains"]
    
    print("\n4. Triggering Ping to '8.8.8.8'...")
    res, code = make_request("/api/ping", method="POST", data={"host": "8.8.8.8"})
    print(f"Response (code {code}):", res)
    assert code == 200
    
    print("\n5. Fetching live report to verify Ping flows...")
    # Wait a moment for flow generation to settle
    time.sleep(0.5)
    report, code = make_request("/api/report")
    print(f"Response (code {code}) summary packet count:", report["summary"]["total_packets"])
    
    # Check if ICMP/Ping is in the applications or protocols or flow list
    flows = report.get("flows", [])
    ping_flows = [f for f in flows if f["app_name"] == "Ping" or f["protocol"] == "ICMP"]
    print(f"Found {len(ping_flows)} Ping/ICMP flows:")
    for pf in ping_flows:
        print(f"  Flow: {pf['src_ip']}:{pf['src_port']} -> {pf['dst_ip']}:{pf['dst_port']} ({pf['app_name']}/{pf['protocol']}) Packets: {pf['packets']}")
    
    assert len(ping_flows) > 0, "No Ping/ICMP flows found in report!"
    
    print("\n6. Unblocking domain 'youtube.com'...")
    res, code = make_request("/api/rules/unblock", method="POST", data={"domain": "youtube.com"})
    print(f"Response (code {code}):", res)
    assert code == 200
    
    print("\n7. Verifying rules list again...")
    rules, code = make_request("/api/rules")
    print(f"Response (code {code}):", rules)
    assert "youtube.com" not in rules["blocked_domains"]
    
    print("\nAll integration tests passed successfully!")

if __name__ == "__main__":
    test_api()
