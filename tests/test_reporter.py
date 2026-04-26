import os
import csv
import pytest
from src.flow_tracker import Flow
from src.reporter import CSVReporter, DPIReportGenerator

def test_csv_reporter_export(tmp_path):
    csv_file = os.path.join(tmp_path, "flows.csv")
    
    # Mock flows
    flow_1 = Flow(flow_key=("192.168.1.5", 1234, "10.0.0.1", 80, 6), protocol_name="TCP", start_time=100.0)
    flow_1.app_name = "HTTP"
    flow_1.sni = "example.com"
    flow_1.update("a_to_b", 500, 101.5)
    flow_1.update("b_to_a", 1500, 102.5) # packets=2, bytes=2000, duration=2.5s
    
    flow_2 = Flow(flow_key=("192.168.1.10", 53, "8.8.8.8", 53, 17), protocol_name="UDP", start_time=105.0)
    flow_2.update("a_to_b", 100, 105.0) # packets=1, bytes=100, duration=0.0s
    flow_2.state = "BLOCKED"
    
    CSVReporter.export_flows([flow_1, flow_2], csv_file)
    
    # Assert CSV exists and verify structure/contents
    assert os.path.exists(csv_file)
    
    with open(csv_file, mode="r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)
        
        assert len(rows) == 2
        
        # Verify Row 1
        assert rows[0]["protocol"] == "TCP"
        assert rows[0]["app_name"] == "HTTP"
        assert rows[0]["sni"] == "example.com"
        assert rows[0]["src_ip"] == "192.168.1.5"
        assert int(rows[0]["packets"]) == 2
        assert int(rows[0]["bytes"]) == 2000
        assert float(rows[0]["duration_sec"]) == 2.5
        assert float(rows[0]["packets_per_sec"]) == 0.8
        assert float(rows[0]["bytes_per_sec"]) == 800.0
        assert rows[0]["status"] == "ACTIVE"
        
        # Verify Row 2
        assert rows[1]["protocol"] == "UDP"
        assert rows[1]["app_name"] == "Unclassified"
        assert rows[1]["status"] == "BLOCKED"

def test_dpi_report_generator():
    flow_1 = Flow(flow_key=("192.168.1.5", 1234, "10.0.0.1", 80, 6), protocol_name="TCP", start_time=100.0)
    flow_1.app_name = "HTTP"
    flow_1.update("a_to_b", 1500, 101.5) # packets=1, bytes=1500
    
    flow_2 = Flow(flow_key=("192.168.1.10", 443, "8.8.8.8", 443, 6), protocol_name="TCP", start_time=102.0)
    flow_2.app_name = "HTTPS"
    flow_2.update("a_to_b", 3500, 103.0) # packets=1, bytes=3500

    flow_3 = Flow(flow_key=("192.168.1.15", 5353, "224.0.0.251", 5353, 17), protocol_name="UDP", start_time=105.0)
    flow_3.update("a_to_b", 1000, 105.0) # packets=1, bytes=1000
    
    flows = [flow_1, flow_2, flow_3]
    
    # 1. Test distributions
    dist = DPIReportGenerator.generate_distribution_report(flows)
    
    assert dist["total_packets"] == 3
    assert dist["total_bytes"] == 6000
    
    # Protocols check
    assert dist["protocols"]["TCP"]["packets"] == 2
    assert dist["protocols"]["TCP"]["bytes"] == 5000
    assert pytest.approx(dist["protocols"]["TCP"]["packets_pct"]) == 66.666666
    assert pytest.approx(dist["protocols"]["TCP"]["bytes_pct"]) == 83.333333
    
    assert dist["protocols"]["UDP"]["packets"] == 1
    assert dist["protocols"]["UDP"]["bytes"] == 1000
    
    # Applications check
    assert dist["applications"]["HTTP"]["bytes"] == 1500
    assert dist["applications"]["HTTPS"]["bytes"] == 3500
    assert dist["applications"]["Unclassified"]["bytes"] == 1000

    # 2. Test throughput summary
    tp = DPIReportGenerator.generate_throughput_summary(total_packets=3, total_bytes=6000, duration=2.0)
    assert tp["duration"] == 2.0
    assert tp["avg_pps"] == 1.5
    assert tp["avg_bps"] == 24000.0  # 6000 * 8 / 2
    assert tp["avg_kbps"] == 24.0
