# WireSpectra

A high-performance Deep Packet Inspection (DPI) engine rewritten in Python. 

This project is a progressive rewrite of the original WireSpectra C++ engine, focusing on protocol parsing, flow tracking, and real-time application classification.

## Project Features & Status

<details>
<summary><b>🚀 Click to expand Implemented Features</b></summary>

* **Raw PCAP Parsing**: Decoding of 24-byte global headers and 16-byte packet headers directly from binary format without external parsing packages.
* **Protocol Decoding (Layers 2-4)**:
  * **L2 (Ethernet)**: MAC Address extraction & EtherType mapping.
  * **L3 (IPv4)**: Version, IHL, TTL, Protocol resolution, and IP parsing.
  * **L4 (TCP/UDP)**: Unpacking port endpoints (source/destination) and active TCP control flags (SYN, ACK, FIN, RST, PSH, URG).
* **Application Layer Classification**:
  * **TLS SNI Extraction**: Deep inspects Client Hello handshake messages to classify HTTPS server hostnames.
  * **HTTP Host Extraction**: Decodes TCP request payloads to extract plain-text Host headers.
* **Bidirectional Flow Tracking**: Canonicalizes IP and Port pairs lexicographically to group outbound and inbound traffic into single unified connection stats.
* **Automated Unit Tests**: Fully validated suite using `pytest`.
</details>

<details>
<summary><b>🛠 Click to expand Planned Features (Upcoming Weeks)</b></summary>

* PCAP file exporter (writing parsed/blocked flows back to disk).
* Rule-based traffic filtering, blocking triggers, and firewalls.
* Multi-process architecture to boost throughput on multi-core systems.
</details>

---

## How to Run & Interact

### 1. Requirements
Ensure you have the dependencies installed:
```bash
pip install -r requirements.txt
```

### 2. Running the DPI Engine
To parse and view packet flows from any PCAP file, execute the main entrypoint:
```bash
python src/main.py <path_to_pcap_file>
```

### 3. Running the Test Suite
To run all unit tests for the parsers, flow trackers, and reader:
```bash
pytest tests/
```

---


