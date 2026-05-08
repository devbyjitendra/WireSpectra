# WireSpectra: Deep Packet Inspection & Live Security Dashboard

WireSpectra is a high-performance Deep Packet Inspection (DPI) engine and network analysis suite. Originally designed as a C++ engine, this repository hosts a consolidated, modern implementation combining a Python binary packet parser, an anomaly detection firewall, a live FastAPI streaming server, and a premium glassmorphic React dashboard.

```
WireSpectra/
├── src/                    # Python DPI Engine Core
│   ├── server.py           # FastAPI Live Simulator & API Server
│   ├── main.py             # CLI parser and batch analyzer
│   └── protocols.py, etc.  # Custom L2-L7 decoders
├── frontend/               # React + Vite Dashboard
│   ├── src/                # App.jsx, charts, and CSS components
│   └── vercel.json         # Vercel SPA deployment rules
└── Dockerfile              # Backend container configuration
```

---

## 🚀 Key Features

### 1. Custom Deep Packet Inspection Core
- **Raw PCAP Parser**: Decodes binary global PCAP headers and per-packet headers without any external packet capture libraries (e.g. Scapy).
- **L2-L4 Protocol Decoders**: Parses Ethernet II, IPv4, TCP (including flags: SYN, ACK, FIN, RST, PSH, URG), and UDP.
- **L7 Application Classification**: Performs deep inspection on payload buffers:
  - **TLS/HTTPS**: Extracts SNI (Server Name Indication) from Client Hello handshakes.
  - **HTTP**: Extracts plain-text Host headers from GET/POST payloads.
  - **SSH / DNS / FTP**: Signatures classification for standard services.

### 2. Live Simulator & API Server
- **Continuous Traffic Generator**: Runs a background daemon generating realistic, continuous network traffic.
- **DPI Tracker**: Feeds generated packets directly into the flow parser, updating security alarms and protocol distribution statistics.
- **REST API Endpoints**:
  - `GET /api/report` - Outputs real-time flow distributions and alarms.
  - `GET /api/pcap` - Streams the rolling live PCAP file directly for inspection in Wireshark.
  - `POST /api/reset` - Resets active flows and state logs.

### 3. Intrusion Prevention & Anomaly Firewalls
- **Port Scan Detector**: Flags source IPs scanning multiple destination ports.
- **SYN Flood Shield**: Logs volumetric SYN alerts when unacknowledged handshakes breach safe thresholds.
- **Custom Rule Engine**: Custom rules support actions (`ALERT`, `BLOCK`) against IPs, domains, ports, or regex-based payload contents.

### 4. Premium React Dashboard
- **Glassmorphic Obsidian Theme**: Sleek UI with aurora backgrounds, micro-animations, and visual status signals.
- **Interactive Flows**: Searchable, paginated connection tables showing bandwidth rates and status badges.
- **Streaming & File-Upload fallback**: Live-syncs with the Back4App API, supports drag-and-drop JSON report uploads, and contains simulated test environments.

---

## 🛠 Setup & Run Instructions

### 1. Backend Setup & CLI Usage
Set up a Python virtual environment and install dependencies:
```bash
# Navigate to project root
python -m venv .venv
source .venv/bin/activate  # Or .venv\Scripts\activate on Windows
pip install -r requirements.txt
```

#### Run Batch File Analysis (CLI)
You can parse a static PCAP and print full table reports to the terminal or export reports:
```bash
# Print general statistics
python src/main.py sample.pcap --report

# Export results as JSON to load in dashboard
python src/main.py sample.pcap --export-json report.json
```

#### Run the Live API Server
Launch the FastAPI uvicorn daemon:
```bash
python src/server.py
```
*The server will run on `http://localhost:8080` and start generating continuous packet feeds.*

---

### 2. Frontend Setup
Make sure Node.js is installed, then build or run the development server:
```bash
cd frontend
npm install
npm run dev
```
Open `http://localhost:5173/` in your browser. Click **Connect to Live Stream** to start polling the FastAPI server on port `8080`.

---

### 3. Running Unit Tests
Validate L2-L7 decoding logic, TCP states, rules engine, and anomaly firewalls:
```bash
pytest tests/
```

---

## ☁ Deployment

- **Backend (Back4App or AWS App Runner)**: Deploy using the root-level `Dockerfile` pointing the container port to `8080`. Enable CORS support.
- **Frontend (Vercel)**: Deploy the `frontend/` folder as a React Single Page Application. Configure `VITE_API_URL` to point to your live backend domain, and use the included `vercel.json` rewrite configurations.
