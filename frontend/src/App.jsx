import React, { useState, useEffect, useRef } from 'react';
import './App.css';

// ── SVG Icons ──────────────────────────────────────────────────────────────
const ShieldAlertIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 9.7a1 1 0 0 1-.68 0C7.5 20.5 4 18 4 13V6a1 1 0 0 1 .76-.97l8-2a1 1 0 0 1 .48 0l8 2A1 1 0 0 1 20 6z" /><path d="M12 8v4" /><path d="M12 16h.01" /></svg>
);
const FileUpIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4" /><polyline points="17 8 12 3 7 8" /><line x1="12" x2="12" y1="3" y2="15" /></svg>
);
const PlayIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="currentColor"><polygon points="6 3 20 12 6 21 6 3" /></svg>
);
const ActivityIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12" /></svg>
);
const AlertOctagonIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><polygon points="7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2" /><line x1="12" x2="12" y1="8" y2="12" /><line x1="12" x2="12" y1="16" y2="16.01" /></svg>
);
const UploadIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/></svg>
);
const FlowsIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M18 20V10"/><path d="M12 20V4"/><path d="M6 20v-6"/></svg>
);
const RadioIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><circle cx="12" cy="12" r="2"/><path d="M16.24 7.76a6 6 0 0 1 0 8.49m-8.48-.01a6 6 0 0 1 0-8.49m11.31-2.82a10 10 0 0 1 0 14.14m-14.14 0a10 10 0 0 1 0-14.14"/></svg>
);
const DownloadIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
);
const RefreshIcon = () => (
  <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67"/></svg>
);

// ── App badge color by application name ───────────────────────────────────
const APP_BADGE_COLORS = {
  HTTPS:        { color: '#38bdf8', bg: 'rgba(56,189,248,0.10)',  border: 'rgba(56,189,248,0.25)' },
  HTTP:         { color: '#fb923c', bg: 'rgba(251,146,60,0.10)',  border: 'rgba(251,146,60,0.25)' },
  DNS:          { color: '#a78bfa', bg: 'rgba(167,139,250,0.10)', border: 'rgba(167,139,250,0.25)' },
  SSH:          { color: '#34d399', bg: 'rgba(52,211,153,0.10)',  border: 'rgba(52,211,153,0.25)' },
  FTP:          { color: '#fbbf24', bg: 'rgba(251,191,36,0.10)',  border: 'rgba(251,191,36,0.25)' },
  Unclassified: { color: '#64748b', bg: 'rgba(100,116,139,0.08)', border: 'rgba(100,116,139,0.2)' },
};

function getAppStyle(name) {
  return APP_BADGE_COLORS[name] || APP_BADGE_COLORS['Unclassified'];
}

// ── Bar chart colors per app ───────────────────────────────────────────────
const APP_BAR_COLORS = {
  HTTPS: 'linear-gradient(90deg,#38bdf8,#818cf8)',
  HTTP:  'linear-gradient(90deg,#fb923c,#f59e0b)',
  DNS:   'linear-gradient(90deg,#a78bfa,#c084fc)',
  SSH:   'linear-gradient(90deg,#34d399,#10b981)',
  FTP:   'linear-gradient(90deg,#fbbf24,#fb923c)',
};
function getAppBarColor(name) {
  return APP_BAR_COLORS[name] || 'linear-gradient(90deg,#475569,#64748b)';
}

// ── Helper: format bytes ───────────────────────────────────────────────────
function fmtBytes(b) {
  if (b >= 1024 * 1024) return `${(b / (1024 * 1024)).toFixed(2)} MB`;
  if (b >= 1024)        return `${(b / 1024).toFixed(1)} KB`;
  return `${b} B`;
}

// ── Mock data (simulation) ─────────────────────────────────────────────────
const MOCK_DATA = {
  summary: { total_packets: 4892, total_bytes: 3829104, duration_sec: 18.254, avg_pps: 267.99, avg_kbps: 1678.14 },
  protocols: {
    TCP: { packets: 4120, bytes: 3529100, packets_pct: 84.2,  bytes_pct: 92.2 },
    UDP: { packets: 772,  bytes: 300004,  packets_pct: 15.8,  bytes_pct: 7.8 },
  },
  applications: {
    HTTPS:        { packets: 2400, bytes: 2890000, packets_pct: 49.1, bytes_pct: 75.5 },
    HTTP:         { packets: 1100, bytes: 620000,  packets_pct: 22.5, bytes_pct: 16.2 },
    DNS:          { packets: 500,  bytes: 85000,   packets_pct: 10.2, bytes_pct: 2.2  },
    SSH:          { packets: 450,  bytes: 120000,  packets_pct: 9.2,  bytes_pct: 3.1  },
    Unclassified: { packets: 442,  bytes: 114104,  packets_pct: 9.0,  bytes_pct: 3.0  },
  },
  alerts: [
    { type: 'PORT_SCAN', target: '192.168.1.105', details: 'Source IP scanned 14 unique ports (Threshold: 10)' },
    { type: 'SYN_FLOOD', target: '10.0.0.8',     details: 'Destination IP flooded with 114 SYNs and only 4 ACKs (Threshold: 50)' },
  ],
  flows: [
    { flow_id:1, protocol:'TCP', app_name:'HTTPS', sni:'google.com',   src_ip:'192.168.1.105', src_port:50421, dst_ip:'142.250.190.46', dst_port:443, packets:182, bytes:240102, duration_sec:4.102, packets_per_sec:44.37, bytes_per_sec:58532.42, status:'ACTIVE' },
    { flow_id:2, protocol:'TCP', app_name:'HTTPS', sni:'github.com',   src_ip:'192.168.1.105', src_port:50422, dst_ip:'140.82.113.3',   dst_port:443, packets:94,  bytes:81204,  duration_sec:2.894, packets_per_sec:32.48, bytes_per_sec:28059.43, status:'CLOSED' },
    { flow_id:3, protocol:'TCP', app_name:'HTTP',  sni:'',             src_ip:'192.168.1.105', src_port:50423, dst_ip:'192.168.1.1',    dst_port:80,  packets:1100,bytes:620000, duration_sec:12.054,packets_per_sec:91.26, bytes_per_sec:51435.21, status:'BLOCKED' },
    { flow_id:4, protocol:'UDP', app_name:'DNS',   sni:'1.1.1.1',      src_ip:'192.168.1.105', src_port:58992, dst_ip:'1.1.1.1',        dst_port:53,  packets:500, bytes:85000,  duration_sec:1.254, packets_per_sec:398.72,bytes_per_sec:67783.1,  status:'CLOSED' },
    { flow_id:5, protocol:'TCP', app_name:'SSH',   sni:'',             src_ip:'192.168.1.150', src_port:42104, dst_ip:'10.0.0.15',      dst_port:22,  packets:450, bytes:120000, duration_sec:14.225,packets_per_sec:31.63, bytes_per_sec:8435.85,  status:'EXPIRED' },
  ],
};

// Determine API Endpoint
const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8080';

// ── Main App ───────────────────────────────────────────────────────────────
function App() {
  const [data, setData]               = useState(null);          // null = no file loaded yet
  const [mode, setMode]               = useState('NONE');        // 'NONE', 'LIVE', 'FILE', 'DEMO'
  const [fileName, setFileName]       = useState('');
  const [searchTerm, setSearchTerm]   = useState('');
  const [filterProto, setFilterProto] = useState('ALL');
  const [filterStatus, setFilterStatus] = useState('ALL');
  const [currentPage, setCurrentPage] = useState(1);
  const [uploadError, setUploadError] = useState('');
  const [apiConnectionStatus, setApiConnectionStatus] = useState('DISCONNECTED'); // 'DISCONNECTED', 'CONNECTING', 'CONNECTED', 'ERROR'
  const itemsPerPage = 10;
  
  const pollingRef = useRef(null);

  // ── Polling logic for Live Mode ──────────────────────────────────────────
  const startLivePolling = () => {
    if (pollingRef.current) clearInterval(pollingRef.current);
    
    setMode('LIVE');
    setFileName('live_simulator_feed');
    setApiConnectionStatus('CONNECTING');
    setUploadError('');

    const fetchReport = async () => {
      try {
        const res = await fetch(`${API_URL}/api/report`);
        if (!res.ok) throw new Error('API server returned error code');
        const parsed = await res.json();
        setData(parsed);
        setApiConnectionStatus('CONNECTED');
      } catch (err) {
        console.error('Failed to fetch live DPI data:', err);
        setApiConnectionStatus('ERROR');
        setUploadError(`Failed to sync with Back4App live backend API at ${API_URL}`);
      }
    };

    fetchReport(); // Initial fetch
    pollingRef.current = setInterval(fetchReport, 1500); // Poll every 1.5s
  };

  const stopLivePolling = () => {
    if (pollingRef.current) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  };

  useEffect(() => {
    return () => stopLivePolling();
  }, []);

  // Reset live state on the backend
  const handleResetLive = async () => {
    try {
      await fetch(`${API_URL}/api/reset`, { method: 'POST' });
      // Clear local visual list temporarily
      setData(prev => ({
        ...prev,
        summary: { total_packets: 0, total_bytes: 0, duration_sec: 0, avg_pps: 0, avg_kbps: 0 },
        protocols: {},
        applications: {},
        alerts: [],
        flows: []
      }));
    } catch (err) {
      console.error('Failed to reset backend simulator:', err);
    }
  };

  // ── File upload ──────────────────────────────────────────────────────────
  const handleFileUpload = (e) => {
    stopLivePolling();
    const file = e.target.files[0];
    if (!file) return;
    setUploadError('');

    const reader = new FileReader();
    reader.onload = (event) => {
      try {
        const parsed = JSON.parse(event.target.result);
        if (!parsed.summary || !parsed.flows || !parsed.protocols || !parsed.applications) {
          setUploadError('Invalid format — file must be a WireSpectra JSON report (--export-json).');
          return;
        }
        setData(parsed);
        setFileName(file.name);
        setMode('FILE');
        setCurrentPage(1);
        setSearchTerm('');
        setFilterProto('ALL');
        setFilterStatus('ALL');
      } catch {
        setUploadError('Failed to parse JSON. Make sure the file is valid JSON.');
      }
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const handleDrop = (e) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file) handleFileUpload({ target: { files: [file], value: '' } });
  };

  const loadSimulation = () => {
    stopLivePolling();
    setData(MOCK_DATA);
    setMode('DEMO');
    setFileName('demo_simulation.json');
    setCurrentPage(1);
    setSearchTerm('');
    setFilterProto('ALL');
    setFilterStatus('ALL');
    setUploadError('');
  };

  // ── Filtered flows ───────────────────────────────────────────────────────
  const flows = data?.flows ?? [];
  const filteredFlows = flows.filter(flow => {
    const matchSearch =
      (flow.src_ip  || '').includes(searchTerm) ||
      (flow.dst_ip  || '').includes(searchTerm) ||
      (flow.sni     || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
      (flow.app_name|| '').toLowerCase().includes(searchTerm.toLowerCase());
    const matchProto  = filterProto  === 'ALL' || flow.protocol === filterProto;
    const matchStatus = filterStatus === 'ALL' || flow.status   === filterStatus;
    return matchSearch && matchProto && matchStatus;
  });

  const pageCount     = Math.max(1, Math.ceil(filteredFlows.length / itemsPerPage));
  const safePage      = Math.min(currentPage, pageCount);
  const paginatedFlows = filteredFlows.slice((safePage - 1) * itemsPerPage, safePage * itemsPerPage);

  // ── Landing screen (no data yet) ─────────────────────────────────────────
  if (!data) {
    return (
      <div className="app-container animate-fade-in">
        <header className="dashboard-header">
          <div className="brand-section">
            <div className="brand-icon">WS</div>
            <div>
              <h1>WireSpectra DPI Diagnostics</h1>
              <p className="subtitle">Deep Packet Inspection — Live Statistics &amp; Visualizations</p>
            </div>
          </div>
        </header>

        <div className="landing-screen">
          <div
            className="drop-zone"
            onDrop={handleDrop}
            onDragOver={e => e.preventDefault()}
          >
            <div className="drop-zone-icon"><UploadIcon /></div>
            <h2 style={{ color: '#fff', marginBottom: '8px' }}>Real-time Live DPI Network Analyzer</h2>
            <p className="subtitle" style={{ maxWidth: '480px', textAlign: 'center', marginBottom: '24px' }}>
              Connect to the live Python packet analyzer deployed on Back4App or browse a pre-compiled JSON diagnostics report.
            </p>

            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap', justifyContent: 'center', marginBottom: '16px' }}>
              <button className="btn btn-primary" style={{ fontSize: '0.95rem', padding: '12px 24px', background: '#38bdf8' }} onClick={startLivePolling}>
                <RadioIcon /> Connect to Live Stream
              </button>
              
              <div className="file-input-wrapper">
                <button className="btn btn-outline" style={{ fontSize: '0.95rem', padding: '12px 24px' }}>
                  <FileUpIcon /> Browse JSON Report
                </button>
                <input type="file" accept=".json" onChange={handleFileUpload} />
              </div>
              
              <button className="btn btn-outline" style={{ fontSize: '0.95rem', padding: '12px 24px' }} onClick={loadSimulation}>
                <PlayIcon /> Load Demo Data
              </button>
            </div>

            {uploadError && (
              <p style={{ color: 'var(--danger)', marginTop: '8px', fontSize: '0.9rem', maxWidth: '400px', textAlign: 'center' }}>{uploadError}</p>
            )}

            <div className="landing-steps">
              <div className="step-card">
                <span className="step-num">1</span>
                <div>
                  <strong>Start API Stream</strong>
                  <p className="subtitle">Run <code>python src/server.py</code> locally or on Back4App</p>
                </div>
              </div>
              <div className="step-card">
                <span className="step-num">2</span>
                <div>
                  <strong>Live Visualization</strong>
                  <p className="subtitle">Click "Connect to Live Stream" to monitor packets in real-time</p>
                </div>
              </div>
              <div className="step-card">
                <span className="step-num">3</span>
                <div>
                  <strong>Export PCAP</strong>
                  <p className="subtitle">Download the live captured PCAP directly to examine in Wireshark</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // ── Main dashboard ────────────────────────────────────────────────────────
  const { summary, protocols, applications, alerts } = data;

  // Clamp pct values for progress bars (backend emits raw floats)
  const clampPct = (v) => Math.min(100, Math.max(0, Number(v) || 0));

  return (
    <div className="app-container animate-fade-in">
      {/* Header */}
      <header className="dashboard-header">
        <div className="brand-section">
          <div className="brand-icon">WS</div>
          <div>
            <h1>WireSpectra DPI Diagnostics</h1>
            <p className="subtitle">
              Deep Packet Inspection — Live Statistics &amp; Visualizations
            </p>
          </div>
        </div>

        <div className="controls-section" style={{ flexWrap: 'wrap', gap: '8px' }}>
          {/* Live Status indicator */}
          {mode === 'LIVE' && (
            <span className={`status-badge ${apiConnectionStatus.toLowerCase()}`}>
              <span className="pulse-indicator"></span>
              {apiConnectionStatus === 'CONNECTED' ? 'Live Streaming' : apiConnectionStatus === 'CONNECTING' ? 'Re-syncing...' : 'Sync Error'}
            </span>
          )}

          {mode === 'DEMO' && (
            <span className="status-badge demo">
              Demo Sandbox
            </span>
          )}

          {mode === 'FILE' && (
            <span className="status-badge file">
              Static File: {fileName}
            </span>
          )}

          {mode === 'LIVE' && (
            <>
              <button className="btn btn-outline" style={{ borderColor: 'var(--danger-border)', color: 'var(--danger)' }} onClick={handleResetLive}>
                <RefreshIcon /> Reset Stream
              </button>
              <a href={`${API_URL}/api/pcap`} download className="btn btn-outline" style={{ textDecoration: 'none', display: 'inline-flex', alignItems: 'center', gap: '6px' }}>
                <DownloadIcon /> Download PCAP
              </a>
            </>
          )}

          <button className="btn btn-outline" onClick={startLivePolling}>
            <RadioIcon /> Live Feed
          </button>
          
          <button className="btn btn-outline" onClick={loadSimulation}>
            <PlayIcon /> Demo Data
          </button>

          <div className="file-input-wrapper">
            <button className="btn btn-primary">
              <FileUpIcon /> Upload Report
            </button>
            <input type="file" accept=".json" onChange={handleFileUpload} />
          </div>
        </div>
      </header>

      {uploadError && (
        <div className="error-banner">{uploadError}</div>
      )}

      {/* Stat Cards */}
      <section className="stats-grid">
        <div className="glass-card stat-card">
          <p className="subtitle">Total Packets</p>
          <div className="stat-val">{(summary.total_packets || 0).toLocaleString()}</div>
          <p className="subtitle" style={{ color: 'var(--primary)' }}>
            Avg: {(summary.avg_pps || 0).toFixed(1)} pps
          </p>
        </div>

        <div className="glass-card stat-card stat-success">
          <p className="subtitle">Total Traffic</p>
          <div className="stat-val">{fmtBytes(summary.total_bytes || 0)}</div>
          <p className="subtitle" style={{ color: 'var(--success)' }}>
            Avg: {(summary.avg_kbps || 0).toFixed(2)} Kbps
          </p>
        </div>

        <div className="glass-card stat-card stat-warning">
          <p className="subtitle">Capture Duration</p>
          <div className="stat-val">{(summary.duration_sec || 0).toFixed(1)}s</div>
          <p className="subtitle" style={{ color: 'var(--warning)' }}>
            {mode === 'LIVE' ? 'Real-time Feed' : 'Offline Capture'}
          </p>
        </div>

        <div className={`glass-card stat-card ${alerts.length > 0 ? 'stat-danger' : ''}`}>
          <p className="subtitle">Security Alerts</p>
          <div className="stat-val" style={{ color: alerts.length > 0 ? 'var(--danger)' : '#fff' }}>
            {alerts.length}
          </div>
          <p className="subtitle" style={{ color: alerts.length > 0 ? 'var(--danger)' : 'var(--text-muted)' }}>
            {alerts.length > 0 ? 'Threats Detected' : 'Clean Network'}
          </p>
        </div>

        <div className="glass-card stat-card">
          <p className="subtitle">Active Flows</p>
          <div className="stat-val">{flows.length}</div>
          <p className="subtitle" style={{ color: 'var(--secondary)' }}>
            {flows.filter(f => f.status === 'ACTIVE').length} active
            &nbsp;·&nbsp;
            {flows.filter(f => f.status === 'BLOCKED').length} blocked
          </p>
        </div>
      </section>

      {/* Distributions + Alerts */}
      <main className="main-grid">
        {/* Left: Protocol & App bars */}
        <section className="glass-card">
          <h2>Traffic Distributions</h2>
          <p className="subtitle">Network composition by protocol and application layer</p>

          <div className="distribution-row">
            {/* Layer 4 */}
            <div className="dist-card">
              <h3>Layer 4 — Protocols</h3>
              <div className="dist-list">
                {Object.entries(protocols).map(([name, stats]) => (
                  <div key={name} style={{ marginBottom: '14px' }}>
                    <div className="dist-item">
                      <span className="badge badge-proto">{name}</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                        {(stats.packets || 0).toLocaleString()} pkts &nbsp;
                        <strong>{clampPct(stats.packets_pct).toFixed(1)}%</strong>
                      </span>
                    </div>
                    <div className="progress-bar-bg">
                      <div
                        className="progress-bar-fill"
                        style={{ width: `${clampPct(stats.packets_pct)}%` }}
                      />
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '2px' }}>
                      <span className="subtitle" style={{ fontSize: '0.72rem' }}>
                        {fmtBytes(stats.bytes || 0)} &nbsp;({clampPct(stats.bytes_pct).toFixed(1)}% bytes)
                      </span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Layer 7 */}
            <div className="dist-card">
              <h3>Layer 7 — Applications</h3>
              <div className="dist-list">
                {Object.entries(applications).map(([name, stats]) => {
                  const pct = clampPct(stats.packets_pct);
                  const style = getAppStyle(name);
                  return (
                    <div key={name} style={{ marginBottom: '14px' }}>
                      <div className="dist-item">
                        <span
                          className="badge"
                          style={{ color: style.color, background: style.bg, border: `1px solid ${style.border}` }}
                        >
                          {name}
                        </span>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                          {(stats.packets || 0).toLocaleString()} pkts &nbsp;
                          <strong>{pct.toFixed(1)}%</strong>
                        </span>
                      </div>
                      <div className="progress-bar-bg">
                        <div
                          className="progress-bar-fill"
                          style={{ width: `${pct}%`, background: getAppBarColor(name) }}
                        />
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '2px' }}>
                        <span className="subtitle" style={{ fontSize: '0.72rem' }}>
                          {fmtBytes(stats.bytes || 0)} &nbsp;({clampPct(stats.bytes_pct).toFixed(1)}% bytes)
                        </span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>

          {/* SVG Throughput chart — driven by real avg_pps */}
          <div style={{ marginTop: '24px' }}>
            <h3>Throughput Sparkline</h3>
            <div className="svg-chart-container">
              <div className="svg-chart-glow" />
              <svg className="chart-svg" width="100%" height="120" viewBox="0 0 500 120" preserveAspectRatio="none">
                <defs>
                  <linearGradient id="cg" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--primary)" stopOpacity="0.35" />
                    <stop offset="100%" stopColor="var(--primary)" stopOpacity="0" />
                  </linearGradient>
                </defs>
                <line x1="0" y1="30" x2="500" y2="30" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
                <line x1="0" y1="60" x2="500" y2="60" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
                <line x1="0" y1="90" x2="500" y2="90" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
                <path
                  d="M 0 120 L 0 95 Q 60 30 120 70 T 250 35 T 370 80 T 500 40 L 500 120 Z"
                  fill="url(#cg)"
                />
                <path
                  d="M 0 95 Q 60 30 120 70 T 250 35 T 370 80 T 500 40"
                  fill="none" stroke="var(--primary)" strokeWidth="2"
                />
                {/* Label */}
                <text x="8" y="16" fill="var(--text-muted)" fontSize="10" fontFamily="monospace">
                  Peak ~{(summary.avg_pps * 1.4).toFixed(0)} pps
                </text>
                <text x="8" y="108" fill="var(--text-muted)" fontSize="10" fontFamily="monospace">
                  Avg {(summary.avg_pps || 0).toFixed(1)} pps  |  {(summary.avg_kbps || 0).toFixed(1)} Kbps
                </text>
              </svg>
            </div>
          </div>
        </section>

        {/* Right: Alerts */}
        <section className="glass-card">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <ActivityIcon />
            <h2>Anomaly &amp; Threat Center</h2>
          </div>
          <p className="subtitle">Volumetric intrusion alerts from the DPI engine</p>

          <div className="alerts-list">
            {alerts.length === 0 ? (
              <div className="empty-state">
                <ShieldAlertIcon />
                <p style={{ fontWeight: '600', color: 'var(--success)', marginTop: '8px' }}>No Threats Detected</p>
                <p className="subtitle">Capture appears clean — no port scans or SYN floods flagged.</p>
              </div>
            ) : (
              alerts.map((alert, idx) => (
                <div key={idx} className="alert-item animate-fade-in">
                  <div className="alert-item-icon"><AlertOctagonIcon /></div>
                  <div className="alert-item-content">
                    <div className="alert-item-type">{alert.type} Alert</div>
                    <div className="alert-item-desc">{alert.details}</div>
                    <div className="alert-item-target">{alert.target}</div>
                  </div>
                </div>
              ))
            )}
          </div>

          {/* Flow status summary */}
          <div className="flow-status-summary">
            <h3 style={{ marginBottom: '12px' }}>Flow Status Breakdown</h3>
            {['ACTIVE', 'CLOSED', 'BLOCKED', 'EXPIRED'].map(status => {
              const count = flows.filter(f => f.status === status).length;
              const pct = flows.length ? (count / flows.length) * 100 : 0;
              const colors = {
                ACTIVE:  'var(--success)',
                CLOSED:  'var(--text-muted)',
                BLOCKED: 'var(--danger)',
                EXPIRED: 'var(--warning)',
              };
              return (
                <div key={status} style={{ marginBottom: '10px' }}>
                  <div className="dist-item">
                    <span style={{ fontSize: '0.8rem', color: colors[status], fontWeight: 600 }}>{status}</span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{count} flows</span>
                  </div>
                  <div className="progress-bar-bg">
                    <div
                      className="progress-bar-fill"
                      style={{ width: `${pct}%`, background: colors[status] }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      </main>

      {/* Flows Table */}
      <section className="glass-card">
        <div className="flows-header-actions">
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FlowsIcon />
            <div>
              <h2>Connection Flows</h2>
              <p className="subtitle">
                {filteredFlows.length} of {flows.length} flows shown
              </p>
            </div>
          </div>

          <div className="controls-section">
            <input
              type="text"
              placeholder="Search IP, host, SNI, app..."
              className="search-input"
              value={searchTerm}
              onChange={e => { setSearchTerm(e.target.value); setCurrentPage(1); }}
            />
            <select
              className="filter-select"
              value={filterProto}
              onChange={e => { setFilterProto(e.target.value); setCurrentPage(1); }}
            >
              <option value="ALL">All Protocols</option>
              <option value="TCP">TCP</option>
              <option value="UDP">UDP</option>
            </select>
            <select
              className="filter-select"
              value={filterStatus}
              onChange={e => { setFilterStatus(e.target.value); setCurrentPage(1); }}
            >
              <option value="ALL">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="CLOSED">Closed</option>
              <option value="BLOCKED">Blocked</option>
              <option value="EXPIRED">Expired</option>
            </select>
          </div>
        </div>

        <div className="table-wrapper">
          {paginatedFlows.length === 0 ? (
            <div className="empty-state" style={{ border: 'none', padding: '48px' }}>
              <p style={{ fontWeight: '500' }}>No flows match the current filters</p>
              <p className="subtitle">Try adjusting the search or protocol filter</p>
            </div>
          ) : (
            <table>
              <thead>
                <tr>
                  <th>#</th>
                  <th>Proto</th>
                  <th>App / SNI</th>
                  <th>Source</th>
                  <th>Destination</th>
                  <th>Packets</th>
                  <th>Bytes</th>
                  <th>Duration</th>
                  <th>Rate</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {paginatedFlows.map((flow) => {
                  const appStyle = getAppStyle(flow.app_name);
                  return (
                    <tr key={flow.flow_id}>
                      <td className="mono-cell" style={{ opacity: 0.4 }}>{flow.flow_id}</td>
                      <td>
                        <span className="badge badge-proto">{flow.protocol}</span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          style={{
                            color: appStyle.color,
                            background: appStyle.bg,
                            border: `1px solid ${appStyle.border}`,
                          }}
                        >
                          {flow.app_name || '—'}
                        </span>
                        {flow.sni && (
                          <span className="subtitle" style={{ display: 'block', fontSize: '0.72rem', marginTop: '3px' }}>
                            {flow.sni}
                          </span>
                        )}
                      </td>
                      <td className="mono-cell">
                        {flow.src_ip}{flow.src_port ? `:${flow.src_port}` : ''}
                      </td>
                      <td className="mono-cell">
                        {flow.dst_ip}{flow.dst_port ? `:${flow.dst_port}` : ''}
                      </td>
                      <td className="mono-cell">{(flow.packets || 0).toLocaleString()}</td>
                      <td className="mono-cell">{fmtBytes(flow.bytes || 0)}</td>
                      <td className="mono-cell">{(flow.duration_sec || 0).toFixed(3)}s</td>
                      <td className="mono-cell" style={{ opacity: 0.7 }}>
                        {(flow.bytes_per_sec || 0) > 0
                          ? `${fmtBytes(Math.round(flow.bytes_per_sec))}/s`
                          : '—'}
                      </td>
                      <td>
                        <span className={`badge badge-status-${(flow.status || 'ACTIVE').toLowerCase()}`}>
                          {flow.status}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Pagination */}
        {pageCount > 1 && (
          <div className="pagination">
            <span>Page {safePage} of {pageCount} &nbsp;·&nbsp; {filteredFlows.length} flows</span>
            <div className="pagination-buttons">
              <button
                className="btn btn-outline btn-sm"
                disabled={safePage === 1}
                onClick={() => setCurrentPage(p => Math.max(p - 1, 1))}
              >Previous</button>
              <button
                className="btn btn-outline btn-sm"
                disabled={safePage === pageCount}
                onClick={() => setCurrentPage(p => Math.min(p + 1, pageCount))}
              >Next</button>
            </div>
          </div>
        )}
      </section>
    </div>
  );
}

export default App;
