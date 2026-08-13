import { useState, useRef, useEffect } from 'react'

// ─── Types ────────────────────────────────────────────────────────────────────

type Packet = {
  no: number
  time: string
  src: string
  dst: string
  protocol: string
  length: number
  info: string
  threat: number
}

type TreeNode = {
  label: string
  value?: string
  children?: TreeNode[]
}

// ─── Mock data ────────────────────────────────────────────────────────────────

const MOCK_PACKETS: Packet[] = [
  { no: 1,  time: '0.000000', src: '192.168.1.45',   dst: '8.8.8.8',       protocol: 'DNS',    length: 74,  info: 'Standard query 0x1234 A api.sentinel.io',         threat: 0 },
  { no: 2,  time: '0.002341', src: '8.8.8.8',         dst: '192.168.1.45',  protocol: 'DNS',    length: 90,  info: 'Standard query response A 142.250.80.46',          threat: 0 },
  { no: 3,  time: '0.004812', src: '192.168.1.45',   dst: '142.250.80.46', protocol: 'TLS',    length: 583, info: 'Client Hello, TLSv1.3',                             threat: 0 },
  { no: 4,  time: '0.018234', src: '142.250.80.46',  dst: '192.168.1.45',  protocol: 'TLS',    length: 1460, info: 'Server Hello, Certificate',                         threat: 0 },
  { no: 5,  time: '0.023100', src: '10.0.0.12',      dst: '192.168.1.45',  protocol: 'TCP',    length: 66,  info: 'SYN Flood candidate → 192.168.1.45:22 [SYN]',      threat: 87 },
  { no: 6,  time: '0.023890', src: '10.0.0.13',      dst: '192.168.1.45',  protocol: 'TCP',    length: 66,  info: 'SYN Flood candidate → 192.168.1.45:22 [SYN]',      threat: 87 },
  { no: 7,  time: '0.025003', src: '192.168.1.45',   dst: '172.217.14.78', protocol: 'HTTP',   length: 412, info: 'GET /api/v2/stream HTTP/1.1',                        threat: 0 },
  { no: 8,  time: '0.031200', src: '203.0.113.99',   dst: '192.168.1.45',  protocol: 'ICMP',   length: 84,  info: 'Echo (ping) request id=0x1c2d, seq=1/256',          threat: 0 },
  { no: 9,  time: '0.045678', src: '192.168.1.101',  dst: '255.255.255.0', protocol: 'ARP',    length: 42,  info: 'Who has 192.168.1.1? Tell 192.168.1.101',           threat: 0 },
  { no: 10, time: '0.048900', src: '185.220.101.47', dst: '192.168.1.45',  protocol: 'TCP',    length: 66,  info: 'Port scan detected — SYN to port 443 [TOR exit]',   threat: 94 },
  { no: 11, time: '0.051230', src: '192.168.1.45',   dst: '8.8.4.4',       protocol: 'DNS',    length: 79,  info: 'Standard query 0xABCD AAAA fonts.gstatic.com',      threat: 0 },
  { no: 12, time: '0.062100', src: '192.168.1.45',   dst: '52.84.31.1',    protocol: 'HTTPS',  length: 1460, info: 'Application Data, TLSv1.3',                         threat: 0 },
  { no: 13, time: '0.075432', src: '10.10.0.55',     dst: '192.168.1.45',  protocol: 'SSH',    length: 184, info: 'Encrypted packet len=120',                           threat: 0 },
  { no: 14, time: '0.088001', src: '198.51.100.202', dst: '192.168.1.45',  protocol: 'TCP',    length: 66,  info: 'CVE-2024-3094 XZ Utils backdoor probe attempt',      threat: 99 },
  { no: 15, time: '0.091234', src: '192.168.1.45',   dst: '34.120.54.8',   protocol: 'QUIC',   length: 1232, info: 'Protected Payload, QUIC v1',                        threat: 0 },
]

const TREE_DATA: TreeNode[] = [
  {
    label: 'Frame 14',
    value: '66 bytes on wire, 66 bytes captured',
    children: [
      { label: 'Arrival Time',       value: '2024-11-15 14:32:08.088001 UTC' },
      { label: 'Frame Length',       value: '66 bytes' },
      { label: 'Capture Length',     value: '66 bytes' },
    ],
  },
  {
    label: 'Ethernet II',
    value: 'Src: 00:1a:2b:3c:4d:5e → Dst: ff:ff:ff:ff:ff:ff',
    children: [
      { label: 'Destination',        value: 'ff:ff:ff:ff:ff:ff (Broadcast)' },
      { label: 'Source',             value: '00:1a:2b:3c:4d:5e (Cisco Systems)' },
      { label: 'Type',               value: 'IPv4 (0x0800)' },
    ],
  },
  {
    label: 'Internet Protocol v4',
    value: 'Src: 198.51.100.202 → Dst: 192.168.1.45',
    children: [
      { label: 'Version',            value: '4' },
      { label: 'Header Length',      value: '20 bytes' },
      { label: 'TTL',                value: '128' },
      { label: 'Protocol',           value: 'TCP (6)' },
      { label: 'Src IP',             value: '198.51.100.202 🚩 TOR Exit Node — AS29169' },
      { label: 'Dst IP',             value: '192.168.1.45' },
    ],
  },
  {
    label: 'Transmission Control Protocol',
    value: 'Src Port: 54123 → Dst Port: 22 [SYN]',
    children: [
      { label: 'Source Port',        value: '54123' },
      { label: 'Destination Port',   value: '22 (SSH)' },
      { label: 'Flags',              value: '0x002 (SYN)' },
      { label: 'Checksum',           value: '0x4a7c [correct]' },
    ],
  },
  {
    label: '🔴 Threat Intelligence',
    value: 'Score: 99 — CVE-2024-3094 XZ Utils Backdoor',
    children: [
      { label: 'Threat Type',        value: 'Supply Chain / Backdoor Probe' },
      { label: 'CVE',                value: 'CVE-2024-3094 (CVSS 10.0)' },
      { label: 'IP Reputation',      value: 'Known malicious — CISA advisory' },
      { label: 'First Seen',         value: '2024-04-01 (VirusTotal)' },
      { label: 'ASN',                value: 'AS29169 Giganet Ltd (RU)' },
    ],
  },
  {
    label: '🌍 Geolocation',
    value: 'Kaliningrad, Russia',
    children: [
      { label: 'Country',            value: 'Russia 🇷🇺' },
      { label: 'City',               value: 'Kaliningrad' },
      { label: 'Coordinates',        value: '54.7065° N, 20.5110° E' },
      { label: 'ISP',                value: 'Rostelecom PJSC' },
    ],
  },
]

const HEX_LINES = [
  { offset: '0000', hex: '45 00 00 42 1c 2d 40 00  80 06 4a 7c c6 33 64 ca', ascii: 'E..B.-@...Jz.3d.' },
  { offset: '0010', hex: 'c0 a8 01 2d d3 6b 00 16  eb 7f 00 00 00 00 00 00', ascii: '...-.k..........' },
  { offset: '0020', hex: '70 02 ff ff 4a 7c 00 00  02 04 05 b4 04 02 08 0a', ascii: 'p...J|..........' },
  { offset: '0030', hex: 'f3 a1 22 d3 00 00 00 00  01 03 03 07 00 00 00 00', ascii: '.."..............' },
  { offset: '0040', hex: '00 42 00 00', hex2: '', ascii: '.B..' },
]

const PROTOCOLS = ['TCP', 'UDP', 'DNS', 'TLS', 'HTTPS', 'HTTP', 'ICMP', 'ARP', 'QUIC', 'SSH']

// ─── Sub-components ───────────────────────────────────────────────────────────

function ThreatBadge({ score }: { score: number }) {
  if (score === 0) {
    return (
      <span className="threat-badge" style={{ background: 'rgba(34,197,94,0.12)', color: '#4ADE80', border: '1px solid rgba(74,222,128,0.25)' }}>
        0% Safe
      </span>
    )
  }
  const color = score >= 90 ? '#EF4444' : score >= 60 ? '#F97316' : '#EAB308'
  const bg = score >= 90 ? 'rgba(239,68,68,0.12)' : score >= 60 ? 'rgba(249,115,22,0.12)' : 'rgba(234,179,8,0.12)'
  const border = score >= 90 ? 'rgba(239,68,68,0.3)' : score >= 60 ? 'rgba(249,115,22,0.3)' : 'rgba(234,179,8,0.3)'
  return (
    <span className="threat-badge" style={{ background: bg, color, border: `1px solid ${border}` }}>
      {score}% Risk
    </span>
  )
}

function TreeRow({ node, depth = 0, defaultOpen = false }: { node: TreeNode; depth?: number; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen)
  const hasChildren = node.children && node.children.length > 0
  return (
    <div>
      <div
        className="tree-item flex items-start gap-1 px-3 py-1 rounded"
        style={{ paddingLeft: `${12 + depth * 16}px`, cursor: hasChildren ? 'pointer' : 'default' }}
        onClick={() => hasChildren && setOpen(o => !o)}
      >
        {hasChildren ? (
          <span style={{ color: '#22D3EE', fontSize: 10, marginTop: 3, flexShrink: 0, width: 12 }}>
            {open ? '▼' : '▶'}
          </span>
        ) : (
          <span style={{ width: 12, flexShrink: 0 }} />
        )}
        <span className="font-mono text-xs" style={{ color: '#22D3EE', flexShrink: 0 }}>{node.label}</span>
        {node.value && (
          <span className="font-mono text-xs truncate" style={{ color: '#94A3B8', marginLeft: 6 }}>
            {node.value}
          </span>
        )}
      </div>
      {open && node.children && (
        <div>
          {node.children.map((child, i) => (
            <TreeRow key={i} node={child} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export default function App() {
  const [capturing, setCapturing] = useState(false)
  const [selectedRow, setSelectedRow] = useState<number | null>(14)
  const [treeOpenAll, setTreeOpenAll] = useState(false)
  const [treeKey, setTreeKey] = useState(0)
  const [mockMode, setMockMode] = useState(true)
  const [packets, setPackets] = useState<Packet[]>(MOCK_PACKETS)
  const [bpfFilter, setBpfFilter] = useState('')
  const [iface, setIface] = useState('en0')
  const packetRef = useRef<HTMLDivElement>(null)

  const totalPackets = packets.length
  const threats = packets.filter(p => p.threat > 0).length
  const safe = packets.filter(p => p.threat === 0).length
  const totalBytes = packets.reduce((a, p) => a + p.length, 0)
  const kbytes = (totalBytes / 1024).toFixed(1)

  const protoCount: Record<string, number> = {}
  packets.forEach(p => { protoCount[p.protocol] = (protoCount[p.protocol] || 0) + 1 })
  const topProtos = Object.entries(protoCount).sort((a, b) => b[1] - a[1]).slice(0, 5)

  useEffect(() => {
    if (!capturing) return
    const id = setInterval(() => {
      setPackets(prev => {
        const last = prev[prev.length - 1]
        const protos = PROTOCOLS[Math.floor(Math.random() * PROTOCOLS.length)]
        const threat = Math.random() < 0.05 ? Math.floor(Math.random() * 50 + 50) : 0
        const next: Packet = {
          no: last.no + 1,
          time: (parseFloat(last.time) + Math.random() * 0.015).toFixed(6),
          src: `192.168.1.${Math.floor(Math.random() * 254 + 1)}`,
          dst: `${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
          protocol: protos,
          length: Math.floor(Math.random() * 1400 + 60),
          info: `Live packet #${last.no + 1}`,
          threat,
        }
        const updated = [...prev, next]
        return updated.slice(-200)
      })
      if (packetRef.current) {
        packetRef.current.scrollTop = packetRef.current.scrollHeight
      }
    }, 400)
    return () => clearInterval(id)
  }, [capturing])

  const handleStart = () => setCapturing(true)
  const handleStop = () => setCapturing(false)
  const handleClear = () => { setPackets([]); setCapturing(false) }

  const selectedPacket = packets.find(p => p.no === selectedRow)

  // Panel colors
  const panelBg = '#131C2B'
  const baseBg = '#0B1220'
  const border = '#1E293B'
  const cyan = '#22D3EE'
  const muted = '#94A3B8'

  return (
    <div style={{ width: '100%', minHeight: '100vh', background: baseBg, display: 'flex', flexDirection: 'column', fontFamily: 'Inter, sans-serif' }}>

      {/* ── Title Bar ── */}
      <div style={{ background: '#0A101C', borderBottom: `1px solid ${border}`, height: 40, display: 'flex', alignItems: 'center', paddingLeft: 16, paddingRight: 16, flexShrink: 0, gap: 12 }}>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#FF5F57', display: 'block' }} />
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#FFBD2E', display: 'block' }} />
          <span style={{ width: 12, height: 12, borderRadius: '50%', background: '#28C840', display: 'block' }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginLeft: 8 }}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
            <path d="M12 2L2 7l10 5 10-5-10-5z" stroke={cyan} strokeWidth="1.5" strokeLinejoin="round"/>
            <path d="M2 17l10 5 10-5" stroke={cyan} strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
            <path d="M2 12l10 5 10-5" stroke="#2DD4BF" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" opacity="0.6"/>
          </svg>
          <span style={{ fontWeight: 700, fontSize: 14, color: cyan, letterSpacing: '0.04em' }}>SentinelShark</span>
          <span style={{ fontSize: 11, color: muted, marginLeft: 2 }}>v2.4.1 — Network Intrusion Detection & Analysis</span>
        </div>
        <div style={{ marginLeft: 'auto', display: 'flex', gap: 12, alignItems: 'center' }}>
          <span style={{ fontSize: 11, color: muted, fontFamily: 'JetBrains Mono, monospace' }}>
            {capturing ? <span style={{ color: '#22C55E' }}>● LIVE CAPTURE</span> : <span style={{ color: muted }}>● IDLE</span>}
          </span>
        </div>
      </div>

      {/* ── Toolbar ── */}
      <div style={{ background: panelBg, borderBottom: `1px solid ${border}`, padding: '8px 16px', display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
        {/* Interface dropdown */}
        <select
          value={iface}
          onChange={e => setIface(e.target.value)}
          style={{ background: '#0B1220', border: `1px solid ${border}`, color: '#E2E8F0', borderRadius: 8, padding: '5px 10px', fontSize: 13, fontFamily: 'JetBrains Mono, monospace', cursor: 'pointer', outline: 'none' }}
        >
          <option value="en0">en0 — Ethernet</option>
          <option value="en1">en1 — Wi-Fi</option>
          <option value="lo0">lo0 — Loopback</option>
          <option value="any">any — All Interfaces</option>
        </select>

        {/* BPF Filter */}
        <div style={{ flex: 1, position: 'relative' }}>
          <div style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: muted, fontSize: 13 }}>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
              <circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/>
            </svg>
          </div>
          <input
            value={bpfFilter}
            onChange={e => setBpfFilter(e.target.value)}
            placeholder="BPF Filter — e.g. tcp port 443 or host 192.168.1.1"
            style={{ width: '100%', background: '#0B1220', border: `1px solid ${border}`, color: '#E2E8F0', borderRadius: 8, padding: '5px 12px 5px 32px', fontSize: 13, fontFamily: 'JetBrains Mono, monospace', outline: 'none' }}
          />
        </div>

        {/* Action Buttons */}
        <button
          className={`btn ${capturing ? 'capturing' : ''}`}
          onClick={handleStart}
          disabled={capturing}
          style={{ background: capturing ? 'rgba(34,197,94,0.3)' : '#22C55E', border: capturing ? '1px solid #22C55E' : 'none', color: '#fff', borderRadius: 8, padding: '5px 14px', fontSize: 13, fontWeight: 600, cursor: capturing ? 'not-allowed' : 'pointer', display: 'flex', alignItems: 'center', gap: 6, whiteSpace: 'nowrap' }}
        >
          <span style={{ width: 6, height: 6, background: capturing ? '#22C55E' : '#fff', borderRadius: '50%', display: 'inline-block', animation: capturing ? 'pulse-glow 1s infinite' : 'none' }} />
          Start Capture
        </button>

        <button
          className="btn"
          onClick={handleStop}
          disabled={!capturing}
          style={{ background: !capturing ? 'rgba(30,41,59,0.5)' : 'rgba(239,68,68,0.15)', border: `1px solid ${!capturing ? border : '#EF4444'}`, color: !capturing ? '#475569' : '#EF4444', borderRadius: 8, padding: '5px 14px', fontSize: 13, fontWeight: 600, cursor: !capturing ? 'not-allowed' : 'pointer', whiteSpace: 'nowrap' }}
        >
          ■ Stop
        </button>

        <button className="btn" onClick={handleClear} style={{ background: 'transparent', border: `1px solid ${border}`, color: '#94A3B8', borderRadius: 8, padding: '5px 12px', fontSize: 13, fontWeight: 500, cursor: 'pointer' }}>
          Clear
        </button>

        <button className="btn" style={{ background: 'rgba(37,99,235,0.15)', border: '1px solid #2563EB', color: '#3B82F6', borderRadius: 8, padding: '5px 12px', fontSize: 13, fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap' }}>
          💾 Save
        </button>

        <button
          className="btn"
          onClick={() => setMockMode(m => !m)}
          style={{ background: mockMode ? 'rgba(37,99,235,0.25)' : 'transparent', border: `1px solid ${mockMode ? '#3B82F6' : border}`, color: mockMode ? '#3B82F6' : muted, borderRadius: 8, padding: '5px 12px', fontSize: 13, fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap' }}
        >
          {mockMode ? '⚡ Mock ON' : '⚡ Mock OFF'}
        </button>

        <button className="btn" style={{ background: 'rgba(37,99,235,0.15)', border: '1px solid #2563EB', color: '#3B82F6', borderRadius: 8, padding: '5px 12px', fontSize: 13, fontWeight: 500, cursor: 'pointer', whiteSpace: 'nowrap' }}>
          🔑 API Keys
        </button>
      </div>

      {/* ── Main Content ── */}
      <div style={{ flex: 1, display: 'flex', minHeight: 0, overflow: 'hidden' }}>

        {/* ── Left: Packet Table (75%) ── */}
        <div style={{ flex: 3, display: 'flex', flexDirection: 'column', borderRight: `1px solid ${border}`, minWidth: 0 }}>
          {/* Table header */}
          <div style={{ background: '#0A101C', borderBottom: `1px solid ${border}`, display: 'grid', gridTemplateColumns: '48px 90px 140px 140px 80px 64px 1fr 110px', alignItems: 'center', padding: '0 12px', height: 32, flexShrink: 0 }}>
            {['No.', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info', 'Threat Score'].map(h => (
              <div key={h} style={{ fontSize: 11, fontWeight: 700, color: cyan, letterSpacing: '0.06em', textTransform: 'uppercase', padding: '0 4px', fontFamily: 'JetBrains Mono, monospace' }}>{h}</div>
            ))}
          </div>

          {/* Packet rows */}
          <div ref={packetRef} style={{ flex: 1, overflowY: 'auto', minHeight: 0 }}>
            {packets.map((p, i) => {
              const isSelected = selectedRow === p.no
              const isSafe = p.threat === 0
              const isThreat = p.threat > 0
              let bg = i % 2 === 0 ? panelBg : '#0f1622'
              if (isThreat) bg = 'rgba(239,68,68,0.07)'
              if (isSafe && i % 2 === 0 && p.protocol === 'DNS') bg = 'rgba(15,46,30,0.5)'
              if (isSelected) bg = 'rgba(29,78,216,0.35)'

              return (
                <div
                  key={p.no}
                  className="packet-row"
                  onClick={() => setSelectedRow(p.no)}
                  style={{ background: bg, display: 'grid', gridTemplateColumns: '48px 90px 140px 140px 80px 64px 1fr 110px', alignItems: 'center', padding: '0 12px', height: 26, borderBottom: `1px solid rgba(30,41,59,0.5)` }}
                >
                  <span className="font-mono" style={{ fontSize: 12, color: muted }}>{p.no}</span>
                  <span className="font-mono" style={{ fontSize: 12, color: muted }}>{p.time}</span>
                  <span className="font-mono" style={{ fontSize: 12, color: p.threat > 0 ? '#FCA5A5' : '#E2E8F0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.src}</span>
                  <span className="font-mono" style={{ fontSize: 12, color: '#E2E8F0', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{p.dst}</span>
                  <ProtoTag proto={p.protocol} />
                  <span className="font-mono" style={{ fontSize: 12, color: muted }}>{p.length}</span>
                  <span className="font-mono" style={{ fontSize: 12, color: p.threat > 0 ? '#FCA5A5' : muted, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', paddingRight: 8 }}>{p.info}</span>
                  <div style={{ display: 'flex', alignItems: 'center' }}>
                    <ThreatBadge score={p.threat} />
                  </div>
                </div>
              )
            })}
            {packets.length === 0 && (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 120, color: muted, fontSize: 13, fontFamily: 'JetBrains Mono, monospace' }}>
                No packets captured. Start capture or enable Mock Mode.
              </div>
            )}
          </div>
        </div>

        {/* ── Right Sidebar (25%) ── */}
        <div style={{ width: 300, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 0, overflowY: 'auto', background: '#0d1523' }}>
          <div style={{ padding: '12px 12px 0', display: 'flex', flexDirection: 'column', gap: 8 }}>

            {/* Stat cards 2x2 grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              <StatCard label="Total Packets" value={totalPackets.toLocaleString()} color={cyan} />
              <StatCard label="Data Traffic" value={`${kbytes} KB`} color="#2DD4BF" />
              <StatCard label="Safe Packets" value={safe.toLocaleString()} color="#4ADE80" />
              <StatCard label="Threats Detected" value={threats.toLocaleString()} color={threats > 0 ? '#EF4444' : '#94A3B8'} />
            </div>

            {/* Protocol Breakdown */}
            <div className="card-glow" style={{ background: panelBg, border: `1px solid ${border}`, borderRadius: 10, padding: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: cyan, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 8, fontFamily: 'JetBrains Mono, monospace' }}>Protocol Breakdown</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                {topProtos.map(([proto, count]) => (
                  <div key={proto} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span className="font-mono" style={{ fontSize: 11, color: muted, width: 46 }}>{proto}</span>
                    <div style={{ flex: 1, height: 4, background: '#1E293B', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ height: '100%', width: `${(count / totalPackets) * 100}%`, background: protoColor(proto), borderRadius: 2, transition: 'width 0.5s ease' }} />
                    </div>
                    <span className="font-mono" style={{ fontSize: 11, color: '#E2E8F0', width: 24, textAlign: 'right' }}>{count}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Threat Intel API Queue */}
            <div className="card-glow" style={{ background: panelBg, border: `1px solid ${border}`, borderRadius: 10, padding: 12 }}>
              <div style={{ fontSize: 11, fontWeight: 700, color: cyan, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 8, fontFamily: 'JetBrains Mono, monospace' }}>Threat Intel API Queue</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, color: muted }}>VirusTotal</span>
                  <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#22C55E' }}>● Connected</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, color: muted }}>AbuseIPDB</span>
                  <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#22C55E' }}>● Connected</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, color: muted }}>Shodan</span>
                  <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#F59E0B' }}>◐ Rate Limited</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <span style={{ fontSize: 12, color: muted }}>OTX AlienVault</span>
                  <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#EF4444' }}>✕ Offline</span>
                </div>
                <div style={{ marginTop: 6 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{ fontSize: 11, color: muted }}>Queue Processing</span>
                    <span style={{ fontSize: 11, fontFamily: 'JetBrains Mono, monospace', color: '#E2E8F0' }}>7 / 12</span>
                  </div>
                  <div style={{ height: 4, background: '#1E293B', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ height: '100%', width: '58%', background: 'linear-gradient(90deg, #22D3EE, #2DD4BF)', borderRadius: 2 }} />
                  </div>
                </div>
              </div>
            </div>

            {/* Selected packet info */}
            {selectedPacket && (
              <div className="card-glow" style={{ background: panelBg, border: `1px solid ${selectedPacket.threat > 0 ? 'rgba(239,68,68,0.4)' : border}`, borderRadius: 10, padding: 12 }}>
                <div style={{ fontSize: 11, fontWeight: 700, color: cyan, letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 8, fontFamily: 'JetBrains Mono, monospace' }}>Selected: Packet #{selectedPacket.no}</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {[
                    ['Protocol', selectedPacket.protocol],
                    ['Source', selectedPacket.src],
                    ['Dest', selectedPacket.dst],
                    ['Size', `${selectedPacket.length} bytes`],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', gap: 8 }}>
                      <span style={{ fontSize: 11, color: muted, flexShrink: 0 }}>{k}</span>
                      <span className="font-mono" style={{ fontSize: 11, color: '#E2E8F0', textAlign: 'right', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          </div>
        </div>
      </div>

      {/* ── Bottom Split Panel ── */}
      <div style={{ height: 260, flexShrink: 0, display: 'flex', borderTop: `1px solid ${border}` }}>

        {/* Left: Packet Details */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', borderRight: `1px solid ${border}`, minWidth: 0 }}>
          <div style={{ background: '#0A101C', borderBottom: `1px solid ${border}`, padding: '0 12px', height: 32, display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: cyan, letterSpacing: '0.04em' }}>Packet Details (Dissection)</span>
            <div style={{ display: 'flex', gap: 6 }}>
              <button
                onClick={() => { setTreeOpenAll(true); setTreeKey(k => k + 1) }}
                style={{ background: 'transparent', border: `1px solid ${border}`, color: muted, borderRadius: 6, padding: '2px 8px', fontSize: 11, cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace' }}
              >
                Expand All
              </button>
              <button
                onClick={() => { setTreeOpenAll(false); setTreeKey(k => k + 1) }}
                style={{ background: 'transparent', border: `1px solid ${border}`, color: muted, borderRadius: 6, padding: '2px 8px', fontSize: 11, cursor: 'pointer', fontFamily: 'JetBrains Mono, monospace' }}
              >
                Collapse All
              </button>
            </div>
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '4px 0', background: panelBg }}>
            {TREE_DATA.map((node, i) => (
              <TreeRow key={`${treeKey}-${i}`} node={node} defaultOpen={treeOpenAll || i < 2} />
            ))}
          </div>
        </div>

        {/* Right: Hex Viewer */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0 }}>
          <div style={{ background: '#0A101C', borderBottom: `1px solid ${border}`, padding: '0 12px', height: 32, display: 'flex', alignItems: 'center', gap: 8, flexShrink: 0 }}>
            <span style={{ fontSize: 12, fontWeight: 700, color: cyan, letterSpacing: '0.04em' }}>Raw Packet Bytes</span>
            <span style={{ fontSize: 11, color: muted, fontFamily: 'JetBrains Mono, monospace' }}>Hex / ASCII</span>
            {selectedPacket && (
              <span style={{ fontSize: 11, color: muted, fontFamily: 'JetBrains Mono, monospace', marginLeft: 'auto' }}>{selectedPacket.length} bytes</span>
            )}
          </div>
          <div style={{ flex: 1, background: '#000810', overflowY: 'auto', padding: 10, display: 'flex', flexDirection: 'column', gap: 0 }}>
            {/* Hex dump */}
            <div style={{ flex: 1 }}>
              {HEX_LINES.map((line, i) => (
                <div key={i} className="font-mono" style={{ display: 'flex', gap: 16, fontSize: 12, lineHeight: '20px' }}>
                  <span style={{ color: '#475569', userSelect: 'none', width: 36, flexShrink: 0 }}>{line.offset}</span>
                  <span style={{ color: '#22D3EE', letterSpacing: '0.05em', flex: 1 }}>{line.hex}</span>
                  <span style={{ color: '#2DD4BF', opacity: 0.7, letterSpacing: '0.02em', width: 130, flexShrink: 0 }}>{line.ascii}</span>
                </div>
              ))}
            </div>
            {/* Hash fields */}
            <div style={{ marginTop: 10, paddingTop: 10, borderTop: `1px solid #1a2535`, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              <HashChip label="MD5" value="a1b2c3d4e5f67890abcdef1234567890" />
              <HashChip label="SHA256" value="3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6789abcdef012345" />
            </div>
          </div>
        </div>
      </div>

      {/* ── Status Bar ── */}
      <div style={{ height: 26, background: '#060c14', borderTop: `1px solid ${border}`, display: 'flex', alignItems: 'center', paddingLeft: 16, paddingRight: 16, justifyContent: 'space-between', flexShrink: 0 }}>
        <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
          <span className="font-mono" style={{ fontSize: 11, color: capturing ? '#22C55E' : muted }}>
            {capturing ? `● Capturing on ${iface}` : '○ Capture stopped'}
          </span>
          {bpfFilter && (
            <span className="font-mono" style={{ fontSize: 11, color: '#F59E0B' }}>⚑ Filter: {bpfFilter}</span>
          )}
          <span className="font-mono" style={{ fontSize: 11, color: muted }}>{packets.length} pkts · {kbytes} KB</span>
          {threats > 0 && (
            <span className="font-mono" style={{ fontSize: 11, color: '#EF4444' }}>⚠ {threats} threat{threats > 1 ? 's' : ''} detected</span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
          <span className="font-mono" style={{ fontSize: 11, color: muted }}>tshark</span>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#22C55E', display: 'inline-block' }} />
          <span className="font-mono" style={{ fontSize: 11, color: '#22C55E' }}>available</span>
          <span className="font-mono" style={{ fontSize: 11, color: muted, marginLeft: 8 }}>SentinelShark v2.4.1</span>
        </div>
      </div>

    </div>
  )
}

// ─── Small helper components ──────────────────────────────────────────────────

function StatCard({ label, value, color }: { label: string; value: string; color: string }) {
  return (
    <div className="card-glow" style={{ background: '#131C2B', border: '1px solid #1E293B', borderRadius: 10, padding: '10px 12px', display: 'flex', flexDirection: 'column', gap: 4 }}>
      <span style={{ fontSize: 10, color: '#94A3B8', textTransform: 'uppercase', letterSpacing: '0.06em', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>{label}</span>
      <span style={{ fontSize: 20, fontWeight: 700, color, fontFamily: 'JetBrains Mono, monospace', lineHeight: 1 }}>{value}</span>
    </div>
  )
}

function ProtoTag({ proto }: { proto: string }) {
  const colors: Record<string, [string, string]> = {
    DNS:   ['#1e3a5f', '#60A5FA'],
    TLS:   ['#1a3a2a', '#34D399'],
    HTTPS: ['#1a3a2a', '#34D399'],
    HTTP:  ['#2a2a1a', '#FBBF24'],
    TCP:   ['#1e293b', '#94A3B8'],
    UDP:   ['#2a1e3a', '#A78BFA'],
    ICMP:  ['#1e2a3a', '#38BDF8'],
    ARP:   ['#1a1a2a', '#818CF8'],
    QUIC:  ['#1a3a3a', '#2DD4BF'],
    SSH:   ['#2a1a1a', '#F87171'],
  }
  const [bg, fg] = colors[proto] || ['#1e293b', '#94A3B8']
  return (
    <span className="font-mono" style={{ fontSize: 11, fontWeight: 600, color: fg, background: bg, padding: '1px 6px', borderRadius: 4, display: 'inline-block' }}>
      {proto}
    </span>
  )
}

function HashChip({ label, value }: { label: string; value: string }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6, background: '#0a1520', border: '1px solid #1a2535', borderRadius: 6, padding: '3px 8px' }}>
      <span className="font-mono" style={{ fontSize: 10, color: '#22D3EE', fontWeight: 600, flexShrink: 0 }}>{label}</span>
      <span className="font-mono" style={{ fontSize: 10, color: '#475569', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 280 }}>{value}</span>
    </div>
  )
}

function protoColor(proto: string): string {
  const map: Record<string, string> = {
    DNS: '#60A5FA', TLS: '#34D399', HTTPS: '#34D399', HTTP: '#FBBF24',
    TCP: '#94A3B8', UDP: '#A78BFA', ICMP: '#38BDF8', ARP: '#818CF8',
    QUIC: '#2DD4BF', SSH: '#F87171',
  }
  return map[proto] || '#94A3B8'
}
