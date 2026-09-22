import { useState, useEffect, useRef, Fragment } from 'react'

// ── Types ────────────────────────────────────────────────────────────────────
interface TelemetryRow {
  no: number
  time: string
  pid: number
  process: string
  src: string
  dst: string
  proto: string
  len: number
  mitre: string
  severity: 'CRITICAL' | 'HIGH' | 'LOW' | 'SAFE'
  info: string
  isNew?: boolean
}

// ── Synthetic telemetry data ──────────────────────────────────────────────────
const ALL_ROWS: TelemetryRow[] = [
  { no: 1, time: '14:23:01.442', pid: 4821, process: 'python3', src: '192.168.1.42:45231', dst: '185.220.101.47:443', proto: 'TLS', len: 1340, mitre: 'T1071', severity: 'CRITICAL', info: 'TLS to known Tor exit node' },
  { no: 2, time: '14:23:01.891', pid: 1337, process: 'curl', src: '192.168.1.42:52441', dst: '104.21.45.89:80', proto: 'HTTP', len: 542, mitre: 'T1105', severity: 'HIGH', info: 'GET /download/payload.sh' },
  { no: 3, time: '14:23:02.120', pid: 2891, process: 'bash', src: '192.168.1.42:41231', dst: '10.0.0.1:22', proto: 'SSH', len: 288, mitre: 'T1021.004', severity: 'LOW', info: 'SSH lateral movement' },
  { no: 4, time: '14:23:02.445', pid: 9012, process: 'Google Chrome', src: '192.168.1.42:55221', dst: '8.8.8.8:53', proto: 'DNS', len: 64, mitre: '—', severity: 'SAFE', info: 'DNS query: accounts.google.com' },
  { no: 5, time: '14:23:03.112', pid: 1337, process: 'curl', src: '192.168.1.42:52442', dst: '104.21.45.89:80', proto: 'HTTP', len: 8192, mitre: 'T1105', severity: 'HIGH', info: 'HTTP/1.1 200 OK (binary download)' },
  { no: 6, time: '14:23:03.889', pid: 4821, process: 'python3', src: '192.168.1.42:45232', dst: '185.220.101.47:9001', proto: 'TCP', len: 128, mitre: 'T1571', severity: 'CRITICAL', info: 'Non-standard port 9001 (C2?)' },
  { no: 7, time: '14:23:04.221', pid: 3344, process: 'nc', src: '192.168.1.42:4444', dst: '203.0.113.42:4444', proto: 'TCP', len: 92, mitre: 'T1059', severity: 'CRITICAL', info: 'Reverse shell via netcat' },
  { no: 8, time: '14:23:04.778', pid: 5521, process: 'sshd', src: '10.0.0.2:22', dst: '198.51.100.33:61234', proto: 'SSH', len: 556, mitre: '—', severity: 'SAFE', info: 'Accepted publickey for analyst' },
  { no: 9, time: '14:23:05.110', pid: 7723, process: 'wget', src: '192.168.1.42:58832', dst: '91.108.4.234:80', proto: 'HTTP', len: 320, mitre: 'T1105', severity: 'HIGH', info: 'Fetching remote shell script' },
  { no: 10, time: '14:23:05.654', pid: 4821, process: 'python3', src: '192.168.1.42:45233', dst: '185.220.101.47:443', proto: 'TLS', len: 284, mitre: 'T1095', severity: 'CRITICAL', info: 'Non-HTTP protocol over TLS (C2)' },
]

// ── Utility hooks ─────────────────────────────────────────────────────────────
function useReveal() {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    const el = ref.current
    if (!el) return
    const obs = new IntersectionObserver(([entry]) => {
      if (entry.isIntersecting) {
        el.querySelectorAll('.reveal').forEach(r => r.classList.add('in'))
        obs.disconnect()
      }
    }, { threshold: 0.08 })
    obs.observe(el)
    return () => obs.disconnect()
  }, [])
  return ref
}

// ── Logo ──────────────────────────────────────────────────────────────────────
function Logo({ size = 28 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 40 40" fill="none" aria-hidden="true">
      {/* Abstract geometric shark fin */}
      <path d="M6 32 L19 5 L24 17 L35 9 L30 32 Z" fill="currentColor" opacity="0.95" />
      <line x1="3" y1="33.5" x2="37" y2="33.5" stroke="currentColor" strokeWidth="1.5" opacity="0.5" />
      <circle cx="34" cy="25" r="2" fill="var(--accent)" />
    </svg>
  )
}

// ── Severity badge ────────────────────────────────────────────────────────────
function SevBadge({ s }: { s: TelemetryRow['severity'] }) {
  const cls = { CRITICAL: 'sev-critical', HIGH: 'sev-high', SAFE: 'sev-safe', LOW: 'sev-low' }[s]
  return <span className={cls}>{s}</span>
}

// ── Nav ───────────────────────────────────────────────────────────────────────
function Nav() {
  const [scrolled, setScrolled] = useState(false)
  const [menuOpen, setMenuOpen] = useState(false)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 40)
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  const links = ['Product', 'Capabilities', 'Architecture', 'Security', 'Documentation']

  useEffect(() => {
    if (!menuOpen) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setMenuOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [menuOpen])

  return (
    <nav aria-label="Primary" className={`nav ${scrolled ? 'nav-scrolled' : ''}`}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', height: 60 }}>
        {/* Logo */}
        <a href="#" style={{ display: 'flex', alignItems: 'center', gap: 10, textDecoration: 'none', color: 'var(--text)' }}>
          <Logo size={28} />
          <span className="font-display" style={{ fontSize: 18, fontWeight: 700, letterSpacing: '0.02em', color: 'var(--text)' }}>
            SentinelShark
          </span>
        </a>

        {/* Desktop links */}
        <div className="hide-mobile" style={{ display: 'flex', alignItems: 'center', gap: 32 }}>
          {links.map(l => (
            <a key={l} href={`#${l.toLowerCase()}`} style={{ color: 'var(--muted)', fontSize: 13, fontWeight: 500, textDecoration: 'none', letterSpacing: '0.01em', transition: 'color 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--muted)')}
            >{l}</a>
          ))}
        </div>

        {/* Actions */}
        <div className="hide-mobile" style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <a href="https://github.com/DebdootManna/SentinelShark" target="_blank" rel="noopener noreferrer"
            style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--muted)', fontSize: 13, fontWeight: 500, textDecoration: 'none', padding: '6px 12px', border: '1px solid var(--border)', borderRadius: 6, transition: 'all 0.2s' }}
            onMouseEnter={e => { e.currentTarget.style.color = 'var(--text)'; e.currentTarget.style.borderColor = 'var(--border-mid)' }}
            onMouseLeave={e => { e.currentTarget.style.color = 'var(--muted)'; e.currentTarget.style.borderColor = 'var(--border)' }}
          >
            <GitHubIcon size={14} /> GitHub
          </a>
          <a href="https://github.com/DebdootManna/SentinelShark" target="_blank" rel="noopener noreferrer"
            style={{ background: 'var(--accent)', color: '#000', fontSize: 13, fontWeight: 600, textDecoration: 'none', padding: '7px 16px', borderRadius: 6, letterSpacing: '0.01em', transition: 'opacity 0.2s' }}
            onMouseEnter={e => (e.currentTarget.style.opacity = '0.85')}
            onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
          >Get Started</a>
        </div>

        {/* Mobile menu button */}
        <button type="button" className="hide-tablet" onClick={() => setMenuOpen(!menuOpen)} aria-expanded={menuOpen} aria-controls="mobile-menu" aria-label="Toggle navigation menu" style={{ background: 'none', border: 'none', color: 'var(--text)', cursor: 'pointer', padding: 4 }}>
          <div style={{ width: 20, height: 1.5, background: 'currentColor', marginBottom: 5 }} />
          <div style={{ width: 14, height: 1.5, background: 'currentColor', marginBottom: 5 }} />
          <div style={{ width: 20, height: 1.5, background: 'currentColor' }} />
        </button>
      </div>

      {/* Mobile menu */}
      {menuOpen && (
        <div id="mobile-menu" style={{ background: 'var(--surface)', borderBottom: '1px solid var(--border)', padding: '16px 24px' }}>
          {links.map(l => (
            <a key={l} href={`#${l.toLowerCase()}`} onClick={() => setMenuOpen(false)} style={{ display: 'block', color: 'var(--muted)', fontSize: 15, fontWeight: 500, textDecoration: 'none', padding: '10px 0', borderBottom: '1px solid var(--border)' }}>{l}</a>
          ))}
          <div style={{ display: 'flex', gap: 12, marginTop: 16 }}>
            <a href="https://github.com/DebdootManna/SentinelShark" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--text)', fontSize: 13, fontWeight: 500, textDecoration: 'none' }}>GitHub</a>
            <a href="https://github.com/DebdootManna/SentinelShark" target="_blank" rel="noopener noreferrer" style={{ background: 'var(--accent)', color: '#000', fontSize: 13, fontWeight: 600, textDecoration: 'none', padding: '6px 14px', borderRadius: 5 }}>Get Started</a>
          </div>
        </div>
      )}
    </nav>
  )
}

// ── Live Telemetry Stream (Hero visual) ────────────────────────────────────────
function TelemetryStream() {
  const [rows, setRows] = useState<TelemetryRow[]>(ALL_ROWS.slice(0, 6))
  const [newRowIdx, setNewRowIdx] = useState<number | null>(null)
  const counter = useRef(11)

  useEffect(() => {
    if (typeof window !== 'undefined' && window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) {
      return
    }
    const interval = setInterval(() => {
      const template = ALL_ROWS[Math.floor(Math.random() * ALL_ROWS.length)]
      const newRow: TelemetryRow = {
        ...template,
        no: counter.current++,
        time: new Date().toISOString().substr(11, 12),
        isNew: true,
      }
      setRows(prev => {
        const next = [newRow, ...prev].slice(0, 7)
        return next
      })
      setNewRowIdx(newRow.no)
      setTimeout(() => setNewRowIdx(null), 1200)
    }, 2200)
    return () => clearInterval(interval)
  }, [])

  const colStyle: React.CSSProperties = {
    fontFamily: 'JetBrains Mono, monospace',
    fontSize: 11,
    padding: '6px 10px',
    whiteSpace: 'nowrap',
    overflow: 'hidden',
    textOverflow: 'ellipsis',
    maxWidth: 160,
    borderBottom: '1px solid var(--border)',
  }

  const thStyle: React.CSSProperties = {
    ...colStyle,
    color: 'var(--dim)',
    fontSize: 10,
    letterSpacing: '0.08em',
    textTransform: 'uppercase',
    fontWeight: 500,
    paddingTop: 8,
    paddingBottom: 8,
    borderBottom: '1px solid var(--border-mid)',
  }

  return (
    <div className="product-window" style={{ maxWidth: '100%', overflow: 'hidden' }}>
      <div className="product-titlebar">
        <div className="dot dot-r" /><div className="dot dot-y" /><div className="dot dot-g" />
        <span style={{ marginLeft: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)' }}>
          SentinelShark — Live Capture [eth0]
        </span>
        <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)' }}>
          <span className="animate-scan" style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent)', display: 'inline-block' }} />
          LIVE
        </span>
      </div>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 900 }}>
          <thead>
            <tr>
              {['No.', 'Time', 'PID', 'Process', 'Source', 'Destination', 'Proto', 'Len', 'MITRE', 'Severity', 'Info'].map(h => (
                <th key={h} scope="col" style={{ ...thStyle, textAlign: 'left' }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr key={row.no} className={row.no === newRowIdx ? 'row-new' : ''}
                style={{ transition: 'background 0.3s' }}>
                <td style={{ ...colStyle, color: 'var(--dim)' }}>{row.no}</td>
                <td style={{ ...colStyle, color: 'var(--muted)' }}>{row.time}</td>
                <td style={{ ...colStyle, color: 'var(--accent)' }}>{row.pid}</td>
                <td style={{ ...colStyle, color: 'var(--text)', fontWeight: 500 }}>{row.process}</td>
                <td style={{ ...colStyle, color: 'var(--muted)' }}>{row.src}</td>
                <td style={{ ...colStyle, color: row.severity === 'CRITICAL' ? 'var(--red)' : row.severity === 'HIGH' ? 'var(--amber)' : 'var(--muted)' }}>{row.dst}</td>
                <td style={{ ...colStyle, color: 'var(--text)' }}>{row.proto}</td>
                <td style={{ ...colStyle, color: 'var(--muted)' }}>{row.len}</td>
                <td style={{ ...colStyle }}>{row.mitre !== '—' ? <span className="mitre-tag">{row.mitre}</span> : <span style={{ color: 'var(--dim)' }}>—</span>}</td>
                <td style={{ ...colStyle }}><SevBadge s={row.severity} /></td>
                <td style={{ ...colStyle, color: 'var(--muted)', maxWidth: 200 }}>{row.info}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Hero ──────────────────────────────────────────────────────────────────────
function Hero() {
  return (
    <section id="product" aria-labelledby="hero-heading" style={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', justifyContent: 'center', paddingTop: 80, paddingBottom: 60 }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', width: '100%' }}>
        {/* Eyebrow */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 32, animation: 'fadeIn 0.8s ease forwards' }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>Open-source EDR</span>
          <span style={{ width: 32, height: 1, background: 'var(--accent)', opacity: 0.4 }} />
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--muted)', letterSpacing: '0.12em', textTransform: 'uppercase' }}>v0.1 · Python 3.10+</span>
        </div>

        {/* Headline */}
        <h1 id="hero-heading" className="font-display" style={{
          fontSize: 'clamp(3.5rem, 10vw, 9rem)',
          fontWeight: 900,
          lineHeight: 0.92,
          letterSpacing: '-0.02em',
          color: 'var(--text)',
          marginBottom: 40,
          maxWidth: 1000,
          animation: 'fadeInUp 0.9s ease forwards',
        }}>
          Your network<br />
          is talking.<br />
          <span className="text-shimmer">SentinelShark</span><br />
          listens.
        </h1>

        {/* Subhead + CTAs */}
        <div style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'flex-end', gap: 48, marginBottom: 64, animation: 'fadeInUp 1s ease 0.15s forwards', opacity: 0 }}>
          <p style={{ maxWidth: 480, fontSize: 17, lineHeight: 1.65, color: 'var(--muted)', fontWeight: 400 }}>
            SentinelShark is an open-source EDR and SecOps workstation that correlates network traffic, host processes, threat intelligence, and security telemetry in real time.
          </p>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            <a href="https://github.com/DebdootManna/SentinelShark" target="_blank" rel="noopener noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'var(--accent)', color: '#000', fontSize: 14, fontWeight: 600, textDecoration: 'none', padding: '12px 24px', borderRadius: 7, letterSpacing: '0.01em', transition: 'opacity 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.85')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            >
              <GitHubIcon size={15} /> View on GitHub
            </a>
            <a href="#architecture"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'transparent', color: 'var(--text)', fontSize: 14, fontWeight: 500, textDecoration: 'none', padding: '12px 24px', borderRadius: 7, border: '1px solid var(--border-mid)', letterSpacing: '0.01em', transition: 'border-color 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--muted)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-mid)')}
            >Explore the architecture</a>
          </div>
        </div>

        {/* Live telemetry */}
        <div style={{ animation: 'fadeInUp 1s ease 0.3s forwards', opacity: 0 }}>
          <TelemetryStream />
        </div>
      </div>
    </section>
  )
}

// ── Big Statement ─────────────────────────────────────────────────────────────
function BigStatement() {
  const ref = useReveal()
  return (
    <section ref={ref} className="section" style={{ borderTop: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 80, alignItems: 'start' }} className="stack-mobile">
          <div>
            <h2 className="font-display reveal" style={{ fontSize: 'clamp(3rem, 6vw, 5.5rem)', fontWeight: 800, lineHeight: 0.95, letterSpacing: '-0.01em', color: 'var(--text)' }}>
              From packet<br />to process<br />to response.
            </h2>
          </div>
          <div style={{ paddingTop: 8 }}>
            <p className="reveal reveal-d1" style={{ fontSize: 17, lineHeight: 1.75, color: 'var(--muted)', marginBottom: 24 }}>
              A packet is not just a packet.
            </p>
            <p className="reveal reveal-d2" style={{ fontSize: 16, lineHeight: 1.75, color: 'var(--muted)', marginBottom: 24 }}>
              SentinelShark connects raw network activity to the local process responsible for it — correlating PID, parent process, command-line arguments, executable path, and SHA-256 binary hash.
            </p>
            <p className="reveal reveal-d3" style={{ fontSize: 16, lineHeight: 1.75, color: 'var(--muted)' }}>
              Every event is enriched with threat intelligence, tagged with MITRE ATT&CK context, and normalized into Google SecOps / Chronicle UDM — giving analysts a complete picture from the first packet.
            </p>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Product UI Mockup ─────────────────────────────────────────────────────────
function ProductUI() {
  const ref = useReveal()
  const [activeTab, setActiveTab] = useState<'packet' | 'detection' | 'udm' | 'hex'>('detection')

  const udmJson = `{
  "metadata": {
    "event_timestamp": "2024-01-15T14:23:01.442Z",
    "event_type": "NETWORK_CONNECTION",
    "product_name": "SentinelShark"
  },
  "principal": {
    "hostname": "workstation-01",
    "process": {
      "pid": 4821,
      "file": {
        "full_path": "/usr/bin/python3",
        "sha256": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3"
      },
      "command_line": "python3 /tmp/.cache/updater.py"
    },
    "user": { "userid": "analyst" }
  },
  "target": {
    "ip": ["185.220.101.47"],
    "port": 9001,
    "network": {
      "direction": "OUTBOUND",
      "ip_protocol": "TCP"
    }
  },
  "security_result": {
    "severity": "CRITICAL",
    "category": "NETWORK_SUSPICIOUS",
    "detection_fields": [
      { "key": "mitre_technique", "value": "T1571" },
      { "key": "abuse_score", "value": "87" },
      { "key": "vt_malicious", "value": "12" }
    ]
  }
}`

  const renderJSON = (json: string) => {
    return json.replace(
      /"([^"]+)"(:)/g, (_, key, colon) => `<span class="json-key">"${key}"</span>${colon}`
    ).replace(
      /: "([^"]+)"/g, (_, val) => `: <span class="json-str">"${val}"</span>`
    ).replace(
      /: (\d+)/g, (_, val) => `: <span class="json-num">${val}</span>`
    )
  }

  const tabs = ['packet', 'detection', 'udm', 'hex'] as const
  const tabLabels: Record<typeof tabs[number], string> = { packet: 'Packet', detection: 'Detection', udm: 'UDM JSON', hex: 'Hex' }

  return (
    <section id="capabilities" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)', background: 'linear-gradient(180deg, var(--surface) 0%, var(--bg) 100%)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 48 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Workstation</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
            The forensic workstation.
          </h2>
        </div>

        <div className="reveal reveal-d1 product-window">
          {/* Titlebar */}
          <div className="product-titlebar">
            <div className="dot dot-r" /><div className="dot dot-y" /><div className="dot dot-g" />
            <span style={{ marginLeft: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)' }}>SentinelShark EDR — Investigation Workspace</span>
            <span style={{ marginLeft: 'auto', fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--red)', display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--red)', display: 'inline-block' }} className="animate-scan" />
              2 CRITICAL · 3 HIGH
            </span>
          </div>

          {/* Mini telemetry table */}
          <div style={{ overflowX: 'auto', borderBottom: '1px solid var(--border)' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', minWidth: 900 }}>
              <thead>
                <tr>
                  {['No.', 'Time', 'PID', 'Process', 'Source', 'Destination', 'Proto', 'Len', 'MITRE', 'Severity', 'Info'].map(h => (
                    <th key={h} scope="col" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', padding: '7px 10px', textAlign: 'left', borderBottom: '1px solid var(--border-mid)', whiteSpace: 'nowrap' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {ALL_ROWS.slice(0, 5).map((row, i) => (
                  <tr key={row.no} style={{ background: i === 2 ? 'var(--accent-dim)' : 'transparent', cursor: 'pointer', transition: 'background 0.15s' }}
                    onMouseEnter={e => { if (i !== 2) e.currentTarget.style.background = 'var(--surface-2)' }}
                    onMouseLeave={e => { if (i !== 2) e.currentTarget.style.background = 'transparent' }}
                  >
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--dim)', borderBottom: '1px solid var(--border)' }}>{row.no}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>{row.time}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: i === 2 ? 'var(--accent)' : 'var(--accent)', borderBottom: '1px solid var(--border)' }}>{row.pid}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--text)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>{row.process}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>{row.src}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: row.severity === 'CRITICAL' ? 'var(--red)' : row.severity === 'HIGH' ? 'var(--amber)' : 'var(--muted)', borderBottom: '1px solid var(--border)' }}>{row.dst}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--text)', borderBottom: '1px solid var(--border)' }}>{row.proto}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--muted)', borderBottom: '1px solid var(--border)' }}>{row.len}</td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', borderBottom: '1px solid var(--border)' }}>{row.mitre !== '—' ? <span className="mitre-tag">{row.mitre}</span> : <span style={{ color: 'var(--dim)' }}>—</span>}</td>
                    <td style={{ padding: '5px 10px', borderBottom: '1px solid var(--border)' }}><SevBadge s={row.severity} /></td>
                    <td style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, padding: '5px 10px', color: 'var(--muted)', borderBottom: '1px solid var(--border)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 180 }}>{row.info}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Three-panel workspace */}
          <div className="workspace-grid">
            {/* Left: Process info */}
            <div style={{ borderRight: '1px solid var(--border)', padding: 16 }}>
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 14 }}>Process Context</div>
              {[
                ['PID', '4821'],
                ['PPID', '1402'],
                ['Process', 'python3'],
                ['User', 'analyst (uid=1000)'],
                ['Path', '/usr/bin/python3'],
                ['Args', '/tmp/.cache/updater.py'],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', flexDirection: 'column', marginBottom: 10, paddingBottom: 10, borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 3 }}>{k}</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--text)', wordBreak: 'break-all' }}>{v}</span>
                </div>
              ))}
              <div style={{ marginBottom: 10, paddingBottom: 10, borderBottom: '1px solid var(--border)' }}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 3 }}>SHA-256</div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--muted)', wordBreak: 'break-all' }}>a665a459204...ae3</div>
              </div>
            </div>

            {/* Center: Tabs */}
            <div style={{ borderRight: '1px solid var(--border)' }}>
              <div style={{ display: 'flex', borderBottom: '1px solid var(--border)' }}>
                {tabs.map(t => (
                  <button key={t} type="button" onClick={() => setActiveTab(t)} aria-pressed={activeTab === t} style={{ background: 'none', border: 'none', borderBottom: activeTab === t ? '2px solid var(--accent)' : '2px solid transparent', color: activeTab === t ? 'var(--text)' : 'var(--muted)', fontFamily: 'JetBrains Mono, monospace', fontSize: 12, padding: '10px 16px', cursor: 'pointer', transition: 'color 0.15s', marginBottom: -1 }}>{tabLabels[t]}</button>
                ))}
              </div>
              <div style={{ padding: 16, height: 280, overflowY: 'auto' }}>
                {activeTab === 'detection' && (
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16 }}>
                      <span className="sev-critical">CRITICAL</span>
                      <span className="mitre-tag">T1571</span>
                      <span className="mitre-tag">T1095</span>
                    </div>
                    <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--text)', fontWeight: 500, marginBottom: 8 }}>Non-Standard Port Communication</div>
                    <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6, marginBottom: 16 }}>
                      python3 established an outbound TCP connection to 185.220.101.47:9001. Port 9001 is associated with Tor relay traffic and C2 frameworks. Process SHA-256 confirmed via VirusTotal: 12 malicious engines.
                    </div>
                    {[['AbuseIPDB Score', '87%', 'var(--red)'], ['VT Malicious', '12 engines', 'var(--red)'], ['VT Suspicious', '3 engines', 'var(--amber)'], ['Country', 'DE (Tor exit)', 'var(--muted)'], ['ASN', 'AS24940 Hetzner', 'var(--muted)']].map(([k, v, c]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid var(--border)' }}>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)' }}>{k}</span>
                        <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: c as string }}>{v}</span>
                      </div>
                    ))}
                  </div>
                )}
                {activeTab === 'udm' && (
                  <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, lineHeight: 1.65, color: 'var(--muted)', overflow: 'auto' }} dangerouslySetInnerHTML={{ __html: renderJSON(udmJson) }} />
                )}
                {activeTab === 'packet' && (
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)', lineHeight: 1.8 }}>
                    {['Frame 6: 128 bytes', '  Ethernet II, Src: 00:1b:21:ef:32:a1', '  IPv4: 192.168.1.42 → 185.220.101.47', '    TTL: 64  Protocol: TCP  Checksum: 0xf3cd', '  TCP: 45232 → 9001 [SYN, ACK]', '    Seq: 0x00000001', '    Ack: 0x00000001', '    Window: 65535', '    Options: MSS=1460, SACK, Timestamps'].map((l, i) => (
                      <div key={i} style={{ color: l.startsWith('  ') ? 'var(--muted)' : 'var(--text)' }}>{l}</div>
                    ))}
                  </div>
                )}
                {activeTab === 'hex' && (
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, lineHeight: 1.9 }}>
                    {[
                      ['0000:', '45 00 00 80 00 01 40 00  40 06 f3 cd c0 a8 01 2a', 'E..@..@.@......*'],
                      ['0010:', 'b9 dc 65 2f b0 d0 23 29  00 50 00 16 00 00 00 00', '..e/.#).P......'],
                      ['0020:', '50 02 20 00 91 7c 00 00  16 03 01 00 f1 01 00 00', 'P. ..|.........'],
                    ].map(([off, hex, asc]) => (
                      <div key={off} className="hex-row">
                        <span className="hex-offset">{off}</span>
                        <span className="hex-bytes">{hex}</span>
                        <span className="hex-ascii">{asc}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>

            {/* Right: Analytics */}
            <div style={{ padding: 16 }}>
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 14 }}>Analytics</div>
              <div style={{ marginBottom: 20 }}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--muted)', marginBottom: 8 }}>Protocol breakdown</div>
                {[['TCP', 62, 'var(--accent)'], ['TLS', 21, 'var(--text)'], ['HTTP', 11, 'var(--muted)'], ['DNS', 6, 'var(--dim)']].map(([p, pct, c]) => (
                  <div key={p as string} style={{ marginBottom: 6 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: c as string }}>{p}</span>
                      <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)' }}>{pct}%</span>
                    </div>
                    <div style={{ height: 3, background: 'var(--surface-3)', borderRadius: 2 }}>
                      <div style={{ height: '100%', width: `${pct}%`, background: c as string, borderRadius: 2, opacity: 0.7 }} />
                    </div>
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--muted)', marginBottom: 8 }}>MITRE coverage</div>
                {['T1059', 'T1071', 'T1105', 'T1571', 'T1095'].map(t => (
                  <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 6 }}>
                    <span className="mitre-tag" style={{ fontSize: 10 }}>{t}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Capabilities ──────────────────────────────────────────────────────────────
function Capabilities() {
  const ref = useReveal()
  const caps = [
    { num: '01', title: 'Network Visibility', desc: 'Live packet capture via PyShark and TShark. PCAP/PCAPNG import and export. BPF filtering. Mock mode for offline analysis. Protocol dissection across TCP, UDP, DNS, HTTP, TLS and more.', accent: false },
    { num: '02', title: 'Process Correlation', desc: 'Map every network socket to the process responsible for it. PID, PPID, process name, command-line arguments, executable path, SHA-256 binary hash, and user privilege context — all correlated at 200ms polling intervals.', accent: false },
    { num: '03', title: 'Threat Intelligence', desc: 'VirusTotal, AbuseIPDB, Shodan, and IPinfo enrichment for public IPs. SQLite caching with in-memory TTLCache. Rate limiting, request deduplication, and exponential backoff on HTTP 429.', accent: true },
    { num: '04', title: 'MITRE ATT&CK', desc: 'Detect living-off-the-land binary (LOLBin) activity. Tag suspicious behaviors with technique identifiers including T1059, T1105, T1071, T1571, T1095, T1021.004 and more.', accent: false },
    { num: '05', title: 'SecOps Telemetry', desc: 'Normalize security events into Google SecOps / Chronicle Unified Data Model (UDM) JSON. Live UDM inspector. Fields include metadata, principal, target, network, and security_result.', accent: false },
    { num: '06', title: 'Incident Response', desc: 'Operator-triggered containment actions: Kill Process (with PID 0/1 safeguards), Block Remote IP via platform-native firewall rules, and Quarantine Binary by stripping permissions and moving the executable.', accent: false },
  ]
  return (
    <section ref={ref} className="section" style={{ borderTop: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 56 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Capabilities</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
            Six disciplines.<br />One workstation.
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 1, border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
          {caps.map((cap, i) => (
            <div key={cap.num} className={`reveal reveal-d${(i % 4) + 1}`}
              style={{ padding: '36px 32px', background: cap.accent ? 'var(--accent-dim)' : 'var(--surface)', borderRight: '1px solid var(--border)', borderBottom: '1px solid var(--border)', transition: 'background 0.2s' }}
              onMouseEnter={e => { if (!cap.accent) e.currentTarget.style.background = 'var(--surface-2)' }}
              onMouseLeave={e => { if (!cap.accent) e.currentTarget.style.background = 'var(--surface)' }}
            >
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: cap.accent ? 'var(--accent)' : 'var(--dim)', letterSpacing: '0.08em', marginBottom: 16 }}>{cap.num}</div>
              <h3 className="font-display" style={{ fontSize: 'clamp(1.5rem, 3vw, 2rem)', fontWeight: 700, color: cap.accent ? 'var(--accent)' : 'var(--text)', letterSpacing: '-0.01em', lineHeight: 1.05, marginBottom: 16 }}>{cap.title}</h3>
              <p style={{ fontSize: 14, lineHeight: 1.7, color: cap.accent ? 'rgba(45,212,191,0.75)' : 'var(--muted)' }}>{cap.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

// ── Packet Chain ──────────────────────────────────────────────────────────────
function PacketChain() {
  const ref = useReveal()
  const chain = [
    { label: 'Captured', value: 'PACKET', desc: 'Raw bytes off the wire' },
    { label: 'Correlated', value: 'SOCKET', desc: 'Kernel socket → process mapping' },
    { label: 'Identified', value: 'PROCESS', desc: 'PID · PPID · SHA-256 · User' },
    { label: 'Enriched', value: 'THREAT INTEL', desc: 'VirusTotal · AbuseIPDB · Shodan · IPinfo' },
    { label: 'Tagged', value: 'MITRE ATT&CK', desc: 'Technique classification + LOLBin detection' },
    { label: 'Normalized', value: 'UDM', desc: 'Google SecOps / Chronicle Unified Data Model' },
    { label: 'Actioned', value: 'RESPONSE', desc: 'Kill · Block · Quarantine' },
  ]
  return (
    <section id="security" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 80, alignItems: 'start' }} className="stack-mobile">
          <div>
            <div className="reveal" style={{ marginBottom: 32 }}>
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Pipeline</span>
              <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4.5rem)', fontWeight: 800, lineHeight: 0.95, letterSpacing: '-0.01em' }}>
                A packet is<br />only the<br />beginning.
              </h2>
            </div>
            <p className="reveal reveal-d1" style={{ fontSize: 15, lineHeight: 1.75, color: 'var(--muted)' }}>
              SentinelShark's detection pipeline transforms a raw network packet into a fully contextualized, threat-enriched, MITRE-tagged security event — all in real time without blocking the UI thread.
            </p>
          </div>
          <div>
            {chain.map((step, i) => (
              <div key={step.value} className={`reveal reveal-d${Math.min(i + 1, 5)}`} style={{ display: 'flex', gap: 20, alignItems: 'flex-start', marginBottom: i < chain.length - 1 ? 0 : 0 }}>
                <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
                  <div style={{ width: 8, height: 8, borderRadius: '50%', background: i === 0 ? 'var(--accent)' : i === chain.length - 1 ? 'var(--red)' : 'var(--border-mid)', border: '1px solid var(--border-mid)', marginTop: 14, flexShrink: 0 }} />
                  {i < chain.length - 1 && <div style={{ width: 1, height: 48, background: 'linear-gradient(180deg, var(--border-mid), transparent)', margin: '4px 0' }} />}
                </div>
                <div style={{ paddingBottom: i < chain.length - 1 ? 0 : 0, marginBottom: 0 }}>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 4, marginTop: 8 }}>{step.label}</div>
                  <div className="font-display" style={{ fontSize: 'clamp(1.5rem, 3vw, 2.2rem)', fontWeight: 800, letterSpacing: '-0.01em', color: i === 0 ? 'var(--accent)' : i === chain.length - 1 ? 'var(--red)' : 'var(--text)', lineHeight: 1, marginBottom: 4 }}>{step.value}</div>
                  <div style={{ fontSize: 13, color: 'var(--muted)', marginBottom: 8 }}>{step.desc}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Threat Intelligence ───────────────────────────────────────────────────────
function ThreatIntel() {
  const ref = useReveal()
  const providers = [
    {
      name: 'VirusTotal',
      tag: 'vt',
      fields: [
        { k: 'Malicious', v: '12 / 72 engines', c: 'var(--red)' },
        { k: 'Suspicious', v: '3 / 72 engines', c: 'var(--amber)' },
        { k: 'Harmless', v: '57 / 72 engines', c: 'var(--green)' },
        { k: 'Engine', v: 'Microsoft, Kaspersky, ESET', c: 'var(--muted)' },
      ]
    },
    {
      name: 'AbuseIPDB',
      tag: 'aipdb',
      fields: [
        { k: 'Abuse Score', v: '87 / 100', c: 'var(--red)' },
        { k: 'Reports', v: '342 reports', c: 'var(--amber)' },
        { k: 'Country', v: 'DE', c: 'var(--muted)' },
        { k: 'ISP', v: 'Hetzner Online GmbH', c: 'var(--muted)' },
      ]
    },
    {
      name: 'Shodan',
      tag: 'shodan',
      fields: [
        { k: 'Open Ports', v: '22, 80, 443, 9001', c: 'var(--muted)' },
        { k: 'Tags', v: 'tor, vpn, hosting', c: 'var(--amber)' },
        { k: 'CPEs', v: 'cpe:nginx/1.21.0', c: 'var(--muted)' },
        { k: 'CVEs', v: 'CVE-2021-23017', c: 'var(--red)' },
      ]
    },
    {
      name: 'IPinfo',
      tag: 'ipinfo',
      fields: [
        { k: 'ASN', v: 'AS24940', c: 'var(--accent)' },
        { k: 'Org', v: 'Hetzner Online GmbH', c: 'var(--muted)' },
        { k: 'Location', v: 'Frankfurt, DE', c: 'var(--muted)' },
        { k: 'Privacy', v: 'Tor · Hosting · VPN', c: 'var(--amber)' },
      ]
    },
  ]

  return (
    <section id="threat-intel" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end', flexWrap: 'wrap', gap: 24, marginBottom: 56 }}>
          <div className="reveal">
            <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Intelligence</span>
            <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
              Four sources.<br />One verdict.
            </h2>
          </div>
          <p className="reveal reveal-d1" style={{ maxWidth: 380, fontSize: 14, lineHeight: 1.75, color: 'var(--muted)' }}>
            Public IPs are enriched through four threat-intelligence providers. Private and loopback addresses are filtered before any API call — conserving quota while focusing analysis where it matters.
          </p>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(260px, 1fr))', gap: 16 }}>
          {providers.map((p, i) => (
            <div key={p.name} className={`ti-card reveal reveal-d${i + 1}`}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--accent)', background: 'var(--accent-dim)', border: '1px solid rgba(45,212,191,0.2)', padding: '2px 8px', borderRadius: 4, letterSpacing: '0.06em', textTransform: 'uppercase' }}>{p.tag}</div>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--text)', fontWeight: 500 }}>{p.name}</span>
              </div>
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
                {p.fields.map(f => (
                  <div key={f.k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 10 }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>{f.k}</span>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: f.c }}>{f.v}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="reveal" style={{ marginTop: 32, padding: '16px 20px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, display: 'flex', alignItems: 'center', gap: 12 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)' }}>→</span>
          <p style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)' }}>
            Results are cached in SQLite + in-memory TTLCache (24h TTL). Rate limiting enforced at 30 req/min with exponential backoff on HTTP 429. Shodan/InternetDB used as a no-key fallback when a primary key is absent.
          </p>
        </div>
      </div>
    </section>
  )
}

// ── MITRE Section ─────────────────────────────────────────────────────────────
function MitreSection() {
  const ref = useReveal()
  const lolbins = ['curl', 'wget', 'python', 'python3', 'bash', 'zsh', 'sh', 'nc', 'ncat', 'socat', 'powershell', 'cmd']
  const techniques = [
    { id: 'T1059', name: 'Command & Scripting Interpreter', procs: ['bash', 'sh', 'python', 'powershell', 'cmd'] },
    { id: 'T1059.004', name: 'Unix Shell', procs: ['bash', 'zsh', 'sh'] },
    { id: 'T1105', name: 'Ingress Tool Transfer', procs: ['curl', 'wget'] },
    { id: 'T1095', name: 'Non-Application Layer Protocol', procs: ['nc', 'ncat', 'socat'] },
    { id: 'T1071', name: 'Application Layer Protocol', procs: ['curl', 'python'] },
    { id: 'T1071.001', name: 'Web Protocols', procs: ['curl', 'wget', 'python'] },
    { id: 'T1571', name: 'Non-Standard Port', procs: ['nc', 'python', 'socat'] },
    { id: 'T1021.004', name: 'SSH Lateral Movement', procs: ['ssh', 'bash'] },
  ]
  return (
    <section id="mitre" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 56 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Detection</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
            Living off the land<br />doesn't hide anymore.
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 48 }} className="stack-mobile">
          <div>
            <div className="reveal" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 16 }}>Monitored LOLBins</div>
            <div className="reveal reveal-d1" style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
              {lolbins.map(b => (
                <span key={b} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--amber)', background: 'var(--amber-bg)', border: '1px solid rgba(251,191,36,0.2)', padding: '4px 12px', borderRadius: 4 }}>{b}</span>
              ))}
            </div>
            <p className="reveal reveal-d2" style={{ fontSize: 14, lineHeight: 1.75, color: 'var(--muted)', marginTop: 24 }}>
              When a LOLBin establishes a network connection, SentinelShark flags the event and attaches the appropriate MITRE ATT&CK technique identifiers. No additional configuration required.
            </p>
          </div>
          <div>
            <div className="reveal" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 16 }}>Detected Techniques</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {techniques.map((t, i) => (
                <div key={t.id} className={`reveal reveal-d${Math.min(i + 1, 5)}`} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 6 }}>
                  <span className="mitre-tag" style={{ flexShrink: 0 }}>{t.id}</span>
                  <span style={{ fontSize: 13, color: 'var(--text)', flex: 1 }}>{t.name}</span>
                  <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
                    {t.procs.slice(0, 3).map(p => (
                      <span key={p} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--amber)', background: 'rgba(251,191,36,0.08)', padding: '1px 6px', borderRadius: 3 }}>{p}</span>
                    ))}
                    {t.procs.length > 3 && <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)' }}>+{t.procs.length - 3}</span>}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Chronicle / SecOps ─────────────────────────────────────────────────────────
function ChronicleSection() {
  const ref = useReveal()
  const [copied, setCopied] = useState(false)

  const udm = {
    metadata: { event_timestamp: '2024-01-15T14:23:01.442Z', event_type: 'NETWORK_CONNECTION', product_name: 'SentinelShark', vendor_name: 'SentinelShark' },
    principal: { hostname: 'workstation-01', process: { pid: 4821, file: { full_path: '/usr/bin/python3', sha256: 'a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3' }, command_line: 'python3 /tmp/.cache/updater.py' }, user: { userid: 'analyst', uid: '1000' } },
    target: { ip: ['185.220.101.47'], port: 9001, network: { direction: 'OUTBOUND', ip_protocol: 'TCP', session_duration: { seconds: 3 } } },
    security_result: { severity: 'CRITICAL', category: 'NETWORK_SUSPICIOUS', detection_fields: [{ key: 'mitre_technique', value: 'T1571' }, { key: 'abuse_score', value: '87' }, { key: 'vt_malicious', value: '12' }, { key: 'lolbin_detected', value: 'true' }] },
  }

  const handleCopy = () => {
    navigator.clipboard.writeText(JSON.stringify(udm, null, 2)).catch(() => {})
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  return (
    <section id="documentation" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 56 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>SecOps Integration</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
            Speak SecOps natively.
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 32, alignItems: 'stretch' }} className="stack-mobile">
          {/* Left: human-readable detection */}
          <div className="reveal" style={{ background: 'var(--surface)', border: '1px solid var(--border-mid)', borderRadius: 8, padding: 32 }}>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 20 }}>Human-readable detection</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 20 }}>
              <span className="sev-critical">CRITICAL</span>
              <span className="mitre-tag">T1571</span>
            </div>
            <div className="font-display" style={{ fontSize: 24, fontWeight: 700, color: 'var(--text)', marginBottom: 12 }}>Non-Standard Port Communication</div>
            <p style={{ fontSize: 14, color: 'var(--muted)', lineHeight: 1.7, marginBottom: 24 }}>
              Process <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--amber)' }}>python3</span> (PID 4821) established an outbound TCP connection to <span style={{ fontFamily: 'JetBrains Mono', color: 'var(--red)' }}>185.220.101.47:9001</span>. Port 9001 is non-standard and associated with Tor relay traffic. Binary confirmed malicious by 12 VirusTotal engines. AbuseIPDB score: 87%.
            </p>
            <div style={{ borderTop: '1px solid var(--border)', paddingTop: 20 }}>
              {[['Timestamp', '2024-01-15 14:23:01 UTC'], ['Host', 'workstation-01'], ['User', 'analyst (uid=1000)'], ['Process', 'python3 /tmp/.cache/updater.py'], ['Binary SHA-256', 'a665a459...ae3'], ['Destination', '185.220.101.47:9001 (DE)']].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '7px 0', borderBottom: '1px solid var(--border)' }}>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)' }}>{k}</span>
                  <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--muted)' }}>{v}</span>
                </div>
              ))}
            </div>
          </div>

          {/* Right: UDM JSON */}
          <div className="reveal reveal-d1" style={{ background: 'var(--surface)', border: '1px solid var(--border-mid)', borderRadius: 8, overflow: 'hidden' }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '12px 20px', borderBottom: '1px solid var(--border)', background: 'var(--surface-2)' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase' }}>Chronicle UDM JSON</span>
              </div>
              <button type="button" onClick={handleCopy} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: copied ? 'var(--green)' : 'var(--accent)', background: 'none', border: '1px solid', borderColor: copied ? 'rgba(74,222,128,0.3)' : 'rgba(45,212,191,0.3)', padding: '4px 12px', borderRadius: 4, cursor: 'pointer', transition: 'all 0.2s' }}>
                {copied ? '✓ Copied' : 'Copy UDM JSON'}
              </button>
            </div>
            <div style={{ padding: 20, overflowY: 'auto', maxHeight: 480 }}>
              <pre style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, lineHeight: 1.75, margin: 0, color: 'var(--muted)', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                <UDMRenderer udm={udm} indent={0} />
              </pre>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

function UDMRenderer({ udm, indent }: { udm: unknown; indent: number }) {
  const pad = '  '.repeat(indent)
  if (typeof udm === 'string') return <span className="json-str">"{udm}"</span>
  if (typeof udm === 'number') return <span className="json-num">{udm}</span>
  if (typeof udm === 'boolean') return <span className="json-bool">{String(udm)}</span>
  if (udm === null) return <span className="json-null">null</span>
  if (Array.isArray(udm)) {
    if (udm.length === 0) return <span>{'[]'}</span>
    return (
      <>
        {'[\n'}
        {udm.map((v, i) => (
          <span key={i}>{pad}  <UDMRenderer udm={v} indent={indent + 1} />{i < udm.length - 1 ? ',' : ''}{'\n'}</span>
        ))}
        {pad}{']'}
      </>
    )
  }
  if (typeof udm === 'object' && udm !== null) {
    const entries = Object.entries(udm)
    return (
      <>
        {'{\n'}
        {entries.map(([k, v], i) => (
          <span key={k}>{pad}  <span className="json-key">"{k}"</span>: <UDMRenderer udm={v} indent={indent + 1} />{i < entries.length - 1 ? ',' : ''}{'\n'}</span>
        ))}
        {pad}{'}'}
      </>
    )
  }
  return <span>{String(udm)}</span>
}

// ── Incident Response ─────────────────────────────────────────────────────────
function IncidentResponse() {
  const ref = useReveal()
  const [activeAction, setActiveAction] = useState<string | null>(null)

  const actions = [
    {
      id: 'kill',
      title: 'Kill Process',
      icon: '⊗',
      color: 'var(--red)',
      cardClass: 'ir-kill',
      desc: 'Terminate the suspicious process immediately. Protected against accidental termination of PID 0 or PID 1.',
      dialog: { title: 'Terminate process?', detail: 'python3 · PID 4821', warning: 'This action will immediately terminate the process. This cannot be undone.', confirm: 'Kill PID 4821', cancel: 'Cancel' },
    },
    {
      id: 'block',
      title: 'Block Remote IP',
      icon: '⊘',
      color: 'var(--amber)',
      cardClass: 'ir-block',
      desc: 'Add a deny rule for the remote IP using platform-native firewall mechanisms (iptables on Linux, pf on macOS, netsh on Windows).',
      dialog: { title: 'Block remote IP?', detail: '185.220.101.47 · Port 9001', warning: 'This will add a firewall rule blocking all traffic to/from this IP.', confirm: 'Block 185.220.101.47', cancel: 'Cancel' },
    },
    {
      id: 'quarantine',
      title: 'Quarantine Binary',
      icon: '⊡',
      color: 'var(--amber)',
      cardClass: 'ir-quarantine',
      desc: 'Move the suspicious executable to a quarantine directory and strip all execution permissions, preventing re-execution.',
      dialog: { title: 'Quarantine binary?', detail: '/usr/bin/python3 → /quarantine/', warning: 'The binary will be moved and stripped of execute permissions. Restore manually if this is a false positive.', confirm: 'Quarantine binary', cancel: 'Cancel' },
    },
  ]

  return (
    <section id="response" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 20 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Response</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em', marginBottom: 16 }}>
            Detect. Decide. Contain.
          </h2>
          <p style={{ fontSize: 15, color: 'var(--muted)', maxWidth: 560, lineHeight: 1.7 }}>
            Containment actions are always operator-triggered. SentinelShark surfaces the intelligence; you make the call.
          </p>
        </div>

        {/* Detection → Decision → Containment flow */}
        <div className="reveal reveal-d1" style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 48, background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
          {['Detection', 'Decision', 'Containment'].map((step, i) => (
            <Fragment key={step}>
              <div key={step} style={{ flex: 1, padding: '20px 24px', textAlign: 'center' }}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 6 }}>Step {i + 1}</div>
                <div className="font-display" style={{ fontSize: 20, fontWeight: 700, color: i === 0 ? 'var(--red)' : i === 2 ? 'var(--accent)' : 'var(--text)' }}>{step}</div>
              </div>
              {i < 2 && <div style={{ color: 'var(--dim)', fontSize: 18, padding: '0 4px' }}>→</div>}
            </Fragment>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(300px, 1fr))', gap: 20 }}>
          {actions.map((action, i) => (
            <div key={action.id} className={`reveal reveal-d${i + 1}`}>
              <div className={`ir-card ${action.cardClass}`} style={{ cursor: 'pointer' }} onClick={() => setActiveAction(action.id)}
                onMouseEnter={e => (e.currentTarget.style.opacity = '0.9')}
                onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
                  <span style={{ fontSize: 24, color: action.color }}>{action.icon}</span>
                  <h3 className="font-display" style={{ fontSize: 22, fontWeight: 700, color: action.color, letterSpacing: '-0.01em' }}>{action.title}</h3>
                </div>
                <p style={{ fontSize: 14, color: 'var(--muted)', lineHeight: 1.65, marginBottom: 20 }}>{action.desc}</p>
                <button type="button" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: action.color, background: 'none', border: `1px solid ${action.color}`, borderRadius: 5, padding: '6px 14px', cursor: 'pointer', opacity: 0.8, transition: 'opacity 0.2s' }}>
                  View confirmation dialog →
                </button>
              </div>

              {/* Confirmation dialog preview */}
              {activeAction === action.id && (
                <div style={{ marginTop: 12, background: 'var(--surface-2)', border: `1px solid ${action.color}`, borderRadius: 8, padding: 20 }}>
                  <div className="font-display" style={{ fontSize: 16, fontWeight: 700, color: action.color, marginBottom: 8 }}>{action.dialog.title}</div>
                  <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--text)', marginBottom: 12, padding: '8px 12px', background: 'var(--surface-3)', borderRadius: 5 }}>{action.dialog.detail}</div>
                  <p style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.6, marginBottom: 16 }}>{action.dialog.warning}</p>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <button type="button" onClick={() => setActiveAction(null)} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, background: action.color, color: '#000', border: 'none', padding: '7px 16px', borderRadius: 5, cursor: 'pointer', fontWeight: 600 }}>{action.dialog.confirm}</button>
                    <button type="button" onClick={() => setActiveAction(null)} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, background: 'none', color: 'var(--muted)', border: '1px solid var(--border-mid)', padding: '7px 16px', borderRadius: 5, cursor: 'pointer' }}>{action.dialog.cancel}</button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}

// ── Architecture ──────────────────────────────────────────────────────────────
function Architecture() {
  const ref = useReveal()
  return (
    <section id="architecture" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 56 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Architecture</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
            Non-blocking<br />by design.
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 48 }} className="stack-mobile">
          {/* Architecture diagram */}
          <div className="reveal">
            <div style={{ background: 'var(--surface)', border: '1px solid var(--border-mid)', borderRadius: 8, padding: 28, fontFamily: 'JetBrains Mono, monospace' }}>
              <div style={{ fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 20 }}>System Architecture</div>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
                {[
                  { label: 'PyQt6 UI', note: 'Main Thread · 60 FPS', accent: true },
                  null,
                  { label: 'qasync Event Loop', note: 'asyncio integration', accent: false },
                  null,
                  { label: 'LiveCaptureThread', note: 'QThread · sniff_continuously()', accent: false },
                  null,
                  { label: 'ThreatIntelQueueManager', note: 'Async · rate limited · deduped', accent: false },
                  null,
                  { label: 'PyShark / TShark', note: 'Packet capture + BPF filtering', accent: false },
                  null,
                  { label: 'ThreatIntelClient', note: 'httpx · exponential backoff', accent: false },
                ].map((item, i) => (
                  item === null ? (
                    <div key={i} className="arch-connector">↓</div>
                  ) : (
                    <div key={i} className={`arch-node ${item.accent ? 'arch-node-accent' : ''}`} style={{ width: '100%', maxWidth: 340 }}>
                      <div style={{ fontWeight: 500, marginBottom: 2 }}>{item.label}</div>
                      <div style={{ fontSize: 10, color: item.accent ? 'rgba(45,212,191,0.6)' : 'var(--dim)' }}>{item.note}</div>
                    </div>
                  )
                ))}
                <div className="arch-connector">↓</div>
                {/* TI providers row */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 6, width: '100%', maxWidth: 340 }}>
                  {['VirusTotal', 'AbuseIPDB', 'Shodan', 'IPinfo'].map(p => (
                    <div key={p} style={{ background: 'var(--surface-3)', border: '1px solid var(--border)', borderRadius: 5, padding: '6px 4px', fontSize: 10, textAlign: 'center', color: 'var(--muted)' }}>{p}</div>
                  ))}
                </div>
                <div className="arch-connector">↓</div>
                <div className="arch-node" style={{ width: '100%', maxWidth: 340, borderColor: 'var(--border-mid)', color: 'var(--muted)' }}>
                  <div style={{ fontWeight: 500 }}>SQLite + TTLCache</div>
                  <div style={{ fontSize: 10, color: 'var(--dim)' }}>threatcache.db · 24h TTL</div>
                </div>
              </div>
            </div>
          </div>

          {/* Architecture notes */}
          <div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
              {[
                { title: 'Thread-safe packet capture', body: 'LiveCaptureThread runs PyShark\'s sniff_continuously() on a dedicated QThread, emitting Qt signals to the main UI thread. No blocking operations in the GUI event loop.' },
                { title: 'Async threat intelligence', body: 'ThreatIntelQueueManager manages concurrent API requests using asyncio integrated with PyQt6 via qasync. Rate limiting at 30 req/min, HTTP 429 triggers exponential backoff.' },
                { title: 'Request deduplication', body: 'IPs already in-flight or cached are short-circuited at the queue manager. SQLite provides cross-session persistence; TTLCache provides sub-millisecond in-memory lookups.' },
                { title: 'Mock mode', body: 'When TShark is unavailable, SentinelShark falls back to a synthetic traffic generator. Full UI functionality is preserved for offline testing and development.' },
              ].map((item, i) => (
                <div key={item.title} className={`reveal reveal-d${i + 1}`} style={{ padding: '20px 24px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8 }}>
                  <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start' }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', marginTop: 2 }}>→</span>
                    <div>
                      <div style={{ fontWeight: 600, color: 'var(--text)', marginBottom: 6, fontSize: 14 }}>{item.title}</div>
                      <div style={{ fontSize: 13, color: 'var(--muted)', lineHeight: 1.7 }}>{item.body}</div>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── PCAP + Forensics ──────────────────────────────────────────────────────────
function PcapSection() {
  const ref = useReveal()
  return (
    <section id="forensics" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 64, alignItems: 'center' }} className="stack-mobile">
          <div>
            <div className="reveal">
              <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Forensics</span>
              <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em', marginBottom: 20 }}>
                Inspect the past.<br />Understand the present.
              </h2>
            </div>
            <p className="reveal reveal-d1" style={{ fontSize: 15, lineHeight: 1.75, color: 'var(--muted)', marginBottom: 24 }}>
              Import PCAP, PCAPNG, and CAP files for historical forensic analysis. Every imported capture receives the same threat enrichment pipeline as live traffic — VirusTotal, AbuseIPDB, Shodan, and IPinfo applied retroactively.
            </p>
            <div className="reveal reveal-d2" style={{ display: 'flex', gap: 10, flexWrap: 'wrap', marginBottom: 24 }}>
              {['.pcap', '.pcapng', '.cap'].map(ext => (
                <span key={ext} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--accent)', background: 'var(--accent-dim)', border: '1px solid rgba(45,212,191,0.2)', padding: '4px 12px', borderRadius: 4 }}>{ext}</span>
              ))}
            </div>
            <div className="reveal reveal-d3" style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {['Raw Hex + ASCII payload inspection', 'MD5 and SHA-256 payload hashes', 'BPF filter expression support', 'Wireshark-compatible PCAPNG export'].map(f => (
                <div key={f} style={{ display: 'flex', gap: 10, alignItems: 'center' }}>
                  <span style={{ color: 'var(--accent)', fontSize: 12 }}>✓</span>
                  <span style={{ fontSize: 14, color: 'var(--muted)' }}>{f}</span>
                </div>
              ))}
            </div>
          </div>
          <div className="reveal reveal-d1">
            <div className="product-window">
              <div className="product-titlebar">
                <div className="dot dot-r" /><div className="dot dot-y" /><div className="dot dot-g" />
                <span style={{ marginLeft: 8, fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)' }}>Packet Hex Inspector</span>
              </div>
              <div style={{ padding: 20 }}>
                <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.06em', textTransform: 'uppercase', marginBottom: 12 }}>Frame 6 · 128 bytes</div>
                <div style={{ marginBottom: 16 }}>
                  {[
                    ['0000:', '45 00 00 80 00 01 40 00  40 06 f3 cd c0 a8 01 2a', 'E.....@.@......*'],
                    ['0010:', 'b9 dc 65 2f b0 d0 23 29  00 50 00 16 6e 4a f1 30', '..e/#).P..nJ.0'],
                    ['0020:', '16 03 01 00 f1 01 00 00  ed 03 03 e5 7c f8 92 1a', '............|...'],
                    ['0030:', 'a2 4b 2e f5 91 c3 d4 08  00 20 f8 6a 3e 12 b4 c1', '.K....... .j>...'],
                    ['0040:', 'c0 2b c0 2f 00 9e c0 0a  c0 14 00 35 00 9c c0 09', '.+./.......5....'],
                    ['0050:', 'c0 13 00 2f 00 ff 01 00  00 9c 00 0d 00 18 00 16', '.../............'],
                  ].map(([off, hex, asc]) => (
                    <div key={off} className="hex-row" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, lineHeight: 1.8, display: 'grid', gridTemplateColumns: '64px 1fr 1fr', gap: 12 }}>
                      <span style={{ color: 'var(--dim)' }}>{off}</span>
                      <span style={{ color: '#93c5fd' }}>{hex}</span>
                      <span style={{ color: 'var(--green)' }}>{asc}</span>
                    </div>
                  ))}
                </div>
                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
                  <div style={{ display: 'flex', gap: 24 }}>
                    <div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>MD5</div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--muted)' }}>d8e8fca2dc0f896fd7cb4cb0031ba249</div>
                    </div>
                    <div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 4 }}>SHA-256</div>
                      <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--muted)' }}>a665a459...ae3</div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Developer Experience ──────────────────────────────────────────────────────
function DeveloperSection() {
  const ref = useReveal()
  return (
    <section id="developer" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px' }}>
        <div className="reveal" style={{ marginBottom: 56 }}>
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 12 }}>Developer</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(2.5rem, 5vw, 4rem)', fontWeight: 800, lineHeight: 1, letterSpacing: '-0.01em' }}>
            Up and running<br />in minutes.
          </h2>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 48 }} className="stack-mobile">
          <div>
            <div className="reveal code-block">
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 16 }}>Installation</div>
              {[
                ['$ ', 'git clone https://github.com/DebdootManna/SentinelShark'],
                ['$ ', 'cd SentinelShark'],
                ['$ ', 'python3 -m venv venv'],
                ['$ ', 'source venv/bin/activate'],
                ['$ ', 'pip install -r requirements.txt'],
                ['$ ', 'python run.py'],
              ].map(([p, c], i) => (
                <div key={i} style={{ marginBottom: i === 2 ? 12 : 4 }}>
                  <span className="prompt">{p}</span>
                  <span className="cmd">{c}</span>
                </div>
              ))}
              <div style={{ marginTop: 16, paddingTop: 16, borderTop: '1px solid var(--border)' }}>
                <span className="comment"># TShark optional — Mock Mode available for offline testing</span>
              </div>
            </div>
          </div>
          <div>
            <div className="reveal reveal-d1" style={{ marginBottom: 24 }}>
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 16 }}>Platform compatibility</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {[['macOS', 'Full support · pf firewall integration · lsof socket fallback'],
                  ['Linux', 'Full support · iptables firewall integration'],
                  ['Windows', 'Full support · netsh firewall integration'],
                ].map(([os, note]) => (
                  <div key={os} style={{ display: 'flex', gap: 12, alignItems: 'center', padding: '12px 16px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 6 }}>
                    <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 13, color: 'var(--text)', fontWeight: 500, minWidth: 72 }}>{os}</span>
                    <span style={{ fontSize: 13, color: 'var(--muted)' }}>{note}</span>
                  </div>
                ))}
              </div>
            </div>
            <div className="reveal reveal-d2">
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 16 }}>Requirements</div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {['Python 3.10+', 'PyQt6', 'PyShark', 'httpx', 'psutil', 'qasync', 'TShark (optional)'].map(r => (
                  <span key={r} style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)', background: 'var(--surface)', border: '1px solid var(--border)', padding: '4px 10px', borderRadius: 4 }}>{r}</span>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}

// ── Open Source ───────────────────────────────────────────────────────────────
function OpenSourceSection() {
  const ref = useReveal()
  return (
    <section id="open-source" ref={ref} className="section" style={{ borderTop: '1px solid var(--border)', background: 'var(--surface)' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', textAlign: 'center' }}>
        <div className="reveal">
          <span style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--accent)', letterSpacing: '0.12em', textTransform: 'uppercase', display: 'block', marginBottom: 24 }}>Open source</span>
          <h2 className="font-display" style={{ fontSize: 'clamp(3.5rem, 8vw, 7rem)', fontWeight: 900, lineHeight: 0.92, letterSpacing: '-0.02em', color: 'var(--text)', marginBottom: 32 }}>
            Built<br />in the open.
          </h2>
          <p style={{ fontSize: 17, color: 'var(--muted)', maxWidth: 520, margin: '0 auto 40px', lineHeight: 1.7 }}>
            SentinelShark is MIT-licensed. Read the source, file issues, contribute. No telemetry, no license enforcement, no call-home.
          </p>
          <div style={{ display: 'flex', gap: 12, justifyContent: 'center', flexWrap: 'wrap', marginBottom: 64 }}>
            <a href="https://github.com/DebdootManna/SentinelShark" target="_blank" rel="noopener noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'var(--accent)', color: '#000', fontSize: 15, fontWeight: 600, textDecoration: 'none', padding: '13px 28px', borderRadius: 7, transition: 'opacity 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.85')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            ><GitHubIcon size={16} /> View on GitHub</a>
            <a href="https://github.com/DebdootManna/SentinelShark/wiki" target="_blank" rel="noopener noreferrer"
              style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: 'transparent', color: 'var(--text)', fontSize: 15, fontWeight: 500, textDecoration: 'none', padding: '13px 28px', borderRadius: 7, border: '1px solid var(--border-mid)', transition: 'border-color 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--muted)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border-mid)')}
            >Documentation</a>
          </div>
        </div>
        <div className="reveal reveal-d1" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(200px, 1fr))', gap: 16, borderTop: '1px solid var(--border)', paddingTop: 48 }}>
          {[
            { label: 'License', value: 'MIT', link: 'https://github.com/DebdootManna/SentinelShark/blob/main/LICENSE' },
            { label: 'Repository', value: 'GitHub', link: 'https://github.com/DebdootManna/SentinelShark' },
            { label: 'Architecture', value: 'Wiki', link: 'https://github.com/DebdootManna/SentinelShark/wiki/ARCHITECTURE.md' },
            { label: 'User Guide', value: 'Wiki', link: 'https://github.com/DebdootManna/SentinelShark/wiki/USERGUIDE.md' },
            { label: 'Developer Guide', value: 'Wiki', link: 'https://github.com/DebdootManna/SentinelShark/wiki/DEVELOPERGUIDE.md' },
          ].map(({ label, value, link }) => (
            <a key={label} href={link} target="_blank" rel="noopener noreferrer" style={{ display: 'block', padding: '20px 16px', background: 'var(--surface-2)', border: '1px solid var(--border)', borderRadius: 8, textDecoration: 'none', transition: 'border-color 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--border-mid)')}
              onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
            >
              <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)', letterSpacing: '0.08em', textTransform: 'uppercase', marginBottom: 8 }}>{label}</div>
              <div style={{ fontSize: 15, color: 'var(--accent)', fontWeight: 500 }}>{value} →</div>
            </a>
          ))}
        </div>
      </div>
    </section>
  )
}

// ── Footer ────────────────────────────────────────────────────────────────────
function Footer() {
  return (
    <footer style={{ borderTop: '1px solid var(--border)', padding: '40px 0' }}>
      <div style={{ maxWidth: 1280, margin: '0 auto', padding: '0 24px', display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 24 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Logo size={22} />
          <div>
            <div className="font-display" style={{ fontSize: 16, fontWeight: 700, color: 'var(--text)' }}>SentinelShark</div>
            <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 10, color: 'var(--dim)' }}>Network Intrusion & EDR · MIT License</div>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 24, flexWrap: 'wrap' }}>
          {[['GitHub', 'https://github.com/DebdootManna/SentinelShark'], ['Documentation', 'https://github.com/DebdootManna/SentinelShark/wiki'], ['Architecture', 'https://github.com/DebdootManna/SentinelShark/wiki/ARCHITECTURE.md'], ['User Guide', 'https://github.com/DebdootManna/SentinelShark/wiki/USERGUIDE.md']].map(([label, href]) => (
            <a key={label} href={href} target="_blank" rel="noopener noreferrer" style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 12, color: 'var(--muted)', textDecoration: 'none', transition: 'color 0.2s' }}
              onMouseEnter={e => (e.currentTarget.style.color = 'var(--text)')}
              onMouseLeave={e => (e.currentTarget.style.color = 'var(--muted)')}
            >{label}</a>
          ))}
        </div>
        <div style={{ fontFamily: 'JetBrains Mono, monospace', fontSize: 11, color: 'var(--dim)' }}>
          Built by <a href="https://github.com/DebdootManna" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--muted)', textDecoration: 'none' }}>Debdoot Manna</a>
        </div>
      </div>
    </footer>
  )
}

// ── SVG Icons ─────────────────────────────────────────────────────────────────
function GitHubIcon({ size = 16 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
      <path d="M12 0C5.37 0 0 5.373 0 12c0 5.302 3.438 9.8 8.207 11.387.6.113.793-.261.793-.577v-2.234c-3.338.726-4.033-1.416-4.033-1.416-.546-1.387-1.333-1.756-1.333-1.756-1.089-.745.083-.729.083-.729 1.205.084 1.839 1.237 1.839 1.237 1.07 1.834 2.807 1.304 3.492.997.107-.775.418-1.305.762-1.604-2.665-.305-5.467-1.334-5.467-5.931 0-1.311.469-2.381 1.236-3.221-.124-.303-.535-1.524.117-3.176 0 0 1.008-.322 3.301 1.23A11.509 11.509 0 0 1 12 5.803c1.02.005 2.047.138 3.006.404 2.291-1.552 3.297-1.23 3.297-1.23.653 1.653.242 2.874.118 3.176.77.84 1.235 1.911 1.235 3.221 0 4.609-2.807 5.624-5.479 5.921.43.372.823 1.102.823 2.222v3.293c0 .319.192.694.801.576C20.566 21.797 24 17.3 24 12c0-6.627-5.373-12-12-12z" />
    </svg>
  )
}

// ── App ───────────────────────────────────────────────────────────────────────
export default function App() {
  return (
    <div style={{ background: 'var(--bg)', color: 'var(--text)', fontFamily: "'Inter', sans-serif" }}>
      <a className="skip-link" href="#main">Skip to content</a>
      <Nav />
      <main id="main">
      <Hero />
      <BigStatement />
      <ProductUI />
      <Capabilities />
      <PacketChain />
      <ThreatIntel />
      <MitreSection />
      <ChronicleSection />
      <IncidentResponse />
      <Architecture />
      <PcapSection />
      <DeveloperSection />
      <OpenSourceSection />
      </main>
      <Footer />
    </div>
  )
}
