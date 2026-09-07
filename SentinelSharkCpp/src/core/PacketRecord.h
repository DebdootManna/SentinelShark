#pragma once
#include <cstdint>
#include <QString>
#include <QByteArray>

namespace SS {

/// Severity levels — stored as uint8_t in PacketRecord to minimize size.
enum class Severity : uint8_t {
    Safe     = 0,
    Medium   = 1,
    High     = 2,
    Critical = 3
};

inline const char* severityStr(Severity s) noexcept {
    switch (s) {
        case Severity::Critical: return "CRITICAL";
        case Severity::High:     return "HIGH";
        case Severity::Medium:   return "MEDIUM";
        default:                 return "SAFE";
    }
}

/// Lightweight fixed-size packet record stored in the ring buffer.
/// Hot-path fields use fixed char arrays to avoid heap allocation.
/// QString/QByteArray lazy fields are only populated on row selection.
struct PacketRecord {
    // ── Hot-path fields (populated in capture thread) ─────────────────────
    uint32_t no          = 0;
    char     time[16]    = {};   // "HH:MM:SS.mmm\0"
    uint32_t pid         = 0;
    char     process[64] = {};   // process name
    char     src[46]     = {};   // source IP (IPv4 or IPv6)
    uint16_t src_port    = 0;
    char     dst[46]     = {};   // destination IP
    uint16_t dst_port    = 0;
    char     protocol[8] = {};   // TCP/UDP/DNS/HTTP/HTTPS/SSH/ICMP
    uint32_t length      = 0;
    char     mitre[16]   = {};   // e.g. "T1059.001\0"
    Severity severity    = Severity::Safe;
    char     info[192]   = {};   // human-readable summary

    // ── Lazy fields (populated only when row is selected) ─────────────────
    bool     lazy_loaded = false;
    QByteArray raw_bytes;          // raw packet bytes (kept empty until needed)
    QString    hex_dump;           // Wireshark-style hex dump
    QString    ascii_str;          // ASCII representation
    QString    payload_md5;
    QString    payload_sha256;
    QString    exe_path;           // full path to process executable
    QString    cmdline;            // process command line
    QString    username;           // process owner

    // Helpers
    QString srcStr()      const noexcept { return QString::fromLatin1(src); }
    QString dstStr()      const noexcept { return QString::fromLatin1(dst); }
    QString processStr()  const noexcept { return QString::fromLatin1(process); }
    QString protocolStr() const noexcept { return QString::fromLatin1(protocol); }
    QString mitreStr()    const noexcept { return QString::fromLatin1(mitre); }
    QString timeStr()     const noexcept { return QString::fromLatin1(time); }
    QString infoStr()     const noexcept { return QString::fromLatin1(info); }

    QString srcEndpoint() const noexcept {
        return src_port ? QStringLiteral("%1:%2").arg(srcStr()).arg(src_port) : srcStr();
    }
    QString dstEndpoint() const noexcept {
        return dst_port ? QStringLiteral("%1:%2").arg(dstStr()).arg(dst_port) : dstStr();
    }
};

} // namespace SS
