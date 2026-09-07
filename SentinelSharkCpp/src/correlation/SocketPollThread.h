#pragma once

// ============================================================================
// SocketPollThread.h  —  SS::SocketPollThread
// ============================================================================
// Background QThread that polls Windows TCP/UDP socket tables every 1 second
// and maintains a lock-free map from (ip, port) → owning PID / process name.
//
// Design goals:
//   • Zero locks on the hot read path (lookup()).
//     Readers atomically load a shared_ptr snapshot; the writer atomically
//     swaps in a freshly-built map once per second.
//   • Four-tuple matching → port-only fallback for robustness.
//   • IPv4 and IPv6 tables are both enumerated.
//
// Windows APIs used:
//   GetExtendedTcpTable  (iphlpapi.h)  — TCP_TABLE_OWNER_PID_ALL
//   GetExtendedUdpTable  (iphlpapi.h)  — UDP_TABLE_OWNER_PID
// ============================================================================

#include <cstdint>
#include <memory>
#include <atomic>
#include <unordered_map>

#include <QString>
#include <QThread>
#include <QReadWriteLock>

namespace SS {

/// Owning PID and resolved process name for a single socket entry.
struct PidEntry {
    uint32_t pid         = 0;
    QString  processName;       ///< Empty string when unknown
};

class SocketPollThread : public QThread {
    Q_OBJECT

public:
    // ── Types ─────────────────────────────────────────────────────────────────

    /// Primary socket map: packed 64-bit key → PidEntry.
    /// Key encoding: ((uint64_t)localIp << 16) | localPort
    /// For IPv6 we use a CRC-32 of the 16-byte address folded into 32 bits.
    using SocketMap = std::unordered_map<uint64_t, PidEntry>;

    // ── Singleton ─────────────────────────────────────────────────────────────

    /// Returns the application-wide singleton.  Must be started explicitly
    /// by the caller: SocketPollThread::instance().start().
    static SocketPollThread& instance();

    // ── Public API ────────────────────────────────────────────────────────────

    /// Look up the owning PID / process name for a connection.
    ///
    /// Matching strategy (first hit wins):
    ///   1. Exact key on socketMap_ keyed by (srcIp, srcPort)  — local side
    ///   2. Exact key on socketMap_ keyed by (dstIp, dstPort)  — remote side
    ///        (for connections seen from the remote perspective)
    ///   3. Port-only fallback in portMap_ keyed by srcPort
    ///   4. Port-only fallback in portMap_ keyed by dstPort
    ///
    /// Returns {0, ""} when no match is found.
    PidEntry lookup(const QString& srcIp, uint16_t srcPort,
                    const QString& dstIp, uint16_t dstPort) const;

    /// Signal the poll loop to exit.  Call before joining / deleting.
    void stop();

protected:
    // ── QThread entry point ──────────────────────────────────────────────────

    void run() override;

private:
    // ── Lifecycle ─────────────────────────────────────────────────────────────

    explicit SocketPollThread(QObject* parent = nullptr);

    // Non-copyable singleton.
    SocketPollThread(const SocketPollThread&)            = delete;
    SocketPollThread& operator=(const SocketPollThread&) = delete;

    // ── Internal helpers ──────────────────────────────────────────────────────

    /// Rebuild both socketMap_ and portMap_ from current OS tables.
    /// Creates new heap maps, populates them, then atomically swaps into the
    /// atomic shared_ptr members so readers see a consistent snapshot.
    void buildMaps();

    /// Pack an IPv4 address (host-byte-order DWORD) and port into a 64-bit key.
    static constexpr uint64_t makeKey(uint32_t ip, uint16_t port) noexcept {
        return (static_cast<uint64_t>(ip) << 16) | static_cast<uint64_t>(port);
    }

    /// Convert a dotted-decimal IP string to a host-byte-order uint32_t.
    /// Returns 0 on parse failure.
    static uint32_t ipv4ToUint32(const QString& ip) noexcept;

    // ── Data members ──────────────────────────────────────────────────────────
    mutable QReadWriteLock mapLock_;

    /// Full (ip+port) → PidEntry map.
    std::shared_ptr<SocketMap> socketMap_;

    /// Port-only fallback map.
    std::shared_ptr<SocketMap> portMap_;

    /// Set to false by stop() to break out of the poll loop in run().
    std::atomic<bool> running_{ false };
};

} // namespace SS
