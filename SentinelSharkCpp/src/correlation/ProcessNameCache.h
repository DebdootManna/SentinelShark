#pragma once

// ============================================================================
// ProcessNameCache.h  —  SS::ProcessNameCache
// ============================================================================
// Thread-safe PID → ProcessInfo lookup cache.
//
// Policy:
//   • TTL  : 30 seconds (kTtlMs). After expiry the entry is refreshed via
//             Win32 QueryFullProcessImageNameW on the next get() call.
//   • LRU  : When the cache would exceed kMaxEntries, the least-recently-
//             accessed entry (by accessMs timestamp) is evicted.
//   • Short-circuit for PID 0 (System Idle) and PID 4 (System kernel) which
//             never change, so we avoid opening handles for them.
//
// All public methods are safe to call from any thread; QMutex guards all
// accesses to cache_.
// ============================================================================

#include <cstdint>

#include <QHash>
#include <QMutex>
#include <QString>

// UdmNormalizer.h defines both ProcessInfo and ThreatIntelResult.
// We depend only on ProcessInfo here, but including the full header avoids
// the need for a manual forward-declaration of the struct fields.
#include "udm/UdmNormalizer.h"

namespace SS {

/// Singleton, thread-safe PID → ProcessInfo cache with 30 s TTL and
/// LRU eviction capped at 256 entries.
class ProcessNameCache {
public:
    // ── Singleton access ────────────────────────────────────────────────────

    /// Returns the single application-wide instance.
    /// Thread-safe due to C++11 magic-static guarantees.
    static ProcessNameCache& instance();

    // ── Public API ──────────────────────────────────────────────────────────

    /// Return ProcessInfo for the given PID.
    ///
    /// Fast path: if the entry exists and has not expired, the cached value is
    /// returned immediately with no system calls.
    /// Slow path: refresh(pid) is called, the Win32 APIs are invoked, and the
    /// new entry is stored before returning.
    SS::ProcessInfo get(uint32_t pid);

    /// Forcibly remove a PID from the cache (e.g., on process-exit events so
    /// that stale data is not served when the PID is later reused).
    void invalidate(uint32_t pid);

private:
    // ── Private types ────────────────────────────────────────────────────────

    /// One slot in the hash-map.
    struct Entry {
        SS::ProcessInfo info;

        /// Absolute deadline in ms-since-epoch after which this entry must be
        /// refreshed.  Computed as QDateTime::currentMSecsSinceEpoch() + kTtlMs
        /// at insertion/refresh time.
        qint64 expireMs = 0;

        /// Last-access time (ms-since-epoch) used for LRU eviction decisions.
        qint64 accessMs = 0;
    };

    // ── Constants ────────────────────────────────────────────────────────────

    static constexpr int   kMaxEntries = 256;      ///< Hard cap on cache size
    static constexpr qint64 kTtlMs     = 30'000;   ///< 30-second TTL

    // ── Lifecycle ────────────────────────────────────────────────────────────

    ProcessNameCache() = default;

    // Disallow copy and move — this is a singleton.
    ProcessNameCache(const ProcessNameCache&)            = delete;
    ProcessNameCache& operator=(const ProcessNameCache&) = delete;

    // ── Private helpers ──────────────────────────────────────────────────────

    /// Query the OS for pid, then insert/update cache_.
    ///
    /// Win32 calls performed (in order, each guarded against failure):
    ///   1. OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ)
    ///   2. QueryFullProcessImageNameW  → exePath  → name via QFileInfo
    ///   3. NtQueryInformationProcess (ProcessCommandLineInformation)
    ///      → cmdline (best-effort; remains empty on access-denied / failure)
    ///
    /// sha256 is intentionally left empty — it is computed lazily by the UI
    /// layer only when a row is selected, keeping the capture hot-path fast.
    void refresh(uint32_t pid);

    /// When cache_ is at kMaxEntries, scan for the entry with the smallest
    /// accessMs and erase it to make room.
    void evictLru();

    // ── Data members ─────────────────────────────────────────────────────────

    QHash<uint32_t, Entry> cache_;  ///< PID → cache entry map
    QMutex                 mutex_;  ///< Protects cache_ for multi-thread access
};

} // namespace SS
