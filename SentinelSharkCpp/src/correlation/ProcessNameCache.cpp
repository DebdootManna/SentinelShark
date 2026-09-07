// ============================================================================
// ProcessNameCache.cpp  —  SS::ProcessNameCache implementation
// ============================================================================
// Windows-only implementation that uses:
//   • OpenProcess / QueryFullProcessImageNameW   (Kernel32 / Psapi)
//   • NtQueryInformationProcess                  (Ntdll, runtime-loaded)
//   • QDateTime::currentMSecsSinceEpoch          (Qt6 Core)
//   • QFileInfo for basename extraction
//
// The PEB command-line path uses the undocumented-but-stable
// ProcessCommandLineInformation (60) sub-class of NtQueryInformationProcess.
// We load ntdll.dll at runtime so that the rest of the binary is not linked
// to ntdll for this one purpose.
// ============================================================================

// winsock2 must come before windows.h to prevent Winsock 1 header conflicts.
#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>

// UNICODE_STRING / PROCESS_BASIC_INFORMATION etc. from the NT DDK subset
// included in the Windows SDK under <winternl.h>.
#include <winternl.h>

#include <cstring>
#include <algorithm>

#include <QDateTime>
#include <QFileInfo>
#include <QString>

#include "correlation/ProcessNameCache.h"
// UdmNormalizer.h pulled in via the header already.

namespace SS {

// ── NtQueryInformationProcess plumbing ──────────────────────────────────────

/// Function-pointer type for NtQueryInformationProcess.
using NtQueryInformationProcess_t = NTSTATUS(NTAPI*)(
    HANDLE           ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID            ProcessInformation,
    ULONG            ProcessInformationLength,
    PULONG           ReturnLength
);

/// Load the function pointer once, lazily, from ntdll.dll.
static NtQueryInformationProcess_t resolveNtQueryInformationProcess() noexcept {
    static NtQueryInformationProcess_t fn = nullptr;
    if (!fn) {
        HMODULE hNtDll = ::GetModuleHandleW(L"ntdll.dll");
        if (hNtDll) {
            fn = reinterpret_cast<NtQueryInformationProcess_t>(
                ::GetProcAddress(hNtDll, "NtQueryInformationProcess"));
        }
    }
    return fn;
}

// ProcessCommandLineInformation = 60 (not in all SDK versions of the enum)
static constexpr PROCESSINFOCLASS kProcessCommandLineInfo =
    static_cast<PROCESSINFOCLASS>(60);

// ── Singleton ────────────────────────────────────────────────────────────────

ProcessNameCache& ProcessNameCache::instance() {
    static ProcessNameCache s_instance;
    return s_instance;
}

// ── Public: get ──────────────────────────────────────────────────────────────

SS::ProcessInfo ProcessNameCache::get(uint32_t pid) {
    QMutexLocker lock(&mutex_);

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();

    auto it = cache_.find(pid);
    if (it != cache_.end()) {
        if (nowMs < it->expireMs) {
            // Cache hit — touch the access time for LRU accounting.
            it->accessMs = nowMs;
            return it->info;
        }
        // Expired — fall through to refresh (entry will be overwritten).
    }

    // Release the lock while performing the (potentially blocking) OS call,
    // then re-acquire to write the result.
    lock.unlock();
    refresh(pid);
    lock.relock();

    // After refresh the entry should exist; if something went very wrong
    // (e.g., another thread evicted it immediately), return a default.
    it = cache_.find(pid);
    if (it != cache_.end()) {
        it->accessMs = QDateTime::currentMSecsSinceEpoch();
        return it->info;
    }

    // Fallback: return a minimally populated ProcessInfo.
    SS::ProcessInfo fallback;
    fallback.pid  = pid;
    fallback.name = QStringLiteral("<unknown:%1>").arg(pid);
    return fallback;
}

// ── Public: invalidate ───────────────────────────────────────────────────────

void ProcessNameCache::invalidate(uint32_t pid) {
    QMutexLocker lock(&mutex_);
    cache_.remove(pid);
}

// ── Private: evictLru ────────────────────────────────────────────────────────

void ProcessNameCache::evictLru() {
    // Called with mutex_ held.
    // Linear scan is acceptable for up to 256 entries.
    if (cache_.size() < kMaxEntries)
        return;

    uint32_t lruPid     = 0;
    qint64   lruAccess  = std::numeric_limits<qint64>::max();

    for (auto it = cache_.cbegin(); it != cache_.cend(); ++it) {
        if (it->accessMs < lruAccess) {
            lruAccess = it->accessMs;
            lruPid    = it.key();
        }
    }

    cache_.remove(lruPid);
}

// ── Private: refresh ─────────────────────────────────────────────────────────

void ProcessNameCache::refresh(uint32_t pid) {
    // ── Well-known pseudo-processes ──────────────────────────────────────────
    // PIDs 0 and 4 are fixed in Windows; opening a handle is not possible or
    // meaningful for them.
    if (pid == 0 || pid == 4) {
        SS::ProcessInfo info;
        info.pid      = pid;
        info.name     = (pid == 0) ? QStringLiteral("System Idle")
                                   : QStringLiteral("System");
        info.exePath  = (pid == 0) ? QString() : QStringLiteral("ntoskrnl.exe");
        info.cmdline  = QString();
        info.sha256   = QString(); // computed lazily in UI layer

        const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
        Entry e;
        e.info     = std::move(info);
        e.expireMs = nowMs + kTtlMs;
        e.accessMs = nowMs;

        QMutexLocker lock(&mutex_);
        evictLru();
        cache_.insert(pid, std::move(e));
        return;
    }

    // ── Open a limited-access handle ─────────────────────────────────────────
    // PROCESS_QUERY_LIMITED_INFORMATION does not require SeDebugPrivilege and
    // is sufficient for QueryFullProcessImageNameW.
    // PROCESS_VM_READ is added as a best-effort for PEB access; it may be
    // denied for elevated processes — handled gracefully below.
    HANDLE hProcess = ::OpenProcess(
        PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
        FALSE,
        static_cast<DWORD>(pid));

    // If VM_READ was denied, try without it (sufficient for image name).
    if (!hProcess) {
        hProcess = ::OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION,
            FALSE,
            static_cast<DWORD>(pid));
    }

    SS::ProcessInfo info;
    info.pid = pid;

    if (hProcess) {
        // ── Executable path ───────────────────────────────────────────────────
        wchar_t exePathBuf[MAX_PATH + 1] = {};
        DWORD   exePathLen = MAX_PATH;

        if (::QueryFullProcessImageNameW(hProcess, 0, exePathBuf, &exePathLen)) {
            info.exePath = QString::fromWCharArray(exePathBuf, static_cast<int>(exePathLen));
            info.name    = QFileInfo(info.exePath).fileName();
        } else {
            // Fallback: try the older GetModuleFileNameExW (requires PROCESS_VM_READ)
            wchar_t fallbackBuf[MAX_PATH + 1] = {};
            DWORD   written = ::GetModuleFileNameExW(
                hProcess, nullptr, fallbackBuf, MAX_PATH);
            if (written > 0) {
                info.exePath = QString::fromWCharArray(fallbackBuf, static_cast<int>(written));
                info.name    = QFileInfo(info.exePath).fileName();
            } else {
                info.name = QStringLiteral("<pid:%1>").arg(pid);
            }
        }

        // ── Command line via NtQueryInformationProcess ────────────────────────
        // ProcessCommandLineInformation (class 60) returns a UNICODE_STRING
        // describing the command line.  The buffer is heap-allocated by the
        // kernel, so we call twice: first to get the required size, then to
        // receive the data.
        auto ntQIP = resolveNtQueryInformationProcess();
        if (ntQIP) {
            ULONG   retLen = 0;
            NTSTATUS st = ntQIP(hProcess, kProcessCommandLineInfo,
                                nullptr, 0, &retLen);
            // STATUS_INFO_LENGTH_MISMATCH = 0xC0000004 — expected on first call
            if (retLen > 0) {
                std::vector<BYTE> buf(retLen);
                st = ntQIP(hProcess, kProcessCommandLineInfo,
                           buf.data(), retLen, &retLen);
                if (NT_SUCCESS(st)) {
                    // The buffer contains a UNICODE_STRING whose Buffer member
                    // points into the same allocation, offset past the header.
                    auto* ustr = reinterpret_cast<UNICODE_STRING*>(buf.data());
                    if (ustr->Buffer && ustr->Length > 0) {
                        info.cmdline = QString::fromWCharArray(
                            ustr->Buffer,
                            ustr->Length / sizeof(wchar_t));
                    }
                }
            }
        }

        ::CloseHandle(hProcess);
    } else {
        // Could not open the process (terminated, access denied, etc.)
        info.name = QStringLiteral("<pid:%1>").arg(pid);
    }

    // sha256 deliberately left empty — computed lazily in the UI layer.
    info.sha256 = QString();

    const qint64 nowMs = QDateTime::currentMSecsSinceEpoch();
    Entry e;
    e.info     = std::move(info);
    e.expireMs = nowMs + kTtlMs;
    e.accessMs = nowMs;

    QMutexLocker lock(&mutex_);
    evictLru();
    cache_.insert(pid, std::move(e));
}

} // namespace SS
