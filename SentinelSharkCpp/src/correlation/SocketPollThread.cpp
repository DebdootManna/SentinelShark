// SocketPollThread.cpp  —  SS::SocketPollThread
// Polls Windows TCP/UDP extended tables every 1 second.
// Builds two maps atomically:
//   socketMap_  : (ip32 << 16 | port) -> PidEntry  (for O(1) packet correlation)
//   portMap_    : port -> PidEntry                  (fallback when IP doesn't match)

// Winsock2 must be included before windows.h to avoid redefinition errors
#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "SocketPollThread.h"
#include "../correlation/ProcessNameCache.h"
#include <QThread>
#include <QHostAddress>
#include <cstring>
#include <vector>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

namespace SS {

// ── Singleton ─────────────────────────────────────────────────────────────────

SocketPollThread& SocketPollThread::instance() {
    static SocketPollThread inst;
    return inst;
}

SocketPollThread::SocketPollThread(QObject* parent)
    : QThread(parent)
{
    setObjectName(QStringLiteral("SocketPollThread"));
    socketMap_ = std::make_shared<SocketMap>();
    portMap_   = std::make_shared<SocketMap>();
}

// ── Public API ────────────────────────────────────────────────────────────────

void SocketPollThread::stop() {
    running_.store(false, std::memory_order_relaxed);
}

PidEntry SocketPollThread::lookup(const QString& srcIp, uint16_t srcPort,
                                   const QString& dstIp, uint16_t dstPort) const
{
    std::shared_ptr<SocketMap> sockMap;
    std::shared_ptr<SocketMap> prtMap;
    {
        QReadLocker locker(&mapLock_);
        sockMap = socketMap_;
        prtMap  = portMap_;
    }

    if (!sockMap || !prtMap) return {};

    const uint32_t srcIp4 = ipv4ToUint32(srcIp);
    const uint32_t dstIp4 = ipv4ToUint32(dstIp);

    // 1. Exact match on local side (src)
    if (srcIp4 && srcPort) {
        auto it = sockMap->find(makeKey(srcIp4, srcPort));
        if (it != sockMap->end()) return it->second;
    }

    // 2. Exact match on remote side (dst)
    if (dstIp4 && dstPort) {
        auto it = sockMap->find(makeKey(dstIp4, dstPort));
        if (it != sockMap->end()) return it->second;
    }

    // 3. Port-only fallback (src port)
    if (srcPort) {
        auto it = prtMap->find(makeKey(0, srcPort));
        if (it != prtMap->end()) return it->second;
    }

    // 4. Port-only fallback (dst port)
    if (dstPort) {
        auto it = prtMap->find(makeKey(0, dstPort));
        if (it != prtMap->end()) return it->second;
    }

    return {};
}

// ── Thread entry point ────────────────────────────────────────────────────────

void SocketPollThread::run() {
    running_.store(true, std::memory_order_relaxed);

    // Kick off once immediately so the first captured packet has data
    buildMaps();

    while (running_.load(std::memory_order_relaxed)) {
        QThread::msleep(1000);
        if (!running_.load(std::memory_order_relaxed)) break;
        buildMaps();
    }
}

// ── Map building ──────────────────────────────────────────────────────────────

void SocketPollThread::buildMaps() {
    auto newSock = std::make_shared<SocketMap>();
    auto newPort = std::make_shared<SocketMap>();

    auto& cache = ProcessNameCache::instance();

    // ── IPv4 TCP ─────────────────────────────────────────────────────────────
    {
        DWORD bufSize = 32768;
        std::vector<BYTE> buf(bufSize);

        DWORD ret = GetExtendedTcpTable(buf.data(), &bufSize,
                                         FALSE,  // bOrder (unsorted is fine)
                                         AF_INET,
                                         TCP_TABLE_OWNER_PID_ALL,
                                         0);
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(bufSize);
            ret = GetExtendedTcpTable(buf.data(), &bufSize,
                                       FALSE, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0);
        }

        if (ret == NO_ERROR) {
            const auto* table = reinterpret_cast<const MIB_TCPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row = table->table[i];
                const uint32_t localIp   = ntohl(row.dwLocalAddr);
                const uint16_t localPort = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                const uint32_t pid       = row.dwOwningPid;

                if (localPort == 0 || pid == 0) continue;

                ProcessInfo info = cache.get(pid);
                PidEntry entry{pid, info.name.isEmpty() ? QString::number(pid) : info.name};

                (*newSock)[makeKey(localIp, localPort)] = entry;
                (*newPort)[makeKey(0,       localPort)] = entry;
            }
        }
    }

    // ── IPv4 UDP ─────────────────────────────────────────────────────────────
    {
        DWORD bufSize = 32768;
        std::vector<BYTE> buf(bufSize);

        DWORD ret = GetExtendedUdpTable(buf.data(), &bufSize,
                                         FALSE, AF_INET,
                                         UDP_TABLE_OWNER_PID, 0);
        if (ret == ERROR_INSUFFICIENT_BUFFER) {
            buf.resize(bufSize);
            ret = GetExtendedUdpTable(buf.data(), &bufSize,
                                       FALSE, AF_INET,
                                       UDP_TABLE_OWNER_PID, 0);
        }

        if (ret == NO_ERROR) {
            const auto* table = reinterpret_cast<const MIB_UDPTABLE_OWNER_PID*>(buf.data());
            for (DWORD i = 0; i < table->dwNumEntries; ++i) {
                const auto& row      = table->table[i];
                const uint32_t localIp   = ntohl(row.dwLocalAddr);
                const uint16_t localPort = ntohs(static_cast<uint16_t>(row.dwLocalPort));
                const uint32_t pid       = row.dwOwningPid;

                if (localPort == 0 || pid == 0) continue;

                ProcessInfo info = cache.get(pid);
                PidEntry entry{pid, info.name.isEmpty() ? QString::number(pid) : info.name};

                (*newSock)[makeKey(localIp, localPort)] = entry;
                (*newPort)[makeKey(0,       localPort)] = entry;
            }
        }
    }

    // Atomically replace the maps
    {
        QWriteLocker locker(&mapLock_);
        socketMap_ = std::move(newSock);
        portMap_   = std::move(newPort);
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

uint32_t SocketPollThread::ipv4ToUint32(const QString& ip) noexcept {
    QHostAddress addr(ip);
    if (addr.protocol() == QAbstractSocket::IPv4Protocol)
        return addr.toIPv4Address(); // host byte order
    return 0;
}

} // namespace SS
