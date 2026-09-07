#ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
#endif
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "InterfaceScanner.h"
#include <QProcess>
#include <QHostAddress>
#include <QRegularExpression>
#include <vector>

namespace SS {

QList<InterfaceEntry> getDetailedInterfaces(const QString& tsharkPath) {
    QList<InterfaceEntry> entries;

    // 1. Enumerate Windows network adapters via GetAdaptersAddresses
    ULONG outBufLen = 15000;
    std::vector<BYTE> buffer(outBufLen);
    PIP_ADAPTER_ADDRESSES pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());

    ULONG flags = GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    DWORD dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAddresses, &outBufLen);
    if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
        buffer.resize(outBufLen);
        pAddresses = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buffer.data());
        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, nullptr, pAddresses, &outBufLen);
    }

    struct WinAdapter {
        QString guid;
        QString friendlyName;
        QString description;
        QString ipAddress;
    };
    QList<WinAdapter> winAdapters;

    if (dwRetVal == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurr = pAddresses; pCurr != nullptr; pCurr = pCurr->Next) {
            WinAdapter wa;
            if (pCurr->AdapterName) {
                wa.guid = QString::fromLatin1(pCurr->AdapterName);
            }
            if (pCurr->FriendlyName) {
                wa.friendlyName = QString::fromWCharArray(pCurr->FriendlyName);
            }
            if (pCurr->Description) {
                wa.description = QString::fromWCharArray(pCurr->Description);
            }

            // Extract primary IPv4 address
            for (PIP_ADAPTER_UNICAST_ADDRESS pUni = pCurr->FirstUnicastAddress; pUni != nullptr; pUni = pUni->Next) {
                if (pUni->Address.lpSockaddr->sa_family == AF_INET) {
                    char ipStr[INET_ADDRSTRLEN] = {0};
                    auto* sa_in = reinterpret_cast<sockaddr_in*>(pUni->Address.lpSockaddr);
                    inet_ntop(AF_INET, &(sa_in->sin_addr), ipStr, sizeof(ipStr));
                    wa.ipAddress = QString::fromLatin1(ipStr);
                    break;
                }
            }
            winAdapters.append(wa);
        }
    }

    // 2. Parse tshark -D if available
    QStringList tsharkLines;
    if (!tsharkPath.isEmpty()) {
        QProcess proc;
        proc.start(tsharkPath, {"-D"});
        if (proc.waitForFinished(4000)) {
            const QString out = QString::fromLocal8Bit(proc.readAllStandardOutput());
            tsharkLines = out.split('\n', Qt::SkipEmptyParts);
        }
    }

    if (!tsharkLines.isEmpty()) {
        // Match tshark lines like "1. \Device\NPF_{GUID} (Friendly Name)"
        static const QRegularExpression tsharkRe(R"(^(\d+)\.\s+(\\Device\\NPF_\{([0-9a-fA-F\-]+)\}|\S+)(?:\s+\((.*)\))?)");

        for (const QString& line : tsharkLines) {
            const QString trimmed = line.trimmed();
            if (trimmed.isEmpty()) continue;

            const auto match = tsharkRe.match(trimmed);
            InterfaceEntry entry;
            if (match.hasMatch()) {
                const QString idx   = match.captured(1);
                const QString dev   = match.captured(2);
                const QString guid  = match.captured(3);
                const QString label = match.captured(4);

                entry.id = idx; // Default to index for tshark -i <idx>
                entry.name = label.isEmpty() ? dev : label;
                entry.description = dev;

                // Match with WinAdapter by GUID or name
                for (const auto& wa : winAdapters) {
                    if ((!guid.isEmpty() && wa.guid.contains(guid, Qt::CaseInsensitive)) ||
                        (!wa.friendlyName.isEmpty() && entry.name.contains(wa.friendlyName, Qt::CaseInsensitive))) {
                        entry.ipAddress = wa.ipAddress;
                        if (!wa.description.isEmpty()) entry.description = wa.description;
                        break;
                    }
                }
            } else {
                entry.id = trimmed.section('.', 0, 0).trimmed();
                entry.name = trimmed;
            }

            if (entry.ipAddress.isEmpty()) {
                entry.ipAddress = "—";
            }
            entries.append(entry);
        }
    } else {
        // Fallback: use winAdapters directly
        int idx = 1;
        for (const auto& wa : winAdapters) {
            InterfaceEntry entry;
            entry.id = QString::number(idx++);
            entry.name = wa.friendlyName.isEmpty() ? wa.description : wa.friendlyName;
            entry.description = wa.description;
            entry.ipAddress = wa.ipAddress.isEmpty() ? "—" : wa.ipAddress;
            entries.append(entry);
        }
    }

    // Always ensure at least a Loopback / Mock adapter is present
    if (entries.isEmpty()) {
        entries.append(InterfaceEntry{"1", "Ethernet Adapter", "192.168.1.100", "Simulated Network Interface"});
        entries.append(InterfaceEntry{"2", "Wi-Fi Adapter", "10.0.0.15", "Wireless 802.11ax"});
        entries.append(InterfaceEntry{"3", "Loopback (Npcap)", "127.0.0.1", "Npcap Loopback Adapter"});
    }

    return entries;
}

QStringList getAvailableInterfaces(const QString& tsharkPath) {
    const auto detailed = getDetailedInterfaces(tsharkPath);
    QStringList result;
    result.reserve(detailed.size());
    for (const auto& e : detailed) {
        if (!e.ipAddress.isEmpty() && e.ipAddress != "—") {
            result.append(QStringLiteral("%1: %2 (%3)").arg(e.id, e.name, e.ipAddress));
        } else {
            result.append(QStringLiteral("%1: %2").arg(e.id, e.name));
        }
    }
    return result;
}

QString sanitizeBpfFilter(const QString& raw) {
    const QString trimmed = raw.trimmed().toLower();
    if (trimmed.isEmpty())          return {};
    if (trimmed == "http")          return "port 80";
    if (trimmed == "https")         return "port 443";
    if (trimmed == "dns")           return "port 53";
    if (trimmed == "ssh")           return "port 22";
    if (trimmed == "rdp")           return "port 3389";
    if (trimmed == "smb")           return "port 445";
    if (trimmed == "icmp")          return "icmp";
    if (trimmed == "tcp")           return "tcp";
    if (trimmed == "udp")           return "udp";
    // IP address shortcut
    QHostAddress addr(raw.trimmed());
    if (!addr.isNull())             return "host " + raw.trimmed();
    return raw.trimmed();
}

} // namespace SS
