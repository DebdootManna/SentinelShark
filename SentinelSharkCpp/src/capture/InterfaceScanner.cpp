#include "InterfaceScanner.h"
#include <QProcess>
#include <QHostAddress>

namespace SS {

QStringList getAvailableInterfaces(const QString& tsharkPath) {
    if (tsharkPath.isEmpty()) return {"1", "2", "3"};

    QProcess proc;
    proc.start(tsharkPath, {"-D"});
    if (!proc.waitForFinished(5000)) return {"1", "2", "3"};

    QStringList result;
    const QString output = QString::fromLocal8Bit(proc.readAllStandardOutput());
    for (const QString& line : output.split('\n', Qt::SkipEmptyParts)) {
        const QString trimmed = line.trimmed();
        if (!trimmed.isEmpty())
            result << trimmed;
    }
    return result.isEmpty() ? QStringList{"1", "2", "3"} : result;
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
