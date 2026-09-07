#pragma once
#include <QString>
#include <QStringList>
#include <QList>

namespace SS {

struct InterfaceEntry {
    QString id;           // e.g. "1" or "\\Device\\NPF_{...}"
    QString name;         // e.g. "Wi-Fi" or "Ethernet"
    QString ipAddress;    // e.g. "192.168.1.100"
    QString description;  // e.g. "Intel(R) Wi-Fi 6 AX201"
};

/// Enumerate detailed network interfaces with name, IP address, and description.
QList<InterfaceEntry> getDetailedInterfaces(const QString& tsharkPath);

/// Enumerate available network interfaces as string list.
QStringList getAvailableInterfaces(const QString& tsharkPath);

/// Translate user-friendly filter shortcuts to valid BPF syntax.
QString sanitizeBpfFilter(const QString& raw);

} // namespace SS
