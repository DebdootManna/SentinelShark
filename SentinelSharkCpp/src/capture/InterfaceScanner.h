#pragma once
#include <QString>
#include <QStringList>

namespace SS {

/// Enumerate available network interfaces by running "tshark -D".
/// Returns list of interface strings like "1: \\Device\\NPF_{GUID} (Ethernet)".
/// Falls back to ["1", "2", "3"] if tshark is not available.
QStringList getAvailableInterfaces(const QString& tsharkPath);

/// Translate user-friendly filter shortcuts to valid BPF syntax.
/// E.g. "http" -> "port 80", "dns" -> "port 53", "192.168.1.1" -> "host 192.168.1.1"
QString sanitizeBpfFilter(const QString& raw);

} // namespace SS
