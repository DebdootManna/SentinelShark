#pragma once
#include <QStringList>
#include <QString>
#include "../core/PacketRecord.h"

namespace SS {

/// Stateless MITRE ATT&CK behavioral heuristics engine.
/// All methods are static — no instance required.
/// Direct C++ port of Python app/core/secops_engine.py.
class HeuristicsEngine {
public:
    HeuristicsEngine() = delete;

    /// Evaluate MITRE ATT&CK techniques for a given process/network event.
    /// @param processName  The process executable name (e.g., "powershell.exe")
    /// @param proto        Protocol string (e.g., "TCP", "DNS", "HTTPS")
    /// @param dstPort      Destination port number
    /// @return             List of MITRE technique IDs (may be empty for benign traffic)
    static QStringList evaluate(const QString& processName,
                                const QString& proto,
                                uint16_t       dstPort);

    /// Compute severity from threat intel scores and MITRE tags.
    static Severity computeSeverity(int                abuseScore,
                                    int                vtMalicious,
                                    const QStringList& mitreTags,
                                    bool               isLolbinProcess);

    /// Returns true if the process name is in the LOLBIN set.
    static bool isLolbin(const QString& processName);

    /// Human-readable name for a MITRE technique ID.
    static QString techniqueDescription(const QString& techniqueId);
};

} // namespace SS
