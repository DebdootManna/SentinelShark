#pragma once
#include <QString>
#include <QStringList>
#include <QList>
#include <QJsonObject>
#include "../core/PacketRecord.h"

namespace SS {

/// Aggregated threat intelligence result from all 4 APIs.
/// Matches Python ThreatIntelClient.lookup_ip() output schema.
struct ThreatIntelResult {
    QString     ip;
    int         abuseScore      = 0;
    int         vtMalicious     = 0;
    int         vtSuspicious    = 0;
    int         vtHarmless      = 0;
    int         reportsCount    = 0;
    QString     country;
    QString     domain;
    QString     isp;
    QStringList shodanTags;
    QStringList shodanVulns;
    QList<int>  shodanPorts;
    QString     ipinfoCity;
    QString     ipinfoRegion;
    QString     ipinfoOrg;
    QString     ipinfoTimezone;
    QString     ipinfoLoc;       // "lat,lon"
    bool        isPublic        = true;
    bool        has429          = false;  // rate limit hit
    bool        enriched        = false;  // true once async lookup completes
};

/// Process metadata (from Windows APIs / cache).
struct ProcessInfo {
    uint32_t pid     = 0;
    uint32_t ppid    = 0;
    QString  name;
    QString  cmdline;
    QString  username;
    QString  exePath;
    QString  sha256;   // empty until explicitly requested
};

/// Generates Google SecOps UDM-format JSON from packet + process + threat intel data.
class UdmNormalizer {
public:
    UdmNormalizer() = delete;

    /// Produce a UDM-compliant QJsonObject.
    static QJsonObject normalize(const PacketRecord&    pkt,
                                 const ProcessInfo&     proc,
                                 const ThreatIntelResult& intel);

    /// Pretty-print a QJsonObject to a formatted QString.
    static QString toFormattedJson(const QJsonObject& udm);

    /// Quick single-line JSON for clipboard copy (matches App.tsx "Copy UDM JSON" button).
    static QString toCompactJson(const PacketRecord& pkt,
                                 const ProcessInfo&  proc,
                                 const ThreatIntelResult& intel);
};

} // namespace SS
