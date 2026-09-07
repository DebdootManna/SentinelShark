#include "UdmNormalizer.h"
#include <QJsonArray>
#include <QJsonDocument>
#include <QDateTime>

namespace SS {

QJsonObject UdmNormalizer::normalize(const PacketRecord&     pkt,
                                      const ProcessInfo&      proc,
                                      const ThreatIntelResult& intel)
{
    // ── metadata ─────────────────────────────────────────────────────────────
    QJsonObject metadata;
    metadata["event_timestamp"]     = pkt.timeStr();
    metadata["event_type"]          = "NETWORK_CONNECTION";
    metadata["product_name"]        = "SentinelShark";
    metadata["product_version"]     = "2.0.0";
    metadata["ingestion_timestamp"] = QDateTime::currentDateTimeUtc()
                                          .toString(Qt::ISODate);

    // ── principal (local host / process) ──────────────────────────────────────
    QJsonObject procFile;
    if (!proc.exePath.isEmpty())
        procFile["full_path"] = proc.exePath;
    if (!proc.sha256.isEmpty())
        procFile["sha256"]    = proc.sha256;

    QJsonObject procObj;
    if (proc.pid > 0) procObj["pid"] = static_cast<qint64>(proc.pid);
    if (!procFile.isEmpty()) procObj["file"] = procFile;
    if (!proc.cmdline.isEmpty()) procObj["command_line"] = proc.cmdline;

    QJsonObject user;
    if (!proc.username.isEmpty()) user["userid"] = proc.username;

    QJsonObject principal;
    principal["ip"] = pkt.srcStr();
    if (pkt.src_port > 0) principal["port"] = pkt.src_port;
    if (!procObj.isEmpty()) principal["process"] = procObj;
    if (!user.isEmpty())    principal["user"]    = user;

    // ── target ───────────────────────────────────────────────────────────────
    QJsonObject target;
    target["ip"]   = pkt.dstStr();
    if (pkt.dst_port > 0) target["port"] = pkt.dst_port;
    if (!intel.domain.isEmpty()) target["hostname"] = intel.domain;
    if (!intel.country.isEmpty()) {
        QJsonObject loc;
        loc["country_or_region"] = intel.country;
        if (!intel.ipinfoCity.isEmpty())   loc["city"]         = intel.ipinfoCity;
        if (!intel.ipinfoRegion.isEmpty()) loc["state"]        = intel.ipinfoRegion;
        if (!intel.ipinfoLoc.isEmpty())    loc["name"]         = intel.ipinfoLoc;
        target["location"] = loc;
    }

    // ── network ──────────────────────────────────────────────────────────────
    QJsonObject network;
    network["application_protocol"] = pkt.protocolStr();
    network["sent_bytes"]           = static_cast<qint64>(pkt.length);
    if (pkt.dst_port > 0) network["destination_port"] = pkt.dst_port;
    if (pkt.src_port > 0) network["source_port"]      = pkt.src_port;

    // ── security_result ───────────────────────────────────────────────────────
    QJsonObject secResult;
    secResult["severity"]    = QString(severityStr(pkt.severity));
    secResult["threat_name"] = pkt.mitreStr().isEmpty() ? "UNKNOWN" : pkt.mitreStr();
    secResult["summary"]     = pkt.infoStr();

    // Threat scores sub-object
    if (intel.enriched) {
        QJsonObject scores;
        scores["abuse_score"]    = intel.abuseScore;
        scores["vt_malicious"]   = intel.vtMalicious;
        scores["vt_suspicious"]  = intel.vtSuspicious;
        scores["reports_count"]  = intel.reportsCount;
        secResult["threat_feed_info"] = scores;
    }

    // Shodan tags as labels array
    if (!intel.shodanTags.isEmpty()) {
        QJsonArray labels;
        for (const auto& tag : intel.shodanTags)
            labels.append(QJsonObject{{"key", "shodan_tag"}, {"value", tag}});
        QJsonObject about;
        about["labels"] = labels;
        secResult["about"] = QJsonArray{about};
    }

    // Shodan open ports
    if (!intel.shodanPorts.isEmpty()) {
        QJsonArray ports;
        for (int p : intel.shodanPorts)
            ports.append(p);
        secResult["shodan_open_ports"] = ports;
    }

    // Known vulnerabilities
    if (!intel.shodanVulns.isEmpty()) {
        QJsonArray vulns;
        for (const auto& v : intel.shodanVulns)
            vulns.append(v);
        secResult["vulnerabilities"] = vulns;
    }

    // ── Assemble UDM ─────────────────────────────────────────────────────────
    QJsonObject udm;
    udm["metadata"]        = metadata;
    udm["principal"]       = principal;
    udm["target"]          = target;
    udm["network"]         = network;
    udm["security_result"] = QJsonArray{secResult};

    return udm;
}

QString UdmNormalizer::toFormattedJson(const QJsonObject& udm) {
    return QJsonDocument(udm).toJson(QJsonDocument::Indented);
}

QString UdmNormalizer::toCompactJson(const PacketRecord&     pkt,
                                      const ProcessInfo&      proc,
                                      const ThreatIntelResult& intel)
{
    return QJsonDocument(normalize(pkt, proc, intel)).toJson(QJsonDocument::Compact);
}

} // namespace SS
