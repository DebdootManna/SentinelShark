#include "ThreatIntelWorker.h"
#include "../config/AppConfig.h"
#include <QNetworkRequest>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QHostAddress>
#include <QMutexLocker>
#include <QUrl>

namespace SS {

ThreatIntelWorker::ThreatIntelWorker(QObject* parent)
    : QObject(parent)
    , nam_(new QNetworkAccessManager(this))
    , cache_(200)       // max 200 cached results
{
    const auto& cfg = AppConfig::instance();
    abuseipdbKey_  = cfg.abuseipdbApiKey;
    virustotalKey_ = cfg.virustotalApiKey;
    ipinfoKey_     = cfg.ipinfoApiKey;
    shodanKey_     = cfg.shodanApiKey;
}

void ThreatIntelWorker::setApiKeys(const QString& abuseipdb, const QString& virustotal,
                                    const QString& ipinfo,    const QString& shodan)
{
    abuseipdbKey_  = abuseipdb;
    virustotalKey_ = virustotal;
    ipinfoKey_     = ipinfo;
    shodanKey_     = shodan;
}

bool ThreatIntelWorker::isPublicIp(const QString& ip) const {
    QHostAddress addr(ip);
    if (addr.isNull() || addr.isLoopback()) return false;
    // RFC1918 + link-local
    const auto protocol = addr.protocol();
    if (protocol == QAbstractSocket::IPv4Protocol) {
        const quint32 v = addr.toIPv4Address();
        const auto inRange = [&](quint32 a, quint32 b) { return v >= a && v <= b; };
        if (inRange(0xC0A80000, 0xC0A8FFFF)) return false; // 192.168.x.x
        if (inRange(0xAC100000, 0xAC1FFFFF)) return false; // 172.16-31.x.x
        if (inRange(0x0A000000, 0x0AFFFFFF)) return false; // 10.x.x.x
        if (inRange(0xA9FE0000, 0xA9FEFFFF)) return false; // 169.254.x.x
        if (inRange(0x7F000000, 0x7FFFFFFF)) return false; // 127.x.x.x
    }
    return true;
}

void ThreatIntelWorker::lookup(const QString& ip) {
    // Check cache
    {
        QMutexLocker lock(&cacheMutex_);
        if (auto* cached = cache_.object(ip)) {
            emit lookupComplete(*cached);
            return;
        }
    }

    if (!isPublicIp(ip)) {
        ThreatIntelResult r;
        r.ip       = ip;
        r.isPublic = false;
        r.country  = "LOCAL";
        r.enriched = true;
        emit lookupComplete(r);
        return;
    }

    // Already in-flight?
    if (pending_.contains(ip)) return;

    PendingResult pr;
    pr.result.ip = ip;
    pr.pendingCount = 4;
    // Disable enriched until all 4 done
    pr.result.enriched = false;
    pending_[ip] = pr;

    // ── AbuseIPDB ─────────────────────────────────────────────────────────
    if (!abuseipdbKey_.isEmpty()) {
        QNetworkRequest req(QUrl(QStringLiteral("https://api.abuseipdb.com/api/v2/check?ipAddress=%1&maxAgeInDays=90").arg(ip)));
        req.setRawHeader("Key", abuseipdbKey_.toLatin1());
        req.setRawHeader("Accept", "application/json");
        auto* reply = nam_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, ip]() {
            onAbuseIpdbReply(reply, ip);
        });
    } else {
        pending_[ip].pendingCount--;
        maybeEmit(ip);
    }

    // ── VirusTotal ────────────────────────────────────────────────────────
    if (!virustotalKey_.isEmpty()) {
        QNetworkRequest req(QUrl(QStringLiteral("https://www.virustotal.com/api/v3/ip_addresses/%1").arg(ip)));
        req.setRawHeader("x-apikey", virustotalKey_.toLatin1());
        auto* reply = nam_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, ip]() {
            onVirusTotalReply(reply, ip);
        });
    } else {
        pending_[ip].pendingCount--;
        maybeEmit(ip);
    }

    // ── IPinfo ────────────────────────────────────────────────────────────
    {
        QString url = QStringLiteral("https://ipinfo.io/%1/json").arg(ip);
        if (!ipinfoKey_.isEmpty()) url += "?token=" + ipinfoKey_;
        QNetworkRequest req((QUrl(url)));
        auto* reply = nam_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, ip]() {
            onIpInfoReply(reply, ip);
        });
    }

    // ── Shodan InternetDB (free, no key needed) ───────────────────────────
    {
        QNetworkRequest req(QUrl(QStringLiteral("https://internetdb.shodan.io/%1").arg(ip)));
        auto* reply = nam_->get(req);
        connect(reply, &QNetworkReply::finished, this, [this, reply, ip]() {
            onShodanReply(reply, ip);
        });
    }
}

void ThreatIntelWorker::onAbuseIpdbReply(QNetworkReply* reply, const QString& ip) {
    reply->deleteLater();
    if (pending_.contains(ip)) {
        if (reply->error() == QNetworkReply::NoError) {
            const auto doc  = QJsonDocument::fromJson(reply->readAll());
            const auto data = doc.object().value("data").toObject();
            pending_[ip].result.abuseScore   = data.value("abuseConfidenceScore").toInt();
            pending_[ip].result.reportsCount = data.value("totalReports").toInt();
            pending_[ip].result.country      = data.value("countryCode").toString();
            pending_[ip].result.domain       = data.value("domain").toString();
        }
        pending_[ip].pendingCount--;
        maybeEmit(ip);
    }
}

void ThreatIntelWorker::onVirusTotalReply(QNetworkReply* reply, const QString& ip) {
    reply->deleteLater();
    if (pending_.contains(ip)) {
        if (reply->error() == QNetworkReply::NoError) {
            const auto doc  = QJsonDocument::fromJson(reply->readAll());
            const auto stats = doc.object()
                                .value("data").toObject()
                                .value("attributes").toObject()
                                .value("last_analysis_stats").toObject();
            pending_[ip].result.vtMalicious  = stats.value("malicious").toInt();
            pending_[ip].result.vtSuspicious = stats.value("suspicious").toInt();
            pending_[ip].result.vtHarmless   = stats.value("harmless").toInt();
        }
        pending_[ip].pendingCount--;
        maybeEmit(ip);
    }
}

void ThreatIntelWorker::onIpInfoReply(QNetworkReply* reply, const QString& ip) {
    reply->deleteLater();
    if (pending_.contains(ip)) {
        if (reply->error() == QNetworkReply::NoError) {
            const auto doc  = QJsonDocument::fromJson(reply->readAll());
            const auto obj  = doc.object();
            pending_[ip].result.ipinfoCity    = obj.value("city").toString();
            pending_[ip].result.ipinfoRegion  = obj.value("region").toString();
            pending_[ip].result.ipinfoOrg     = obj.value("org").toString();
            pending_[ip].result.ipinfoTimezone= obj.value("timezone").toString();
            pending_[ip].result.ipinfoLoc     = obj.value("loc").toString();
            // Fill country fallback
            if (pending_[ip].result.country.isEmpty())
                pending_[ip].result.country = obj.value("country").toString();
            if (pending_[ip].result.isp.isEmpty())
                pending_[ip].result.isp = obj.value("org").toString();
        }
        pending_[ip].pendingCount--;
        maybeEmit(ip);
    }
}

void ThreatIntelWorker::onShodanReply(QNetworkReply* reply, const QString& ip) {
    reply->deleteLater();
    if (pending_.contains(ip)) {
        if (reply->error() == QNetworkReply::NoError) {
            const auto doc = QJsonDocument::fromJson(reply->readAll());
            const auto obj = doc.object();
            for (const auto& v : obj.value("tags").toArray())
                pending_[ip].result.shodanTags << v.toString();
            for (const auto& v : obj.value("vulns").toArray())
                pending_[ip].result.shodanVulns << v.toString();
            for (const auto& v : obj.value("ports").toArray())
                pending_[ip].result.shodanPorts << v.toInt();
            const auto hostnames = obj.value("hostnames").toArray();
            if (!hostnames.isEmpty() && pending_[ip].result.domain.isEmpty())
                pending_[ip].result.domain = hostnames.first().toString();
        }
        pending_[ip].pendingCount--;
        maybeEmit(ip);
    }
}

void ThreatIntelWorker::maybeEmit(const QString& ip) {
    if (!pending_.contains(ip)) return;
    if (pending_[ip].pendingCount > 0) return;

    ThreatIntelResult result = pending_[ip].result;
    result.enriched = true;
    pending_.remove(ip);

    // Cache the result
    {
        QMutexLocker lock(&cacheMutex_);
        cache_.insert(ip, new ThreatIntelResult(result));
    }

    emit lookupComplete(result);
}

void ThreatIntelWorker::clearCache() {
    QMutexLocker lock(&cacheMutex_);
    cache_.clear();
}

} // namespace SS
