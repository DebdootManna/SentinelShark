#pragma once
#include <QObject>
#include <QString>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QCache>
#include <QMutex>
#include "../udm/UdmNormalizer.h"

namespace SS {

/// Asynchronous threat intelligence lookup using QNetworkAccessManager.
/// Queries AbuseIPDB, VirusTotal, IPinfo, and Shodan InternetDB concurrently.
/// Results are cached in a QCache<200> with configurable TTL.
class ThreatIntelWorker : public QObject {
    Q_OBJECT
public:
    explicit ThreatIntelWorker(QObject* parent = nullptr);

    /// Start an async lookup for ip. Emits lookupComplete() when done.
    /// If the IP is private/loopback, immediately emits with is_public=false.
    /// If cached, immediately emits with cached result.
    void lookup(const QString& ip);

    /// Clear the result cache.
    void clearCache();

    /// Set API keys (read from AppConfig)
    void setApiKeys(const QString& abuseipdb, const QString& virustotal,
                    const QString& ipinfo, const QString& shodan);

signals:
    void lookupComplete(const ThreatIntelResult& result);
    void lookupError(const QString& ip, const QString& error);

private slots:
    void onAbuseIpdbReply(QNetworkReply* reply, const QString& ip);
    void onVirusTotalReply(QNetworkReply* reply, const QString& ip);
    void onIpInfoReply(QNetworkReply* reply, const QString& ip);
    void onShodanReply(QNetworkReply* reply, const QString& ip);

private:
    struct PendingResult {
        ThreatIntelResult result;
        int               pendingCount = 4; // decrements as each API responds
    };

    bool isPublicIp(const QString& ip) const;
    void maybeEmit(const QString& ip);

    QNetworkAccessManager*           nam_;
    QString                          abuseipdbKey_;
    QString                          virustotalKey_;
    QString                          ipinfoKey_;
    QString                          shodanKey_;

    QHash<QString, PendingResult>    pending_;  // in-flight lookups
    QCache<QString, ThreatIntelResult> cache_;  // key=ip, up to 200 entries
    QMutex                           cacheMutex_;
};

} // namespace SS
