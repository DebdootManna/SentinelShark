#include "AppConfig.h"
#include <QStandardPaths>
#include <QFileInfo>
#include <QProcess>
#include <memory>

namespace SS {

AppConfig& AppConfig::instance() {
    static AppConfig inst;
    return inst;
}

AppConfig::AppConfig() {
    settings_ = std::make_unique<QSettings>(
        QSettings::IniFormat,
        QSettings::UserScope,
        QStringLiteral("SentinelShark"),
        QStringLiteral("SentinelShark")
    );
    load();
}

void AppConfig::load() {
    abuseipdbApiKey        = settings_->value("api/abuseipdb",   QString{}).toString();
    virustotalApiKey       = settings_->value("api/virustotal",  QString{}).toString();
    ipinfoApiKey           = settings_->value("api/ipinfo",      QString{}).toString();
    shodanApiKey           = settings_->value("api/shodan",      QString{}).toString();
    tsharkPath             = settings_->value("capture/tshark_path",        QString{}).toString();
    defaultInterface       = settings_->value("capture/interface",          QStringLiteral("auto")).toString();
    bpfFilter              = settings_->value("capture/bpf_filter",         QString{}).toString();
    mockMode               = settings_->value("behavior/mock_mode",         false).toBool();
    autoScroll             = settings_->value("behavior/auto_scroll",       true).toBool();
    cacheTtlHours          = settings_->value("behavior/cache_ttl_hours",   24).toInt();
    maxRequestsPerMinute   = settings_->value("behavior/max_req_per_min",   30).toInt();
}

void AppConfig::save() {
    settings_->setValue("api/abuseipdb",          abuseipdbApiKey);
    settings_->setValue("api/virustotal",          virustotalApiKey);
    settings_->setValue("api/ipinfo",              ipinfoApiKey);
    settings_->setValue("api/shodan",              shodanApiKey);
    settings_->setValue("capture/tshark_path",     tsharkPath);
    settings_->setValue("capture/interface",       defaultInterface);
    settings_->setValue("capture/bpf_filter",      bpfFilter);
    settings_->setValue("behavior/mock_mode",      mockMode);
    settings_->setValue("behavior/auto_scroll",    autoScroll);
    settings_->setValue("behavior/cache_ttl_hours",cacheTtlHours);
    settings_->setValue("behavior/max_req_per_min",maxRequestsPerMinute);
    settings_->sync();
    emit settingsChanged();
}

QString AppConfig::findTshark() const {
    // 1. User-configured path
    if (!tsharkPath.isEmpty() && QFileInfo::exists(tsharkPath))
        return tsharkPath;

    // 2. System PATH
    const QString fromPath = QStandardPaths::findExecutable(QStringLiteral("tshark"));
    if (!fromPath.isEmpty())
        return fromPath;

    // 3. Common Windows installation paths
    static const QStringList kCommonPaths = {
        R"(C:\Program Files\Wireshark\tshark.exe)",
        R"(C:\Program Files (x86)\Wireshark\tshark.exe)",
        R"(C:\Tools\Wireshark\tshark.exe)",
    };
    for (const auto& p : kCommonPaths) {
        if (QFileInfo::exists(p))
            return p;
    }
    return {};
}

bool AppConfig::isTsharkAvailable() const {
    return !findTshark().isEmpty();
}

} // namespace SS
