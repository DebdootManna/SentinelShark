#pragma once
#include <QObject>
#include <QString>
#include <QSettings>

namespace SS {

/// Application configuration singleton.
/// Settings stored at: %APPDATA%\SentinelShark\SentinelShark.ini
class AppConfig : public QObject {
    Q_OBJECT
public:
    static AppConfig& instance();

    // API keys
    QString abuseipdbApiKey;
    QString virustotalApiKey;
    QString ipinfoApiKey;
    QString shodanApiKey;

    // Capture settings
    QString tsharkPath;            ///< Override path; empty = auto-detect
    QString defaultInterface;      ///< e.g. "1" or "\\Device\\NPF_{GUID}"
    QString bpfFilter;

    // Behavior
    bool    mockMode              = false;
    bool    autoScroll            = true;
    int     cacheTtlHours         = 24;
    int     maxRequestsPerMinute  = 30;

    void    load();
    void    save();

    /// Locate tshark.exe. Returns empty string if not found.
    QString findTshark() const;
    bool    isTsharkAvailable() const;

signals:
    void settingsChanged();

private:
    AppConfig();
    AppConfig(const AppConfig&)            = delete;
    AppConfig& operator=(const AppConfig&) = delete;

    std::unique_ptr<QSettings> settings_;
};

} // namespace SS
