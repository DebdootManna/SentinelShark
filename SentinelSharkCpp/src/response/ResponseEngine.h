#pragma once
#include <QThread>
#include <QString>
#include <cstdint>

namespace SS {

/// Windows-native Active Incident Response Engine.
/// All operations run in a background QThread to avoid blocking the GUI.
class ResponseWorkerThread : public QThread {
    Q_OBJECT
public:
    enum class Action { KillProcess, BlockIp, QuarantineFile };

    static ResponseWorkerThread* killProcess(uint32_t pid, const QString& processName,
                                              QObject* parent = nullptr);
    static ResponseWorkerThread* blockIp(const QString& ip, QObject* parent = nullptr);
    static ResponseWorkerThread* quarantine(uint32_t pid, QObject* parent = nullptr);

signals:
    void actionCompleted(bool success, const QString& message);

protected:
    void run() override;

private:
    ResponseWorkerThread(Action action, uint32_t pid, const QString& strArg,
                          QObject* parent);

    Action   action_;
    uint32_t pid_    = 0;
    QString  strArg_;

    // ── Static worker functions (called from run()) ─────────────────────────
    static std::pair<bool, QString> doKillProcess(uint32_t pid, const QString& name);
    static std::pair<bool, QString> doBlockIp(const QString& ip);
    static std::pair<bool, QString> doQuarantine(uint32_t pid);
};

} // namespace SS
