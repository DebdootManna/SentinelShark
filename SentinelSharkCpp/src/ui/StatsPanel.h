#pragma once
#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include <QFrame>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QMap>
#include <QVector>
#include "../core/PacketRecord.h"

namespace SS {

/// Sleek metric card displaying a title and value matching the Python EDR UI.
class StatCard : public QFrame {
    Q_OBJECT
public:
    StatCard(const QString& title, const QString& initialValue, const QString& accentColor, QWidget* parent = nullptr);
    void setValue(const QString& val);

private:
    QLabel* titleLabel_ = nullptr;
    QLabel* valueLabel_ = nullptr;
    QString accentColor_;
};

/// Collapsible card container with title, toggle button (−/+), and inner layout.
class CollapsibleCard : public QFrame {
    Q_OBJECT
public:
    CollapsibleCard(const QString& title, int expandedMinHeight = 140, QWidget* parent = nullptr);
    QVBoxLayout* contentLayout() { return contentLayout_; }
    void setTitle(const QString& title);

public slots:
    void toggleCollapse();

private:
    bool isCollapsed_ = false;
    int expandedMinHeight_ = 140;
    QLabel* titleLabel_ = nullptr;
    QPushButton* toggleBtn_ = nullptr;
    QWidget* contentWidget_ = nullptr;
    QVBoxLayout* contentLayout_ = nullptr;
};

/// High-performance NIDS Statistics Panel matching the Python workstation.
class StatsPanel : public QWidget {
    Q_OBJECT
public:
    explicit StatsPanel(QWidget* parent = nullptr);

    /// Live batch update from packet queue
    void updatePacketsBatch(const QVector<PacketRecord>& batch);

    /// Update selected packet card
    void setSelectedPacket(const PacketRecord& pkt);

    /// Reset all counters and clear panels
    void resetStats();

    /// Update threat queue counters
    void updateQueueStatus(int pending, int inProgress);

    /// Refresh API keys display status
    void refreshApiStatus();

private:
    void setupUi();
    void refreshProtocolBars();
    void refreshEdrSections();

    uint64_t totalPackets_ = 0;
    uint64_t totalBytes_ = 0;
    uint64_t safeCount_ = 0;
    uint64_t criticalCount_ = 0;

    QMap<QString, uint64_t> protocols_;
    QMap<QString, uint64_t> processes_;
    QMap<QString, uint64_t> mitreTechniques_;

    // Metric Cards (2x2 grid)
    StatCard* cardPackets_ = nullptr;
    StatCard* cardBytes_ = nullptr;
    StatCard* cardSafe_ = nullptr;
    StatCard* cardThreats_ = nullptr;

    // MITRE Card
    CollapsibleCard* mitreCard_ = nullptr;
    QLabel* mitreEmptyLabel_ = nullptr;
    struct MitreRowWidget {
        QWidget* container = nullptr;
        QLabel* tag = nullptr;
        QLabel* name = nullptr;
        QProgressBar* bar = nullptr;
        QLabel* count = nullptr;
    };
    QVector<MitreRowWidget> mitreRows_;

    // Top Processes Card
    CollapsibleCard* procCard_ = nullptr;
    QLabel* procEmptyLabel_ = nullptr;
    struct ProcRowWidget {
        QWidget* container = nullptr;
        QLabel* rank = nullptr;
        QLabel* name = nullptr;
        QProgressBar* bar = nullptr;
        QLabel* count = nullptr;
    };
    QVector<ProcRowWidget> procRows_;

    // Protocol Breakdown Card
    CollapsibleCard* protoCard_ = nullptr;
    QLabel* protoEmptyLabel_ = nullptr;
    struct ProtoRowWidget {
        QWidget* container = nullptr;
        QLabel* label = nullptr;
        QProgressBar* bar = nullptr;
        QLabel* count = nullptr;
    };
    QMap<QString, ProtoRowWidget> protoRows_;

    // Threat Intel Queue Card
    CollapsibleCard* queueCard_ = nullptr;
    QLabel* vtStatusLabel_ = nullptr;
    QLabel* abuseStatusLabel_ = nullptr;
    QLabel* shodanStatusLabel_ = nullptr;
    QLabel* ipinfoStatusLabel_ = nullptr;
    QLabel* queueCounterLabel_ = nullptr;
    QProgressBar* queueBar_ = nullptr;

    // Selected Packet Card
    CollapsibleCard* pktCard_ = nullptr;
    QLabel* pktEmptyLabel_ = nullptr;
    struct PktDetailRow {
        QWidget* container = nullptr;
        QLabel* val = nullptr;
    };
    QMap<QString, PktDetailRow> pktDetailWidgets_;
};

} // namespace SS
