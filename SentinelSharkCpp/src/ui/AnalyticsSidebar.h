#pragma once
#include <QWidget>
#include <QLabel>
#include <QProgressBar>
#include "../core/PacketRecord.h"
#include "../core/RingBuffer.h"

namespace SS {

/// Right sidebar: Analytics panel (w=260px)
/// Matches App.tsx "Right Sidebar: Analytics"
/// Shows: Incident Severity distribution, Top Suspicious Processes,
///         MITRE ATT&CK Coverage bars, Session Stats grid.
class AnalyticsSidebar : public QWidget {
    Q_OBJECT
public:
    explicit AnalyticsSidebar(QWidget* parent = nullptr);

    /// Recompute all analytics from the current ring buffer contents.
    /// Called every 5 seconds from a QTimer in MainWindow.
    void refresh(const RingBuffer<PacketRecord, 3000>& buf, uint64_t totalReceived);

private:
    void setupUi();

    struct SevBar { QLabel* countLabel; QProgressBar* bar; QLabel* nameLabel; };
    struct ProcRow { QLabel* rankLabel; QLabel* nameLabel; QProgressBar* bar; QLabel* countLabel; };
    struct MitreRow { QLabel* tagLabel; QLabel* nameLabel; QProgressBar* bar; QLabel* countLabel; };

    // Severity distribution
    SevBar sevBars_[4]; // Critical, High, Medium, Safe
    QWidget* stackedBar_ = nullptr;

    // Top processes
    static constexpr int kTopN = 6;
    ProcRow procRows_[kTopN];

    // MITRE coverage
    static constexpr int kMitreN = 6;
    MitreRow mitreRows_[kMitreN];

    // Session stats
    QLabel* statLabels_[6] = {};
    static const char* kStatNames[6];
};

} // namespace SS
