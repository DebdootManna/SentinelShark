#pragma once
#include <QWidget>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include "../core/PacketRecord.h"
#include "../udm/UdmNormalizer.h"

namespace SS {

/// Center panel: Detection Detail + Action Bar
/// Matches App.tsx "Bottom-Center: Event detail + Action bar"
class DetectionDetailPanel : public QWidget {
    Q_OBJECT
public:
    explicit DetectionDetailPanel(QWidget* parent = nullptr);

    void populate(const PacketRecord& pkt,
                  const ProcessInfo&  proc,
                  const ThreatIntelResult& intel);

signals:
    void killProcessRequested(uint32_t pid, const QString& processName);
    void blockIpRequested(const QString& ip);
    void quarantineRequested(uint32_t pid, const QString& processName);
    void udmJsonCopied(const QString& json);

private:
    void setupUi();

    // Alert banner
    QWidget* alertBanner_;
    QLabel*  alertTitleLabel_;
    QLabel*  alertInfoLabel_;
    QLabel*  alertMitreLabel_;
    QLabel*  alertTimeLabel_;
    QLabel*  alertSrcLabel_;
    QLabel*  alertDstLabel_;
    QLabel*  alertProtoLabel_;
    QLabel*  alertPortLabel_;

    // UDM JSON viewer
    QTextEdit* udmJsonEdit_;

    // Related alerts list
    QWidget* relatedAlertsWidget_;

    // Action bar buttons
    QPushButton* killBtn_;
    QPushButton* blockBtn_;
    QPushButton* quarantineBtn_;
    QPushButton* copyUdmBtn_;

    // Case ID label
    QLabel* caseIdLabel_;

    // Cached state for action button callbacks
    uint32_t currentPid_ = 0;
    QString  currentProcess_;
    QString  currentDstIp_;
    QString  currentUdmJson_;

private slots:
    void onKillClicked();
    void onBlockClicked();
    void onQuarantineClicked();
    void onCopyUdmClicked();
};

} // namespace SS
