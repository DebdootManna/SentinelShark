#pragma once
#include <QWidget>
#include <QLabel>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QScrollArea>
#include "../core/PacketRecord.h"
#include "../udm/UdmNormalizer.h"

namespace SS {

/// Collapsible section widget — matches React <CollapsibleSection>
class CollapsibleSection : public QWidget {
    Q_OBJECT
public:
    CollapsibleSection(const QString& title, const QString& icon,
                       QWidget* parent = nullptr);
    QWidget* body(); ///< Add child widgets to body()

private slots:
    void toggle();

private:
    QPushButton* header_;
    QWidget*     body_;
    bool         open_ = true;
};

/// Left panel: Threat Intel Summary + Host & Process Forensics
/// Matches App.tsx "Bottom-Left: Inspection Panel" (w=380)
class InspectionPanel : public QWidget {
    Q_OBJECT
public:
    explicit InspectionPanel(QWidget* parent = nullptr);

    /// Populate with data for the selected packet.
    void populate(const PacketRecord& pkt,
                  const ProcessInfo&  proc,
                  const ThreatIntelResult& intel);

    /// Update only the threat intel section (called asynchronously after API returns).
    void updateIntel(const ThreatIntelResult& intel);

signals:
    void vtCheckRequested(const QString& sha256);
    void copyRequested(const QString& text);

private:
    void setupUi();
    void applyStyle();

    // ── Threat Intel section ────────────────────────────────────────────────
    QLabel*       intelIpLabel_;
    QLabel*       intelPortLabel_;
    QLabel*       intelSeverityLabel_;
    QLabel*       intelAbuseLabel_;
    QLabel*       intelVtLabel_;
    QLabel*       intelGeoLabel_;
    QLabel*       intelIspLabel_;
    QLabel*       intelTagsLabel_;

    // ── Process Forensics section ───────────────────────────────────────────
    QTextEdit*    cmdlineEdit_;
    QLabel*       exePathLabel_;
    QLabel*       sha256Label_;
    QPushButton*  copyHashBtn_;
    QPushButton*  vtCheckBtn_;
    QLabel*       lineageLabel_;
    QLabel*       userLabel_;
    QLabel*       privilegeLabel_;
    QLabel*       hostnameLabel_;
    QLabel*       osLabel_;
};

} // namespace SS
