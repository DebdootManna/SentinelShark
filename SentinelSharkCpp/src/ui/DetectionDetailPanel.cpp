#include "DetectionDetailPanel.h"
#include "../udm/UdmNormalizer.h"
#include "../model/PacketTableModel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFrame>
#include <QScrollArea>
#include <QApplication>
#include <QClipboard>

namespace SS {

DetectionDetailPanel::DetectionDetailPanel(QWidget* parent)
    : QWidget(parent)
{
    setupUi();
}

void DetectionDetailPanel::setupUi() {
    setObjectName("DetectionDetailPanel");
    setStyleSheet("QWidget#DetectionDetailPanel { background: #0D1117; }");

    auto* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // Panel header
    auto* header = new QFrame(this);
    header->setFixedHeight(32);
    header->setStyleSheet("background: #161B22; border-bottom: 1px solid #30363D;");
    auto* headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(14, 0, 14, 0);
    auto* headerLabel = new QLabel("📋  DETECTION DETAIL", header);
    headerLabel->setStyleSheet("color: #8B949E; font-size: 11px; font-weight: 700; letter-spacing: 0.08em;");
    headerLayout->addWidget(headerLabel);

    // Scroll area
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background: #0D1117; border: none;");

    auto* content = new QWidget(scroll);
    content->setStyleSheet("background: #0D1117;");
    auto* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(12, 12, 12, 12);
    contentLayout->setSpacing(12);

    // Alert banner
    alertBanner_ = new QFrame(content);
    alertBanner_->setStyleSheet("QFrame { background: #3D1A1A; border: 1px solid #5A1E1E; border-radius: 6px; }");
    auto* bannerLayout = new QVBoxLayout(alertBanner_);
    bannerLayout->setContentsMargins(14, 10, 14, 10);
    bannerLayout->setSpacing(6);

    auto* bannerTop = new QHBoxLayout();
    auto* bannerLeft = new QVBoxLayout();
    alertTitleLabel_ = new QLabel("⚠ CRITICAL THREAT DETECTED", alertBanner_);
    alertTitleLabel_->setStyleSheet("color:#F85149; font-size:12px; font-weight:700;");
    alertInfoLabel_  = new QLabel("—", alertBanner_);
    alertInfoLabel_->setStyleSheet("color:#E6EDF3; font-size:11px;");
    alertInfoLabel_->setWordWrap(true);
    bannerLeft->addWidget(alertTitleLabel_);
    bannerLeft->addWidget(alertInfoLabel_);
    alertMitreLabel_ = new QLabel("—", alertBanner_);
    alertMitreLabel_->setStyleSheet("background:#1F3A5F; color:#58A6FF; border:1px solid #2A4A7A; border-radius:3px; padding:2px 6px; font-size:10px; font-weight:700; font-family:'JetBrains Mono',Consolas;");
    alertMitreLabel_->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    bannerTop->addLayout(bannerLeft);
    bannerTop->addStretch();
    bannerTop->addWidget(alertMitreLabel_);

    auto* bannerBottom = new QHBoxLayout();
    bannerBottom->setSpacing(16);
    auto addMetaItem = [&](const QString& lbl, QLabel*& val) {
        auto* col = new QVBoxLayout();
        auto* lblW = new QLabel(lbl, alertBanner_);
        lblW->setStyleSheet("color:#484F58; font-size:9px; text-transform:uppercase; letter-spacing:0.06em;");
        val = new QLabel("—", alertBanner_);
        val->setStyleSheet("color:#E6EDF3; font-size:10px; font-family:'JetBrains Mono',Consolas;");
        col->addWidget(lblW);
        col->addWidget(val);
        bannerBottom->addLayout(col);
    };
    addMetaItem("TIME",  alertTimeLabel_);
    addMetaItem("SRC",   alertSrcLabel_);
    addMetaItem("DST",   alertDstLabel_);
    addMetaItem("PROTO", alertProtoLabel_);
    addMetaItem("PORT",  alertPortLabel_);

    auto* sep = new QFrame(alertBanner_);
    sep->setFrameShape(QFrame::HLine);
    sep->setStyleSheet("border: none; border-top: 1px solid #5A1E1E;");

    bannerLayout->addLayout(bannerTop);
    bannerLayout->addWidget(sep);
    bannerLayout->addLayout(bannerBottom);
    contentLayout->addWidget(alertBanner_);

    // UDM JSON
    auto* udmHdr = new QLabel("UDM EVENT JSON", content);
    udmHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    contentLayout->addWidget(udmHdr);

    udmJsonEdit_ = new QTextEdit(content);
    udmJsonEdit_->setReadOnly(true);
    udmJsonEdit_->setMaximumHeight(200);
    udmJsonEdit_->setStyleSheet("QTextEdit { background:#080C11; color:#8B949E; border:1px solid #30363D; border-radius:4px; font-family:'JetBrains Mono',Consolas; font-size:9px; padding:10px; }");
    contentLayout->addWidget(udmJsonEdit_);

    // Related alerts
    auto* relatedHdr = new QLabel("RELATED ALERTS (LAST 24H)", content);
    relatedHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    contentLayout->addWidget(relatedHdr);

    relatedAlertsWidget_ = new QWidget(content);
    auto* relLayout = new QVBoxLayout(relatedAlertsWidget_);
    relLayout->setContentsMargins(0, 0, 0, 0);
    relLayout->setSpacing(4);
    const struct { const char* time; const char* desc; const char* sev; } kRelated[] = {
        {"08:52", "Same process spawned suspicious child",      "HIGH"},
        {"08:41", "Persistence via scheduled task added",       "CRITICAL"},
        {"07:13", "First connection to this external IP",       "MEDIUM"},
    };
    for (const auto& a : kRelated) {
        auto* row = new QFrame(relatedAlertsWidget_);
        row->setStyleSheet("QFrame { background:#21262D; border:1px solid #30363D; border-radius:3px; }");
        auto* rLayout = new QHBoxLayout(row);
        rLayout->setContentsMargins(8, 5, 8, 5);
        auto* timeL = new QLabel(a.time, row);
        timeL->setStyleSheet("color:#484F58; font-size:9px; font-family:'JetBrains Mono',Consolas;");
        timeL->setFixedWidth(32);
        auto* descL = new QLabel(a.desc, row);
        descL->setStyleSheet("color:#8B949E; font-size:10px;");
        auto* sevL = new QLabel(a.sev, row);
        const QColor sevBg = QString(a.sev) == "CRITICAL" ? QColor("#3D1A1A") :
                              QString(a.sev) == "HIGH"     ? QColor("#2D1F1A") :
                                                             QColor("#3D2E0A");
        const QColor sevFg = QString(a.sev) == "CRITICAL" ? QColor("#F85149") :
                              QString(a.sev) == "HIGH"     ? QColor("#FF7B72") :
                                                             QColor("#D29922");
        sevL->setStyleSheet(QStringLiteral("background:%1; color:%2; border-radius:3px; padding:2px 7px; font-size:10px; font-weight:700;")
                                .arg(sevBg.name(), sevFg.name()));
        rLayout->addWidget(timeL);
        rLayout->addWidget(descL, 1);
        rLayout->addWidget(sevL);
        relLayout->addWidget(row);
    }
    contentLayout->addWidget(relatedAlertsWidget_);
    contentLayout->addStretch();

    scroll->setWidget(content);

    // Action bar
    auto* actionBar = new QFrame(this);
    actionBar->setFixedHeight(50);
    actionBar->setStyleSheet("QFrame { background:#161B22; border-top:1px solid #30363D; }");
    auto* actionLayout = new QHBoxLayout(actionBar);
    actionLayout->setContentsMargins(14, 0, 14, 0);
    actionLayout->setSpacing(8);

    auto* irLabel = new QLabel("IR ACTIONS", actionBar);
    irLabel->setStyleSheet("color:#484F58; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    actionLayout->addWidget(irLabel);
    actionLayout->addSpacing(4);

    killBtn_ = new QPushButton("⛔  Kill Process", actionBar);
    killBtn_->setStyleSheet("QPushButton { background:#3D1A1A; color:#F85149; border:1px solid rgba(248,81,73,0.38); border-radius:4px; font-size:11px; font-weight:700; padding:6px 14px; } QPushButton:hover { background:#5A1E1E; }");
    killBtn_->setCursor(Qt::PointingHandCursor);

    blockBtn_ = new QPushButton("🛡  Block Remote IP", actionBar);
    blockBtn_->setStyleSheet("QPushButton { background:#3D2E0A; color:#D29922; border:1px solid rgba(210,153,34,0.38); border-radius:4px; font-size:11px; font-weight:700; padding:6px 14px; } QPushButton:hover { background:#5A4010; }");
    blockBtn_->setCursor(Qt::PointingHandCursor);

    quarantineBtn_ = new QPushButton("📦  Quarantine Binary", actionBar);
    quarantineBtn_->setStyleSheet("QPushButton { background:transparent; color:#E6EDF3; border:1px solid #30363D; border-radius:4px; font-size:11px; font-weight:600; padding:6px 14px; } QPushButton:hover { background:#161B22; }");
    quarantineBtn_->setCursor(Qt::PointingHandCursor);

    copyUdmBtn_ = new QPushButton("📋  Copy UDM JSON", actionBar);
    copyUdmBtn_->setStyleSheet("QPushButton { background:transparent; color:#8B949E; border:none; font-size:11px; font-weight:500; padding:6px 14px; } QPushButton:hover { color:#E6EDF3; }");
    copyUdmBtn_->setCursor(Qt::PointingHandCursor);

    caseIdLabel_ = new QLabel("Case ID  INC-2024-0001", actionBar);
    caseIdLabel_->setStyleSheet("color:#58A6FF; font-size:10px; font-family:'JetBrains Mono',Consolas;");

    actionLayout->addWidget(killBtn_);
    actionLayout->addWidget(blockBtn_);
    actionLayout->addWidget(quarantineBtn_);
    actionLayout->addWidget(copyUdmBtn_);
    actionLayout->addStretch();
    actionLayout->addWidget(caseIdLabel_);

    outerLayout->addWidget(header);
    outerLayout->addWidget(scroll, 1);
    outerLayout->addWidget(actionBar);

    connect(killBtn_,       &QPushButton::clicked, this, &DetectionDetailPanel::onKillClicked);
    connect(blockBtn_,      &QPushButton::clicked, this, &DetectionDetailPanel::onBlockClicked);
    connect(quarantineBtn_, &QPushButton::clicked, this, &DetectionDetailPanel::onQuarantineClicked);
    connect(copyUdmBtn_,    &QPushButton::clicked, this, &DetectionDetailPanel::onCopyUdmClicked);
}

void DetectionDetailPanel::populate(const PacketRecord& pkt,
                                     const ProcessInfo&  proc,
                                     const ThreatIntelResult& intel)
{
    currentPid_     = pkt.pid;
    currentProcess_ = pkt.processStr();
    currentDstIp_   = pkt.dstStr();

    // Alert banner
    const auto sc = severityColors(pkt.severity);
    alertBanner_->setStyleSheet(QStringLiteral(
        "QFrame { background:%1; border:1px solid %2; border-radius:6px; }")
            .arg(sc.bg.name(), sc.border.name()));

    const QString title = pkt.severity == Severity::Critical ? "⚠ CRITICAL THREAT DETECTED" :
                           pkt.severity == Severity::High     ? "⚡ HIGH SEVERITY EVENT"      :
                                                                "ℹ MEDIUM SEVERITY EVENT";
    alertTitleLabel_->setText(title);
    alertTitleLabel_->setStyleSheet(QStringLiteral("color:%1; font-size:12px; font-weight:700;")
                                        .arg(sc.fg.name()));
    alertInfoLabel_->setText(pkt.infoStr());
    alertMitreLabel_->setText(pkt.mitreStr().isEmpty() ? "—" : pkt.mitreStr());
    alertTimeLabel_->setText(pkt.timeStr());
    alertSrcLabel_->setText(pkt.srcStr());
    alertDstLabel_->setText(pkt.dstStr());
    alertProtoLabel_->setText(pkt.protocolStr());
    alertPortLabel_->setText(QString::number(pkt.dst_port));

    // UDM JSON
    const QJsonObject udm  = UdmNormalizer::normalize(pkt, proc, intel);
    currentUdmJson_         = UdmNormalizer::toCompactJson(pkt, proc, intel);
    udmJsonEdit_->setPlainText(UdmNormalizer::toFormattedJson(udm));

    // Case ID (simple counter for now)
    static uint64_t caseNo = 847;
    caseIdLabel_->setText(QStringLiteral("Case ID  INC-2024-%1").arg(++caseNo, 4, 10, QLatin1Char('0')));
}

void DetectionDetailPanel::onKillClicked() {
    emit killProcessRequested(currentPid_, currentProcess_);
}
void DetectionDetailPanel::onBlockClicked() {
    emit blockIpRequested(currentDstIp_);
}
void DetectionDetailPanel::onQuarantineClicked() {
    emit quarantineRequested(currentPid_, currentProcess_);
}
void DetectionDetailPanel::onCopyUdmClicked() {
    QApplication::clipboard()->setText(currentUdmJson_);
    emit udmJsonCopied(currentUdmJson_);
}

} // namespace SS
