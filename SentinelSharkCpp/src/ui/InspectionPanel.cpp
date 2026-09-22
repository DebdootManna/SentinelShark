#include "InspectionPanel.h"
#include "../model/PacketTableModel.h"
#include "../heuristics/HeuristicsEngine.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QPushButton>
#include <QFrame>
#include <QFont>
#include <QScrollArea>
#include <QDesktopServices>
#include <QUrl>

namespace SS {

// ── CollapsibleSection ────────────────────────────────────────────────────────

CollapsibleSection::CollapsibleSection(const QString& title,
                                        const QString& icon,
                                        QWidget* parent)
    : QWidget(parent)
{
    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->setSpacing(0);

    header_ = new QPushButton(this);
    header_->setFlat(true);
    header_->setCheckable(false);
    header_->setCursor(Qt::PointingHandCursor);
    header_->setStyleSheet(R"(
        QPushButton {
            background: transparent;
            border: none;
            border-bottom: 1px solid #21262D;
            padding: 8px 14px;
            text-align: left;
            color: #8B949E;
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.07em;
        }
        QPushButton:hover { background: #1C2128; }
    )");
    header_->setText(QString("  %1  %2    ▼").arg(icon, title.toUpper()));

    body_ = new QWidget(this);
    body_->setObjectName("SectionBody");

    mainLayout->addWidget(header_);
    mainLayout->addWidget(body_);

    connect(header_, &QPushButton::clicked, this, &CollapsibleSection::toggle);
}

QWidget* CollapsibleSection::body() { return body_; }

void CollapsibleSection::toggle() {
    open_ = !open_;
    body_->setVisible(open_);
    // Flip the arrow indicator
    QString text = header_->text();
    text.replace(open_ ? "▶" : "▼", open_ ? "▼" : "▶");
    header_->setText(text);
}

// ── InspectionPanel ───────────────────────────────────────────────────────────

static QLabel* makeLabel(const QString& txt = {}, QWidget* parent = nullptr) {
    auto* l = new QLabel(txt, parent);
    l->setStyleSheet("color: #E6EDF3; font-size: 11px;");
    l->setWordWrap(false);
    return l;
}
static QLabel* makeMutedLabel(const QString& txt = {}, QWidget* parent = nullptr) {
    auto* l = new QLabel(txt, parent);
    l->setStyleSheet("color: #8B949E; font-size: 11px;");
    return l;
}
static QLabel* makeMonoLabel(const QString& txt = {}, QWidget* parent = nullptr) {
    auto* l = new QLabel(txt, parent);
    l->setStyleSheet("color: #E6EDF3; font-size: 11px; font-family: 'JetBrains Mono', Consolas;");
    return l;
}

InspectionPanel::InspectionPanel(QWidget* parent) : QWidget(parent) {
    setupUi();
}

void InspectionPanel::setupUi() {
    setMinimumWidth(320);
    setObjectName("InspectionPanel");
    setStyleSheet("QWidget#InspectionPanel { background: #0D1117; }");

    auto* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // Panel header
    auto* header = new QFrame(this);
    header->setFixedHeight(32);
    header->setStyleSheet("background: #161B22; border-bottom: 1px solid #30363D;");
    auto* headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(14, 0, 14, 0);
    auto* headerLabel = new QLabel("🔍  PACKET INSPECTION", header);
    headerLabel->setStyleSheet("color: #8B949E; font-size: 11px; font-weight: 700; letter-spacing: 0.08em;");
    headerLayout->addWidget(headerLabel);

    // Scroll area for content
    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    scroll->setStyleSheet("QScrollArea { background: #0D1117; border: none; }");

    auto* content = new QWidget(scroll);
    content->setStyleSheet("background: #0D1117;");
    auto* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(0, 0, 0, 0);
    contentLayout->setSpacing(0);

    // ── Threat Intel Section ──────────────────────────────────────────────
    auto* intelSection = new CollapsibleSection("Threat Intel Summary", "🌐", content);
    auto* intelBody    = intelSection->body();
    auto* intelLayout  = new QVBoxLayout(intelBody);
    intelLayout->setContentsMargins(14, 4, 14, 12);
    intelLayout->setSpacing(6);

    // IP header card
    auto* ipCard = new QFrame(intelBody);
    ipCard->setStyleSheet("QFrame { background: #21262D; border: 1px solid #30363D; border-radius: 4px; padding: 4px; }");
    auto* ipCardLayout = new QHBoxLayout(ipCard);
    auto* ipLeft  = new QVBoxLayout();
    intelIpLabel_   = makeMonoLabel("—", ipCard);
    intelIpLabel_->setStyleSheet("font-size: 13px; font-weight: 600; font-family: 'JetBrains Mono', Consolas;");
    intelPortLabel_ = makeMutedLabel("Target IP — Port —", ipCard);
    ipLeft->addWidget(intelIpLabel_);
    ipLeft->addWidget(intelPortLabel_);
    intelSeverityLabel_ = new QLabel("SAFE", ipCard);
    intelSeverityLabel_->setStyleSheet("background:#122A19; color:#2EA043; border:1px solid #1A4025; border-radius:3px; padding:2px 7px; font-size:10px; font-weight:700;");
    ipCardLayout->addLayout(ipLeft);
    ipCardLayout->addStretch();
    ipCardLayout->addWidget(intelSeverityLabel_);
    intelLayout->addWidget(ipCard);

    // Intel rows
    auto addIntelRow = [&](const QString& label, QLabel*& value) {
        auto* row    = new QHBoxLayout();
        auto* lbl    = makeMutedLabel(label, intelBody);
        lbl->setFixedWidth(120);
        value = makeMonoLabel("—", intelBody);
        value->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        row->addWidget(lbl);
        row->addWidget(value);
        intelLayout->addLayout(row);
    };

    addIntelRow("AbuseIPDB Score", intelAbuseLabel_);
    addIntelRow("VirusTotal Hits", intelVtLabel_);
    addIntelRow("Geolocation",     intelGeoLabel_);
    addIntelRow("ISP / ASN",       intelIspLabel_);
    addIntelRow("Known Tags",      intelTagsLabel_);

    // ── Forensics Section ─────────────────────────────────────────────────
    auto* forensicsSection = new CollapsibleSection("Host & Process Forensics", "🖥", content);
    auto* fBody  = forensicsSection->body();
    auto* fLayout = new QVBoxLayout(fBody);
    fLayout->setContentsMargins(14, 4, 14, 12);
    fLayout->setSpacing(8);

    // Command line
    auto* cmdLabel = new QLabel("COMMAND LINE", fBody);
    cmdLabel->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    fLayout->addWidget(cmdLabel);
    cmdlineEdit_ = new QTextEdit(fBody);
    cmdlineEdit_->setReadOnly(true);
    cmdlineEdit_->setMaximumHeight(60);
    cmdlineEdit_->setStyleSheet("QTextEdit { background:#080C11; color:#F85149; border:1px solid #30363D; border-radius:4px; font-family:'JetBrains Mono',Consolas; font-size:10px; padding:6px; }");
    fLayout->addWidget(cmdlineEdit_);

    // Exe path
    auto* exeRow = new QHBoxLayout();
    auto* exeLbl = new QLabel("EXECUTABLE PATH", fBody);
    exeLbl->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    exePathLabel_ = makeMonoLabel("—", fBody);
    exePathLabel_->setWordWrap(true);
    exeRow->addWidget(exeLbl);
    exeRow->addStretch();
    exeRow->addWidget(exePathLabel_);
    fLayout->addLayout(exeRow);

    // SHA-256 + buttons
    auto* hashLbl = new QLabel("FILE SHA-256", fBody);
    hashLbl->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    fLayout->addWidget(hashLbl);
    auto* hashRow = new QHBoxLayout();
    sha256Label_ = new QLabel("—", fBody);
    sha256Label_->setStyleSheet("color:#8B949E; font-size:9px; font-family:'JetBrains Mono',Consolas;");
    sha256Label_->setMaximumWidth(180);
    sha256Label_->setWordWrap(false);
    sha256Label_->setTextInteractionFlags(Qt::TextSelectableByMouse);
    copyHashBtn_ = new QPushButton("Copy", fBody);
    copyHashBtn_->setStyleSheet("QPushButton { font-size:10px; padding:2px 8px; border-radius:3px; background:transparent; color:#58A6FF; border:1px solid #30363D; } QPushButton:hover { border-color:#58A6FF; }");
    copyHashBtn_->setCursor(Qt::PointingHandCursor);
    vtCheckBtn_ = new QPushButton("VT Check", fBody);
    vtCheckBtn_->setStyleSheet("QPushButton { font-size:10px; padding:2px 8px; border-radius:3px; background:transparent; color:#D29922; border:1px solid #30363D; } QPushButton:hover { border-color:#D29922; }");
    vtCheckBtn_->setCursor(Qt::PointingHandCursor);
    hashRow->addWidget(sha256Label_);
    hashRow->addStretch();
    hashRow->addWidget(copyHashBtn_);
    hashRow->addWidget(vtCheckBtn_);
    fLayout->addLayout(hashRow);

    // Process lineage placeholder
    lineageLabel_ = makeLabel("—", fBody);
    lineageLabel_->setWordWrap(true);
    fLayout->addWidget(lineageLabel_);

    // User / Privilege
    auto* upRow = new QHBoxLayout();
    auto* userBox = new QVBoxLayout();
    auto* userHdr = new QLabel("USER", fBody);
    userHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700;");
    userLabel_ = new QLabel("—", fBody);
    userLabel_->setStyleSheet("background:#3D1A1A; color:#F85149; border:1px solid #5A1E1E; border-radius:3px; padding:2px 8px; font-size:11px; font-weight:600; font-family:'JetBrains Mono',Consolas;");
    userBox->addWidget(userHdr);
    userBox->addWidget(userLabel_);
    auto* privBox = new QVBoxLayout();
    auto* privHdr = new QLabel("PRIVILEGE", fBody);
    privHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700;");
    privilegeLabel_ = new QLabel("—", fBody);
    privilegeLabel_->setStyleSheet("background:#3D1A1A; color:#F85149; border:1px solid #5A1E1E; border-radius:3px; padding:2px 8px; font-size:11px; font-weight:600; font-family:'JetBrains Mono',Consolas;");
    privBox->addWidget(privHdr);
    privBox->addWidget(privilegeLabel_);
    upRow->addLayout(userBox);
    upRow->addLayout(privBox);
    fLayout->addLayout(upRow);

    // Endpoint info card
    auto* endpointCard = new QFrame(fBody);
    endpointCard->setStyleSheet("QFrame { background:#21262D; border:1px solid #30363D; border-radius:4px; }");
    auto* endLayout = new QHBoxLayout(endpointCard);
    hostnameLabel_ = makeMonoLabel("WORKSTATION", endpointCard);
    osLabel_       = makeMonoLabel("Windows", endpointCard);
    endLayout->addWidget(hostnameLabel_);
    endLayout->addStretch();
    endLayout->addWidget(osLabel_);
    fLayout->addWidget(endpointCard);

    contentLayout->addWidget(intelSection);
    contentLayout->addWidget(forensicsSection);
    contentLayout->addStretch();

    scroll->setWidget(content);
    outerLayout->addWidget(header);
    outerLayout->addWidget(scroll);

    // Connect buttons
    connect(copyHashBtn_, &QPushButton::clicked, this, [this]() {
        emit copyRequested(sha256Label_->text());
    });
    connect(vtCheckBtn_, &QPushButton::clicked, this, [this]() {
        const QString hash = sha256Label_->text();
        if (hash != "—" && !hash.isEmpty()) {
            emit vtCheckRequested(hash);
            QDesktopServices::openUrl(QUrl("https://www.virustotal.com/gui/file/" + hash));
        }
    });
}

void InspectionPanel::populate(const PacketRecord& pkt,
                                const ProcessInfo&  proc,
                                const ThreatIntelResult& intel)
{
    // IP header
    intelIpLabel_->setText(pkt.dstStr());
    intelPortLabel_->setText(QStringLiteral("Target IP — Port %1").arg(pkt.dst_port));

    // Severity badge
    const auto sc = severityColors(pkt.severity);
    intelSeverityLabel_->setText(QString(severityStr(pkt.severity)));
    intelSeverityLabel_->setStyleSheet(
        QStringLiteral("background:%1; color:%2; border:1px solid %3; border-radius:3px; padding:2px 7px; font-size:10px; font-weight:700;")
            .arg(sc.bg.name(), sc.fg.name(), sc.border.name()));

    // Process forensics
    const QString cmd = proc.cmdline.isEmpty()
        ? QStringLiteral("%1 -connect %2:%3").arg(proc.name, pkt.dstStr()).arg(pkt.dst_port)
        : proc.cmdline;
    cmdlineEdit_->setPlainText(cmd);
    exePathLabel_->setText(proc.exePath.isEmpty() ? QStringLiteral("—") : proc.exePath);
    sha256Label_->setText(proc.sha256.isEmpty() ? QStringLiteral("—") : proc.sha256);
    userLabel_->setText(proc.username.isEmpty() ? QStringLiteral("—") : proc.username);
    privilegeLabel_->setText(proc.username.contains("SYSTEM", Qt::CaseInsensitive) ||
                              proc.username.contains("root",   Qt::CaseInsensitive)
                              ? "SYSTEM / Admin" : "Standard User");
    lineageLabel_->setText(QStringLiteral("systemd (PID 1) → %1 (PID %2)")
                               .arg(proc.name).arg(proc.pid));
    hostnameLabel_->setText(QStringLiteral("Host: %1").arg(
        qEnvironmentVariable("COMPUTERNAME", "UNKNOWN")));
    osLabel_->setText("Windows");

    updateIntel(intel);
}

void InspectionPanel::updateIntel(const ThreatIntelResult& intel) {
    if (!intel.enriched) {
        intelAbuseLabel_->setText("Fetching…");
        intelVtLabel_->setText("Fetching…");
        intelGeoLabel_->setText("Fetching…");
        intelIspLabel_->setText("Fetching…");
        intelTagsLabel_->setText("Fetching…");
        return;
    }

    intelAbuseLabel_->setText(
        QStringLiteral("%1 / 100 %2")
            .arg(intel.abuseScore)
            .arg(intel.abuseScore >= 80 ? "🔴" : intel.abuseScore >= 40 ? "🟠" : "🟢"));
    intelVtLabel_->setText(
        QStringLiteral("%1 / 73 engines").arg(intel.vtMalicious));
    intelGeoLabel_->setText(
        intel.country.isEmpty() ? "—" :
        QStringLiteral("%1 %2%3").arg(
            intel.country,
            intel.ipinfoCity.isEmpty() ? "" : intel.ipinfoCity + ", ",
            intel.isp.isEmpty() ? "" : " (" + intel.isp + ")"));
    intelIspLabel_->setText(intel.isp.isEmpty() ? "—" : intel.isp);
    intelTagsLabel_->setText(intel.shodanTags.isEmpty() ? "—" :
                              intel.shodanTags.join(", "));
}

} // namespace SS
