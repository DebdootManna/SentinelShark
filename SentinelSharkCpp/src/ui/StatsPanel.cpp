#include "StatsPanel.h"
#include "../config/AppConfig.h"
#include "../heuristics/HeuristicsEngine.h"
#include <QScrollArea>
#include <QFont>
#include <algorithm>

namespace SS {

static const QStringList kTrackedProtocols = {
    "TCP", "HTTPS", "HTTP", "DNS", "TLS", "UDP",
    "ICMP", "ICMPV6", "ARP", "QUIC", "SSH", "OTHER"
};

static QString protocolColor(const QString& proto) {
    if (proto == "DNS")              return "#60A5FA";
    if (proto == "TLS" || proto == "HTTPS") return "#34D399";
    if (proto == "HTTP")             return "#FBBF24";
    if (proto == "TCP")              return "#94A3B8";
    if (proto == "UDP")              return "#A78BFA";
    if (proto == "ICMP" || proto == "ICMPV6") return "#38BDF8";
    if (proto == "ARP")              return "#818CF8";
    if (proto == "QUIC")             return "#2DD4BF";
    if (proto == "SSH")              return "#F87171";
    return "#94A3B8";
}

// ── StatCard ──────────────────────────────────────────────────────────────────

StatCard::StatCard(const QString& title, const QString& initialValue,
                   const QString& accentColor, QWidget* parent)
    : QFrame(parent), accentColor_(accentColor)
{
    setObjectName("StatCard");
    setMinimumSize(120, 58);
    setStyleSheet(R"(
        QFrame#StatCard {
            background-color: #131C2B;
            border: 1px solid #1E293B;
            border-radius: 10px;
        }
    )");

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(12, 10, 12, 10);
    layout->setSpacing(4);

    titleLabel_ = new QLabel(title, this);
    titleLabel_->setStyleSheet(
        "font-size: 10px; color: #94A3B8; font-weight: 600; "
        "font-family: 'JetBrains Mono', Consolas, monospace; "
        "text-transform: uppercase; letter-spacing: 0.06em; "
        "border: none; background: transparent;");
    layout->addWidget(titleLabel_);

    valueLabel_ = new QLabel(initialValue, this);
    valueLabel_->setStyleSheet(QString(
        "font-size: 16px; font-weight: bold; color: %1; "
        "font-family: 'JetBrains Mono', Consolas, monospace; "
        "border: none; background: transparent;").arg(accentColor_));
    layout->addWidget(valueLabel_);
}

void StatCard::setValue(const QString& val) {
    valueLabel_->setText(val);
}

// ── CollapsibleCard ───────────────────────────────────────────────────────────

CollapsibleCard::CollapsibleCard(const QString& title, int expandedMinHeight, QWidget* parent)
    : QFrame(parent), expandedMinHeight_(expandedMinHeight)
{
    setObjectName("CollapsibleCard");
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
    setMinimumHeight(expandedMinHeight_);
    setStyleSheet(R"(
        QFrame#CollapsibleCard {
            background-color: #131C2B;
            border: 1px solid #1E293B;
            border-radius: 12px;
        }
    )");

    auto* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(14, 12, 14, 12);
    mainLayout->setSpacing(8);

    // Header bar
    auto* headerLayout = new QHBoxLayout();
    headerLayout->setContentsMargins(0, 0, 0, 0);

    titleLabel_ = new QLabel(title, this);
    titleLabel_->setStyleSheet(
        "color: #22D3EE; font-weight: 700; font-size: 11px; "
        "font-family: 'JetBrains Mono', Consolas, monospace; "
        "text-transform: uppercase; letter-spacing: 0.05em; "
        "background: transparent; border: none;");
    headerLayout->addWidget(titleLabel_);
    headerLayout->addStretch();

    toggleBtn_ = new QPushButton("−", this);
    toggleBtn_->setFixedSize(22, 22);
    toggleBtn_->setCursor(Qt::PointingHandCursor);
    toggleBtn_->setToolTip("Collapse / Expand Section");
    toggleBtn_->setStyleSheet(R"(
        QPushButton {
            background-color: rgba(30, 41, 59, 0.6);
            border: 1px solid #1E293B;
            color: #94A3B8;
            border-radius: 6px;
            font-weight: bold;
            font-size: 13px;
            padding: 0px;
        }
        QPushButton:hover {
            background-color: #1E293B;
            color: #22D3EE;
            border-color: #38BDF8;
        }
    )");
    connect(toggleBtn_, &QPushButton::clicked, this, &CollapsibleCard::toggleCollapse);
    headerLayout->addWidget(toggleBtn_);
    mainLayout->addLayout(headerLayout);

    // Content container
    contentWidget_ = new QWidget(this);
    contentWidget_->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
    contentLayout_ = new QVBoxLayout(contentWidget_);
    contentLayout_->setContentsMargins(0, 4, 0, 0);
    contentLayout_->setSpacing(8);

    mainLayout->addWidget(contentWidget_);
}

void CollapsibleCard::toggleCollapse() {
    isCollapsed_ = !isCollapsed_;
    contentWidget_->setVisible(!isCollapsed_);
    toggleBtn_->setText(isCollapsed_ ? "+" : "−");
    if (isCollapsed_) {
        setFixedHeight(44);
    } else {
        setMinimumHeight(expandedMinHeight_);
        setMaximumHeight(QWIDGETSIZE_MAX);
    }
}

void CollapsibleCard::setTitle(const QString& title) {
    titleLabel_->setText(title);
}

// ── StatsPanel ────────────────────────────────────────────────────────────────

StatsPanel::StatsPanel(QWidget* parent)
    : QWidget(parent)
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Minimum);
    setupUi();
    refreshApiStatus();
}

void StatsPanel::setupUi() {
    setObjectName("StatsPanel");
    setStyleSheet("QWidget#StatsPanel { background-color: #0D1117; }");

    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(10, 10, 10, 10);
    layout->setSpacing(14);

    // 1. Metric Cards 2x2 Grid
    auto* grid = new QGridLayout();
    grid->setSpacing(10);

    cardPackets_ = new StatCard("TOTAL EVENTS", "0", "#58A6FF", this);
    cardBytes_   = new StatCard("DATA TRAFFIC", "0.0 KB", "#3FB950", this);
    cardSafe_    = new StatCard("SAFE EVENTS", "0", "#2EA043", this);
    cardThreats_ = new StatCard("THREATS DETECTED", "0", "#F85149", this);

    grid->addWidget(cardPackets_, 0, 0);
    grid->addWidget(cardBytes_,   0, 1);
    grid->addWidget(cardSafe_,    1, 0);
    grid->addWidget(cardThreats_, 1, 1);

    layout->addLayout(grid);

    // 2. MITRE ATT&CK Coverage Panel
    mitreCard_ = new CollapsibleCard("MITRE ATT&CK COVERAGE", 140, this);
    auto* mitreLayout = mitreCard_->contentLayout();
    mitreLayout->setSpacing(5);

    mitreEmptyLabel_ = new QLabel("No techniques tagged yet", this);
    mitreEmptyLabel_->setStyleSheet("color: #8B949E; font-family: monospace; font-size: 11px;");
    mitreLayout->addWidget(mitreEmptyLabel_);

    for (int i = 0; i < 5; ++i) {
        auto* container = new QWidget(this);
        auto* row = new QHBoxLayout(container);
        row->setContentsMargins(0, 2, 0, 2);
        row->setSpacing(6);

        auto* tag = new QLabel(this);
        tag->setFixedWidth(68);
        tag->setStyleSheet(
            "color: #58A6FF; font-family: 'JetBrains Mono', Consolas, monospace; "
            "font-size: 9px; font-weight: 700; background-color: #1F3A5F; "
            "border: 1px solid #2A4A7A; border-radius: 3px; padding: 1px 3px;");

        auto* name = new QLabel(this);
        name->setFixedWidth(85);
        name->setStyleSheet("color: #8B949E; font-size: 10px;");

        auto* bar = new QProgressBar(this);
        bar->setRange(0, 100);
        bar->setValue(0);
        bar->setTextVisible(false);
        bar->setFixedHeight(5);
        bar->setStyleSheet(
            "QProgressBar { background-color: #21262D; border: none; border-radius: 2px; } "
            "QProgressBar::chunk { background-color: #D29922; border-radius: 2px; }");

        auto* count = new QLabel("0", this);
        count->setFixedWidth(34);
        count->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count->setStyleSheet("color: #E6EDF3; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 10px;");

        row->addWidget(tag);
        row->addWidget(name);
        row->addWidget(bar, 1);
        row->addWidget(count);

        container->setVisible(false);
        mitreLayout->addWidget(container);
        mitreRows_.append({container, tag, name, bar, count});
    }
    layout->addWidget(mitreCard_);

    // 3. Top Processes Panel
    procCard_ = new CollapsibleCard("TOP PROCESSES", 140, this);
    auto* procLayout = procCard_->contentLayout();
    procLayout->setSpacing(5);

    procEmptyLabel_ = new QLabel("No process telemetry recorded", this);
    procEmptyLabel_->setStyleSheet("color: #8B949E; font-family: monospace; font-size: 11px;");
    procLayout->addWidget(procEmptyLabel_);

    for (int i = 0; i < 5; ++i) {
        auto* container = new QWidget(this);
        auto* row = new QHBoxLayout(container);
        row->setContentsMargins(0, 2, 0, 2);
        row->setSpacing(6);

        auto* rank = new QLabel(QString("%1.").arg(i + 1), this);
        rank->setFixedWidth(14);
        rank->setStyleSheet("color: #484F58; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 10px;");

        auto* name = new QLabel(this);
        name->setFixedWidth(80);
        name->setStyleSheet("color: #E6EDF3; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 10px; font-weight: 600;");

        auto* bar = new QProgressBar(this);
        bar->setRange(0, 100);
        bar->setValue(0);
        bar->setTextVisible(false);
        bar->setFixedHeight(5);
        bar->setStyleSheet(
            "QProgressBar { background-color: #21262D; border: none; border-radius: 2px; } "
            "QProgressBar::chunk { background-color: #58A6FF; border-radius: 2px; }");

        auto* count = new QLabel("0", this);
        count->setFixedWidth(36);
        count->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count->setStyleSheet("color: #8B949E; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 10px;");

        row->addWidget(rank);
        row->addWidget(name);
        row->addWidget(bar, 1);
        row->addWidget(count);

        container->setVisible(false);
        procLayout->addWidget(container);
        procRows_.append({container, rank, name, bar, count});
    }
    layout->addWidget(procCard_);

    // 4. Protocol Breakdown Panel
    protoCard_ = new CollapsibleCard("PROTOCOL BREAKDOWN", 170, this);
    auto* protoLayout = protoCard_->contentLayout();
    protoLayout->setSpacing(8);

    protoEmptyLabel_ = new QLabel("No protocol data recorded", this);
    protoEmptyLabel_->setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;");
    protoLayout->addWidget(protoEmptyLabel_);

    for (const auto& proto : kTrackedProtocols) {
        auto* container = new QWidget(this);
        auto* row = new QHBoxLayout(container);
        row->setContentsMargins(0, 2, 0, 2);
        row->setSpacing(8);

        auto* label = new QLabel(proto, this);
        label->setFixedWidth(52);
        label->setStyleSheet("color: #94A3B8; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;");

        auto* bar = new QProgressBar(this);
        bar->setRange(0, 100);
        bar->setValue(0);
        bar->setTextVisible(false);
        bar->setFixedHeight(6);
        QString color = protocolColor(proto);
        bar->setStyleSheet(QString(
            "QProgressBar { background-color: #1E293B; border: none; border-radius: 3px; } "
            "QProgressBar::chunk { background-color: %1; border-radius: 3px; }").arg(color));

        auto* count = new QLabel("0", this);
        count->setFixedWidth(36);
        count->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        count->setStyleSheet("color: #E2E8F0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;");

        row->addWidget(label);
        row->addWidget(bar, 1);
        row->addWidget(count);

        container->setVisible(false);
        protoLayout->addWidget(container);
        protoRows_[proto] = {container, label, bar, count};
    }
    layout->addWidget(protoCard_);

    // 5. Threat Intel API Queue Panel
    queueCard_ = new CollapsibleCard("THREAT INTEL API QUEUE", 190, this);
    auto* queueLayout = queueCard_->contentLayout();
    queueLayout->setSpacing(8);

    auto makeStatusRow = [this, queueLayout](const QString& name, QLabel*& statusLbl) {
        auto* row = new QHBoxLayout();
        row->setContentsMargins(0, 2, 0, 2);
        auto* lbl = new QLabel(name, this);
        lbl->setStyleSheet("color: #94A3B8; font-size: 11px;");
        statusLbl = new QLabel(this);
        statusLbl->setStyleSheet("font-family: monospace; font-size: 11px;");
        row->addWidget(lbl);
        row->addStretch();
        row->addWidget(statusLbl);
        queueLayout->addLayout(row);
    };

    makeStatusRow("VirusTotal", vtStatusLabel_);
    makeStatusRow("AbuseIPDB", abuseStatusLabel_);
    makeStatusRow("Shodan", shodanStatusLabel_);
    makeStatusRow("IPinfo", ipinfoStatusLabel_);

    auto* qHeader = new QHBoxLayout();
    qHeader->setContentsMargins(0, 4, 0, 0);
    auto* qLabel = new QLabel("Queue Processing", this);
    qLabel->setStyleSheet("color: #94A3B8; font-size: 11px;");
    queueCounterLabel_ = new QLabel("0 / 0", this);
    queueCounterLabel_->setStyleSheet("color: #E2E8F0; font-family: monospace; font-size: 11px;");
    qHeader->addWidget(qLabel);
    qHeader->addStretch();
    qHeader->addWidget(queueCounterLabel_);
    queueLayout->addLayout(qHeader);

    queueBar_ = new QProgressBar(this);
    queueBar_->setRange(0, 100);
    queueBar_->setValue(0);
    queueBar_->setTextVisible(false);
    queueBar_->setFixedHeight(5);
    queueBar_->setStyleSheet(
        "QProgressBar { background-color: #1E293B; border: none; border-radius: 2px; } "
        "QProgressBar::chunk { background-color: #38BDF8; border-radius: 2px; }");
    queueLayout->addWidget(queueBar_);
    layout->addWidget(queueCard_);

    // 6. Selected Packet Card
    pktCard_ = new CollapsibleCard("SELECTED PACKET", 140, this);
    auto* pktLayout = pktCard_->contentLayout();
    pktLayout->setSpacing(6);

    pktEmptyLabel_ = new QLabel("No packet selected", this);
    pktEmptyLabel_->setStyleSheet("color: #94A3B8; font-family: monospace; font-size: 11px;");
    pktLayout->addWidget(pktEmptyLabel_);

    const QStringList keys = {"Protocol", "Source", "Dest", "Size"};
    for (const auto& k : keys) {
        auto* container = new QWidget(this);
        auto* row = new QHBoxLayout(container);
        row->setContentsMargins(0, 2, 0, 2);
        row->setSpacing(8);

        auto* lblK = new QLabel(k, this);
        lblK->setStyleSheet("color: #94A3B8; font-size: 11px;");

        auto* lblV = new QLabel("", this);
        lblV->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        lblV->setStyleSheet("color: #E2E8F0; font-family: 'JetBrains Mono', Consolas, monospace; font-size: 11px;");

        row->addWidget(lblK);
        row->addStretch();
        row->addWidget(lblV);

        container->setVisible(false);
        pktLayout->addWidget(container);
        pktDetailWidgets_[k] = {container, lblV};
    }
    layout->addWidget(pktCard_);
    layout->addStretch();
}

void StatsPanel::refreshApiStatus() {
    auto& cfg = AppConfig::instance();
    auto setLabel = [](QLabel* lbl, bool configured) {
        if (!lbl) return;
        if (configured) {
            lbl->setText("Connected");
            lbl->setStyleSheet("color: #22C55E; font-family: monospace; font-size: 11px; font-weight: bold;");
        } else {
            lbl->setText("Not Configured");
            lbl->setStyleSheet("color: #64748B; font-family: monospace; font-size: 11px;");
        }
    };

    setLabel(vtStatusLabel_, !cfg.virustotalApiKey.trimmed().isEmpty());
    setLabel(abuseStatusLabel_, !cfg.abuseipdbApiKey.trimmed().isEmpty());
    setLabel(shodanStatusLabel_, !cfg.shodanApiKey.trimmed().isEmpty());
    setLabel(ipinfoStatusLabel_, !cfg.ipinfoApiKey.trimmed().isEmpty());
}

void StatsPanel::updatePacketsBatch(const QVector<PacketRecord>& batch) {
    if (batch.isEmpty()) return;

    for (const auto& r : batch) {
        ++totalPackets_;
        totalBytes_ += static_cast<uint64_t>(r.length);

        if (r.severity == Severity::Critical || r.severity == Severity::High) {
            ++criticalCount_;
        } else {
            ++safeCount_;
        }

        // Protocol
        QString proto = r.protocolStr().toUpper().trimmed();
        if (!kTrackedProtocols.contains(proto)) {
            proto = "OTHER";
        }
        protocols_[proto]++;

        // Process
        QString proc = r.processStr().trimmed();
        if (!proc.isEmpty() && proc != "—" && proc != "unknown") {
            processes_[proc]++;
        }

        // MITRE technique
        QString mitre = r.mitreStr().trimmed();
        if (!mitre.isEmpty() && mitre != "—") {
            const QStringList tags = mitre.split(',', Qt::SkipEmptyParts);
            for (const auto& t : tags) {
                QString clean = t.trimmed();
                if (!clean.isEmpty()) {
                    mitreTechniques_[clean]++;
                }
            }
        }
    }

    // Update Metric Cards
    cardPackets_->setValue(QString::number(totalPackets_));

    if (totalBytes_ > 1024 * 1024) {
        cardBytes_->setValue(QStringLiteral("%1 MB").arg(totalBytes_ / (1024.0 * 1024.0), 0, 'f', 1));
    } else {
        cardBytes_->setValue(QStringLiteral("%1 KB").arg(totalBytes_ / 1024.0, 0, 'f', 1));
    }

    cardSafe_->setValue(QString::number(safeCount_));
    cardThreats_->setValue(QString::number(criticalCount_));

    refreshProtocolBars();
    refreshEdrSections();
}

void StatsPanel::refreshProtocolBars() {
    uint64_t maxProto = 1;
    for (auto it = protocols_.constBegin(); it != protocols_.constEnd(); ++it) {
        if (it.value() > maxProto) maxProto = it.value();
    }

    bool hasAny = false;
    for (const auto& proto : kTrackedProtocols) {
        auto it = protoRows_.find(proto);
        if (it == protoRows_.end()) continue;

        uint64_t count = protocols_.value(proto, 0);
        if (count > 0) {
            hasAny = true;
            it->container->setVisible(true);
            it->count->setText(QString::number(count));
            it->bar->setValue(static_cast<int>((count * 100) / maxProto));
        } else {
            it->container->setVisible(false);
        }
    }

    protoEmptyLabel_->setVisible(!hasAny);
}

void StatsPanel::refreshEdrSections() {
    // 1. MITRE Techniques
    QList<QPair<QString, uint64_t>> mitreList;
    for (auto it = mitreTechniques_.constBegin(); it != mitreTechniques_.constEnd(); ++it) {
        mitreList.append({it.key(), it.value()});
    }
    std::sort(mitreList.begin(), mitreList.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    uint64_t maxMitre = mitreList.isEmpty() ? 1 : mitreList.first().second;
    bool hasMitre = !mitreList.isEmpty();
    mitreEmptyLabel_->setVisible(!hasMitre);

    for (int i = 0; i < mitreRows_.size(); ++i) {
        if (i < mitreList.size()) {
            const QString tag = mitreList[i].first;
            const uint64_t count = mitreList[i].second;
            mitreRows_[i].tag->setText(tag);
            mitreRows_[i].name->setText(HeuristicsEngine::techniqueDescription(tag));
            mitreRows_[i].count->setText(QString::number(count));
            mitreRows_[i].bar->setValue(static_cast<int>((count * 100) / maxMitre));
            mitreRows_[i].container->setVisible(true);
        } else {
            mitreRows_[i].container->setVisible(false);
        }
    }

    // 2. Top Processes
    QList<QPair<QString, uint64_t>> procList;
    for (auto it = processes_.constBegin(); it != processes_.constEnd(); ++it) {
        procList.append({it.key(), it.value()});
    }
    std::sort(procList.begin(), procList.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });

    uint64_t maxProc = procList.isEmpty() ? 1 : procList.first().second;
    bool hasProc = !procList.isEmpty();
    procEmptyLabel_->setVisible(!hasProc);

    for (int i = 0; i < procRows_.size(); ++i) {
        if (i < procList.size()) {
            const QString procName = procList[i].first;
            const uint64_t count = procList[i].second;
            procRows_[i].rank->setText(QString("%1.").arg(i + 1));
            procRows_[i].name->setText(procName);
            procRows_[i].count->setText(QString::number(count));

            bool isLolbin = HeuristicsEngine::isLolbin(procName);
            procRows_[i].bar->setStyleSheet(QString(
                "QProgressBar { background-color: #21262D; border: none; border-radius: 2px; } "
                "QProgressBar::chunk { background-color: %1; border-radius: 2px; }")
                .arg(isLolbin ? "#F85149" : "#58A6FF"));
            procRows_[i].bar->setValue(static_cast<int>((count * 100) / maxProc));
            procRows_[i].container->setVisible(true);
        } else {
            procRows_[i].container->setVisible(false);
        }
    }
}

void StatsPanel::setSelectedPacket(const PacketRecord& pkt) {
    if (pkt.no == 0) {
        pktEmptyLabel_->setVisible(true);
        for (auto& row : pktDetailWidgets_) {
            row.container->setVisible(false);
        }
        return;
    }

    pktEmptyLabel_->setVisible(false);

    if (pktDetailWidgets_.contains("Protocol")) {
        pktDetailWidgets_["Protocol"].val->setText(pkt.protocolStr());
        pktDetailWidgets_["Protocol"].container->setVisible(true);
    }
    if (pktDetailWidgets_.contains("Source")) {
        pktDetailWidgets_["Source"].val->setText(pkt.srcEndpoint());
        pktDetailWidgets_["Source"].container->setVisible(true);
    }
    if (pktDetailWidgets_.contains("Dest")) {
        pktDetailWidgets_["Dest"].val->setText(pkt.dstEndpoint());
        pktDetailWidgets_["Dest"].container->setVisible(true);
    }
    if (pktDetailWidgets_.contains("Size")) {
        pktDetailWidgets_["Size"].val->setText(QStringLiteral("%1 bytes").arg(pkt.length));
        pktDetailWidgets_["Size"].container->setVisible(true);
    }
}

void StatsPanel::resetStats() {
    totalPackets_ = 0;
    totalBytes_ = 0;
    safeCount_ = 0;
    criticalCount_ = 0;
    protocols_.clear();
    processes_.clear();
    mitreTechniques_.clear();

    cardPackets_->setValue("0");
    cardBytes_->setValue("0.0 KB");
    cardSafe_->setValue("0");
    cardThreats_->setValue("0");

    refreshProtocolBars();
    refreshEdrSections();
    setSelectedPacket({});
}

void StatsPanel::updateQueueStatus(int pending, int inProgress) {
    int total = pending + inProgress;
    queueCounterLabel_->setText(QStringLiteral("%1 / %2").arg(inProgress).arg(total));
    queueBar_->setValue(total > 0 ? (inProgress * 100 / total) : 0);
}

} // namespace SS
