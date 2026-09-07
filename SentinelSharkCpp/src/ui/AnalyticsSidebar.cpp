#include "AnalyticsSidebar.h"
#include "../model/PacketTableModel.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QProgressBar>
#include <QFrame>
#include <QScrollArea>
#include <QMap>
#include <algorithm>

namespace SS {

const char* AnalyticsSidebar::kStatNames[6] = {
    "Endpoints", "Active C2", "Blocked IPs", "Clean", "Open Cases", "MTTR"
};

static QProgressBar* makeBar(QWidget* parent, const QColor& color) {
    auto* bar = new QProgressBar(parent);
    bar->setRange(0, 100);
    bar->setValue(0);
    bar->setFixedHeight(4);
    bar->setTextVisible(false);
    bar->setStyleSheet(QStringLiteral(
        "QProgressBar { background:#21262D; border-radius:2px; border:none; }"
        "QProgressBar::chunk { background:%1; border-radius:2px; }"
    ).arg(color.name()));
    return bar;
}

AnalyticsSidebar::AnalyticsSidebar(QWidget* parent) : QWidget(parent) {
    setupUi();
}

void AnalyticsSidebar::setupUi() {
    setFixedWidth(260);
    setObjectName("AnalyticsSidebar");
    setStyleSheet("QWidget#AnalyticsSidebar { background:#0D1117; }");

    auto* outerLayout = new QVBoxLayout(this);
    outerLayout->setContentsMargins(0, 0, 0, 0);
    outerLayout->setSpacing(0);

    // Header
    auto* header = new QFrame(this);
    header->setFixedHeight(32);
    header->setStyleSheet("background:#161B22; border-bottom:1px solid #30363D;");
    auto* headerLayout = new QHBoxLayout(header);
    headerLayout->setContentsMargins(14, 0, 14, 0);
    auto* headerLabel = new QLabel("📊  ANALYTICS", header);
    headerLabel->setStyleSheet("color:#8B949E; font-size:11px; font-weight:700; letter-spacing:0.08em;");
    headerLayout->addWidget(headerLabel);
    outerLayout->addWidget(header);

    auto* scroll = new QScrollArea(this);
    scroll->setWidgetResizable(true);
    scroll->setFrameShape(QFrame::NoFrame);
    scroll->setStyleSheet("background:#0D1117; border:none;");

    auto* content = new QWidget(scroll);
    content->setStyleSheet("background:#0D1117;");
    auto* contentLayout = new QVBoxLayout(content);
    contentLayout->setContentsMargins(12, 10, 12, 10);
    contentLayout->setSpacing(14);

    // ── Severity Distribution ─────────────────────────────────────────────
    auto* sevHdr = new QLabel("INCIDENT SEVERITY", content);
    sevHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    contentLayout->addWidget(sevHdr);

    const struct { const char* name; QColor color; } kSevDef[4] = {
        {"Critical", QColor("#F85149")},
        {"High",     QColor("#FF7B72")},
        {"Medium",   QColor("#D29922")},
        {"Safe",     QColor("#2EA043")},
    };
    for (int i = 0; i < 4; ++i) {
        auto* row   = new QHBoxLayout();
        auto* nameL = new QLabel(kSevDef[i].name, content);
        nameL->setStyleSheet(QStringLiteral("color:%1; font-size:10px; font-weight:600;")
                                 .arg(kSevDef[i].color.name()));
        nameL->setFixedWidth(55);
        auto* bar    = makeBar(content, kSevDef[i].color);
        auto* countL = new QLabel("0", content);
        countL->setStyleSheet("color:#8B949E; font-size:10px; font-family:'JetBrains Mono',Consolas;");
        countL->setFixedWidth(25);
        countL->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        row->addWidget(nameL);
        row->addWidget(bar, 1);
        row->addWidget(countL);
        contentLayout->addLayout(row);
        sevBars_[i] = {countL, bar, nameL};
    }
    // Stacked bar placeholder
    stackedBar_ = new QFrame(content);
    stackedBar_->setFixedHeight(6);
    stackedBar_->setStyleSheet("background:#21262D; border-radius:3px;");
    contentLayout->addWidget(stackedBar_);

    // Separator
    auto* sep1 = new QFrame(content);
    sep1->setFrameShape(QFrame::HLine);
    sep1->setStyleSheet("border:none; border-top:1px solid #21262D;");
    contentLayout->addWidget(sep1);

    // ── Top Suspicious Processes ──────────────────────────────────────────
    auto* procHdr = new QLabel("TOP SUSPICIOUS PROCESSES", content);
    procHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    contentLayout->addWidget(procHdr);

    for (int i = 0; i < kTopN; ++i) {
        auto* row    = new QHBoxLayout();
        auto* rankL  = new QLabel(QString::number(i + 1), content);
        rankL->setStyleSheet("color:#484F58; font-size:9px; font-family:'JetBrains Mono',Consolas;");
        rankL->setFixedWidth(14);
        rankL->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        auto* nameL  = new QLabel("—", content);
        nameL->setStyleSheet("background:#21262D; color:#E6EDF3; border:1px solid #30363D; border-radius:3px; padding:1px 6px; font-size:10px; font-family:'JetBrains Mono',Consolas;");
        nameL->setFixedWidth(90);
        auto* bar    = makeBar(content, QColor("#8B949E"));
        auto* countL = new QLabel("0", content);
        countL->setStyleSheet("color:#484F58; font-size:9px; font-family:'JetBrains Mono',Consolas;");
        countL->setFixedWidth(22);
        countL->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
        row->addWidget(rankL);
        row->addWidget(nameL);
        row->addWidget(bar, 1);
        row->addWidget(countL);
        contentLayout->addLayout(row);
        procRows_[i] = {rankL, nameL, bar, countL};
    }

    // Separator
    auto* sep2 = new QFrame(content);
    sep2->setFrameShape(QFrame::HLine);
    sep2->setStyleSheet("border:none; border-top:1px solid #21262D;");
    contentLayout->addWidget(sep2);

    // ── MITRE ATT&CK Coverage ─────────────────────────────────────────────
    auto* mitreHdr = new QLabel("MITRE ATT&CK COVERAGE", content);
    mitreHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    contentLayout->addWidget(mitreHdr);

    for (int i = 0; i < kMitreN; ++i) {
        auto* row   = new QHBoxLayout();
        auto* tagL  = new QLabel("—", content);
        tagL->setStyleSheet("background:#1F3A5F; color:#58A6FF; border:1px solid #2A4A7A; border-radius:3px; padding:1px 5px; font-size:9px; font-family:'JetBrains Mono',Consolas;");
        tagL->setFixedWidth(56);
        tagL->setAlignment(Qt::AlignCenter);
        auto* nameL = new QLabel("—", content);
        nameL->setStyleSheet("color:#8B949E; font-size:9px;");
        auto* bar   = makeBar(content, QColor("#58A6FF"));
        auto* countL= new QLabel("0", content);
        countL->setStyleSheet("color:#484F58; font-size:9px; font-family:'JetBrains Mono',Consolas;");
        countL->setFixedWidth(18);
        countL->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

        auto* col = new QVBoxLayout();
        col->addWidget(nameL);
        col->addWidget(bar);

        row->addWidget(tagL);
        row->addLayout(col, 1);
        row->addWidget(countL);
        contentLayout->addLayout(row);
        mitreRows_[i] = {tagL, nameL, bar, countL};
    }

    // Separator
    auto* sep3 = new QFrame(content);
    sep3->setFrameShape(QFrame::HLine);
    sep3->setStyleSheet("border:none; border-top:1px solid #21262D;");
    contentLayout->addWidget(sep3);

    // ── Session Stats ─────────────────────────────────────────────────────
    auto* statsHdr = new QLabel("SESSION STATS", content);
    statsHdr->setStyleSheet("color:#8B949E; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    contentLayout->addWidget(statsHdr);

    auto* statsGrid = new QGridLayout();
    statsGrid->setSpacing(6);
    const QColor kStatColors[6] = {
        QColor("#E6EDF3"), QColor("#F85149"), QColor("#D29922"),
        QColor("#2EA043"), QColor("#58A6FF"), QColor("#8B949E"),
    };
    for (int i = 0; i < 6; ++i) {
        auto* card = new QFrame(content);
        card->setStyleSheet("QFrame { background:#21262D; border:1px solid #30363D; border-radius:4px; }");
        auto* cLayout = new QVBoxLayout(card);
        cLayout->setContentsMargins(8, 7, 8, 7);
        statLabels_[i] = new QLabel("—", card);
        statLabels_[i]->setStyleSheet(QStringLiteral("color:%1; font-size:14px; font-weight:700; font-family:'JetBrains Mono',Consolas;")
                                          .arg(kStatColors[i].name()));
        auto* nameL = new QLabel(kStatNames[i], card);
        nameL->setStyleSheet("color:#484F58; font-size:9px; text-transform:uppercase; letter-spacing:0.06em;");
        cLayout->addWidget(statLabels_[i]);
        cLayout->addWidget(nameL);
        statsGrid->addWidget(card, i / 2, i % 2);
    }
    contentLayout->addLayout(statsGrid);
    contentLayout->addStretch();

    scroll->setWidget(content);
    outerLayout->addWidget(scroll, 1);
}

void AnalyticsSidebar::refresh(const RingBuffer<PacketRecord, 3000>& buf,
                                uint64_t totalReceived)
{
    // Count severities
    int sevCount[4] = {};
    QMap<QString, int> procCount;
    QMap<QString, int> mitreCount;

    const size_t n = buf.size();
    for (size_t i = 0; i < n; ++i) {
        const auto& r = buf[i];
        const int si = static_cast<int>(r.severity);
        if (si >= 0 && si < 4) ++sevCount[si];

        const QString proc = r.processStr();
        if (!proc.isEmpty() && proc != "unknown")
            procCount[proc]++;

        const QString mitre = r.mitreStr();
        if (!mitre.isEmpty() && mitre != "—") {
            // Use base technique (first 5 chars) for grouping
            const QString base = mitre.left(5);
            mitreCount[base]++;
        }
    }

    // Update severity bars
    const int total = sevCount[0] + sevCount[1] + sevCount[2] + sevCount[3];
    // Note: enum order is Safe=0, Medium=1, High=2, Critical=3
    // Display order: Critical=3, High=2, Medium=1, Safe=0
    const int displayOrder[4] = {3, 2, 1, 0};
    for (int di = 0; di < 4; ++di) {
        const int si = displayOrder[di];
        const int c  = sevCount[si];
        sevBars_[di].countLabel->setText(QString::number(c));
        sevBars_[di].bar->setValue(total > 0 ? (c * 100 / total) : 0);
    }

    // Update process rows
    QList<QPair<QString, int>> procList;
    for (auto it = procCount.begin(); it != procCount.end(); ++it)
        procList.append({it.key(), it.value()});
    std::sort(procList.begin(), procList.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    const int maxProc = procList.isEmpty() ? 1 : procList.first().second;
    for (int i = 0; i < kTopN; ++i) {
        if (i < procList.size()) {
            procRows_[i].nameLabel->setText(procList[i].first);
            procRows_[i].countLabel->setText(QString::number(procList[i].second));
            procRows_[i].bar->setValue(procList[i].second * 100 / maxProc);
        } else {
            procRows_[i].nameLabel->setText("—");
            procRows_[i].countLabel->setText("0");
            procRows_[i].bar->setValue(0);
        }
    }

    // Update MITRE rows
    QList<QPair<QString, int>> mitreList;
    for (auto it = mitreCount.begin(); it != mitreCount.end(); ++it)
        mitreList.append({it.key(), it.value()});
    std::sort(mitreList.begin(), mitreList.end(),
              [](const auto& a, const auto& b) { return a.second > b.second; });
    const int maxMitre = mitreList.isEmpty() ? 1 : mitreList.first().second;
    for (int i = 0; i < kMitreN; ++i) {
        if (i < mitreList.size()) {
            mitreRows_[i].tagLabel->setText(mitreList[i].first);
            mitreRows_[i].countLabel->setText(QString::number(mitreList[i].second));
            mitreRows_[i].bar->setValue(mitreList[i].second * 100 / maxMitre);
        } else {
            mitreRows_[i].tagLabel->setText("—");
            mitreRows_[i].countLabel->setText("0");
            mitreRows_[i].bar->setValue(0);
        }
    }

    // Session stats (simple derived values)
    const int critCount = sevCount[3];
    statLabels_[0]->setText("—");            // Endpoints (N/A without agent mgmt)
    statLabels_[1]->setText(QString::number(critCount));
    statLabels_[2]->setText("0");            // Blocked IPs (updated by ResponseEngine)
    statLabels_[3]->setText(QString::number(sevCount[0]));
    statLabels_[4]->setText(QString::number(critCount / 3 + 1));
    statLabels_[5]->setText("—");
}

} // namespace SS
