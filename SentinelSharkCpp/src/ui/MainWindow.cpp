#include "MainWindow.h"
#include "InspectionPanel.h"
#include "DetectionDetailPanel.h"
#include "AnalyticsSidebar.h"
#include "SettingsDialog.h"
#include "../model/SeverityDelegate.h"
#include "../capture/CaptureThread.h"
#include "../capture/MockCaptureThread.h"
#include "../capture/InterfaceScanner.h"
#include "../correlation/SocketPollThread.h"
#include "../correlation/ProcessNameCache.h"
#include "../config/AppConfig.h"
#include "../threatintel/ThreatIntelWorker.h"
#include "../response/ResponseEngine.h"
#include <QApplication>
#include <QClipboard>
#include <QFile>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QDateTime>
#include <QCloseEvent>
#include <QScrollBar>
#include <QFrame>
#include <QSplitter>
#include <QFont>
#include <QLabel>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStatusBar>
#include <QMessageBox>
#include <QGraphicsOpacityEffect>
#include <QPropertyAnimation>

namespace SS {

// ── Constructor / Destructor ──────────────────────────────────────────────────

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("SentinelShark EDR");
    setMinimumSize(1280, 720);
    resize(1440, 900);

    // Load stylesheet from resource
    QFile styleFile(":/style.qss");
    if (styleFile.open(QFile::ReadOnly)) {
        qApp->setStyleSheet(styleFile.readAll());
    }

    setupUi();

    // ── Timers ────────────────────────────────────────────────────────────
    drainTimer_ = new QTimer(this);
    drainTimer_->setInterval(40); // 25 FPS
    connect(drainTimer_, &QTimer::timeout, this, &MainWindow::drainQueue);
    drainTimer_->start();

    analyticsTimer_ = new QTimer(this);
    analyticsTimer_->setInterval(5000);
    connect(analyticsTimer_, &QTimer::timeout, this, &MainWindow::refreshAnalytics);
    analyticsTimer_->start();

    clockTimer_ = new QTimer(this);
    clockTimer_->setInterval(1000);
    connect(clockTimer_, &QTimer::timeout, this, &MainWindow::updateClock);
    clockTimer_->start();
    updateClock();

    toastTimer_ = new QTimer(this);
    toastTimer_->setSingleShot(true);
    connect(toastTimer_, &QTimer::timeout, this, [this]() {
        if (toastWidget_) toastWidget_->hide();
    });

    // ── Services ─────────────────────────────────────────────────────────
    threatIntel_ = new ThreatIntelWorker(this);
    connect(threatIntel_, &ThreatIntelWorker::lookupComplete,
            this, &MainWindow::onThreatIntelComplete);

    // ── Start background threads ──────────────────────────────────────────
    SocketPollThread::instance().start();

    // Auto-start in mock mode if no tshark
    if (AppConfig::instance().mockMode || !AppConfig::instance().isTsharkAvailable()) {
        startCapture();
    }
}

MainWindow::~MainWindow() {
    stopCapture();
    SocketPollThread::instance().stop();
    SocketPollThread::instance().wait(3000);
}

void MainWindow::closeEvent(QCloseEvent* event) {
    stopCapture();
    event->accept();
}

// ── UI Setup ──────────────────────────────────────────────────────────────────

void MainWindow::setupUi() {
    auto* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    auto* rootLayout = new QVBoxLayout(centralWidget);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // ── TitleBar (h=40) ───────────────────────────────────────────────────
    setupTitleBar();
    rootLayout->addWidget(titleBar_);

    // ── Main content ──────────────────────────────────────────────────────
    auto* mainSplitter = new QSplitter(Qt::Vertical, centralWidget);
    mainSplitter->setHandleWidth(2);
    mainSplitter->setStyleSheet("QSplitter::handle { background: #30363D; }");

    // ── TOP: Table area ───────────────────────────────────────────────────
    auto* tableArea = new QWidget(mainSplitter);
    auto* tableLayout = new QVBoxLayout(tableArea);
    tableLayout->setContentsMargins(0, 0, 0, 0);
    tableLayout->setSpacing(0);

    setupTableToolbar();
    tableLayout->addWidget(titleBar_->findChild<QWidget*>("tableToolbar")); // re-parent below

    // Create the actual toolbar widget
    auto* toolbar = new QFrame(tableArea);
    toolbar->setFixedHeight(34);
    toolbar->setStyleSheet("QFrame { background:#161B22; border-bottom:1px solid #30363D; }");
    auto* tbLayout = new QHBoxLayout(toolbar);
    tbLayout->setContentsMargins(12, 0, 12, 0);
    tbLayout->setSpacing(6);

    auto* tlabel = new QLabel("🦈  LIVE TELEMETRY", toolbar);
    tlabel->setStyleSheet("color:#8B949E; font-size:10px; font-weight:700; letter-spacing:0.08em;");
    tbLayout->addWidget(tlabel);

    auto* sep1 = new QFrame(toolbar);
    sep1->setFrameShape(QFrame::VLine);
    sep1->setStyleSheet("color:#30363D;");
    sep1->setFixedWidth(1);
    tbLayout->addWidget(sep1);

    // Severity filter pills
    const struct { const char* label; int sev; const char* style; } kFilters[] = {
        {"ALL",      -1, "color:#8B949E; border:1px solid transparent;"},
        {"CRITICAL",  3, "color:#F85149; border:1px solid transparent;"},
        {"HIGH",      2, "color:#FF7B72; border:1px solid transparent;"},
        {"MEDIUM",    1, "color:#D29922; border:1px solid transparent;"},
        {"SAFE",      0, "color:#2EA043; border:1px solid transparent;"},
    };
    for (const auto& f : kFilters) {
        auto* btn = new QPushButton(f.label, toolbar);
        const int sev = f.sev;
        btn->setStyleSheet(QStringLiteral(
            "QPushButton { %1 background:transparent; border-radius:3px; font-size:10px; font-weight:600; letter-spacing:0.06em; padding:2px 8px; cursor:pointer; }"
            "QPushButton:hover { background:#1C2128; }"
        ).arg(f.style));
        btn->setCursor(Qt::PointingHandCursor);
        connect(btn, &QPushButton::clicked, this, [this, sev]() { setSeverityFilter(sev); });
        tbLayout->addWidget(btn);
    }

    tbLayout->addStretch();

    startBtn_ = new QPushButton("▶  Start", toolbar);
    startBtn_->setStyleSheet("QPushButton { background:#122A19; color:#2EA043; border:1px solid #1A4025; border-radius:3px; font-size:10px; font-weight:700; padding:3px 10px; } QPushButton:hover { background:#1A4025; }");
    startBtn_->setCursor(Qt::PointingHandCursor);
    connect(startBtn_, &QPushButton::clicked, this, &MainWindow::startCapture);

    stopBtn_ = new QPushButton("■  Stop", toolbar);
    stopBtn_->setStyleSheet("QPushButton { background:#3D1A1A; color:#F85149; border:1px solid #5A1E1E; border-radius:3px; font-size:10px; font-weight:700; padding:3px 10px; } QPushButton:hover { background:#5A1E1E; }");
    stopBtn_->setCursor(Qt::PointingHandCursor);
    connect(stopBtn_, &QPushButton::clicked, this, &MainWindow::stopCapture);

    auto* settingsBtn = new QPushButton("⚙", toolbar);
    settingsBtn->setFixedWidth(28);
    settingsBtn->setStyleSheet("QPushButton { background:transparent; color:#8B949E; border:none; font-size:14px; } QPushButton:hover { color:#E6EDF3; }");
    settingsBtn->setCursor(Qt::PointingHandCursor);
    connect(settingsBtn, &QPushButton::clicked, this, &MainWindow::openSettings);

    tbLayout->addWidget(startBtn_);
    tbLayout->addWidget(stopBtn_);
    tbLayout->addWidget(settingsBtn);

    tableLayout->addWidget(toolbar);

    // QTableView
    tableView_ = new QTableView(tableArea);
    model_     = new PacketTableModel(this);
    tableView_->setModel(model_);

    auto* delegate = new SeverityDelegate(tableView_);
    tableView_->setItemDelegateForColumn(Col::SEVERITY, delegate);
    tableView_->setItemDelegateForColumn(Col::MITRE,    delegate);

    tableView_->setStyleSheet(R"(
        QTableView {
            background: #0D1117;
            color: #E6EDF3;
            border: none;
            gridline-color: #21262D;
            selection-background-color: transparent;
        }
        QTableView::item { padding: 0px 10px; border-bottom: 1px solid #21262D; }
        QTableView::item:selected { background: rgba(88,166,255,0.1); }
        QHeaderView::section {
            background: #161B22;
            color: #8B949E;
            font-size: 9px;
            font-weight: 700;
            letter-spacing: 0.8px;
            border: none;
            border-bottom: 1px solid #30363D;
            padding: 5px 10px;
        }
    )");
    tableView_->setAlternatingRowColors(false);
    tableView_->setSelectionBehavior(QAbstractItemView::SelectRows);
    tableView_->setSelectionMode(QAbstractItemView::SingleSelection);
    tableView_->setShowGrid(false);
    tableView_->verticalHeader()->setVisible(false);
    tableView_->verticalHeader()->setDefaultSectionSize(24);
    tableView_->horizontalHeader()->setStretchLastSection(true);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::NO,       QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::TIME,     QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::PID,      QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::PROCESS,  QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::SOURCE,   QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::DEST,     QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::PROTOCOL, QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::LENGTH,   QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::MITRE,    QHeaderView::Fixed);
    tableView_->horizontalHeader()->setSectionResizeMode(Col::SEVERITY, QHeaderView::Fixed);
    tableView_->setColumnWidth(Col::NO,       44);
    tableView_->setColumnWidth(Col::TIME,     90);
    tableView_->setColumnWidth(Col::PID,      52);
    tableView_->setColumnWidth(Col::PROCESS,  110);
    tableView_->setColumnWidth(Col::SOURCE,   145);
    tableView_->setColumnWidth(Col::DEST,     145);
    tableView_->setColumnWidth(Col::PROTOCOL, 64);
    tableView_->setColumnWidth(Col::LENGTH,   55);
    tableView_->setColumnWidth(Col::MITRE,    88);
    tableView_->setColumnWidth(Col::SEVERITY, 78);

    connect(tableView_->selectionModel(),
            &QItemSelectionModel::currentRowChanged,
            this, &MainWindow::onRowSelected);

    tableLayout->addWidget(tableView_);
    mainSplitter->addWidget(tableArea);

    // ── BOTTOM: 3 panels ──────────────────────────────────────────────────
    auto* bottomSplitter = new QSplitter(Qt::Horizontal, mainSplitter);
    bottomSplitter->setHandleWidth(2);
    bottomSplitter->setStyleSheet("QSplitter::handle { background: #30363D; }");

    inspectionPanel_ = new InspectionPanel(bottomSplitter);
    connect(inspectionPanel_, &InspectionPanel::copyRequested, this, [this](const QString& t) {
        QApplication::clipboard()->setText(t);
        showToast("📋 Copied to clipboard");
    });

    detailPanel_ = new DetectionDetailPanel(bottomSplitter);
    connect(detailPanel_, &DetectionDetailPanel::killProcessRequested,
            this, &MainWindow::onKillRequested);
    connect(detailPanel_, &DetectionDetailPanel::blockIpRequested,
            this, &MainWindow::onBlockIpRequested);
    connect(detailPanel_, &DetectionDetailPanel::quarantineRequested,
            this, &MainWindow::onQuarantineRequested);
    connect(detailPanel_, &DetectionDetailPanel::udmJsonCopied, this, [this](const QString&) {
        showToast("📋 UDM JSON copied to clipboard");
    });

    analyticsPanel_ = new AnalyticsSidebar(bottomSplitter);

    bottomSplitter->addWidget(inspectionPanel_);
    bottomSplitter->addWidget(detailPanel_);
    bottomSplitter->addWidget(analyticsPanel_);
    bottomSplitter->setStretchFactor(1, 1); // center panel stretches

    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setSizes({450, 350}); // 45% / 55% split

    rootLayout->addWidget(mainSplitter);

    // ── Toast ─────────────────────────────────────────────────────────────
    toastWidget_ = new QFrame(centralWidget);
    toastWidget_->setStyleSheet("QFrame { background:#161B22; border:1px solid #30363D; border-radius:6px; }");
    toastWidget_->hide();
    toastWidget_->setFixedWidth(400);
    auto* toastLayout = new QHBoxLayout(toastWidget_);
    toastLayout->setContentsMargins(18, 10, 18, 10);
    auto* toastDot = new QLabel("●", toastWidget_);
    toastDot->setStyleSheet("color:#2EA043; font-size:8px;");
    toastLabel_ = new QLabel(toastWidget_);
    toastLabel_->setStyleSheet("color:#E6EDF3; font-size:12px; font-weight:500;");
    toastLayout->addWidget(toastDot);
    toastLayout->addWidget(toastLabel_);
    toastWidget_->setParent(centralWidget);
    toastWidget_->raise();
}

void MainWindow::setupTitleBar() {
    titleBar_ = new QWidget(this);
    titleBar_->setFixedHeight(40);
    titleBar_->setObjectName("TitleBar");
    titleBar_->setStyleSheet("QWidget#TitleBar { background:#161B22; border-bottom:1px solid #30363D; }");

    auto* layout = new QHBoxLayout(titleBar_);
    layout->setContentsMargins(16, 0, 16, 0);
    layout->setSpacing(0);

    // Logo
    auto* logoLabel = new QLabel(titleBar_);
    logoLabel->setText("<span style='font-weight:700; font-size:13px; letter-spacing:0.04em;'>SENTINEL<span style='color:#58A6FF;'>SHARK</span></span>");
    logoLabel->setTextFormat(Qt::RichText);
    auto* edrBadge = new QLabel("EDR", titleBar_);
    edrBadge->setStyleSheet("background:#1F3A5F; color:#58A6FF; border:1px solid rgba(88,166,255,0.13); border-radius:2px; padding:1px 5px; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    layout->addWidget(logoLabel);
    layout->addSpacing(8);
    layout->addWidget(edrBadge);
    layout->addSpacing(24);

    // Nav tabs
    const char* kTabs[] = {"Overview", "Detections", "Endpoints", "Hunt", "Intel", "Settings"};
    for (int i = 0; i < 6; ++i) {
        auto* btn = new QPushButton(kTabs[i], titleBar_);
        const bool active = (i == 0);
        btn->setStyleSheet(QStringLiteral(
            "QPushButton { padding:0 14px; height:40px; background:transparent; border:none; "
            "border-bottom: 2px solid %1; color:%2; font-size:11px; font-weight:%3; letter-spacing:0.04em; }"
            "QPushButton:hover { color:#E6EDF3; }")
                .arg(active ? "#58A6FF" : "transparent",
                     active ? "#58A6FF" : "#8B949E",
                     active ? "600" : "400"));
        btn->setFixedHeight(40);
        btn->setCursor(Qt::PointingHandCursor);
        if (i == 5) connect(btn, &QPushButton::clicked, this, &MainWindow::openSettings);
        layout->addWidget(btn);
    }

    layout->addStretch();

    // Critical alert indicator
    criticalLabel_ = new QLabel("● 0 CRITICAL", titleBar_);
    criticalLabel_->setStyleSheet("color:#F85149; font-size:10px; font-weight:600; letter-spacing:0.06em;");

    // Packet counter
    pktCountLabel_ = new QLabel("0 pkts", titleBar_);
    pktCountLabel_->setStyleSheet("color:#58A6FF; font-size:11px; font-family:'JetBrains Mono',Consolas;");

    // Clock
    clockLabel_ = new QLabel("00:00:00 UTC", titleBar_);
    clockLabel_->setStyleSheet("color:#8B949E; font-size:11px; font-family:'JetBrains Mono',Consolas;");

    // Sensor status
    sensorLabel_ = new QLabel("● SENSOR ONLINE", titleBar_);
    sensorLabel_->setStyleSheet("color:#2EA043; font-size:10px;");

    auto addSep = [&]() {
        auto* sep = new QFrame(titleBar_);
        sep->setFrameShape(QFrame::VLine);
        sep->setFixedSize(1, 16);
        sep->setStyleSheet("background:#30363D;");
        layout->addWidget(sep);
        layout->addSpacing(8);
    };

    layout->addWidget(criticalLabel_);
    layout->addSpacing(8); addSep();
    layout->addWidget(pktCountLabel_);
    layout->addSpacing(8); addSep();
    layout->addWidget(clockLabel_);
    layout->addSpacing(8); addSep();
    layout->addWidget(sensorLabel_);
}

void MainWindow::setupTableToolbar() {
    // Toolbar is created inline in setupUi() — this is intentionally a no-op here
}

// ── Capture Control ───────────────────────────────────────────────────────────

void MainWindow::startCapture() {
    if (captureThread_ || mockThread_) return;

    auto& cfg = AppConfig::instance();

    if (cfg.mockMode || !cfg.isTsharkAvailable()) {
        mockThread_ = new MockCaptureThread(&queue_, this);
        connect(mockThread_, &MockCaptureThread::statusChanged, this, [this](const QString& s) {
            statusBar()->showMessage(s);
        });
        mockThread_->start();
        sensorLabel_->setText("● MOCK CAPTURE");
        sensorLabel_->setStyleSheet("color:#D29922; font-size:10px;");
        showToast("🦈 Mock capture started");
    } else {
        const QString tshark = cfg.findTshark();
        const QString iface  = cfg.defaultInterface == "auto" ? "1" : cfg.defaultInterface;
        const QString bpf    = sanitizeBpfFilter(cfg.bpfFilter);

        captureThread_ = new CaptureThread(&queue_, tshark, iface, bpf, this);
        connect(captureThread_, &CaptureThread::statusChanged, this, [this](const QString& s) {
            statusBar()->showMessage(s);
        });
        connect(captureThread_, &CaptureThread::captureError, this, [this](const QString& e) {
            showToast("❌ " + e, 5000);
        });
        captureThread_->start();
        sensorLabel_->setText("● SENSOR ONLINE");
        sensorLabel_->setStyleSheet("color:#2EA043; font-size:10px;");
        showToast("🦈 Capture started on interface " + iface);
    }
}

void MainWindow::stopCapture() {
    if (captureThread_) {
        captureThread_->stop();
        captureThread_->wait(3000);
        captureThread_->deleteLater();
        captureThread_ = nullptr;
    }
    if (mockThread_) {
        mockThread_->stop();
        mockThread_->wait(3000);
        mockThread_->deleteLater();
        mockThread_ = nullptr;
    }
    sensorLabel_->setText("● SENSOR OFFLINE");
    sensorLabel_->setStyleSheet("color:#F85149; font-size:10px;");
}

// ── Queue Drain (40ms timer) ──────────────────────────────────────────────────

void MainWindow::drainQueue() {
    QVector<PacketRecord> batch;
    batch.reserve(50);

    PacketRecord rec;
    int drained = 0;
    while (drained < 50 && queue_.try_pop(rec)) {
        batch.append(rec);
        ++drained;
    }

    if (batch.isEmpty()) return;

    model_->addPackets(batch);
    pktCount_ += static_cast<uint64_t>(batch.size());
    pktCountLabel_->setText(QStringLiteral("%1 pkts").arg(pktCount_));

    // Count critical packets
    int crit = 0;
    for (const auto& r : std::as_const(batch))
        if (r.severity == Severity::Critical) ++crit;
    // Update critical counter label (cumulative)
    static int totalCrit = 0;
    totalCrit += crit;
    criticalLabel_->setText(QStringLiteral("● %1 CRITICAL").arg(totalCrit));

    // Auto-scroll
    if (AppConfig::instance().autoScroll) {
        tableView_->scrollToBottom();
    }
}

// ── Analytics (5s timer) ──────────────────────────────────────────────────────

void MainWindow::refreshAnalytics() {
    analyticsPanel_->refresh(model_->ringBuffer(), model_->totalReceived());
}

// ── Row Selection ─────────────────────────────────────────────────────────────

void MainWindow::onRowSelected(const QModelIndex& current, const QModelIndex&) {
    if (!current.isValid()) return;

    const int row = current.row();
    if (row < 0 || row >= model_->rowCount()) return;

    selectedRow_ = row;
    const PacketRecord& pkt = model_->recordAt(row);

    // Lazy: get process info from cache
    selectedProc_ = ProcessNameCache::instance().get(pkt.pid);
    if (selectedProc_.name.isEmpty()) {
        selectedProc_.pid  = pkt.pid;
        selectedProc_.name = pkt.processStr();
    }

    // Reset intel (will be populated asynchronously)
    selectedIntel_ = ThreatIntelResult{};
    selectedIntel_.ip = pkt.dstStr();

    // Populate panels immediately with what we have
    inspectionPanel_->populate(pkt, selectedProc_, selectedIntel_);
    detailPanel_->populate(pkt, selectedProc_, selectedIntel_);

    // Start async threat intel lookup
    threatIntel_->lookup(pkt.dstStr());
}

// ── Threat Intel Result ───────────────────────────────────────────────────────

void MainWindow::onThreatIntelComplete(const ThreatIntelResult& result) {
    selectedIntel_ = result;
    if (selectedRow_ < 0) return;

    inspectionPanel_->updateIntel(result);
    // Re-populate detail panel with enriched data
    if (selectedRow_ < model_->rowCount()) {
        const PacketRecord& pkt = model_->recordAt(selectedRow_);
        detailPanel_->populate(pkt, selectedProc_, result);
    }
}

// ── Response Actions ──────────────────────────────────────────────────────────

void MainWindow::onKillRequested(uint32_t pid, const QString& processName) {
    auto* worker = ResponseWorkerThread::killProcess(pid, processName, this);
    connect(worker, &ResponseWorkerThread::actionCompleted,
            this, &MainWindow::onActionCompleted);
    worker->start();
    showToast(QStringLiteral("⛔ Kill signal sent to PID %1 (%2)…").arg(pid).arg(processName));
}

void MainWindow::onBlockIpRequested(const QString& ip) {
    auto* worker = ResponseWorkerThread::blockIp(ip, this);
    connect(worker, &ResponseWorkerThread::actionCompleted,
            this, &MainWindow::onActionCompleted);
    worker->start();
    showToast(QStringLiteral("🛡 Creating firewall block rule for %1…").arg(ip));
}

void MainWindow::onQuarantineRequested(uint32_t pid, const QString& processName) {
    auto* worker = ResponseWorkerThread::quarantine(pid, this);
    connect(worker, &ResponseWorkerThread::actionCompleted,
            this, &MainWindow::onActionCompleted);
    worker->start();
    showToast(QStringLiteral("📦 Quarantining binary for %1 (PID %2)…").arg(processName).arg(pid));
}

void MainWindow::onActionCompleted(bool success, const QString& message) {
    showToast(success ? "✅ " + message : "❌ " + message, success ? 3000 : 5000);
    // Auto-delete the worker
    if (auto* worker = qobject_cast<ResponseWorkerThread*>(sender())) {
        worker->deleteLater();
    }
}

// ── UI Helpers ────────────────────────────────────────────────────────────────

void MainWindow::updateClock() {
    clockLabel_->setText(QDateTime::currentDateTimeUtc().toString("HH:mm:ss") + " UTC");
}

void MainWindow::showToast(const QString& message, int durationMs) {
    toastLabel_->setText(message);
    toastWidget_->adjustSize();

    // Center at bottom of window
    const QPoint center = rect().center();
    toastWidget_->move(center.x() - toastWidget_->width() / 2,
                        height() - toastWidget_->height() - 20);
    toastWidget_->show();
    toastWidget_->raise();

    toastTimer_->stop();
    toastTimer_->start(durationMs);
}

void MainWindow::setSeverityFilter(int severity) {
    currentSeverityFilter_ = severity;
    // TODO: connect to a QSortFilterProxyModel for live filtering
    // For now, just show a toast indicating filter state
    const QString label = severity == -1 ? "ALL" :
                          severity == 3  ? "CRITICAL" :
                          severity == 2  ? "HIGH" :
                          severity == 1  ? "MEDIUM" : "SAFE";
    showToast(QStringLiteral("Filter: %1").arg(label));
}

void MainWindow::openSettings() {
    if (!settingsDialog_) {
        settingsDialog_ = new SettingsDialog(this);
        connect(settingsDialog_, &SettingsDialog::settingsSaved, this, [this]() {
            threatIntel_->setApiKeys(
                AppConfig::instance().abuseipdbApiKey,
                AppConfig::instance().virustotalApiKey,
                AppConfig::instance().ipinfoApiKey,
                AppConfig::instance().shodanApiKey);
        });
    }
    settingsDialog_->exec();
}

// ── Helper: ring buffer accessor for AnalyticsSidebar ────────────────────────
// Forward declaration workaround — AnalyticsSidebar::refresh takes the ring buffer directly.
// We add a pass-through here.

} // namespace SS
