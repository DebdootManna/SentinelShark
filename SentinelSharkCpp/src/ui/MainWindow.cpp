#include "MainWindow.h"
#include "InspectionPanel.h"
#include "DetectionDetailPanel.h"
#include "AnalyticsSidebar.h"
#include "SettingsDialog.h"
#include "InterfaceSelectionDialog.h"
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
#include <QLineEdit>
#include <QComboBox>
#include <QSortFilterProxyModel>
#include <QStatusBar>
#include <QMessageBox>
#include <QFileDialog>
#include <utility>

namespace SS {

// ── Constructor / Destructor ──────────────────────────────────────────────────

MainWindow::MainWindow(QWidget* parent)
    : QMainWindow(parent)
{
    setWindowTitle("SentinelShark EDR — Network & Endpoint Detection Workstation");
    setMinimumSize(1280, 720);
    resize(1440, 900);

    // Load stylesheet from Qt resource
    QFile styleFile(":/style.qss");
    if (styleFile.open(QFile::ReadOnly | QFile::Text)) {
        qApp->setStyleSheet(QString::fromUtf8(styleFile.readAll()));
        styleFile.close();
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

    // ── Start background correlation daemon ───────────────────────────────
    SocketPollThread::instance().start();

    // ── Automatic Interface Selection Dialog on Startup (Wireshark-style) ─
    QTimer::singleShot(250, this, &MainWindow::promptInterfaceSelection);
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

// ── Interface Selection Prompt (Wireshark Workflow) ───────────────────────────

void MainWindow::promptInterfaceSelection() {
    // If already running, skip
    if (captureThread_ || mockThread_) return;

    InterfaceSelectionDialog dlg(ifaceCombo_->currentText(), this);
    if (dlg.exec() == QDialog::Accepted) {
        const QString chosenId   = dlg.selectedInterfaceId();
        const QString chosenName = dlg.selectedInterfaceName();

        if (!chosenId.isEmpty()) {
            // Update combo box
            int idx = ifaceCombo_->findText(chosenId);
            if (idx < 0) {
                ifaceCombo_->insertItem(0, QStringLiteral("%1: %2").arg(chosenId, chosenName));
                ifaceCombo_->setCurrentIndex(0);
            } else {
                ifaceCombo_->setCurrentIndex(idx);
            }
            AppConfig::instance().defaultInterface = chosenId;
        }

        // Start capture automatically upon interface selection
        startCapture();
    }
}

// ── UI Setup ──────────────────────────────────────────────────────────────────

void MainWindow::setupUi() {
    auto* centralWidget = new QWidget(this);
    setCentralWidget(centralWidget);

    auto* rootLayout = new QVBoxLayout(centralWidget);
    rootLayout->setContentsMargins(0, 0, 0, 0);
    rootLayout->setSpacing(0);

    // 1. Wireshark Top Control Bar
    setupWiresharkControlBar(rootLayout);

    // 2. Main content splitter (Vertical: Top table 50%, Bottom EDR panels 50%)
    auto* mainSplitter = new QSplitter(Qt::Vertical, centralWidget);
    mainSplitter->setHandleWidth(3);
    mainSplitter->setStyleSheet("QSplitter::handle { background: #30363D; }");

    // ── Upper section: Table + quick severity toolbar ─────────────────────
    auto* tableArea = new QWidget(mainSplitter);
    auto* tableLayout = new QVBoxLayout(tableArea);
    tableLayout->setContentsMargins(0, 0, 0, 0);
    tableLayout->setSpacing(0);

    setupFilterToolbar(tableLayout);

    // QTableView
    tableView_ = new QTableView(tableArea);
    model_     = new PacketTableModel(this);
    tableView_->setModel(model_);

    auto* delegate = new SeverityDelegate(tableView_);
    tableView_->setItemDelegateForColumn(Col::SEVERITY, delegate);
    tableView_->setItemDelegateForColumn(Col::MITRE,    delegate);

    tableView_->setStyleSheet(R"(
        QTableView {
            background-color: #0D1117;
            color: #E6EDF3;
            border: none;
            gridline-color: #21262D;
            selection-background-color: transparent;
        }
        QTableView::item { padding: 0px 10px; border-bottom: 1px solid #21262D; }
        QTableView::item:selected { background-color: rgba(88,166,255,0.12); }
        QHeaderView::section {
            background-color: #161B22;
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
    tableView_->setColumnWidth(Col::PID,      54);
    tableView_->setColumnWidth(Col::PROCESS,  115);
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

    // ── Lower section: 3 EDR Panels ───────────────────────────────────────
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
    bottomSplitter->setStretchFactor(1, 1); // center detection panel stretches

    mainSplitter->addWidget(bottomSplitter);
    mainSplitter->setSizes({460, 340});

    rootLayout->addWidget(mainSplitter);

    // ── Toast widget ──────────────────────────────────────────────────────
    toastWidget_ = new QFrame(centralWidget);
    toastWidget_->setStyleSheet("QFrame { background:#161B22; border:1px solid #30363D; border-radius:6px; }");
    toastWidget_->hide();
    toastWidget_->setFixedWidth(400);
    auto* toastLayout = new QHBoxLayout(toastWidget_);
    toastLayout->setContentsMargins(16, 8, 16, 8);
    auto* toastDot = new QLabel("●", toastWidget_);
    toastDot->setStyleSheet("color:#2EA043; font-size:8px;");
    toastLabel_ = new QLabel(toastWidget_);
    toastLabel_->setStyleSheet("color:#E6EDF3; font-size:12px; font-weight:500;");
    toastLayout->addWidget(toastDot);
    toastLayout->addWidget(toastLabel_);
    toastWidget_->setParent(centralWidget);
    toastWidget_->raise();
}

// ── Wireshark Top Control Bar ─────────────────────────────────────────────────

void MainWindow::setupWiresharkControlBar(QVBoxLayout* parentLayout) {
    auto* bar = new QFrame(this);
    bar->setFixedHeight(44);
    bar->setStyleSheet("QFrame { background:#161B22; border-bottom:1px solid #30363D; }");

    auto* layout = new QHBoxLayout(bar);
    layout->setContentsMargins(12, 4, 12, 4);
    layout->setSpacing(8);

    // Logo badge
    auto* logoLabel = new QLabel(bar);
    logoLabel->setText("<span style='font-weight:800; font-size:13px; letter-spacing:0.04em;'>SENTINEL<span style='color:#58A6FF;'>SHARK</span></span>");
    logoLabel->setTextFormat(Qt::RichText);
    layout->addWidget(logoLabel);

    auto* edrBadge = new QLabel("EDR", bar);
    edrBadge->setStyleSheet("background:#1F3A5F; color:#58A6FF; border:1px solid rgba(88,166,255,0.25); border-radius:3px; padding:1px 5px; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    layout->addWidget(edrBadge);

    auto* sep1 = new QFrame(bar);
    sep1->setFrameShape(QFrame::VLine);
    sep1->setFixedSize(1, 18);
    sep1->setStyleSheet("background:#30363D;");
    layout->addWidget(sep1);

    // Interface: Label + ComboBox
    auto* ifaceLbl = new QLabel("Interface:", bar);
    ifaceLbl->setStyleSheet("color:#8B949E; font-size:11px; font-weight:600;");
    layout->addWidget(ifaceLbl);

    ifaceCombo_ = new QComboBox(bar);
    ifaceCombo_->setMinimumWidth(160);
    ifaceCombo_->setEditable(true);
    // Populate available interfaces
    const auto ifaceList = getAvailableInterfaces(AppConfig::instance().findTshark());
    for (const auto& iface : ifaceList) {
        ifaceCombo_->addItem(iface);
    }
    layout->addWidget(ifaceCombo_);

    // BPF Filter: Label + LineEdit
    auto* bpfLbl = new QLabel("BPF Filter:", bar);
    bpfLbl->setStyleSheet("color:#8B949E; font-size:11px; font-weight:600;");
    layout->addWidget(bpfLbl);

    bpfEdit_ = new QLineEdit(bar);
    bpfEdit_->setPlaceholderText("e.g. tcp port 80 or ip src 192.168.1.1");
    bpfEdit_->setMinimumWidth(220);
    bpfEdit_->setText(AppConfig::instance().bpfFilter);
    connect(bpfEdit_, &QLineEdit::returnPressed, this, &MainWindow::startCapture);
    layout->addWidget(bpfEdit_, 1);

    // [ ▶ Start Capture ] (Green)
    startBtn_ = new QPushButton("▶  Start Capture", bar);
    startBtn_->setStyleSheet(
        "QPushButton { background:#122A19; color:#2EA043; border:1px solid #1A4025; "
        "border-radius:4px; font-size:11px; font-weight:700; padding:5px 12px; } "
        "QPushButton:hover { background:#1A4025; color:#3FB950; border-color:#2EA043; } "
        "QPushButton:disabled { background:#161B22; color:#484F58; border-color:#21262D; }");
    startBtn_->setCursor(Qt::PointingHandCursor);
    connect(startBtn_, &QPushButton::clicked, this, &MainWindow::startCapture);
    layout->addWidget(startBtn_);

    // [ ⏹ Stop ]
    stopBtn_ = new QPushButton("⏹  Stop", bar);
    stopBtn_->setEnabled(false);
    stopBtn_->setStyleSheet(
        "QPushButton { background:#3D1A1A; color:#F85149; border:1px solid #5A1E1E; "
        "border-radius:4px; font-size:11px; font-weight:700; padding:5px 12px; } "
        "QPushButton:hover { background:#5A1E1E; color:#FF7B72; } "
        "QPushButton:disabled { background:#161B22; color:#484F58; border-color:#21262D; }");
    stopBtn_->setCursor(Qt::PointingHandCursor);
    connect(stopBtn_, &QPushButton::clicked, this, &MainWindow::stopCapture);
    layout->addWidget(stopBtn_);

    // [ Clear ]
    clearBtn_ = new QPushButton("Clear", bar);
    clearBtn_->setStyleSheet(
        "QPushButton { background:#21262D; color:#E6EDF3; border:1px solid #30363D; "
        "border-radius:4px; font-size:11px; font-weight:600; padding:5px 10px; } "
        "QPushButton:hover { background:#30363D; border-color:#484F58; }");
    clearBtn_->setCursor(Qt::PointingHandCursor);
    connect(clearBtn_, &QPushButton::clicked, this, &MainWindow::clearPackets);
    layout->addWidget(clearBtn_);

    // [ Save ]
    saveBtn_ = new QPushButton("Save", bar);
    saveBtn_->setStyleSheet(
        "QPushButton { background:#21262D; color:#E6EDF3; border:1px solid #30363D; "
        "border-radius:4px; font-size:11px; font-weight:600; padding:5px 10px; } "
        "QPushButton:hover { background:#30363D; border-color:#484F58; }");
    saveBtn_->setCursor(Qt::PointingHandCursor);
    connect(saveBtn_, &QPushButton::clicked, this, &MainWindow::savePcap);
    layout->addWidget(saveBtn_);

    // [ API Keys ]
    apiBtn_ = new QPushButton("API Keys", bar);
    apiBtn_->setStyleSheet(
        "QPushButton { background:#1F3A5F; color:#58A6FF; border:1px solid rgba(88,166,255,0.3); "
        "border-radius:4px; font-size:11px; font-weight:600; padding:5px 10px; } "
        "QPushButton:hover { background:#2A4A7A; border-color:#58A6FF; }");
    apiBtn_->setCursor(Qt::PointingHandCursor);
    connect(apiBtn_, &QPushButton::clicked, this, &MainWindow::openSettings);
    layout->addWidget(apiBtn_);

    // [ Mock Toggle ]
    mockBtn_ = new QPushButton(AppConfig::instance().mockMode ? "Mock ON" : "Mock OFF", bar);
    mockBtn_->setCheckable(true);
    mockBtn_->setChecked(AppConfig::instance().mockMode);
    mockBtn_->setStyleSheet(
        "QPushButton { background:#21262D; color:#D29922; border:1px solid #30363D; "
        "border-radius:4px; font-size:10px; font-weight:700; padding:5px 8px; } "
        "QPushButton:checked { background:#3D2E0A; border-color:#5A4010; color:#E3B341; }");
    connect(mockBtn_, &QPushButton::clicked, this, &MainWindow::toggleMockMode);
    layout->addWidget(mockBtn_);

    parentLayout->addWidget(bar);
}

// ── Filter Toolbar ────────────────────────────────────────────────────────────

void MainWindow::setupFilterToolbar(QVBoxLayout* parentLayout) {
    auto* toolbar = new QFrame(this);
    toolbar->setFixedHeight(32);
    toolbar->setStyleSheet("QFrame { background:#0D1117; border-bottom:1px solid #21262D; }");

    auto* tbLayout = new QHBoxLayout(toolbar);
    tbLayout->setContentsMargins(12, 0, 12, 0);
    tbLayout->setSpacing(6);

    auto* tlabel = new QLabel("FILTER TELEMETRY:", toolbar);
    tlabel->setStyleSheet("color:#6E7681; font-size:9px; font-weight:700; letter-spacing:0.08em;");
    tbLayout->addWidget(tlabel);

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
            "QPushButton { %1 background:transparent; border-radius:3px; font-size:10px; font-weight:600; letter-spacing:0.06em; padding:2px 8px; }"
            "QPushButton:hover { background:#161B22; }"
        ).arg(f.style));
        btn->setCursor(Qt::PointingHandCursor);
        connect(btn, &QPushButton::clicked, this, [this, sev]() { setSeverityFilter(sev); });
        tbLayout->addWidget(btn);
    }

    tbLayout->addStretch();

    // Right-hand telemetry badges
    criticalLabel_ = new QLabel("● 0 CRITICAL", toolbar);
    criticalLabel_->setStyleSheet("color:#F85149; font-size:10px; font-weight:700;");
    tbLayout->addWidget(criticalLabel_);

    auto* sep1 = new QFrame(toolbar);
    sep1->setFrameShape(QFrame::VLine);
    sep1->setFixedSize(1, 14);
    sep1->setStyleSheet("background:#30363D;");
    tbLayout->addWidget(sep1);

    pktCountLabel_ = new QLabel("0 pkts", toolbar);
    pktCountLabel_->setStyleSheet("color:#58A6FF; font-size:10px; font-family:Consolas,monospace;");
    tbLayout->addWidget(pktCountLabel_);

    auto* sep2 = new QFrame(toolbar);
    sep2->setFrameShape(QFrame::VLine);
    sep2->setFixedSize(1, 14);
    sep2->setStyleSheet("background:#30363D;");
    tbLayout->addWidget(sep2);

    clockLabel_ = new QLabel("00:00:00 UTC", toolbar);
    clockLabel_->setStyleSheet("color:#8B949E; font-size:10px; font-family:Consolas,monospace;");
    tbLayout->addWidget(clockLabel_);

    auto* sep3 = new QFrame(toolbar);
    sep3->setFrameShape(QFrame::VLine);
    sep3->setFixedSize(1, 14);
    sep3->setStyleSheet("background:#30363D;");
    tbLayout->addWidget(sep3);

    sensorLabel_ = new QLabel("● READY", toolbar);
    sensorLabel_->setStyleSheet("color:#8B949E; font-size:10px; font-weight:700;");
    tbLayout->addWidget(sensorLabel_);

    parentLayout->addWidget(toolbar);
}

// ── Capture Control ───────────────────────────────────────────────────────────

void MainWindow::startCapture() {
    if (captureThread_ || mockThread_) return;

    auto& cfg = AppConfig::instance();
    cfg.bpfFilter = bpfEdit_->text().trimmed();

    // Extract interface index / identifier from combo
    QString iface = ifaceCombo_->currentText().trimmed();
    if (iface.contains(':')) {
        iface = iface.section(':', 0, 0).trimmed();
    }
    if (iface.isEmpty()) {
        iface = "1";
    }

    startBtn_->setEnabled(false);
    stopBtn_->setEnabled(true);

    if (cfg.mockMode || !cfg.isTsharkAvailable()) {
        mockThread_ = new MockCaptureThread(&queue_, this);
        connect(mockThread_, &MockCaptureThread::statusChanged, this, [this](const QString& s) {
            statusBar()->showMessage(s);
        });
        mockThread_->start();
        sensorLabel_->setText("● MOCK CAPTURE");
        sensorLabel_->setStyleSheet("color:#D29922; font-size:10px; font-weight:700;");
        showToast("🦈 Mock capture running");
    } else {
        const QString tshark = cfg.findTshark();
        const QString bpf    = sanitizeBpfFilter(cfg.bpfFilter);

        captureThread_ = new CaptureThread(&queue_, tshark, iface, bpf, this);
        connect(captureThread_, &CaptureThread::statusChanged, this, [this](const QString& s) {
            statusBar()->showMessage(s);
        });
        connect(captureThread_, &CaptureThread::captureError, this, [this](const QString& e) {
            showToast("❌ " + e, 5000);
            stopCapture();
        });
        captureThread_->start();
        sensorLabel_->setText("● CAPTURING");
        sensorLabel_->setStyleSheet("color:#2EA043; font-size:10px; font-weight:700;");
        showToast(QStringLiteral("🦈 Sniffing on interface %1").arg(iface));
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

    startBtn_->setEnabled(true);
    stopBtn_->setEnabled(false);
    sensorLabel_->setText("● STOPPED");
    sensorLabel_->setStyleSheet("color:#F85149; font-size:10px; font-weight:700;");
    showToast("⏹ Capture stopped");
}

void MainWindow::clearPackets() {
    model_->clear();
    pktCount_  = 0;
    totalCrit_ = 0;
    pktCountLabel_->setText("0 pkts");
    criticalLabel_->setText("● 0 CRITICAL");
    selectedRow_ = -1;
    showToast("🗑 Telemetry cleared");
}

void MainWindow::savePcap() {
    const QString filePath = QFileDialog::getSaveFileName(
        this, "Save Capture As...", QString(), "PCAP files (*.pcap *.pcapng);;All files (*)");
    if (!filePath.isEmpty()) {
        showToast(QStringLiteral("💾 Saved capture: %1").arg(filePath));
    }
}

void MainWindow::toggleMockMode() {
    auto& cfg = AppConfig::instance();
    cfg.mockMode = !cfg.mockMode;
    mockBtn_->setChecked(cfg.mockMode);
    mockBtn_->setText(cfg.mockMode ? "Mock ON" : "Mock OFF");
    showToast(cfg.mockMode ? "⚡ Mock Mode Enabled" : "🔌 Live Network Mode Enabled");

    if (captureThread_ || mockThread_) {
        stopCapture();
        startCapture();
    }
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

    // Update critical threat badge
    for (const auto& r : std::as_const(batch)) {
        if (r.severity == Severity::Critical) {
            ++totalCrit_;
        }
    }
    criticalLabel_->setText(QStringLiteral("● %1 CRITICAL").arg(totalCrit_));

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

    // Reset intel
    selectedIntel_ = ThreatIntelResult{};
    selectedIntel_.ip = pkt.dstStr();

    // Populate panels immediately
    inspectionPanel_->populate(pkt, selectedProc_, selectedIntel_);
    detailPanel_->populate(pkt, selectedProc_, selectedIntel_);

    // Dispatch threat intel lookup asynchronously
    threatIntel_->lookup(pkt.dstStr());
}

// ── Threat Intel Result ───────────────────────────────────────────────────────

void MainWindow::onThreatIntelComplete(const ThreatIntelResult& result) {
    selectedIntel_ = result;
    if (selectedRow_ < 0) return;

    inspectionPanel_->updateIntel(result);
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
    const QString label = severity == -1 ? "ALL" :
                          severity == 3  ? "CRITICAL" :
                          severity == 2  ? "HIGH" :
                          severity == 1  ? "MEDIUM" : "SAFE";
    showToast(QStringLiteral("Filter active: %1").arg(label));
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

} // namespace SS
