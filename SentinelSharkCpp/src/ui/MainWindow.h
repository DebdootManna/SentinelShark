#pragma once
#include <QMainWindow>
#include <QLabel>
#include <QTimer>
#include <QSplitter>
#include <QTableView>
#include <QComboBox>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QTabWidget>
#include <memory>
#include "../core/PacketRecord.h"
#include "../core/BoundedQueue.h"
#include "../model/PacketTableModel.h"
#include "../correlation/SocketPollThread.h"
#include "../udm/UdmNormalizer.h"

namespace SS {

class InspectionPanel;
class DetectionDetailPanel;
class StatsPanel;
class HexView;
class ThreatIntelWorker;
class CaptureThread;
class MockCaptureThread;
class SettingsDialog;
class InterfaceSelectionDialog;

/// The application main window — Wireshark on top, SecOps/EDR on the bottom.
/// 
/// Top: Wireshark Control Bar
///   [Interface: combo] [BPF Filter: edit] [▶ Start Capture] [⏹ Stop] [Clear] [Save] [API Keys]
/// Upper: High-performance QTableView (PacketTableModel)
/// Lower: 3-Panel Incident Response Layout:
///   [Host & Process Forensics] [Detection Detail & IR Actions] [Live Analytics & Stats]
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);
    ~MainWindow() override;

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    // Startup prompt
    void promptInterfaceSelection();

    // Packet queue drain — called by drainTimer_ every 40ms
    void drainQueue();

    // Analytics refresh — called every 5 seconds
    void refreshAnalytics();

    // Row selection
    void onRowSelected(const QModelIndex& current, const QModelIndex& previous);

    // Threat intel result
    void onThreatIntelComplete(const ThreatIntelResult& result);

    // Response actions
    void onKillRequested(uint32_t pid, const QString& processName);
    void onBlockIpRequested(const QString& ip);
    void onQuarantineRequested(uint32_t pid, const QString& processName);

    // Response result
    void onActionCompleted(bool success, const QString& message);

    // Capture control (Wireshark-style)
    void startCapture();
    void stopCapture();
    void clearPackets();
    void savePcap();
    void toggleMockMode();

    // Toast
    void showToast(const QString& message, int durationMs = 3000);

    // Status bar clock
    void updateClock();

    // Settings
    void openSettings();

    // Filter buttons
    void setSeverityFilter(int severity); // -1 = all

private:
    void setupUi();
    void setupWiresharkControlBar(QVBoxLayout* parentLayout);
    void setupFilterToolbar(QVBoxLayout* parentLayout);
    void setupStatusBar();
    void checkTsharkDependency();

    // ── Bounded queue (shared with capture thread) ─────────────────────────
    BoundedQueue<PacketRecord, 300> queue_;

    // ── Model ──────────────────────────────────────────────────────────────
    PacketTableModel* model_ = nullptr;

    // ── Timers ─────────────────────────────────────────────────────────────
    QTimer* drainTimer_     = nullptr;  // 40ms — drains queue → model
    QTimer* analyticsTimer_ = nullptr;  // 5s   — refreshes analytics sidebar
    QTimer* clockTimer_     = nullptr;  // 1s   — updates live clock
    QTimer* toastTimer_     = nullptr;  // dismisses toast

    // ── Wireshark Top Control Bar Widgets ──────────────────────────────────
    QComboBox*           ifaceCombo_      = nullptr;
    QLineEdit*           bpfEdit_         = nullptr;
    QPushButton*         startBtn_        = nullptr;
    QPushButton*         stopBtn_         = nullptr;
    QPushButton*         clearBtn_        = nullptr;
    QPushButton*         saveBtn_         = nullptr;
    QPushButton*         apiBtn_          = nullptr;
    QPushButton*         mockBtn_         = nullptr;

    // ── Status Bar / Counters ──────────────────────────────────────────────
    QLabel*              pktCountLabel_   = nullptr;
    QLabel*              clockLabel_      = nullptr;
    QLabel*              criticalLabel_   = nullptr;
    QLabel*              sensorLabel_     = nullptr;
    QLabel*              tsharkStatusLabel_ = nullptr;
    QLabel*              captureStatusLabel_ = nullptr;
    QWidget*             toastWidget_     = nullptr;
    QLabel*              toastLabel_      = nullptr;
    QTableView*          tableView_       = nullptr;

    // ── Panels ─────────────────────────────────────────────────────────────
    InspectionPanel*      inspectionPanel_ = nullptr;
    DetectionDetailPanel* detailPanel_     = nullptr;
    QTabWidget*           rightTabs_       = nullptr;
    StatsPanel*           statsPanel_      = nullptr;
    HexView*              hexView_         = nullptr;

    // ── Services ───────────────────────────────────────────────────────────
    ThreatIntelWorker*   threatIntel_      = nullptr;
    CaptureThread*       captureThread_    = nullptr;
    MockCaptureThread*   mockThread_       = nullptr;
    SettingsDialog*      settingsDialog_   = nullptr;

    // ── State ──────────────────────────────────────────────────────────────
    int      currentSeverityFilter_ = -1;  // -1 = all
    int      selectedRow_           = -1;
    uint64_t pktCount_             = 0;
    int      totalCrit_             = 0;

    // Cached data for selected row
    ProcessInfo       selectedProc_;
    ThreatIntelResult selectedIntel_;
};

} // namespace SS
