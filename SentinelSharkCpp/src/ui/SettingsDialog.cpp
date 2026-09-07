#include "SettingsDialog.h"
#include "../config/AppConfig.h"
#include "../capture/MockCaptureThread.h"
#include "../capture/InterfaceScanner.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QFileDialog>
#include <QDialogButtonBox>
#include <QMessageBox>

namespace SS {

SettingsDialog::SettingsDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("SentinelShark — Settings");
    setModal(true);
    setFixedSize(560, 540);
    setStyleSheet("QDialog { background:#0D1117; color:#E6EDF3; } "
                  "QGroupBox { color:#8B949E; border:1px solid #30363D; border-radius:4px; margin-top:8px; padding-top:12px; font-size:10px; font-weight:700; letter-spacing:0.08em; } "
                  "QGroupBox::title { subcontrol-origin:margin; left:10px; top:-4px; background:#0D1117; padding:0 4px; } "
                  "QLabel { color:#8B949E; font-size:10px; } "
                  "QLineEdit { background:#161B22; color:#E6EDF3; border:1px solid #30363D; border-radius:3px; padding:5px 8px; font-size:11px; font-family:'JetBrains Mono',Consolas; } "
                  "QLineEdit:focus { border-color:#58A6FF; } "
                  "QCheckBox { color:#E6EDF3; font-size:11px; } "
                  "QComboBox { background:#161B22; color:#E6EDF3; border:1px solid #30363D; border-radius:3px; padding:4px 8px; font-size:11px; } "
                  "QPushButton { border-radius:3px; padding:6px 14px; font-size:11px; font-weight:600; }");
    setupUi();
    loadFromConfig();
}

void SettingsDialog::setupUi() {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(16, 16, 16, 16);
    layout->setSpacing(12);

    // ── API Keys ──────────────────────────────────────────────────────────
    auto* apiGroup = new QGroupBox("THREAT INTEL API KEYS", this);
    auto* apiGrid  = new QGridLayout(apiGroup);
    apiGrid->setSpacing(8);
    const struct { const char* label; QLineEdit*& edit; } kApiFields[] = {
        {"AbuseIPDB Key",  abuseipdbEdit_},
        {"VirusTotal Key", virustotalEdit_},
        {"IPinfo Token",   ipinfoEdit_},
        {"Shodan API Key", shodanEdit_},
    };
    for (int i = 0; i < 4; ++i) {
        apiGrid->addWidget(new QLabel(kApiFields[i].label, apiGroup), i, 0);
        const_cast<QLineEdit*&>(kApiFields[i].edit) = new QLineEdit(apiGroup);
        const_cast<QLineEdit*&>(kApiFields[i].edit)->setEchoMode(QLineEdit::Password);
        const_cast<QLineEdit*&>(kApiFields[i].edit)->setPlaceholderText("(optional)");
        apiGrid->addWidget(const_cast<QLineEdit*&>(kApiFields[i].edit), i, 1);
    }
    abuseipdbEdit_  = qobject_cast<QLineEdit*>(apiGrid->itemAtPosition(0,1)->widget());
    virustotalEdit_ = qobject_cast<QLineEdit*>(apiGrid->itemAtPosition(1,1)->widget());
    ipinfoEdit_     = qobject_cast<QLineEdit*>(apiGrid->itemAtPosition(2,1)->widget());
    shodanEdit_     = qobject_cast<QLineEdit*>(apiGrid->itemAtPosition(3,1)->widget());
    layout->addWidget(apiGroup);

    // ── Capture ───────────────────────────────────────────────────────────
    auto* capGroup  = new QGroupBox("CAPTURE SETTINGS", this);
    auto* capLayout = new QVBoxLayout(capGroup);
    capLayout->setSpacing(8);

    auto* ifaceRow = new QHBoxLayout();
    ifaceRow->addWidget(new QLabel("Interface:", capGroup));
    ifaceCombo_ = new QComboBox(capGroup);
    ifaceCombo_->addItem("auto");
    auto* detectBtn = new QPushButton("Detect", capGroup);
    detectBtn->setStyleSheet("QPushButton { background:#1F3A5F; color:#58A6FF; border:1px solid #2A4A7A; } QPushButton:hover { background:#2A4A7A; }");
    connect(detectBtn, &QPushButton::clicked, this, &SettingsDialog::onDetectInterfaces);
    ifaceRow->addWidget(ifaceCombo_, 1);
    ifaceRow->addWidget(detectBtn);
    capLayout->addLayout(ifaceRow);

    auto* bpfRow = new QHBoxLayout();
    bpfRow->addWidget(new QLabel("BPF Filter:", capGroup));
    bpfFilterEdit_ = new QLineEdit(capGroup);
    bpfFilterEdit_->setPlaceholderText("e.g. tcp port 443, or 'https', 'dns'");
    bpfRow->addWidget(bpfFilterEdit_);
    capLayout->addLayout(bpfRow);

    auto* tsharkRow = new QHBoxLayout();
    tsharkRow->addWidget(new QLabel("TShark Path:", capGroup));
    tsharkPathEdit_ = new QLineEdit(capGroup);
    tsharkPathEdit_->setPlaceholderText("Leave empty to auto-detect");
    auto* browseBtn = new QPushButton("Browse…", capGroup);
    browseBtn->setStyleSheet("QPushButton { background:transparent; color:#8B949E; border:1px solid #30363D; } QPushButton:hover { border-color:#58A6FF; color:#58A6FF; }");
    connect(browseBtn, &QPushButton::clicked, this, &SettingsDialog::onBrowseTshark);
    tsharkRow->addWidget(tsharkPathEdit_, 1);
    tsharkRow->addWidget(browseBtn);
    capLayout->addLayout(tsharkRow);
    layout->addWidget(capGroup);

    // ── Behavior ──────────────────────────────────────────────────────────
    auto* behavGroup  = new QGroupBox("BEHAVIOR", this);
    auto* behavLayout = new QGridLayout(behavGroup);
    behavLayout->setSpacing(8);
    mockModeCheck_  = new QCheckBox("Mock Mode (no TShark required)", behavGroup);
    autoScrollCheck_= new QCheckBox("Auto-scroll to latest packet",    behavGroup);
    behavLayout->addWidget(mockModeCheck_,   0, 0);
    behavLayout->addWidget(autoScrollCheck_, 1, 0);
    auto* cacheLbl = new QLabel("Cache TTL (hours):", behavGroup);
    cacheTtlEdit_  = new QLineEdit("24", behavGroup);
    cacheTtlEdit_->setFixedWidth(60);
    behavLayout->addWidget(cacheLbl,    0, 1, Qt::AlignRight);
    behavLayout->addWidget(cacheTtlEdit_, 0, 2);
    layout->addWidget(behavGroup);

    layout->addStretch();

    // Buttons
    auto* btnRow = new QHBoxLayout();
    btnRow->addStretch();
    cancelBtn_ = new QPushButton("Cancel", this);
    cancelBtn_->setStyleSheet("QPushButton { background:transparent; color:#8B949E; border:1px solid #30363D; }");
    connect(cancelBtn_, &QPushButton::clicked, this, &QDialog::reject);
    saveBtn_ = new QPushButton("Save Settings", this);
    saveBtn_->setStyleSheet("QPushButton { background:#1F3A5F; color:#58A6FF; border:1px solid #2A4A7A; font-weight:700; }");
    connect(saveBtn_, &QPushButton::clicked, this, &SettingsDialog::onSave);
    btnRow->addWidget(cancelBtn_);
    btnRow->addWidget(saveBtn_);
    layout->addLayout(btnRow);
}

void SettingsDialog::loadFromConfig() {
    const auto& cfg = AppConfig::instance();
    abuseipdbEdit_->setText(cfg.abuseipdbApiKey);
    virustotalEdit_->setText(cfg.virustotalApiKey);
    ipinfoEdit_->setText(cfg.ipinfoApiKey);
    shodanEdit_->setText(cfg.shodanApiKey);
    tsharkPathEdit_->setText(cfg.tsharkPath);
    bpfFilterEdit_->setText(cfg.bpfFilter);
    mockModeCheck_->setChecked(cfg.mockMode);
    autoScrollCheck_->setChecked(cfg.autoScroll);
    cacheTtlEdit_->setText(QString::number(cfg.cacheTtlHours));

    // Populate interface combo
    ifaceCombo_->clear();
    ifaceCombo_->addItem("auto");
    const QString ts = cfg.findTshark();
    if (!ts.isEmpty()) {
        const auto ifaces = getAvailableInterfaces(ts);
        for (const auto& i : ifaces)
            ifaceCombo_->addItem(i);
    }
    const int idx = ifaceCombo_->findText(cfg.defaultInterface);
    ifaceCombo_->setCurrentIndex(idx >= 0 ? idx : 0);
}

void SettingsDialog::onSave() {
    auto& cfg = AppConfig::instance();
    cfg.abuseipdbApiKey   = abuseipdbEdit_->text().trimmed();
    cfg.virustotalApiKey  = virustotalEdit_->text().trimmed();
    cfg.ipinfoApiKey      = ipinfoEdit_->text().trimmed();
    cfg.shodanApiKey      = shodanEdit_->text().trimmed();
    cfg.tsharkPath        = tsharkPathEdit_->text().trimmed();
    cfg.bpfFilter         = bpfFilterEdit_->text().trimmed();
    cfg.defaultInterface  = ifaceCombo_->currentText();
    cfg.mockMode          = mockModeCheck_->isChecked();
    cfg.autoScroll        = autoScrollCheck_->isChecked();
    cfg.cacheTtlHours     = cacheTtlEdit_->text().toInt();
    cfg.save();
    emit settingsSaved();
    accept();
}

void SettingsDialog::onBrowseTshark() {
    const QString path = QFileDialog::getOpenFileName(this,
        "Locate tshark.exe",
        R"(C:\Program Files\Wireshark)",
        "Executables (*.exe);;All files (*)");
    if (!path.isEmpty())
        tsharkPathEdit_->setText(path);
}

void SettingsDialog::onDetectInterfaces() {
    ifaceCombo_->clear();
    ifaceCombo_->addItem("auto");
    const QString ts = AppConfig::instance().findTshark();
    if (ts.isEmpty()) {
        QMessageBox::warning(this, "TShark not found",
            "Could not locate tshark.exe. Please set the path manually.");
        return;
    }
    for (const auto& i : getAvailableInterfaces(ts))
        ifaceCombo_->addItem(i);
}

} // namespace SS
