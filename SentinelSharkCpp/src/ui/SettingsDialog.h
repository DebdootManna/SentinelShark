#pragma once
#include <QDialog>
#include <QLineEdit>
#include <QComboBox>
#include <QCheckBox>
#include <QPushButton>

namespace SS {

/// Application settings dialog (⚙ Settings tab).
/// Reads/writes AppConfig singleton and QSettings.
class SettingsDialog : public QDialog {
    Q_OBJECT
public:
    explicit SettingsDialog(QWidget* parent = nullptr);

signals:
    void settingsSaved();

private slots:
    void onSave();
    void onBrowseTshark();
    void onDetectInterfaces();

private:
    void setupUi();
    void loadFromConfig();

    // API key fields
    QLineEdit* abuseipdbEdit_;
    QLineEdit* virustotalEdit_;
    QLineEdit* ipinfoEdit_;
    QLineEdit* shodanEdit_;

    // Capture fields
    QComboBox* ifaceCombo_;
    QLineEdit* bpfFilterEdit_;
    QLineEdit* tsharkPathEdit_;

    // Behavior
    QCheckBox* mockModeCheck_;
    QCheckBox* autoScrollCheck_;
    QLineEdit* cacheTtlEdit_;

    QPushButton* saveBtn_;
    QPushButton* cancelBtn_;
};

} // namespace SS
