#pragma once
#include <QDialog>
#include <QTableWidget>
#include <QPushButton>
#include <QLabel>
#include <QList>
#include "../capture/InterfaceScanner.h"

namespace SS {

/// Wireshark-style modal dialog displaying all host network interfaces.
/// Displays Interface Name, IP Address, and Device Identifier.
class InterfaceSelectionDialog : public QDialog {
    Q_OBJECT
public:
    explicit InterfaceSelectionDialog(const QString& currentIface = QString(),
                                      QWidget* parent = nullptr);

    /// Returns the chosen interface ID (e.g., "1" or "\\Device\\NPF_{...}")
    QString selectedInterfaceId() const { return selectedId_; }

    /// Returns the chosen interface display name (e.g. "Wi-Fi")
    QString selectedInterfaceName() const { return selectedName_; }

private slots:
    void onRowDoubleClicked(int row, int column);
    void onStartClicked();

private:
    void setupUi(const QString& currentIface);
    void populateTable(const QString& currentIface);

    QTableWidget*         table_ = nullptr;
    QPushButton*          startBtn_ = nullptr;
    QPushButton*          cancelBtn_ = nullptr;
    QList<InterfaceEntry> interfaces_;

    QString selectedId_;
    QString selectedName_;
};

} // namespace SS
