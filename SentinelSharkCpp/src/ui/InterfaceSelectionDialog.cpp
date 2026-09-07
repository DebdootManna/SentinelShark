#include "InterfaceSelectionDialog.h"
#include "../config/AppConfig.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QTableWidgetItem>
#include <QIcon>
#include <QFont>

namespace SS {

InterfaceSelectionDialog::InterfaceSelectionDialog(const QString& currentIface,
                                                   QWidget* parent)
    : QDialog(parent)
{
    setWindowTitle("SentinelShark — Select Network Interface");
    setMinimumSize(720, 480);
    resize(780, 520);
    setModal(true);

    setStyleSheet(R"(
        QDialog {
            background-color: #0D1117;
            color: #E6EDF3;
        }
        QTableWidget {
            background-color: #161B22;
            color: #E6EDF3;
            border: 1px solid #30363D;
            gridline-color: #21262D;
            selection-background-color: rgba(88, 166, 255, 0.2);
            selection-color: #FFFFFF;
            border-radius: 4px;
        }
        QTableWidget::item {
            padding: 6px 10px;
            border-bottom: 1px solid #21262D;
        }
        QTableWidget::item:selected {
            background-color: rgba(88, 166, 255, 0.18);
            border-left: 3px solid #58A6FF;
        }
        QHeaderView::section {
            background-color: #0D1117;
            color: #8B949E;
            border: none;
            border-bottom: 2px solid #30363D;
            padding: 8px 10px;
            font-size: 10px;
            font-weight: 700;
            letter-spacing: 0.08em;
            text-transform: uppercase;
        }
    )");

    setupUi(currentIface);
}

void InterfaceSelectionDialog::setupUi(const QString& currentIface) {
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(20, 20, 20, 20);
    layout->setSpacing(14);

    // Title banner
    auto* titleLabel = new QLabel("🦈  Select Network Interface for Packet Capture", this);
    titleLabel->setStyleSheet("font-size: 15px; font-weight: 700; color: #58A6FF; letter-spacing: 0.04em;");
    layout->addWidget(titleLabel);

    auto* descLabel = new QLabel(
        "Choose an active network adapter to initiate real-time packet dissection and host process telemetry correlation:",
        this);
    descLabel->setStyleSheet("color: #8B949E; font-size: 11px;");
    descLabel->setWordWrap(true);
    layout->addWidget(descLabel);

    // Table widget
    table_ = new QTableWidget(this);
    table_->setColumnCount(3);
    table_->setHorizontalHeaderLabels({"INTERFACE NAME", "IP ADDRESS", "DEVICE IDENTIFIER"});
    table_->setSelectionBehavior(QAbstractItemView::SelectRows);
    table_->setSelectionMode(QAbstractItemView::SingleSelection);
    table_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table_->verticalHeader()->setVisible(false);
    table_->verticalHeader()->setDefaultSectionSize(36);
    table_->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    table_->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    table_->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);
    table_->setShowGrid(false);

    connect(table_, &QTableWidget::cellDoubleClicked, this, &InterfaceSelectionDialog::onRowDoubleClicked);
    layout->addWidget(table_);

    populateTable(currentIface);

    // Bottom action row
    auto* btnRow = new QHBoxLayout();
    btnRow->setSpacing(10);

    auto* hintLabel = new QLabel("💡 Double-click any adapter row to immediately start capture", this);
    hintLabel->setStyleSheet("color: #6E7681; font-size: 10px;");
    btnRow->addWidget(hintLabel);
    btnRow->addStretch();

    cancelBtn_ = new QPushButton("Cancel", this);
    cancelBtn_->setStyleSheet(
        "QPushButton { background: transparent; color: #8B949E; border: 1px solid #30363D; "
        "border-radius: 4px; padding: 7px 16px; font-size: 11px; font-weight: 600; }"
        "QPushButton:hover { background: #161B22; color: #E6EDF3; border-color: #8B949E; }");
    connect(cancelBtn_, &QPushButton::clicked, this, &QDialog::reject);
    btnRow->addWidget(cancelBtn_);

    startBtn_ = new QPushButton("▶  Start Capture on Interface", this);
    startBtn_->setStyleSheet(
        "QPushButton { background: #122A19; color: #2EA043; border: 1px solid #1A4025; "
        "border-radius: 4px; padding: 7px 20px; font-size: 11px; font-weight: 700; }"
        "QPushButton:hover { background: #1A4025; border-color: #2EA043; color: #3FB950; }");
    startBtn_->setCursor(Qt::PointingHandCursor);
    connect(startBtn_, &QPushButton::clicked, this, &InterfaceSelectionDialog::onStartClicked);
    btnRow->addWidget(startBtn_);

    layout->addLayout(btnRow);
}

void InterfaceSelectionDialog::populateTable(const QString& currentIface) {
    const QString tsharkPath = AppConfig::instance().findTshark();
    interfaces_ = getDetailedInterfaces(tsharkPath);

    table_->setRowCount(interfaces_.size());

    int selectedRow = 0;
    const QString target = currentIface.trimmed().toLower();

    for (int row = 0; row < interfaces_.size(); ++row) {
        const auto& entry = interfaces_[row];

        // 1. Name & description
        auto* nameItem = new QTableWidgetItem(entry.name);
        nameItem->setFont(QFont("Segoe UI", 10, QFont::Bold));
        if (!entry.description.isEmpty()) {
            nameItem->setToolTip(entry.description);
        }
        table_->setItem(row, 0, nameItem);

        // 2. IP Address
        auto* ipItem = new QTableWidgetItem(entry.ipAddress);
        ipItem->setFont(QFont("Consolas", 10));
        if (entry.ipAddress != "—") {
            ipItem->setForeground(QColor("#58A6FF"));
        } else {
            ipItem->setForeground(QColor("#6E7681"));
        }
        table_->setItem(row, 1, ipItem);

        // 3. Device Identifier
        auto* idItem = new QTableWidgetItem(entry.description.isEmpty() ? entry.id : entry.description);
        idItem->setFont(QFont("Consolas", 9));
        idItem->setForeground(QColor("#8B949E"));
        table_->setItem(row, 2, idItem);

        // Check if selected
        if (!target.isEmpty() &&
            (entry.id.toLower() == target || entry.name.toLower().contains(target))) {
            selectedRow = row;
        }
    }

    if (interfaces_.size() > 0) {
        table_->selectRow(selectedRow);
    }
}

void InterfaceSelectionDialog::onRowDoubleClicked(int row, int) {
    if (row >= 0 && row < interfaces_.size()) {
        selectedId_   = interfaces_[row].id;
        selectedName_ = interfaces_[row].name;
        accept();
    }
}

void InterfaceSelectionDialog::onStartClicked() {
    const int row = table_->currentRow();
    if (row >= 0 && row < interfaces_.size()) {
        selectedId_   = interfaces_[row].id;
        selectedName_ = interfaces_[row].name;
    } else if (!interfaces_.isEmpty()) {
        selectedId_   = interfaces_.first().id;
        selectedName_ = interfaces_.first().name;
    }
    accept();
}

} // namespace SS
