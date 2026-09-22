#pragma once
#include <QAbstractTableModel>
#include <QVector>
#include <QFont>
#include <QColor>
#include <vector>
#include "../core/PacketRecord.h"

namespace SS {

/// Column indices for the 11-column packet table.
namespace Col {
    constexpr int NO       = 0;
    constexpr int TIME     = 1;
    constexpr int PID      = 2;
    constexpr int PROCESS  = 3;
    constexpr int SOURCE   = 4;
    constexpr int DEST     = 5;
    constexpr int PROTOCOL = 6;
    constexpr int LENGTH   = 7;
    constexpr int MITRE    = 8;
    constexpr int SEVERITY = 9;
    constexpr int INFO     = 10;
    constexpr int COUNT    = 11;
}

/// Qt color tokens mirroring App.tsx `C` object.
namespace Colors {
    // Backgrounds
    static const QColor BG          {"#0D1117"};
    static const QColor SURFACE     {"#161B22"};
    static const QColor BORDER      {"#30363D"};
    static const QColor BORDER_SUBTLE{"#21262D"};
    // Severity backgrounds
    static const QColor CRIT_BG     {"#3D1A1A"};
    static const QColor HIGH_BG     {"#2D1F1A"};
    static const QColor MED_BG      {"#3D2E0A"};
    static const QColor SAFE_BG     {"#122A19"};
    // Severity foregrounds
    static const QColor CRIT_FG     {"#F85149"};
    static const QColor HIGH_FG     {"#FF7B72"};
    static const QColor MED_FG      {"#D29922"};
    static const QColor SAFE_FG     {"#2EA043"};
    // General
    static const QColor ACCENT      {"#58A6FF"};
    static const QColor ACCENT_DIM  {"#1F3A5F"};
    static const QColor TEXT        {"#E6EDF3"};
    static const QColor TEXT_MUTED  {"#8B949E"};
    static const QColor TEXT_DIMMER {"#484F58"};
}

struct SeverityColors {
    QColor bg;
    QColor fg;
    QColor border;
};

inline SeverityColors severityColors(Severity s) noexcept {
    switch (s) {
        case Severity::Critical: return {Colors::CRIT_BG, Colors::CRIT_FG, QColor("#5A1E1E")};
        case Severity::High:     return {Colors::HIGH_BG, Colors::HIGH_FG, QColor("#4A2A20")};
        case Severity::Medium:   return {Colors::MED_BG,  Colors::MED_FG,  QColor("#5A4010")};
        default:                 return {Colors::SAFE_BG, Colors::SAFE_FG,  QColor("#1A4025")};
    }
}

/// QAbstractTableModel backed by a dynamic std::vector<PacketRecord>.
/// Colors are computed on-the-fly in data() — never stored in the buffer.
class PacketTableModel : public QAbstractTableModel {
    Q_OBJECT
public:
    explicit PacketTableModel(QObject* parent = nullptr);

    // QAbstractTableModel overrides
    int rowCount(const QModelIndex& parent = {}) const override;
    int columnCount(const QModelIndex& parent = {}) const override;
    QVariant data(const QModelIndex& index, int role = Qt::DisplayRole) const override;
    QVariant headerData(int section, Qt::Orientation orientation, int role = Qt::DisplayRole) const override;

    /// Called from the GUI QTimer to batch-insert up to N packets.
    /// Wraps beginInsertRows / endInsertRows.
    void addPackets(const QVector<PacketRecord>& packets);

    /// Direct access to the underlying record for the inspection panel.
    const PacketRecord& recordAt(int row) const;
    PacketRecord& recordAt(int row);

    /// Clear all rows.
    void clear();

    /// Total packets received.
    uint64_t totalReceived() const noexcept { return totalReceived_; }

    /// Read-only access to packets vector.
    const std::vector<PacketRecord>& packets() const noexcept { return buf_; }
    const std::vector<PacketRecord>& ringBuffer() const noexcept { return buf_; }

private:
    std::vector<PacketRecord> buf_;
    uint64_t totalReceived_ = 0;
    QFont monoFont_;

    // Header labels (11 columns)
    static const QStringList kHeaders;
};

} // namespace SS
