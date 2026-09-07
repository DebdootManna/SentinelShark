#include "PacketTableModel.h"
#include <QColor>
#include <QBrush>
#include <QFont>
#include <QFontInfo>

namespace SS {

const QStringList PacketTableModel::kHeaders = {
    "NO.", "TIME", "PID", "PROCESS", "SOURCE", "DESTINATION",
    "PROTOCOL", "LENGTH", "MITRE", "SEVERITY", "INFO"
};

PacketTableModel::PacketTableModel(QObject* parent)
    : QAbstractTableModel(parent)
{
    monoFont_.setFamily("JetBrains Mono");
    monoFont_.setPointSize(9);
    if (!QFontInfo(monoFont_).exactMatch()) {
        monoFont_.setFamily("Consolas");
        monoFont_.setPointSize(9);
    }
}

int PacketTableModel::rowCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return static_cast<int>(buf_.size());
}

int PacketTableModel::columnCount(const QModelIndex& parent) const {
    if (parent.isValid()) return 0;
    return Col::COUNT;
}

QVariant PacketTableModel::data(const QModelIndex& index, int role) const {
    if (!index.isValid()) return {};
    if (index.row() < 0 || index.row() >= static_cast<int>(buf_.size())) return {};

    const PacketRecord& rec = buf_[static_cast<size_t>(index.row())];
    const int col = index.column();

    switch (role) {

    case Qt::DisplayRole:
        switch (col) {
        case Col::NO:       return rec.no;
        case Col::TIME:     return rec.timeStr();
        case Col::PID:      return rec.pid > 0 ? QVariant(rec.pid) : QVariant("—");
        case Col::PROCESS:  return rec.processStr();
        case Col::SOURCE:   return rec.srcEndpoint();
        case Col::DEST:     return rec.dstEndpoint();
        case Col::PROTOCOL: return rec.protocolStr();
        case Col::LENGTH:   return rec.length;
        case Col::MITRE:    return rec.mitreStr().isEmpty() ? QString("—") : rec.mitreStr();
        case Col::SEVERITY: return QString(severityStr(rec.severity));
        case Col::INFO:     return rec.infoStr();
        default: return {};
        }

    case Qt::BackgroundRole: {
        // Compute color on-the-fly from severity — never stored
        const auto sc = severityColors(rec.severity);
        return QBrush(sc.bg);
    }

    case Qt::ForegroundRole: {
        const auto sc = severityColors(rec.severity);
        // Source col: always muted
        if (col == Col::SOURCE)   return QBrush(Colors::TEXT_MUTED);
        // Dest col: red on critical, normal otherwise
        if (col == Col::DEST)
            return QBrush(rec.severity == Severity::Critical ? Colors::CRIT_FG : Colors::TEXT);
        // Protocol col: accent blue
        if (col == Col::PROTOCOL) return QBrush(Colors::ACCENT);
        // PID col: accent blue
        if (col == Col::PID)      return QBrush(Colors::ACCENT);
        // Time col: dimmer
        if (col == Col::TIME)     return QBrush(Colors::TEXT_MUTED);
        // Length col: very dim
        if (col == Col::LENGTH)   return QBrush(Colors::TEXT_DIMMER);
        // Info col: muted
        if (col == Col::INFO)     return QBrush(Colors::TEXT_MUTED);
        // MITRE and SEVERITY: handled by delegate, return accent/severity color
        if (col == Col::MITRE)    return QBrush(Colors::ACCENT);
        if (col == Col::SEVERITY) return QBrush(sc.fg);
        // Process col: severity-colored
        if (col == Col::PROCESS)
            return QBrush(rec.severity == Severity::Critical ? Colors::CRIT_FG :
                          rec.severity == Severity::High     ? Colors::HIGH_FG : Colors::TEXT);
        return QBrush(Colors::TEXT);
    }

    case Qt::FontRole:
        // Monospace for data columns
        if (col != Col::INFO) return monoFont_;
        return {};

    case Qt::TextAlignmentRole:
        if (col == Col::NO || col == Col::LENGTH || col == Col::PID)
            return QVariant(Qt::AlignRight | Qt::AlignVCenter);
        return QVariant(Qt::AlignLeft | Qt::AlignVCenter);

    case Qt::ToolTipRole:
        if (col == Col::INFO) return rec.infoStr();
        if (col == Col::MITRE && !rec.mitreStr().isEmpty()) return rec.mitreStr();
        return {};

    default:
        return {};
    }
}

QVariant PacketTableModel::headerData(int section, Qt::Orientation orientation, int role) const {
    if (orientation != Qt::Horizontal) return {};
    if (section < 0 || section >= Col::COUNT) return {};

    switch (role) {
    case Qt::DisplayRole:
        return kHeaders.at(section);
    case Qt::ForegroundRole:
        return QBrush(Colors::TEXT_MUTED);
    case Qt::BackgroundRole:
        return QBrush(Colors::SURFACE);
    case Qt::FontRole: {
        QFont f;
        f.setPointSize(8);
        f.setWeight(QFont::Bold);
        f.setLetterSpacing(QFont::AbsoluteSpacing, 0.8);
        return f;
    }
    default:
        return {};
    }
}

void PacketTableModel::addPackets(const QVector<PacketRecord>& packets) {
    if (packets.isEmpty()) return;

    const int oldSize  = static_cast<int>(buf_.size());
    const int maxCap   = static_cast<int>(kCapacity);
    const int incoming = packets.size();

    if (oldSize + incoming <= maxCap) {
        // Buffer has room: simple append
        beginInsertRows({}, oldSize, oldSize + incoming - 1);
        for (const auto& pkt : packets) {
            buf_.push_back(pkt);
        }
        endInsertRows();
    } else {
        // Buffer will wrap/evict oldest rows: safely reset model mapping
        beginResetModel();
        for (const auto& pkt : packets) {
            buf_.push_back(pkt);
        }
        endResetModel();
    }

    totalReceived_ += static_cast<uint64_t>(incoming);
}

const PacketRecord& PacketTableModel::recordAt(int row) const {
    return buf_[static_cast<size_t>(row)];
}

PacketRecord& PacketTableModel::recordAt(int row) {
    return buf_[static_cast<size_t>(row)];
}

void PacketTableModel::clear() {
    if (buf_.empty()) return;
    beginResetModel();
    buf_.clear();
    totalReceived_ = 0;
    endResetModel();
}

} // namespace SS
