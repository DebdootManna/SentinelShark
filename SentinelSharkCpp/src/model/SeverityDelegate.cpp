#include "SeverityDelegate.h"
#include "PacketTableModel.h"
#include <QPainter>
#include <QFontInfo>
#include <QPainterPath>

namespace SS {

SeverityDelegate::SeverityDelegate(QObject* parent)
    : QStyledItemDelegate(parent)
{
    monoFont_.setFamily("JetBrains Mono");
    monoFont_.setPointSize(8);
    monoFont_.setWeight(QFont::DemiBold);
    if (!QFontInfo(monoFont_).exactMatch()) {
        monoFont_.setFamily("Consolas");
    }
}

void SeverityDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
                              const QModelIndex& index) const
{
    painter->save();
    painter->setRenderHint(QPainter::Antialiasing, true);

    const int col = index.column();

    // Selection / hover background
    if (option.state & QStyle::State_Selected) {
        painter->fillRect(option.rect, option.palette.highlight());
    }

    const QString text = index.data(Qt::DisplayRole).toString();
    const QRect r = option.rect.adjusted(6, 3, -6, -3);

    if (col == Col::SEVERITY) {
        // Draw severity pill matching React <SeverityPill>
        Severity sev = Severity::Safe;
        if      (text == "CRITICAL") sev = Severity::Critical;
        else if (text == "HIGH")     sev = Severity::High;
        else if (text == "MEDIUM")   sev = Severity::Medium;

        const auto sc = severityColors(sev);
        drawPill(painter, r, text, sc.bg, sc.fg, sc.border);

    } else if (col == Col::MITRE) {
        // Draw MITRE tag pill matching React <MitreTag>
        if (text == "—" || text.isEmpty()) {
            painter->setFont(monoFont_);
            painter->setPen(Colors::TEXT_DIMMER);
            painter->drawText(r, Qt::AlignLeft | Qt::AlignVCenter, "—");
        } else {
            drawPill(painter, r, text,
                     Colors::ACCENT_DIM,
                     Colors::ACCENT,
                     QColor("#2A4A7A"));
        }
    } else {
        // Default rendering for other columns
        QStyledItemDelegate::paint(painter, option, index);
    }

    painter->restore();
}

void SeverityDelegate::drawPill(QPainter* painter, const QRectF& rect,
                                  const QString& text, const QColor& bg,
                                  const QColor& fg, const QColor& border) const
{
    // Pill dimensions: height constrained, width from text
    QFontMetrics fm(monoFont_);
    const int tw     = fm.horizontalAdvance(text);
    const int ph     = 16; // pill height in px
    const int pw     = tw + 14; // horizontal padding 7px each side
    const int px     = static_cast<int>(rect.left());
    const int py     = static_cast<int>(rect.center().y() - ph / 2);
    const QRectF pill(px, py, pw, ph);

    QPainterPath path;
    path.addRoundedRect(pill, 3, 3); // 3px radius matching borderRadius: 3 in CSS

    painter->fillPath(path, bg);
    painter->setPen(QPen(border, 1.0));
    painter->drawPath(path);

    painter->setFont(monoFont_);
    painter->setPen(fg);
    painter->drawText(pill, Qt::AlignCenter, text);
}

QSize SeverityDelegate::sizeHint(const QStyleOptionViewItem& option,
                                   const QModelIndex& index) const
{
    const int col = index.column();
    if (col == Col::SEVERITY || col == Col::MITRE) {
        return QSize(90, 24);
    }
    return QStyledItemDelegate::sizeHint(option, index);
}

} // namespace SS
