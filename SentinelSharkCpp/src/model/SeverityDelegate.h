#pragma once
#include <QStyledItemDelegate>
#include <QFont>
#include "../core/PacketRecord.h"

namespace SS {

/// Custom delegate that draws the SEVERITY pill and MITRE tag cells
/// as rounded-rectangle badges matching the App.tsx React design.
class SeverityDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    explicit SeverityDelegate(QObject* parent = nullptr);

    void paint(QPainter* painter, const QStyleOptionViewItem& option,
               const QModelIndex& index) const override;

    QSize sizeHint(const QStyleOptionViewItem& option,
                   const QModelIndex& index) const override;

private:
    void drawPill(QPainter* painter, const QRectF& rect,
                  const QString& text, const QColor& bg,
                  const QColor& fg, const QColor& border) const;

    QFont monoFont_;
};

} // namespace SS
