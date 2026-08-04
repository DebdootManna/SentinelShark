from collections import deque
from PyQt6.QtCore import Qt, QPointF
from PyQt6.QtGui import QPainter, QPainterPath, QColor, QPen, QLinearGradient
from PyQt6.QtWidgets import QWidget


class SparklineWidget(QWidget):
    """
    Custom QWidget that renders real-time activity sparklines.
    Paints smooth neon cyan curves with gradient fill for active traffic,
    and a subtle slate line for idle interfaces.
    """

    def __init__(self, max_points: int = 30, parent=None):
        super().__init__(parent)
        self.max_points = max_points
        self.history = deque([0.0] * max_points, maxlen=max_points)
        self.setMinimumSize(120, 32)
        self.setMaximumHeight(40)

    def add_value(self, val: float):
        """Append a new data point (e.g. KB/s or pkts/s) and trigger repaint."""
        self.history.append(float(val))
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        width = self.width()
        height = self.height()

        # Background container
        painter.fillRect(0, 0, width, height, QColor("#090d16"))

        # Border outline
        painter.setPen(QPen(QColor("#1e293b"), 1))
        painter.drawRoundedRect(0, 0, width - 1, height - 1, 4, 4)

        if not self.history:
            return

        max_val = max(self.history)
        # Avoid division by zero, scale to graph height
        scale_max = max(max_val, 10.0)

        step_x = (width - 8) / max(1, self.max_points - 1)
        padding_y = 6
        usable_h = height - (padding_y * 2)

        points = []
        for i, val in enumerate(self.history):
            x = 4 + i * step_x
            # Invert y because Qt coordinate origin (0,0) is top-left
            normalized = min(val / scale_max, 1.0)
            y = height - padding_y - (normalized * usable_h)
            points.append(QPointF(x, y))

        is_active = max_val > 0.1

        if is_active:
            # 1. Gradient Fill Under Curve
            fill_path = QPainterPath()
            fill_path.moveTo(points[0].x(), height - padding_y)
            for pt in points:
                fill_path.lineTo(pt)
            fill_path.lineTo(points[-1].x(), height - padding_y)
            fill_path.closeSubpath()

            gradient = QLinearGradient(0, 0, 0, height)
            gradient.setColorAt(0.0, QColor(56, 189, 248, 120))  # Semi-transparent cyan top
            gradient.setColorAt(1.0, QColor(56, 189, 248, 5))    # Faded bottom
            painter.fillPath(fill_path, gradient)

            # 2. Main Neon Line
            line_path = QPainterPath()
            line_path.moveTo(points[0])
            for pt in points[1:]:
                line_path.lineTo(pt)

            painter.setPen(QPen(QColor("#38bdf8"), 2))
            painter.drawPath(line_path)

            # 3. Latest Data Point Pulsing Indicator Dot
            last_pt = points[-1]
            painter.setBrush(QColor("#34d399"))  # Vibrant emerald dot
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawEllipse(last_pt, 3.5, 3.5)

        else:
            # Idle Flat Line
            line_path = QPainterPath()
            line_path.moveTo(points[0])
            for pt in points[1:]:
                line_path.lineTo(pt)

            painter.setPen(QPen(QColor("#334155"), 1.5, Qt.PenStyle.DashLine))
            painter.drawPath(line_path)
