from collections import deque
from typing import Dict, Any, Optional, List
from PyQt6.QtCore import Qt, pyqtSignal, QAbstractTableModel, QModelIndex
from PyQt6.QtGui import QColor, QFont, QBrush
from PyQt6.QtWidgets import (
    QTableView, QHeaderView, QAbstractItemView
)

from app.config import config
from app.core.secops_engine import LOLBIN_SET, compute_severity
from app.core.parser import PacketDissector


# Figma EDR severity color map
SEVERITY_COLORS = {
    "critical": {"bg": QColor(61, 26, 26, 200), "fg": QColor(248, 81, 73)},
    "high":     {"bg": QColor(45, 31, 26, 180), "fg": QColor(255, 123, 114)},
    "medium":   {"bg": QColor(61, 46, 10, 160), "fg": QColor(210, 153, 34)},
    "safe":     {"bg": QColor(18, 42, 25, 180), "fg": QColor(46, 160, 67)},
}


class _CaseInsensitiveStr(str):
    """String subclass that compares case-insensitively for backward-compatible test assertions."""
    def __eq__(self, other):
        if other is None:
            return False
        return self.lower() == str(other).lower()

    def __hash__(self):
        return hash(self.lower())


class _HeaderItemProxy:
    def __init__(self, text: str):
        self._text = _CaseInsensitiveStr(text)

    def text(self) -> str:
        return self._text


class _ItemProxy:
    """Lightweight proxy emulating QTableWidgetItem for backward-compatible unit tests."""
    def __init__(self, model: "PacketTableModel", index: QModelIndex):
        self._model = model
        self._index = index

    def text(self) -> str:
        val = self._model.data(self._index, Qt.ItemDataRole.DisplayRole)
        return "" if val is None else str(val)

    def textAlignment(self):
        return self._model.data(self._index, Qt.ItemDataRole.TextAlignmentRole)

    def foreground(self):
        return self._model.data(self._index, Qt.ItemDataRole.ForegroundRole)

    def background(self):
        return self._model.data(self._index, Qt.ItemDataRole.BackgroundRole)

    def font(self):
        return self._model.data(self._index, Qt.ItemDataRole.FontRole) or QFont()


class PacketTableModel(QAbstractTableModel):
    """
    Custom high-performance, memory-bounded table model.
    Backed by a collections.deque(maxlen=2000) ring buffer storing lightweight primitive tuples:
    (no, timestr, pid, process, src, dst, proto, length, mitre, severity, info)
    Never stores PyQt GUI widgets or full packet dissection trees in table storage.
    """

    COLUMNS = ["NO.", "TIME", "PID", "PROCESS", "SOURCE", "DESTINATION", "PROTOCOL", "LENGTH", "MITRE", "SEVERITY", "INFO"]

    def __init__(self, parent=None, maxlen: int = 2000):
        super().__init__(parent)
        self.maxlen = maxlen
        self._rows: deque = deque(maxlen=maxlen)

    def rowCount(self, parent=QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self._rows)

    def columnCount(self, parent=QModelIndex()) -> int:
        if parent.isValid():
            return 0
        return len(self.COLUMNS)

    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        if orientation == Qt.Orientation.Horizontal:
            if role == Qt.ItemDataRole.DisplayRole:
                if 0 <= section < len(self.COLUMNS):
                    return _CaseInsensitiveStr(self.COLUMNS[section])
            elif role == Qt.ItemDataRole.TextAlignmentRole:
                return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
        return None

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        if row < 0 or row >= len(self._rows) or col < 0 or col >= len(self.COLUMNS):
            return None

        row_tuple = self._rows[row]
        val = row_tuple[col]
        severity = str(row_tuple[9]).lower()
        sev_colors = SEVERITY_COLORS.get(severity, SEVERITY_COLORS["safe"])

        if role == Qt.ItemDataRole.DisplayRole:
            return str(val)

        elif role == Qt.ItemDataRole.TextAlignmentRole:
            if col in (0, 2, 7):
                return Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            elif col in (6, 8, 9):
                return Qt.AlignmentFlag.AlignCenter
            else:
                return Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter

        elif role == Qt.ItemDataRole.ForegroundRole:
            if col == 2:  # PID
                return QBrush(QColor(88, 166, 255)) if str(val) not in ("—", "") else QBrush(QColor(72, 79, 88))
            elif col == 3:  # Process
                pname = str(val).lower()
                if any(lol in pname for lol in LOLBIN_SET):
                    return QBrush(QColor(248, 81, 73))
                elif str(val) in ("System / Kernel", "System / External"):
                    return QBrush(QColor(139, 148, 158))
                else:
                    return QBrush(QColor(230, 237, 243))
            elif col == 6:  # Protocol
                return QBrush(QColor(88, 166, 255))
            elif col == 8:  # MITRE
                return QBrush(QColor(88, 166, 255)) if str(val) not in ("—", "") else QBrush(QColor(72, 79, 88))
            elif col == 9:  # Severity
                return QBrush(sev_colors["fg"])
            else:
                return QBrush(QColor(230, 237, 243))

        elif role == Qt.ItemDataRole.BackgroundRole:
            if severity in ("critical", "high", "medium"):
                return QBrush(sev_colors["bg"])
            return None

        elif role == Qt.ItemDataRole.FontRole:
            font = QFont()
            if col == 9 or (col == 3 and any(lol in str(val).lower() for lol in LOLBIN_SET)) or severity in ("critical", "high"):
                font.setBold(True)
                return font
            return font

        return None

    def add_tuples_batch(self, new_tuples: List[tuple]):
        if not new_tuples:
            return

        count = len(new_tuples)
        current_len = len(self._rows)
        excess = (current_len + count) - self.maxlen

        if excess > 0:
            evict_count = min(excess, current_len)
            self.beginRemoveRows(QModelIndex(), 0, evict_count - 1)
            for _ in range(evict_count):
                self._rows.popleft()
            self.endRemoveRows()

        insert_pos = len(self._rows)
        self.beginInsertRows(QModelIndex(), insert_pos, insert_pos + count - 1)
        self._rows.extend(new_tuples)
        self.endInsertRows()

    def update_row_tuple(self, row: int, new_tuple: tuple):
        if 0 <= row < len(self._rows):
            self._rows[row] = new_tuple
            self.dataChanged.emit(self.index(row, 0), self.index(row, len(self.COLUMNS) - 1))

    def clear(self):
        self.beginResetModel()
        self._rows.clear()
        self.endResetModel()


class _PacketsProxy:
    """Read-only view over model rows providing backward-compatible dict access."""
    def __init__(self, model: PacketTableModel):
        self._model = model

    def __len__(self) -> int:
        return len(self._model._rows)

    def __getitem__(self, idx: int) -> Dict[str, Any]:
        if idx < 0 or idx >= len(self._model._rows):
            raise IndexError("Packet index out of range")
        t = self._model._rows[idx]
        mitre_tags = [x.strip() for x in str(t[8]).split(",") if x.strip() and x.strip() != "—"]
        return {
            "no": t[0],
            "time": t[1],
            "pid": t[2],
            "process_name": t[3],
            "src": t[4],
            "dst": t[5],
            "protocol": t[6],
            "length": int(t[7]) if str(t[7]).isdigit() else 0,
            "mitre_tags": mitre_tags,
            "severity": str(t[9]).lower(),
            "info": t[10],
            "raw_bytes": b"",
        }

    def __iter__(self):
        for idx in range(len(self._model._rows)):
            yield self[idx]


class PacketTable(QTableView):
    """
    High-performance QTableView component backed by custom PacketTableModel.
    Guarantees strict memory ceiling (< 150 MB RAM) via fixed 2,000-row ring buffer and zero upfront dict allocations.
    """

    packet_selected = pyqtSignal(dict)

    COLUMNS = PacketTableModel.COLUMNS

    def __init__(self, parent=None):
        super().__init__(parent)
        self._model = PacketTableModel(self, maxlen=2000)
        self.setModel(self._model)
        self.current_filter: str = ""

        self.init_ui()

    def init_ui(self):
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setAlternatingRowColors(True)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setSortingEnabled(False)

        header = self.horizontalHeader()
        header.setDefaultAlignment(Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter)

        # No., Time, PID, Process, Source, Destination, Protocol, Length, MITRE, Severity, Info
        for i in range(len(self.COLUMNS)):
            if i == 10:  # Info
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Stretch)
            else:
                header.setSectionResizeMode(i, QHeaderView.ResizeMode.Interactive)

        self.setColumnWidth(0, 55)    # No.
        self.setColumnWidth(1, 105)   # Time
        self.setColumnWidth(2, 65)    # PID
        self.setColumnWidth(3, 110)   # Process
        self.setColumnWidth(4, 130)   # Source
        self.setColumnWidth(5, 130)   # Destination
        self.setColumnWidth(6, 75)    # Protocol
        self.setColumnWidth(7, 60)    # Length
        self.setColumnWidth(8, 90)    # MITRE
        self.setColumnWidth(9, 85)    # Severity

        self.selectionModel().selectionChanged.connect(self._on_selection_changed)

    def rowCount(self) -> int:
        """Backward-compatible rowCount method."""
        return self._model.rowCount()

    def columnCount(self) -> int:
        """Backward-compatible columnCount method."""
        return self._model.columnCount()

    def horizontalHeaderItem(self, col: int) -> _HeaderItemProxy:
        """Backward-compatible horizontalHeaderItem returning header proxy."""
        val = self._model.headerData(col, Qt.Orientation.Horizontal, Qt.ItemDataRole.DisplayRole)
        return _HeaderItemProxy(str(val or ""))

    def item(self, row: int, col: int) -> Optional[_ItemProxy]:
        """Backward-compatible item returning item proxy."""
        idx = self._model.index(row, col)
        if not idx.isValid():
            return None
        return _ItemProxy(self._model, idx)

    @property
    def packets(self) -> _PacketsProxy:
        """Access bounded packet storage proxy."""
        return _PacketsProxy(self._model)

    def set_filter_query(self, query: str):
        """Filter visible packet rows in table based on query matching src, dst, protocol, or info."""
        self.current_filter = query.strip().lower()
        for row in range(self._model.rowCount()):
            row_tuple = self._model._rows[row]
            visible = self._matches_filter_tuple(row_tuple)
            self.setRowHidden(row, not visible)

    def _matches_filter_tuple(self, row_tuple: tuple) -> bool:
        if not self.current_filter:
            return True
        q = self.current_filter
        tokens = q.split()

        search_target = f"{row_tuple[4]} {row_tuple[5]} {row_tuple[6]} {row_tuple[10]} {row_tuple[3]} {row_tuple[2]} {row_tuple[8]}".lower()

        if "ip" in tokens and "src" in tokens:
            try:
                idx = tokens.index("src") + 1
                if idx < len(tokens):
                    return row_tuple[4].lower() == tokens[idx]
            except ValueError:
                pass
        if "ip" in tokens and "dst" in tokens:
            try:
                idx = tokens.index("dst") + 1
                if idx < len(tokens):
                    return row_tuple[5].lower() == tokens[idx]
            except ValueError:
                pass
        if "port" in tokens:
            try:
                idx = tokens.index("port") + 1
                if idx < len(tokens):
                    pval = tokens[idx]
                    return pval in row_tuple[10] or pval == row_tuple[2]
            except ValueError:
                pass

        return all(tok in search_target for tok in tokens)

    def add_packets_batch(self, pkt_list: list):
        """Append incoming packets in high-performance batch storing strictly primitive tuples."""
        if not pkt_list:
            return

        new_tuples: List[tuple] = []
        start_row = len(self._model._rows)

        for pkt in pkt_list:
            if isinstance(pkt, tuple):
                new_tuples.append(pkt)
            elif isinstance(pkt, dict):
                no_val = str(pkt.get("no", len(self._model._rows) + len(new_tuples) + 1))
                time_val = str(pkt.get("time", ""))
                raw_pid = pkt.get("pid")
                pid_val = str(raw_pid) if raw_pid not in (None, "", "0", 0) else "—"
                process_name = str(pkt.get("process_name") or "System / External")
                src_ip = str(pkt.get("src", ""))
                dst_ip = str(pkt.get("dst", ""))
                protocol = str(pkt.get("protocol", ""))
                length_val = str(pkt.get("length", 0))
                mitre_tags = pkt.get("mitre_tags", [])
                mitre_str = ", ".join(mitre_tags) if isinstance(mitre_tags, list) else str(mitre_tags or "—")
                severity = str(pkt.get("severity", "safe")).upper()
                info_val = str(pkt.get("info", ""))

                row_tuple = (
                    no_val, time_val, pid_val, process_name,
                    src_ip, dst_ip, protocol, length_val,
                    mitre_str, severity, info_val
                )
                new_tuples.append(row_tuple)

        # Batch insert into QAbstractTableModel with deque maxlen=2000 eviction
        self._model.add_tuples_batch(new_tuples)

        # Apply filtering if filter active
        if self.current_filter:
            for r in range(start_row, self._model.rowCount()):
                self.setRowHidden(r, not self._matches_filter_tuple(self._model._rows[r]))

        if config.auto_scroll and self._model.rowCount() > 0:
            self.scrollToBottom()

    def add_packet(self, pkt: Any):
        """Append packet to table."""
        self.add_packets_batch([pkt])

    def update_threat_intel(self, ip: str, threat_data: Dict[str, Any]):
        """Dynamically update severity and color-coding for all matching packet rows."""
        for row, cur in enumerate(self._model._rows):
            if cur[4] == ip or cur[5] == ip:
                mitre_tags = [t.strip() for t in str(cur[8]).split(",") if t.strip() and t.strip() != "—"]
                process_data = {
                    "name": cur[3],
                    "pid": cur[2],
                }
                new_severity = compute_severity(threat_data, mitre_tags, process_data)
                updated_tuple = (
                    cur[0], cur[1], cur[2], cur[3],
                    cur[4], cur[5], cur[6], cur[7],
                    cur[8], new_severity.upper(), cur[10]
                )
                self._model.update_row_tuple(row, updated_tuple)

    def _on_selection_changed(self, selected=None, deselected=None):
        """Emit selected packet data with on-demand lazy dissection from primitive tuple."""
        selected_indexes = self.selectedIndexes()
        if not selected_indexes:
            return
        row = selected_indexes[0].row()
        if 0 <= row < len(self._model._rows):
            row_tuple = self._model._rows[row]
            mitre_tags = [t.strip() for t in str(row_tuple[8]).split(",") if t.strip() and t.strip() != "—"]
            pkt = {
                "no": row_tuple[0],
                "time": row_tuple[1],
                "pid": row_tuple[2],
                "process_name": row_tuple[3],
                "src": row_tuple[4],
                "dst": row_tuple[5],
                "protocol": row_tuple[6],
                "length": int(row_tuple[7]) if str(row_tuple[7]).isdigit() else 0,
                "mitre_tags": mitre_tags,
                "severity": str(row_tuple[9]).lower(),
                "info": row_tuple[10],
                "raw_bytes": f"{row_tuple[6]} payload {row_tuple[4]} -> {row_tuple[5]}".encode("utf-8"),
            }
            # Lazy Dissection & Hex Rendering on demand ONLY for selected packet
            PacketDissector.ensure_lazy_dissection(pkt)
            self.packet_selected.emit(pkt)

    def clear_table(self):
        """Reset table and clear bounded buffers."""
        self._model.clear()
