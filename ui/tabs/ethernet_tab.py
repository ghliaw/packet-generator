"""
ethernet_tab.py
Raw Ethernet Frame 頁籤：讓使用者自訂 Dst MAC、Src MAC、EtherType、Payload。
"""
from PyQt6.QtWidgets import (
    QWidget, QFormLayout, QLineEdit, QTextEdit,
    QGroupBox, QVBoxLayout, QLabel,
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import pyqtSignal


class EthernetTab(QWidget):
    """Raw Ethernet 封包設定頁籤。"""

    fields_changed = pyqtSignal()  # 任何欄位改變時發出，供主視窗更新預覽

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── Ethernet Header ──────────────────────────────────────────── #
        grp = QGroupBox("Ethernet Header")
        form = QFormLayout(grp)
        form.setSpacing(8)
        form.setContentsMargins(10, 14, 10, 10)

        self.dst_mac   = QLineEdit("ff:ff:ff:ff:ff:ff")
        self.src_mac   = QLineEdit("00:11:22:33:44:55")
        self.ethertype = QLineEdit("0x0800")

        self.dst_mac.setPlaceholderText("xx:xx:xx:xx:xx:xx")
        self.src_mac.setPlaceholderText("xx:xx:xx:xx:xx:xx")
        self.ethertype.setPlaceholderText("0x0800")

        form.addRow("Destination MAC:", self.dst_mac)
        form.addRow("Source MAC:", self.src_mac)
        form.addRow("EtherType (hex):", self.ethertype)
        root.addWidget(grp)

        # ── Payload ──────────────────────────────────────────────────── #
        grp2 = QGroupBox("Payload（Hex）")
        lay2 = QVBoxLayout(grp2)
        lay2.setContentsMargins(10, 14, 10, 10)

        hint = QLabel("以 Hex 輸入，可含空格，例如：de ad be ef 00 01 02 03")
        hint.setStyleSheet("color: gray; font-size: 11px;")
        self.payload = QTextEdit()
        self.payload.setFont(QFont("Courier New", 10))
        self.payload.setFixedHeight(90)
        self.payload.setPlaceholderText("de ad be ef ...")

        lay2.addWidget(hint)
        lay2.addWidget(self.payload)
        root.addWidget(grp2)

        root.addStretch()

        # ── Signal 連結 ───────────────────────────────────────────────── #
        for w in (self.dst_mac, self.src_mac, self.ethertype):
            w.textChanged.connect(self.fields_changed)
        self.payload.textChanged.connect(self.fields_changed)

    # ------------------------------------------------------------------ #
    #  公開介面                                                            #
    # ------------------------------------------------------------------ #

    def get_fields(self) -> dict:
        """回傳目前所有欄位的字串值。"""
        return {
            'dst_mac':   self.dst_mac.text(),
            'src_mac':   self.src_mac.text(),
            'ethertype': self.ethertype.text(),
            'payload':   self.payload.toPlainText(),
        }
