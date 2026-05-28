"""
arp_tab.py
ARP 封包頁籤：含 Ethernet Header 與 ARP Header 欄位。
"""
from PyQt6.QtWidgets import (
    QWidget, QFormLayout, QLineEdit, QComboBox,
    QGroupBox, QVBoxLayout,
)
from PyQt6.QtCore import pyqtSignal


class ArpTab(QWidget):
    """ARP 封包設定頁籤。"""

    fields_changed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── Ethernet Header ──────────────────────────────────────────── #
        eth_grp = QGroupBox("Ethernet Header（EtherType 固定為 0x0806）")
        eth_form = QFormLayout(eth_grp)
        eth_form.setSpacing(8)
        eth_form.setContentsMargins(10, 14, 10, 10)

        self.eth_dst = QLineEdit("ff:ff:ff:ff:ff:ff")
        self.eth_src = QLineEdit("00:11:22:33:44:55")
        self.eth_dst.setPlaceholderText("xx:xx:xx:xx:xx:xx")
        self.eth_src.setPlaceholderText("xx:xx:xx:xx:xx:xx")

        eth_form.addRow("Ethernet Dst MAC:", self.eth_dst)
        eth_form.addRow("Ethernet Src MAC:", self.eth_src)
        root.addWidget(eth_grp)

        # ── ARP Header ───────────────────────────────────────────────── #
        arp_grp = QGroupBox("ARP Header")
        arp_form = QFormLayout(arp_grp)
        arp_form.setSpacing(8)
        arp_form.setContentsMargins(10, 14, 10, 10)

        self.op = QComboBox()
        self.op.addItem("1 — Request（who-has）", userData=1)
        self.op.addItem("2 — Reply（is-at）",     userData=2)

        self.hwsrc = QLineEdit("00:11:22:33:44:55")   # Sender MAC
        self.psrc  = QLineEdit("192.168.1.1")           # Sender IP
        self.hwdst = QLineEdit("00:00:00:00:00:00")   # Target MAC
        self.pdst  = QLineEdit("192.168.1.2")           # Target IP

        self.hwsrc.setPlaceholderText("xx:xx:xx:xx:xx:xx")
        self.hwdst.setPlaceholderText("xx:xx:xx:xx:xx:xx  (Request 時填 00:00:00:00:00:00)")
        self.psrc.setPlaceholderText("x.x.x.x")
        self.pdst.setPlaceholderText("x.x.x.x")

        arp_form.addRow("Operation:", self.op)
        arp_form.addRow("Sender MAC (hwsrc):", self.hwsrc)
        arp_form.addRow("Sender IP  (psrc):", self.psrc)
        arp_form.addRow("Target MAC (hwdst):", self.hwdst)
        arp_form.addRow("Target IP  (pdst):", self.pdst)
        root.addWidget(arp_grp)

        root.addStretch()

        # ── Signal 連結 ───────────────────────────────────────────────── #
        for w in (self.eth_dst, self.eth_src,
                  self.hwsrc, self.psrc, self.hwdst, self.pdst):
            w.textChanged.connect(self.fields_changed)
        self.op.currentIndexChanged.connect(self.fields_changed)

    # ------------------------------------------------------------------ #
    #  公開介面                                                            #
    # ------------------------------------------------------------------ #

    def get_fields(self) -> dict:
        return {
            'eth_dst': self.eth_dst.text(),
            'eth_src': self.eth_src.text(),
            'op':      str(self.op.currentData()),
            'hwsrc':   self.hwsrc.text(),
            'psrc':    self.psrc.text(),
            'hwdst':   self.hwdst.text(),
            'pdst':    self.pdst.text(),
        }
