"""
ip_tab.py
IP 封包頁籤：含 Ethernet、IP Header，以及依選擇的 Protocol 動態顯示的子欄位。
支援 ICMP / TCP / UDP / Raw（自訂 Protocol Number）。
"""
from PyQt6.QtWidgets import (
    QWidget, QFormLayout, QLineEdit, QComboBox, QTextEdit,
    QGroupBox, QVBoxLayout, QLabel, QStackedWidget, QSpinBox,
)
from PyQt6.QtGui import QFont
from PyQt6.QtCore import pyqtSignal


class IpTab(QWidget):
    """IP 封包設定頁籤，Protocol 子欄位動態切換。"""

    fields_changed = pyqtSignal()

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(12, 12, 12, 12)
        root.setSpacing(10)

        # ── Ethernet Header ──────────────────────────────────────────── #
        eth_grp = QGroupBox("Ethernet Header（EtherType 固定為 0x0800）")
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

        # ── IP Header ────────────────────────────────────────────────── #
        ip_grp = QGroupBox("IP Header")
        ip_form = QFormLayout(ip_grp)
        ip_form.setSpacing(8)
        ip_form.setContentsMargins(10, 14, 10, 10)

        self.src_ip = QLineEdit("192.168.1.1")
        self.dst_ip = QLineEdit("192.168.1.2")
        self.ttl    = QLineEdit("64")
        self.src_ip.setPlaceholderText("x.x.x.x")
        self.dst_ip.setPlaceholderText("x.x.x.x")
        self.ttl.setPlaceholderText("1-255")

        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["ICMP", "TCP", "UDP", "Raw"])

        ip_form.addRow("Source IP:", self.src_ip)
        ip_form.addRow("Destination IP:", self.dst_ip)
        ip_form.addRow("TTL:", self.ttl)
        ip_form.addRow("Protocol:", self.protocol_combo)
        root.addWidget(ip_grp)

        # ── Protocol 子欄位（QStackedWidget 動態切換）────────────────── #
        self.proto_stack = QStackedWidget()
        root.addWidget(self.proto_stack)

        # Page 0 — ICMP
        self._icmp_page = self._make_icmp_page()
        self.proto_stack.addWidget(self._icmp_page)

        # Page 1 — TCP
        self._tcp_page = self._make_port_page("TCP")
        self.proto_stack.addWidget(self._tcp_page)

        # Page 2 — UDP
        self._udp_page = self._make_port_page("UDP")
        self.proto_stack.addWidget(self._udp_page)

        # Page 3 — Raw
        self._raw_page = self._make_raw_page()
        self.proto_stack.addWidget(self._raw_page)

        # ── Payload（所有 Protocol 共用）────────────────────────────── #
        pay_grp = QGroupBox("Additional Payload（Hex，附加於 L4 之後）")
        pay_lay = QVBoxLayout(pay_grp)
        pay_lay.setContentsMargins(10, 14, 10, 10)

        hint = QLabel("選填。以 Hex 輸入，可含空格")
        hint.setStyleSheet("color: gray; font-size: 11px;")
        self.payload = QTextEdit()
        self.payload.setFont(QFont("Courier New", 10))
        self.payload.setFixedHeight(70)
        self.payload.setPlaceholderText("de ad be ef ...")
        pay_lay.addWidget(hint)
        pay_lay.addWidget(self.payload)
        root.addWidget(pay_grp)

        root.addStretch()

        # ── Signal 連結 ───────────────────────────────────────────────── #
        self.protocol_combo.currentIndexChanged.connect(self._on_protocol_changed)
        self.protocol_combo.currentIndexChanged.connect(self.fields_changed)
        for w in (self.eth_dst, self.eth_src, self.src_ip, self.dst_ip, self.ttl):
            w.textChanged.connect(self.fields_changed)
        self.payload.textChanged.connect(self.fields_changed)

    # ------------------------------------------------------------------ #
    #  子頁面工廠                                                          #
    # ------------------------------------------------------------------ #

    def _make_icmp_page(self) -> QWidget:
        page = QWidget()
        grp = QGroupBox("ICMP Fields")
        form = QFormLayout(grp)
        form.setSpacing(8)
        form.setContentsMargins(10, 14, 10, 10)

        page.icmp_type = QLineEdit("8")
        page.icmp_code = QLineEdit("0")
        page.icmp_type.setPlaceholderText("0-255，Echo Request = 8")
        page.icmp_code.setPlaceholderText("0-255")
        form.addRow("ICMP Type:", page.icmp_type)
        form.addRow("ICMP Code:", page.icmp_code)

        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(grp)

        for w in (page.icmp_type, page.icmp_code):
            w.textChanged.connect(self.fields_changed)
        return page

    def _make_port_page(self, proto_label: str) -> QWidget:
        page = QWidget()
        grp = QGroupBox(f"{proto_label} Fields")
        form = QFormLayout(grp)
        form.setSpacing(8)
        form.setContentsMargins(10, 14, 10, 10)

        page.sport = QLineEdit("1024")
        page.dport = QLineEdit("80" if proto_label == "TCP" else "53")
        page.sport.setPlaceholderText("0-65535")
        page.dport.setPlaceholderText("0-65535")
        form.addRow("Source Port:", page.sport)
        form.addRow("Destination Port:", page.dport)

        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(grp)

        for w in (page.sport, page.dport):
            w.textChanged.connect(self.fields_changed)
        return page

    def _make_raw_page(self) -> QWidget:
        page = QWidget()
        grp = QGroupBox("Raw IP Payload")
        form = QFormLayout(grp)
        form.setSpacing(8)
        form.setContentsMargins(10, 14, 10, 10)

        page.proto_num = QLineEdit("253")
        page.proto_num.setPlaceholderText("IP Protocol Number (0-255)，253/254 為實驗用")
        form.addRow("IP Protocol:", page.proto_num)

        lay = QVBoxLayout(page)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(grp)

        page.proto_num.textChanged.connect(self.fields_changed)
        return page

    # ------------------------------------------------------------------ #
    #  Slot                                                                #
    # ------------------------------------------------------------------ #

    def _on_protocol_changed(self, index: int) -> None:
        self.proto_stack.setCurrentIndex(index)

    # ------------------------------------------------------------------ #
    #  公開介面                                                            #
    # ------------------------------------------------------------------ #

    def get_fields(self) -> dict:
        proto = self.protocol_combo.currentText()
        fields: dict = {
            'eth_dst':  self.eth_dst.text(),
            'eth_src':  self.eth_src.text(),
            'src_ip':   self.src_ip.text(),
            'dst_ip':   self.dst_ip.text(),
            'ttl':      self.ttl.text(),
            'protocol': proto,
            'payload':  self.payload.toPlainText(),
        }
        if proto == 'ICMP':
            fields['icmp_type'] = self._icmp_page.icmp_type.text()
            fields['icmp_code'] = self._icmp_page.icmp_code.text()
        elif proto == 'TCP':
            fields['sport'] = self._tcp_page.sport.text()
            fields['dport'] = self._tcp_page.dport.text()
        elif proto == 'UDP':
            fields['sport'] = self._udp_page.sport.text()
            fields['dport'] = self._udp_page.dport.text()
        elif proto == 'Raw':
            fields['proto_num'] = self._raw_page.proto_num.text()
        return fields
