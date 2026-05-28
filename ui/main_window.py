"""
main_window.py
Packet Generator 主視窗。

佈局：
  ┌─────────────────────────────────────┐
  │  網路介面選擇列                       │
  ├─────────────────────────────────────┤
  │  封包類型 Tab（Ethernet / ARP / IP） │
  ├─────────────────────────────────────┤
  │  傳送控制面板                         │
  ├─────────────────────────────────────┤
  │  狀態列 + Hex Dump 預覽              │
  └─────────────────────────────────────┘
"""
from __future__ import annotations

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QComboBox, QPushButton, QTabWidget,
    QGroupBox, QRadioButton, QLineEdit, QTextEdit,
    QMessageBox, QStatusBar, QButtonGroup, QSplitter,
    QSizePolicy,
)
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtCore import Qt, pyqtSlot

from core.interface_manager import InterfaceManager, NetworkIface
from core.packet_builder import PacketBuilder, PacketBuildError
from core.send_controller import SendWorker
from ui.tabs.ethernet_tab import EthernetTab
from ui.tabs.arp_tab import ArpTab
from ui.tabs.ip_tab import IpTab


class MainWindow(QMainWindow):
    """Packet Generator 主視窗。"""

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("Packet Generator")
        self.setMinimumSize(720, 760)

        self._worker: SendWorker | None = None
        self._interfaces: list[NetworkIface] = []

        self._build_ui()
        self._load_interfaces()

    # ================================================================== #
    #  UI 建構                                                            #
    # ================================================================== #

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(10, 10, 10, 6)
        root.setSpacing(8)

        root.addWidget(self._make_iface_bar())
        root.addWidget(self._make_packet_tabs(), stretch=1)
        root.addWidget(self._make_send_panel())
        root.addWidget(self._make_status_panel())

        # Status bar（視窗最底部）
        self.statusBar().showMessage("就緒")

    # ── 介面選擇列 ──────────────────────────────────────────────────── #

    def _make_iface_bar(self) -> QGroupBox:
        grp = QGroupBox("網路介面")
        lay = QHBoxLayout(grp)
        lay.setContentsMargins(10, 8, 10, 8)

        self.iface_combo = QComboBox()
        self.iface_combo.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        self.refresh_btn = QPushButton("重新整理")
        self.refresh_btn.setFixedWidth(90)
        self.refresh_btn.clicked.connect(self._load_interfaces)

        lay.addWidget(QLabel("選擇介面："))
        lay.addWidget(self.iface_combo)
        lay.addWidget(self.refresh_btn)
        return grp

    # ── 封包類型 Tabs ────────────────────────────────────────────────── #

    def _make_packet_tabs(self) -> QTabWidget:
        self.tabs = QTabWidget()

        self.eth_tab = EthernetTab()
        self.arp_tab = ArpTab()
        self.ip_tab  = IpTab()

        self.tabs.addTab(self.eth_tab, "Ethernet (Raw)")
        self.tabs.addTab(self.arp_tab, "ARP")
        self.tabs.addTab(self.ip_tab,  "IP / ICMP / TCP / UDP")

        # 任何欄位改變時即時更新 Hex Dump 預覽
        self.eth_tab.fields_changed.connect(self._update_preview)
        self.arp_tab.fields_changed.connect(self._update_preview)
        self.ip_tab.fields_changed.connect(self._update_preview)
        self.tabs.currentChanged.connect(self._update_preview)

        return self.tabs

    # ── 傳送控制面板 ─────────────────────────────────────────────────── #

    def _make_send_panel(self) -> QGroupBox:
        grp = QGroupBox("傳送控制")
        outer = QHBoxLayout(grp)
        outer.setContentsMargins(10, 10, 10, 10)
        outer.setSpacing(20)

        # ── 左：個數模式 ─────────────────────────────────────────────── #
        count_grp = QGroupBox("傳送個數")
        count_lay = QVBoxLayout(count_grp)
        count_lay.setSpacing(6)

        self._count_btn_grp = QButtonGroup(self)

        self.rb_count_single   = QRadioButton("單次（1 個）")
        self.rb_count_finite   = QRadioButton("指定個數：")
        self.rb_count_infinite = QRadioButton("無限循環")
        self.rb_count_single.setChecked(True)

        self._count_btn_grp.addButton(self.rb_count_single,   0)
        self._count_btn_grp.addButton(self.rb_count_finite,   1)
        self._count_btn_grp.addButton(self.rb_count_infinite, 2)

        self.count_edit = QLineEdit("10")
        self.count_edit.setFixedWidth(70)
        self.count_edit.setEnabled(False)

        count_finite_row = QHBoxLayout()
        count_finite_row.addWidget(self.rb_count_finite)
        count_finite_row.addWidget(self.count_edit)
        count_finite_row.addStretch()

        count_lay.addWidget(self.rb_count_single)
        count_lay.addLayout(count_finite_row)
        count_lay.addWidget(self.rb_count_infinite)
        outer.addWidget(count_grp)

        # ── 中：速率模式 ─────────────────────────────────────────────── #
        rate_grp = QGroupBox("傳送速率")
        rate_lay = QVBoxLayout(rate_grp)
        rate_lay.setSpacing(6)

        self._rate_btn_grp = QButtonGroup(self)

        self.rb_rate_single   = QRadioButton("單次發送")
        self.rb_rate_max      = QRadioButton("最大速率（無間隔）")
        self.rb_rate_interval = QRadioButton("固定間隔：")
        self.rb_rate_single.setChecked(True)

        self._rate_btn_grp.addButton(self.rb_rate_single,   0)
        self._rate_btn_grp.addButton(self.rb_rate_max,      1)
        self._rate_btn_grp.addButton(self.rb_rate_interval, 2)

        self.interval_edit = QLineEdit("1000")
        self.interval_edit.setFixedWidth(70)
        self.interval_edit.setEnabled(False)
        interval_unit = QLabel("ms")

        rate_interval_row = QHBoxLayout()
        rate_interval_row.addWidget(self.rb_rate_interval)
        rate_interval_row.addWidget(self.interval_edit)
        rate_interval_row.addWidget(interval_unit)
        rate_interval_row.addStretch()

        # 最大速率警告
        warn_label = QLabel("⚠ 最大速率將佔用大量網路頻寬")
        warn_label.setStyleSheet("color: #c0392b; font-size: 11px;")

        rate_lay.addWidget(self.rb_rate_single)
        rate_lay.addWidget(self.rb_rate_max)
        rate_lay.addWidget(warn_label)
        rate_lay.addLayout(rate_interval_row)
        outer.addWidget(rate_grp)

        # ── 右：Send / Stop 按鈕 ────────────────────────────────────── #
        btn_lay = QVBoxLayout()
        btn_lay.setSpacing(8)
        btn_lay.addStretch()

        self.send_btn = QPushButton("▶  Send")
        self.send_btn.setFixedSize(100, 40)
        self.send_btn.setStyleSheet(
            "QPushButton { background-color: #2980b9; color: white; "
            "border-radius: 6px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background-color: #3498db; }"
            "QPushButton:disabled { background-color: #bdc3c7; }"
        )

        self.stop_btn = QPushButton("⏹  Stop")
        self.stop_btn.setFixedSize(100, 40)
        self.stop_btn.setEnabled(False)
        self.stop_btn.setStyleSheet(
            "QPushButton { background-color: #e74c3c; color: white; "
            "border-radius: 6px; font-size: 14px; font-weight: bold; }"
            "QPushButton:hover { background-color: #c0392b; }"
            "QPushButton:disabled { background-color: #bdc3c7; }"
        )

        btn_lay.addWidget(self.send_btn)
        btn_lay.addWidget(self.stop_btn)
        btn_lay.addStretch()
        outer.addLayout(btn_lay)

        # ── Signal 連結 ───────────────────────────────────────────────── #
        self.rb_count_finite.toggled.connect(
            lambda checked: self.count_edit.setEnabled(checked))
        self.rb_rate_interval.toggled.connect(
            lambda checked: self.interval_edit.setEnabled(checked))
        self.rb_rate_single.toggled.connect(self._on_rate_mode_changed)
        self.rb_rate_max.toggled.connect(self._on_rate_mode_changed)
        self.rb_rate_interval.toggled.connect(self._on_rate_mode_changed)

        self.send_btn.clicked.connect(self._on_send)
        self.stop_btn.clicked.connect(self._on_stop)

        return grp

    # ── 狀態 + Hex Dump 面板 ─────────────────────────────────────────── #

    def _make_status_panel(self) -> QGroupBox:
        grp = QGroupBox("封包預覽（Hex Dump）")
        lay = QVBoxLayout(grp)
        lay.setContentsMargins(10, 8, 10, 8)

        self.sent_label = QLabel("已送出：0 個封包")
        self.sent_label.setStyleSheet("font-weight: bold;")

        self.hex_dump = QTextEdit()
        self.hex_dump.setReadOnly(True)
        self.hex_dump.setFont(QFont("Courier New", 9))
        self.hex_dump.setFixedHeight(130)
        self.hex_dump.setPlaceholderText("（封包 Hex Dump 將顯示於此）")

        lay.addWidget(self.sent_label)
        lay.addWidget(self.hex_dump)
        return grp

    # ================================================================== #
    #  邏輯                                                               #
    # ================================================================== #

    def _load_interfaces(self) -> None:
        """從 Scapy 重新載入介面清單。"""
        self.iface_combo.clear()
        try:
            self._interfaces = InterfaceManager.get_interfaces()
        except RuntimeError as exc:
            QMessageBox.critical(self, "介面載入失敗", str(exc))
            return

        if not self._interfaces:
            self.iface_combo.addItem("（找不到介面，請確認 Npcap 已安裝）")
            return

        for iface in self._interfaces:
            self.iface_combo.addItem(iface.display_name(), userData=iface)

    def _current_iface_name(self) -> str | None:
        """回傳目前選取介面的 Scapy 名稱。"""
        iface: NetworkIface | None = self.iface_combo.currentData()
        return iface.name if iface else None

    def _build_current_packet(self):
        """依目前頁籤建立封包，失敗時 raise PacketBuildError。"""
        idx = self.tabs.currentIndex()
        if idx == 0:
            return PacketBuilder.build_ethernet(self.eth_tab.get_fields())
        elif idx == 1:
            return PacketBuilder.build_arp(self.arp_tab.get_fields())
        elif idx == 2:
            return PacketBuilder.build_ip(self.ip_tab.get_fields())
        raise PacketBuildError("未知的頁籤索引")

    @pyqtSlot()
    def _update_preview(self) -> None:
        """即時更新 Hex Dump 預覽。"""
        try:
            pkt = self._build_current_packet()
            self.hex_dump.setPlainText(PacketBuilder.hex_dump(pkt))
        except PacketBuildError:
            self.hex_dump.setPlainText("（輸入尚未完整，無法預覽）")
        except Exception:
            self.hex_dump.setPlainText("（預覽錯誤）")

    @pyqtSlot()
    def _on_rate_mode_changed(self) -> None:
        """速率模式改變時，同步「個數」RadioButton 的可選狀態。
        RATE_SINGLE 時強制個數為 single 並禁用其他選項。"""
        is_single_rate = self.rb_rate_single.isChecked()
        self.rb_count_finite.setEnabled(not is_single_rate)
        self.rb_count_infinite.setEnabled(not is_single_rate)
        if is_single_rate:
            self.rb_count_single.setChecked(True)
            self.count_edit.setEnabled(False)

    # ── Send ─────────────────────────────────────────────────────────── #

    @pyqtSlot()
    def _on_send(self) -> None:
        iface_name = self._current_iface_name()
        if not iface_name:
            QMessageBox.warning(self, "無法發送", "請先選擇網路介面")
            return

        # 建立封包
        try:
            pkt = self._build_current_packet()
        except PacketBuildError as exc:
            QMessageBox.warning(self, "封包建構失敗", str(exc))
            return

        # 讀取傳送參數
        rate_mode  = self._get_rate_mode()
        count_mode = self._get_count_mode()
        count      = self._get_count()
        interval   = self._get_interval_ms()

        if count is None or interval is None:
            return  # 輸入驗證失敗，已顯示錯誤訊息

        # 最大速率 + 無限 警告
        if rate_mode == SendWorker.RATE_MAX and count_mode == SendWorker.COUNT_INFINITE:
            reply = QMessageBox.warning(
                self, "警告",
                "您選擇了「最大速率 × 無限循環」，這將持續佔用網路頻寬。\n確定要繼續嗎？",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            )
            if reply != QMessageBox.StandardButton.Yes:
                return

        # 啟動 Worker
        self._worker = SendWorker(
            packet=pkt,
            iface_name=iface_name,
            rate_mode=rate_mode,
            count_mode=count_mode,
            count=count,
            interval_ms=interval,
        )
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_send_error)

        self._set_sending_state(True)
        self.sent_label.setText("已送出：0 個封包")
        self.statusBar().showMessage("傳送中…")
        self._worker.start()

    @pyqtSlot()
    def _on_stop(self) -> None:
        if self._worker and self._worker.isRunning():
            self._worker.request_stop()
            self.stop_btn.setEnabled(False)
            self.statusBar().showMessage("正在停止…")

    @pyqtSlot(int)
    def _on_progress(self, sent: int) -> None:
        self.sent_label.setText(f"已送出：{sent} 個封包")

    @pyqtSlot(int, str)
    def _on_finished(self, sent: int, msg: str) -> None:
        self.sent_label.setText(f"已送出：{sent} 個封包")
        self.statusBar().showMessage(msg)
        self._set_sending_state(False)

    @pyqtSlot(str)
    def _on_send_error(self, msg: str) -> None:
        self._set_sending_state(False)
        self.statusBar().showMessage(f"錯誤：{msg}")
        QMessageBox.critical(self, "傳送錯誤", msg)

    # ── 輔助方法 ─────────────────────────────────────────────────────── #

    def _set_sending_state(self, sending: bool) -> None:
        """切換 UI 為「傳送中」或「就緒」狀態。"""
        self.send_btn.setEnabled(not sending)
        self.stop_btn.setEnabled(sending)
        self.tabs.setEnabled(not sending)
        self.iface_combo.setEnabled(not sending)
        self.refresh_btn.setEnabled(not sending)
        # 傳送控制區的 RadioButton 與輸入框
        for w in (self.rb_count_single, self.rb_count_finite, self.rb_count_infinite,
                  self.rb_rate_single, self.rb_rate_max, self.rb_rate_interval,
                  self.count_edit, self.interval_edit):
            w.setEnabled(not sending)
        if not sending:
            # 恢復「有條件啟用」的元件
            self.count_edit.setEnabled(self.rb_count_finite.isChecked())
            self.interval_edit.setEnabled(self.rb_rate_interval.isChecked())
            self._on_rate_mode_changed()

    def _get_rate_mode(self) -> str:
        if self.rb_rate_single.isChecked():
            return SendWorker.RATE_SINGLE
        if self.rb_rate_max.isChecked():
            return SendWorker.RATE_MAX
        return SendWorker.RATE_INTERVAL

    def _get_count_mode(self) -> str:
        if self.rb_count_infinite.isChecked():
            return SendWorker.COUNT_INFINITE
        if self.rb_count_finite.isChecked():
            return SendWorker.COUNT_FINITE
        return SendWorker.COUNT_FINITE  # single 模式由 rate_mode 控制

    def _get_count(self) -> int | None:
        if self.rb_count_single.isChecked() or self.rb_rate_single.isChecked():
            return 1
        if self.rb_count_finite.isChecked():
            try:
                val = int(self.count_edit.text())
                if val < 1:
                    raise ValueError
                return val
            except ValueError:
                QMessageBox.warning(self, "輸入錯誤", "傳送個數必須為正整數")
                return None
        return 1  # infinite 模式 count 不使用

    def _get_interval_ms(self) -> float | None:
        if not self.rb_rate_interval.isChecked():
            return 0.0
        try:
            val = float(self.interval_edit.text())
            if val <= 0:
                raise ValueError
            return val
        except ValueError:
            QMessageBox.warning(self, "輸入錯誤", "間隔時間必須為正數（ms）")
            return None
