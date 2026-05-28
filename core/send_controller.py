"""
send_controller.py
QThread-based 傳送控制器，支援三種速率模式與兩種個數模式。

傳送模式組合：
  rate_mode  × count_mode
  ─────────────────────────────────────────────────────────
  SINGLE       —  送一個封包後結束（count_mode 忽略）
  MAX_RATE     × FINITE    — 以最大速率送指定個數
  MAX_RATE     × INFINITE  — 以最大速率持續發送直到 Stop
  FIXED_INTERVAL × FINITE  — 以固定間隔送指定個數
  FIXED_INTERVAL × INFINITE— 以固定間隔持續發送直到 Stop
"""
from __future__ import annotations
import time
from PyQt6.QtCore import QThread, pyqtSignal


class SendWorker(QThread):
    """在背景執行緒中發送 Scapy 封包，透過 Qt Signal 回報進度。"""

    # Signals
    progress = pyqtSignal(int)       # 目前已送出的封包數
    finished = pyqtSignal(int, str)  # (最終送出數, 完成訊息)
    error    = pyqtSignal(str)       # 錯誤訊息

    # ── 速率模式常數 ──────────────────────────────────────────────────── #
    RATE_SINGLE   = 'single'          # 只送一個
    RATE_MAX      = 'max_rate'        # 最大速率（緊密迴圈）
    RATE_INTERVAL = 'fixed_interval'  # 固定間隔

    # ── 個數模式常數 ──────────────────────────────────────────────────── #
    COUNT_FINITE   = 'finite'
    COUNT_INFINITE = 'infinite'

    def __init__(
        self,
        packet,
        iface_name: str,
        rate_mode: str,
        count_mode: str,
        count: int       = 1,
        interval_ms: float = 1000.0,
    ) -> None:
        super().__init__()
        self._packet      = packet
        self._iface_name  = iface_name
        self._rate_mode   = rate_mode
        self._count_mode  = count_mode
        self._count       = count
        self._interval_sec = interval_ms / 1000.0
        self._stop        = False

    def request_stop(self) -> None:
        """從 UI 執行緒呼叫，要求背景執行緒在下一個安全點停止。"""
        self._stop = True

    # ------------------------------------------------------------------ #

    def run(self) -> None:
        from scapy.sendrecv import sendp

        sent = 0
        try:
            if self._rate_mode == self.RATE_SINGLE:
                # ── 單次發送 ───────────────────────────────────────────
                sendp(self._packet, iface=self._iface_name, verbose=False)
                sent = 1
                self.progress.emit(sent)

            elif self._rate_mode == self.RATE_MAX:
                # ── 最大速率：緊密迴圈 ─────────────────────────────────
                while not self._stop:
                    sendp(self._packet, iface=self._iface_name, verbose=False)
                    sent += 1
                    self.progress.emit(sent)
                    if self._count_mode == self.COUNT_FINITE and sent >= self._count:
                        break

            elif self._rate_mode == self.RATE_INTERVAL:
                # ── 固定間隔：可中斷的 sleep ───────────────────────────
                while not self._stop:
                    sendp(self._packet, iface=self._iface_name, verbose=False)
                    sent += 1
                    self.progress.emit(sent)

                    if self._count_mode == self.COUNT_FINITE and sent >= self._count:
                        break

                    # 可中斷的等待：每 5ms 檢查一次 stop flag
                    deadline = time.monotonic() + self._interval_sec
                    while time.monotonic() < deadline:
                        if self._stop:
                            break
                        remaining = deadline - time.monotonic()
                        time.sleep(min(0.005, remaining))

            self.finished.emit(sent, f"完成，共送出 {sent} 個封包")

        except Exception as exc:
            self.error.emit(str(exc))
