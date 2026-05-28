"""
main.py
Packet Generator 程式進入點。

執行需求：
  - Windows 10 / 11
  - Python 3.10+
  - pip install pyqt6 scapy
  - 已安裝 Npcap（Wireshark 安裝時一同安裝）
  - 以「系統管理員」身份執行（Npcap 原始封包注入需要）
"""
import sys
import ctypes

from PyQt6.QtWidgets import QApplication, QMessageBox


def _check_admin() -> bool:
    """Windows 上確認是否以管理員權限執行。"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def main() -> None:
    app = QApplication(sys.argv)
    app.setApplicationName("Packet Generator")
    app.setOrganizationName("Network Lab")

    # 管理員權限提示（僅警告，不強制退出，方便開發測試）
    if not _check_admin():
        QMessageBox.warning(
            None,
            "權限提示",
            "目前並非以系統管理員身份執行。\n\n"
            "Npcap 的原始封包注入功能需要管理員權限，\n"
            "發送封包時可能會失敗。\n\n"
            "建議：右鍵 → 以系統管理員身份執行。",
        )

    # 延遲匯入，讓 QApplication 先建立完成
    from ui.main_window import MainWindow

    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
