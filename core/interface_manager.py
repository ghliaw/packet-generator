"""
interface_manager.py
列舉系統上可用的網路介面（透過 Scapy / Npcap）。
"""
from __future__ import annotations
from dataclasses import dataclass
import sys


@dataclass
class NetworkIface:
    """代表一個網路介面的基本資訊。"""
    name: str          # Scapy/Npcap 使用的介面識別字串
    description: str   # 人類可讀的介面描述
    mac: str           # MAC 位址字串，格式 xx:xx:xx:xx:xx:xx

    def display_name(self) -> str:
        return f"{self.description}  [{self.mac}]"


class InterfaceManager:

    @staticmethod
    def get_interfaces() -> list[NetworkIface]:
        """
        回傳系統上所有可用的網路介面。
        依序嘗試四種方式以兼容不同 Scapy 版本。
        """
        # 強制觸發 Scapy Windows 介面初始化
        if sys.platform == 'win32':
            InterfaceManager._force_init_windows()

        # 方法 1：Windows 專用 get_windows_if_list()（最直接，不依賴 conf.ifaces）
        result = InterfaceManager._try_windows_if_list()
        if result:
            return result

        # 方法 2：conf.ifaces（需確認非 None）
        result = InterfaceManager._try_conf_ifaces()
        if result:
            return result

        # 方法 3：IFACES（舊版 Scapy fallback）
        result = InterfaceManager._try_ifaces()
        if result:
            return result

        raise RuntimeError(
            "找不到任何網路介面。\n\n"
            "請確認：\n"
            "  1. Npcap 已安裝（隨 Wireshark 安裝，或至 https://npcap.com 下載）\n"
            "  2. 程式以「系統管理員」身份執行\n"
            "  3. scapy 已安裝（pip install scapy）"
        )

    # ------------------------------------------------------------------ #

    @staticmethod
    def _force_init_windows() -> None:
        """強制 import scapy.arch.windows 以觸發 conf.ifaces 初始化。"""
        try:
            import scapy.arch.windows  # noqa: F401  side-effect import
        except Exception:
            pass
        try:
            from scapy.config import conf
            # 告知 Scapy 使用 Npcap（若支援此設定）
            if hasattr(conf, 'use_npcap'):
                conf.use_npcap = True
        except Exception:
            pass

    @staticmethod
    def _try_windows_if_list() -> list[NetworkIface]:
        """
        使用 scapy.arch.windows.get_windows_if_list()。
        此函式直接查詢 Windows WMI / 登錄，不依賴 conf.ifaces。

        重要：回傳 dict 的 'name' 是 Windows 顯示名稱（如「乙太網路」），
        sendp() 需要的是 NPF 裝置路徑 \\Device\\NPF_{GUID}，
        因此 NetworkIface.name 必須用 guid 欄位組出 NPF 路徑。
        """
        try:
            from scapy.arch.windows import get_windows_if_list
            result = []
            for iface in get_windows_if_list():
                guid = iface.get('guid', '')
                # sendp() 使用的介面名稱：NPF 裝置路徑
                npf_name = f"\\Device\\NPF_{guid}" if guid else ''
                if not npf_name:
                    continue
                # 人類可讀顯示名稱：優先用 Windows 顯示名稱 + 硬體描述
                win_name   = iface.get('name', '')        # 如「乙太網路」
                hw_desc    = iface.get('description', '') # 如「Realtek USB GbE...」
                if hw_desc and win_name:
                    description = f"{win_name} ({hw_desc})"
                else:
                    description = win_name or hw_desc or npf_name
                mac = iface.get('mac', 'unknown') or 'unknown'
                result.append(NetworkIface(
                    name=npf_name,
                    description=description,
                    mac=mac,
                ))
            return result
        except Exception:
            return []

    @staticmethod
    def _try_conf_ifaces() -> list[NetworkIface]:
        try:
            from scapy.config import conf
            if conf.ifaces is None:
                return []
            result = []
            for name, iface in conf.ifaces.items():
                description = getattr(iface, 'description', None) or str(name)
                mac = getattr(iface, 'mac', '') or 'unknown'
                result.append(NetworkIface(
                    name=str(name),
                    description=description,
                    mac=mac,
                ))
            return result
        except Exception:
            return []

    @staticmethod
    def _try_ifaces() -> list[NetworkIface]:
        try:
            from scapy.interfaces import IFACES
            if not IFACES:
                return []
            result = []
            for iface_name, iface in IFACES.items():
                description = getattr(iface, 'description', None) or iface_name
                mac = getattr(iface, 'mac', '') or 'unknown'
                result.append(NetworkIface(
                    name=iface_name,
                    description=description,
                    mac=mac,
                ))
            return result
        except Exception:
            return []
