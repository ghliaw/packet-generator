"""
interface_manager.py
列舉系統上可用的網路介面（透過 Scapy / Npcap）。
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass
class NetworkIface:
    """代表一個網路介面的基本資訊。"""
    name: str          # Scapy/Npcap 使用的介面識別字串（Windows 上為 NPF GUID 路徑）
    description: str   # 人類可讀的介面描述
    mac: str           # MAC 位址字串，格式 xx:xx:xx:xx:xx:xx

    def display_name(self) -> str:
        return f"{self.description}  [{self.mac}]"


class InterfaceManager:
    """管理網路介面的列舉與查詢。"""

    @staticmethod
    def get_interfaces() -> list[NetworkIface]:
        """
        回傳系統上所有可用的網路介面清單。
        需要 Npcap（Windows）已安裝。
        """
        result: list[NetworkIface] = []
        try:
            from scapy.interfaces import IFACES
            for iface_name, iface in IFACES.items():
                description = getattr(iface, 'description', None) or iface_name
                mac = getattr(iface, 'mac', '') or 'unknown'
                result.append(NetworkIface(
                    name=iface_name,
                    description=description,
                    mac=mac,
                ))
        except Exception as exc:
            # 若 Scapy 或 Npcap 未正確安裝，回傳空清單並讓上層處理
            raise RuntimeError(f"無法列舉網路介面：{exc}") from exc
        return result
