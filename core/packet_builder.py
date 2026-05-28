"""
packet_builder.py
負責將 UI 欄位的字串資料驗證並組裝成 Scapy 封包物件，
以及產生封包的 Hex Dump 字串供 UI 預覽。
"""
from __future__ import annotations


class PacketBuildError(ValueError):
    """封包建構時發生的輸入錯誤。"""


class PacketBuilder:
    """靜態工廠，依封包類型建立對應 Scapy 封包物件。"""

    # ------------------------------------------------------------------ #
    #  輸入驗證工具                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def parse_mac(mac_str: str) -> str:
        """驗證並正規化 MAC 位址，回傳小寫冒號分隔格式。"""
        s = mac_str.strip().replace('-', ':').lower()
        parts = s.split(':')
        if len(parts) != 6:
            raise PacketBuildError(f"MAC 格式錯誤（應為 xx:xx:xx:xx:xx:xx）：{mac_str!r}")
        for p in parts:
            if len(p) != 2:
                raise PacketBuildError(f"MAC 格式錯誤：{mac_str!r}")
            try:
                int(p, 16)
            except ValueError:
                raise PacketBuildError(f"MAC 包含非 hex 字元：{mac_str!r}")
        return s

    @staticmethod
    def parse_hex_payload(hex_str: str) -> bytes:
        """將 hex 字串（可含空格與換行）轉換為 bytes。空字串回傳 b''。"""
        cleaned = hex_str.strip().replace(' ', '').replace('\n', '').replace('\r', '')
        if not cleaned:
            return b''
        if len(cleaned) % 2 != 0:
            raise PacketBuildError("Hex payload 的 hex 字元數必須為偶數")
        try:
            return bytes.fromhex(cleaned)
        except ValueError as exc:
            raise PacketBuildError(f"Hex payload 包含非 hex 字元：{exc}") from exc

    @staticmethod
    def parse_ethertype(type_str: str) -> int:
        """解析 EtherType，接受 0x 前綴或純 hex，回傳整數。"""
        s = type_str.strip().lower().removeprefix('0x')
        try:
            val = int(s, 16)
        except ValueError:
            raise PacketBuildError(f"EtherType 格式錯誤（應為 hex，如 0x0800）：{type_str!r}")
        if not 0 <= val <= 0xFFFF:
            raise PacketBuildError("EtherType 必須在 0x0000 ~ 0xFFFF 範圍內")
        return val

    @staticmethod
    def parse_int(value_str: str, field_name: str, lo: int = 0, hi: int = 65535) -> int:
        """解析整數字串並驗證範圍。"""
        try:
            val = int(value_str.strip())
        except ValueError:
            raise PacketBuildError(f"{field_name} 必須為整數，收到：{value_str!r}")
        if not lo <= val <= hi:
            raise PacketBuildError(f"{field_name} 必須在 {lo}~{hi} 範圍內，收到：{val}")
        return val

    @staticmethod
    def parse_ip(ip_str: str, field_name: str) -> str:
        """基本驗證 IPv4 位址格式。"""
        s = ip_str.strip()
        parts = s.split('.')
        if len(parts) != 4:
            raise PacketBuildError(f"{field_name} 不是合法的 IPv4 位址：{s!r}")
        try:
            for p in parts:
                v = int(p)
                if not 0 <= v <= 255:
                    raise ValueError
        except ValueError:
            raise PacketBuildError(f"{field_name} 不是合法的 IPv4 位址：{s!r}")
        return s

    # ------------------------------------------------------------------ #
    #  封包建構                                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def build_ethernet(fields: dict):
        """
        建立 Raw Ethernet frame。
        fields keys: dst_mac, src_mac, ethertype, payload
        """
        from scapy.layers.l2 import Ether
        from scapy.packet import Raw

        dst = PacketBuilder.parse_mac(fields['dst_mac'])
        src = PacketBuilder.parse_mac(fields['src_mac'])
        etype = PacketBuilder.parse_ethertype(fields['ethertype'])
        payload = PacketBuilder.parse_hex_payload(fields.get('payload', ''))

        pkt = Ether(dst=dst, src=src, type=etype)
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    @staticmethod
    def build_arp(fields: dict):
        """
        建立 ARP 封包（包含 Ethernet header）。
        fields keys: eth_dst, eth_src, op, hwsrc, psrc, hwdst, pdst
        """
        from scapy.layers.l2 import Ether, ARP

        eth_dst = PacketBuilder.parse_mac(fields['eth_dst'])
        eth_src = PacketBuilder.parse_mac(fields['eth_src'])
        op = PacketBuilder.parse_int(fields['op'], 'ARP op', 1, 2)
        hwsrc = PacketBuilder.parse_mac(fields['hwsrc'])
        psrc = PacketBuilder.parse_ip(fields['psrc'], 'Sender IP')
        hwdst = PacketBuilder.parse_mac(fields['hwdst'])
        pdst = PacketBuilder.parse_ip(fields['pdst'], 'Target IP')

        pkt = (Ether(dst=eth_dst, src=eth_src, type=0x0806) /
               ARP(op=op, hwsrc=hwsrc, psrc=psrc, hwdst=hwdst, pdst=pdst))
        return pkt

    @staticmethod
    def build_ip(fields: dict):
        """
        建立 IP 封包（包含 Ethernet header）。
        fields keys: eth_dst, eth_src, src_ip, dst_ip, ttl,
                     protocol ('ICMP'|'TCP'|'UDP'|'Raw'),
                     icmp_type, icmp_code,    （protocol=ICMP 時）
                     sport, dport,             （protocol=TCP/UDP 時）
                     proto_num,                （protocol=Raw 時）
                     payload                   （所有 protocol 皆適用）
        """
        from scapy.layers.l2 import Ether
        from scapy.layers.inet import IP, ICMP, TCP, UDP
        from scapy.packet import Raw

        eth_dst = PacketBuilder.parse_mac(fields['eth_dst'])
        eth_src = PacketBuilder.parse_mac(fields['eth_src'])
        src_ip = PacketBuilder.parse_ip(fields['src_ip'], 'Source IP')
        dst_ip = PacketBuilder.parse_ip(fields['dst_ip'], 'Destination IP')
        ttl = PacketBuilder.parse_int(fields.get('ttl', '64'), 'TTL', 1, 255)
        protocol = fields.get('protocol', 'ICMP')
        payload = PacketBuilder.parse_hex_payload(fields.get('payload', ''))

        eth = Ether(dst=eth_dst, src=eth_src)
        ip = IP(src=src_ip, dst=dst_ip, ttl=ttl)

        if protocol == 'ICMP':
            icmp_type = PacketBuilder.parse_int(fields.get('icmp_type', '8'), 'ICMP Type', 0, 255)
            icmp_code = PacketBuilder.parse_int(fields.get('icmp_code', '0'), 'ICMP Code', 0, 255)
            l4 = ICMP(type=icmp_type, code=icmp_code)

        elif protocol == 'TCP':
            sport = PacketBuilder.parse_int(fields.get('sport', '1024'), 'Src Port', 0, 65535)
            dport = PacketBuilder.parse_int(fields.get('dport', '80'), 'Dst Port', 0, 65535)
            l4 = TCP(sport=sport, dport=dport)

        elif protocol == 'UDP':
            sport = PacketBuilder.parse_int(fields.get('sport', '1024'), 'Src Port', 0, 65535)
            dport = PacketBuilder.parse_int(fields.get('dport', '53'), 'Dst Port', 0, 65535)
            l4 = UDP(sport=sport, dport=dport)

        else:  # Raw — 使用者自訂 IP Protocol 欄位
            proto_num = PacketBuilder.parse_int(fields.get('proto_num', '253'), 'IP Protocol', 0, 255)
            ip.proto = proto_num
            l4 = Raw(load=payload) if payload else Raw(load=b'\x00')
            return eth / ip / l4

        pkt = eth / ip / l4
        if payload:
            pkt = pkt / Raw(load=payload)
        return pkt

    # ------------------------------------------------------------------ #
    #  Hex Dump                                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def hex_dump(pkt) -> str:
        """
        將 Scapy 封包物件轉換為可讀的 Hex Dump 字串，
        格式：  偏移量  hex區   ASCII區
        """
        raw = bytes(pkt)
        if not raw:
            return "(empty)"
        lines = []
        for i in range(0, len(raw), 16):
            chunk = raw[i:i + 16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            lines.append(f"{i:04x}  {hex_part:<47}  {ascii_part}")
        total = f"\n共 {len(raw)} bytes"
        return '\n'.join(lines) + total
