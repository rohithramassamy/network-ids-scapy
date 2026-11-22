import re
from collections import defaultdict

from scapy.all import (
    sniff,
    rdpcap,
    Ether,
    ARP,
    IP,
    IPv6,
    TCP,
    UDP,
    ICMP,
    DNS,
    Raw,
)

from tp1.utils.lib import choose_interface
from tp1.utils.config import logger


class Capture:
    def __init__(self, pcap_file=None, interface=None) -> None:
        self.interface = interface or ""
        self.pcap_file = pcap_file
        self.summary = ""
        self.packets = []
        self.attacks = []
        self.flag = None

    def capture_traffic(self) -> None:
        """Read a PCAP file or capture live traffic."""
        if self.pcap_file:
            logger.info("Lecture du fichier PCAP : %s", self.pcap_file)
            self.packets = rdpcap(self.pcap_file)
        else:
            if not self.interface:
                self.interface = choose_interface()
            if not self.interface:
                raise ValueError("Aucune interface réseau sélectionnée.")
            logger.info("Capture sur l'interface : %s", self.interface)
            self.packets = sniff(iface=self.interface, timeout=10)

        logger.info("%s paquet(s) chargé(s).", len(self.packets))

    def sort_network_protocols(self) -> str:
        """Return the protocol names found in packets."""
        protocols = set()

        layers = [
            ("Ethernet", Ether),
            ("ARP", ARP),
            ("IP", IP),
            ("IPv6", IPv6),
            ("TCP", TCP),
            ("UDP", UDP),
            ("ICMP", ICMP),
            ("DNS", DNS),
        ]

        for packet in self.packets:
            for name, layer in layers:
                if layer in packet:
                    protocols.add(name)

        return ", ".join(sorted(protocols))

    def get_protocol_counts(self) -> dict:
        """Count packets containing each supported protocol."""
        counts = {}

        layers = [
            ("Ethernet", Ether),
            ("ARP", ARP),
            ("IP", IP),
            ("IPv6", IPv6),
            ("TCP", TCP),
            ("UDP", UDP),
            ("ICMP", ICMP),
            ("DNS", DNS),
        ]

        for packet in self.packets:
            for name, layer in layers:
                if layer in packet:
                    counts[name] = counts.get(name, 0) + 1

        return counts

    def get_all_protocols(self) -> str:
        """Return protocol counts as readable text."""
        counts = self.get_protocol_counts()
        return str(counts) if counts else ""

    def analyse(self, protocols: str = "ALL") -> None:
        """Detect basic ARP spoofing, TCP port scans and SQL injection."""
        self.attacks = []
        self.flag = None

        ip_to_macs = defaultdict(set)
        syn_ports = defaultdict(set)

        sql_patterns = (
            r"'\s*or\s+\d+\s*=\s*\d+",
            r"union\s+select",
            r"select\s+.+\s+from",
            r"or\s+['\"]?1['\"]?\s*=\s*['\"]?1",
        )

        for packet in self.packets:
            payload = b""

            if Raw in packet:
                payload = bytes(packet[Raw].load)

            text_payload = payload.decode("utf-8", errors="ignore")

            # Search for a flag in packet payloads.
            if self.flag is None:
                match = re.search(
                    r"ESGI\{[^}\r\n]+\}",
                    text_payload,
                )
                if match:
                    self.flag = match.group(0)

            # ARP: record IP/MAC associations.
            if ARP in packet:
                arp = packet[ARP]

                if arp.psrc and arp.hwsrc:
                    ip_to_macs[arp.psrc].add(arp.hwsrc.lower())

                # An unsolicited ARP reply can be suspicious.
                if arp.op == 2 and arp.psrc and arp.hwsrc:
                    if arp.pdst and arp.pdst == arp.psrc:
                        self._add_attack(
                            "arp_spoofing",
                            arp.hwsrc.lower(),
                        )

            # TCP SYN scan: count distinct destination ports per source IP.
            if IP in packet and TCP in packet:
                ip = packet[IP]
                tcp = packet[TCP]
                flags = int(tcp.flags)

                syn_set = bool(flags & 0x02)
                ack_set = bool(flags & 0x10)

                if syn_set and not ack_set:
                    syn_ports[ip.src].add(int(tcp.dport))

            # SQL injection in HTTP-like payloads.
            if TCP in packet and payload:
                tcp = packet[TCP]

                is_http = (
                    tcp.dport in (80, 8080, 8000)
                    or tcp.sport in (80, 8080, 8000)
                    or b"HTTP" in payload
                )

                if is_http:
                    lowered = text_payload.lower()

                    if any(
                        re.search(pattern, lowered)
                        for pattern in sql_patterns
                    ):
                        attacker = (
                            packet[IP].src
                            if IP in packet
                            else "unknown"
                        )
                        self._add_attack("sql_injection", attacker)

        # Multiple MAC addresses advertising the same IP.
        for ip_address, macs in ip_to_macs.items():
            if len(macs) > 1:
                for mac in sorted(macs):
                    self._add_attack("arp_spoofing", mac)

        # Five or more distinct destination ports trigger a scan alert.
        for source_ip, ports in syn_ports.items():
            if len(ports) >= 5:
                self._add_attack("port_scan", source_ip)

        self.summary = self._gen_summary()

        logger.info("Analyse terminée.")
        logger.info(self.summary)

    def _add_attack(self, attack_type: str, attacker: str) -> None:
        """Add an attack only once for each type and attacker."""
        item = {
            "type": attack_type,
            "attacker": attacker,
        }

        if item not in self.attacks:
            self.attacks.append(item)
            logger.warning("Attaque détectée : %s", item)

    def get_summary(self) -> str:
        return self.summary

    def _gen_summary(self) -> str:
        source = self.pcap_file or self.interface or "Non spécifiée"

        return (
            f"Source : {source}\n"
            f"Nombre total de paquets : {len(self.packets)}\n"
            f"Protocoles : {self.get_all_protocols()}\n"
            f"Attaques : {len(self.attacks)}\n"
            f"Flag trouvé : {'oui' if self.flag else 'non'}"
        )
