"""Network packet capture and traffic analysis using Scapy."""

import time
import threading
import logging
from typing import Callable, Optional, Dict, List
from collections import defaultdict
from dataclasses import dataclass
import ipaddress

try:
    from scapy.all import (
        sniff, ARP, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR,
        get_if_list, get_if_hwaddr, conf, sendp
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logging.warning("Scapy not available. Install with: pip install scapy")

from device_manager import DeviceManager
from intrusion_detector import IntrusionDetector

logger = logging.getLogger(__name__)


@dataclass
class PacketStats:
    """Statistics for captured packets."""
    total_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    icmp_packets: int = 0
    arp_packets: int = 0
    dns_queries: int = 0
    total_bytes: int = 0
    start_time: float = 0
    
    def to_dict(self) -> dict:
        elapsed = time.time() - self.start_time if self.start_time else 1
        return {
            "total_packets": self.total_packets,
            "tcp_packets": self.tcp_packets,
            "udp_packets": self.udp_packets,
            "icmp_packets": self.icmp_packets,
            "arp_packets": self.arp_packets,
            "dns_queries": self.dns_queries,
            "total_bytes": self.total_bytes,
            "packets_per_second": self.total_packets / elapsed,
            "bytes_per_second": self.total_bytes / elapsed,
            "elapsed_seconds": elapsed
        }


class NetworkMonitor:
    """Real-time network packet capture and analysis."""
    
    def __init__(self, config, device_manager: DeviceManager,
                 intrusion_detector: IntrusionDetector):
        self.config = config
        self.device_manager = device_manager
        self.intrusion_detector = intrusion_detector
        
        self.interface = config.network.interface
        self.local_subnet = ipaddress.ip_network(config.network.subnet, strict=False)
        self.gateway_ip = config.network.gateway_ip
        
        self._running = False
        self._capture_thread: Optional[threading.Thread] = None
        self._stats = PacketStats()
        self._lock = threading.RLock()
        
        # Traffic analysis
        self._protocol_stats: Dict[str, int] = defaultdict(int)
        self._port_stats: Dict[int, int] = defaultdict(int)
        self._recent_packets: List[dict] = []
        self._max_recent_packets = config.network.packet_buffer_size
        
        # Callbacks for real-time updates
        self._packet_callbacks: List[Callable] = []
        self._alert_callbacks: List[Callable] = []
        
        # Validate interface
        self._validate_interface()
    
    def _validate_interface(self):
        """Validate that the configured interface exists."""
        if not SCAPY_AVAILABLE:
            logger.warning("Scapy not available - packet capture disabled")
            return
        
        available_interfaces = get_if_list()
        if self.interface not in available_interfaces:
            logger.warning(
                f"Interface '{self.interface}' not found. "
                f"Available: {available_interfaces}"
            )
    
    def start(self):
        """Start packet capture."""
        if not SCAPY_AVAILABLE:
            logger.error("Cannot start capture: Scapy not available")
            return False
        
        if self._running:
            logger.warning("Monitor already running")
            return False
        
        self._running = True
        self._stats = PacketStats(start_time=time.time())
        
        self._capture_thread = threading.Thread(
            target=self._capture_loop,
            daemon=True,
            name="PacketCapture"
        )
        self._capture_thread.start()
        
        logger.info(f"Started packet capture on {self.interface}")
        return True
    
    def stop(self):
        """Stop packet capture."""
        self._running = False
        if self._capture_thread:
            self._capture_thread.join(timeout=5)
            self._capture_thread = None
        logger.info("Stopped packet capture")
    
    def _capture_loop(self):
        """Main packet capture loop."""
        try:
            sniff(
                iface=self.interface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: not self._running
            )
        except PermissionError:
            logger.error(
                "Permission denied for packet capture. "
                "Run with sudo or set CAP_NET_RAW capability."
            )
        except Exception as e:
            logger.error(f"Capture error: {e}")
    
    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            packet_info = self._parse_packet(packet)
            if not packet_info:
                return
            
            with self._lock:
                self._stats.total_packets += 1
                self._stats.total_bytes += len(packet)
                
                # Update protocol stats
                if packet_info.get("protocol"):
                    self._protocol_stats[packet_info["protocol"]] += 1
                    
                    if packet_info["protocol"] == "TCP":
                        self._stats.tcp_packets += 1
                    elif packet_info["protocol"] == "UDP":
                        self._stats.udp_packets += 1
                    elif packet_info["protocol"] == "ICMP":
                        self._stats.icmp_packets += 1
                
                if packet_info.get("dst_port"):
                    self._port_stats[packet_info["dst_port"]] += 1
                
                # Store recent packet
                self._recent_packets.append(packet_info)
                if len(self._recent_packets) > self._max_recent_packets:
                    self._recent_packets.pop(0)
            
            # Update device tracking
            self._update_devices(packet_info)
            
            # Run intrusion detection
            alerts = self.intrusion_detector.analyze_packet(packet_info)
            for alert in alerts:
                self._notify_alert(alert)
            
            # Notify callbacks
            for callback in self._packet_callbacks:
                try:
                    callback(packet_info)
                except Exception as e:
                    logger.error(f"Packet callback error: {e}")
                    
        except Exception as e:
            logger.error(f"Error processing packet: {e}")
    
    def _parse_packet(self, packet) -> Optional[dict]:
        """Parse packet into structured information."""
        info = {
            "timestamp": time.time(),
            "length": len(packet)
        }
        
        # Ethernet layer
        if Ether in packet:
            info["src_mac"] = packet[Ether].src.upper()
            info["dst_mac"] = packet[Ether].dst.upper()
        
        # ARP
        if ARP in packet:
            info["protocol"] = "ARP"
            info["src_ip"] = packet[ARP].psrc
            info["dst_ip"] = packet[ARP].pdst
            
            with self._lock:
                self._stats.arp_packets += 1
            
            # Check for ARP spoofing
            if packet[ARP].op == 2:  # ARP reply
                alert = self.intrusion_detector.check_arp_spoofing(
                    packet[ARP].psrc,
                    packet[ARP].hwsrc.upper()
                )
                if alert:
                    self._notify_alert(alert)
            
            return info
        
        # IP layer
        if IP in packet:
            info["src_ip"] = packet[IP].src
            info["dst_ip"] = packet[IP].dst
            info["ttl"] = packet[IP].ttl
            
            # TCP
            if TCP in packet:
                info["protocol"] = "TCP"
                info["src_port"] = packet[TCP].sport
                info["dst_port"] = packet[TCP].dport
                info["tcp_flags"] = str(packet[TCP].flags)
            
            # UDP
            elif UDP in packet:
                info["protocol"] = "UDP"
                info["src_port"] = packet[UDP].sport
                info["dst_port"] = packet[UDP].dport
                
                # DNS
                if DNS in packet and packet.haslayer(DNSQR):
                    info["dns_query"] = packet[DNSQR].qname.decode(errors="ignore")
                    with self._lock:
                        self._stats.dns_queries += 1
            
            # ICMP
            elif ICMP in packet:
                info["protocol"] = "ICMP"
                info["icmp_type"] = packet[ICMP].type
                info["icmp_code"] = packet[ICMP].code
        
        return info if "src_ip" in info or "src_mac" in info else None
    
    def _update_devices(self, packet_info: dict):
        """Update device manager with packet information."""
        src_mac = packet_info.get("src_mac")
        src_ip = packet_info.get("src_ip")
        
        if src_mac and src_ip:
            # Check if this is a local device
            try:
                if ipaddress.ip_address(src_ip) in self.local_subnet:
                    # Update or create device
                    device = self.device_manager.update_device(src_mac, src_ip)
                    
                    # Check if new device
                    alert = self.intrusion_detector.check_new_device(
                        src_mac, src_ip, device.is_authorized
                    )
                    if alert:
                        self._notify_alert(alert)
                    
                    # Record traffic
                    self.device_manager.record_traffic(
                        src_mac,
                        bytes_sent=packet_info.get("length", 0),
                        packets_sent=1
                    )
                    
                    # Check connection rate
                    alert = self.intrusion_detector.check_connection_rate(src_mac, src_ip)
                    if alert:
                        self._notify_alert(alert)
            except ValueError:
                pass  # Invalid IP address
        
        # Track received traffic
        dst_mac = packet_info.get("dst_mac")
        dst_ip = packet_info.get("dst_ip")
        
        if dst_mac and dst_ip:
            try:
                if ipaddress.ip_address(dst_ip) in self.local_subnet:
                    self.device_manager.record_traffic(
                        dst_mac,
                        bytes_received=packet_info.get("length", 0),
                        packets_received=1
                    )
            except ValueError:
                pass
    
    def _notify_alert(self, alert):
        """Notify registered callbacks of a new alert."""
        for callback in self._alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                logger.error(f"Alert callback error: {e}")
    
    def register_packet_callback(self, callback: Callable):
        """Register a callback for packet events."""
        self._packet_callbacks.append(callback)
    
    def register_alert_callback(self, callback: Callable):
        """Register a callback for alert events."""
        self._alert_callbacks.append(callback)
    
    def get_stats(self) -> dict:
        """Get current packet statistics."""
        with self._lock:
            return self._stats.to_dict()
    
    def get_protocol_stats(self) -> dict:
        """Get protocol distribution statistics."""
        with self._lock:
            total = sum(self._protocol_stats.values())
            return {
                proto: {
                    "count": count,
                    "percentage": (count / total * 100) if total > 0 else 0
                }
                for proto, count in self._protocol_stats.items()
            }
    
    def get_port_stats(self, top_n: int = 20) -> List[dict]:
        """Get top ports by traffic."""
        with self._lock:
            sorted_ports = sorted(
                self._port_stats.items(),
                key=lambda x: x[1],
                reverse=True
            )[:top_n]
            return [
                {"port": port, "count": count, "service": self._get_service_name(port)}
                for port, count in sorted_ports
            ]
    
    def get_recent_packets(self, limit: int = 50) -> List[dict]:
        """Get recent packets."""
        with self._lock:
            return self._recent_packets[-limit:]
    
    def _get_service_name(self, port: int) -> str:
        """Get common service name for a port."""
        services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet",
            25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
            80: "HTTP", 110: "POP3", 123: "NTP", 143: "IMAP",
            443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
            1883: "MQTT", 3389: "RDP", 5353: "mDNS", 8080: "HTTP-Alt",
            8443: "HTTPS-Alt", 8883: "MQTT-TLS"
        }
        return services.get(port, "Unknown")
    
    def perform_network_scan(self) -> List[dict]:
        """Perform ARP scan to discover devices on the network."""
        if not SCAPY_AVAILABLE:
            return []
        
        from scapy.all import ARP, Ether, srp
        
        logger.info(f"Scanning network {self.config.network.subnet}")
        
        # Create ARP request packet
        arp = ARP(pdst=self.config.network.subnet)
        ether = Ether(dst="ff:ff:ff:ff:ff:ff")
        packet = ether / arp
        
        try:
            result = srp(packet, timeout=3, verbose=False, iface=self.interface)[0]
            
            discovered = []
            for sent, received in result:
                mac = received.hwsrc.upper()
                ip = received.psrc
                
                # Update device manager
                device = self.device_manager.update_device(mac, ip)
                
                # Try to resolve hostname
                hostname = self.device_manager.resolve_hostname(ip)
                if hostname:
                    device.hostname = hostname
                
                discovered.append({
                    "mac": mac,
                    "ip": ip,
                    "hostname": hostname,
                    "vendor": device.vendor
                })
                
                # Check for new devices
                alert = self.intrusion_detector.check_new_device(
                    mac, ip, device.is_authorized
                )
                if alert:
                    self._notify_alert(alert)
            
            logger.info(f"Discovered {len(discovered)} devices")
            return discovered
            
        except Exception as e:
            logger.error(f"Network scan failed: {e}")
            return []
    
    @property
    def is_running(self) -> bool:
        """Check if capture is running."""
        return self._running
