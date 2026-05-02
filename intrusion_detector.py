"""Intrusion detection and security monitoring for IoT networks."""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set
from collections import defaultdict
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Security alert severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(Enum):
    """Types of security alerts."""
    NEW_DEVICE = "new_device"
    UNAUTHORIZED_DEVICE = "unauthorized_device"
    PORT_SCAN = "port_scan"
    SUSPICIOUS_PORT = "suspicious_port"
    HIGH_BANDWIDTH = "high_bandwidth"
    ARP_SPOOFING = "arp_spoofing"
    DNS_TUNNELING = "dns_tunneling"
    KNOWN_MALICIOUS_IP = "known_malicious_ip"
    UNUSUAL_TRAFFIC_PATTERN = "unusual_traffic_pattern"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    DEVICE_RAPID_CONNECTIONS = "device_rapid_connections"


@dataclass
class SecurityAlert:
    """Security alert data structure."""
    alert_id: str
    alert_type: AlertType
    severity: AlertSeverity
    timestamp: float
    source_mac: Optional[str]
    source_ip: Optional[str]
    target_ip: Optional[str] = None
    target_port: Optional[int] = None
    description: str = ""
    details: dict = field(default_factory=dict)
    acknowledged: bool = False
    
    def to_dict(self) -> dict:
        """Convert alert to dictionary for API responses."""
        return {
            "alert_id": self.alert_id,
            "type": self.alert_type.value,
            "severity": self.severity.value,
            "timestamp": datetime.fromtimestamp(self.timestamp).isoformat(),
            "source_mac": self.source_mac,
            "source_ip": self.source_ip,
            "target_ip": self.target_ip,
            "target_port": self.target_port,
            "description": self.description,
            "details": self.details,
            "acknowledged": self.acknowledged
        }


class IntrusionDetector:
    """Detects suspicious network activity and potential intrusions."""
    
    def __init__(self, config):
        self.config = config
        self._alerts: List[SecurityAlert] = []
        self._alert_counter = 0
        self._lock = threading.RLock()
        
        # Tracking structures for anomaly detection
        self._port_scan_tracker: Dict[str, Dict[str, Set[int]]] = defaultdict(
            lambda: defaultdict(set)
        )  # source_ip -> target_ip -> set of ports
        self._connection_rate: Dict[str, List[float]] = defaultdict(list)
        self._bandwidth_samples: Dict[str, List[tuple]] = defaultdict(list)
        self._arp_table: Dict[str, str] = {}  # IP -> MAC mapping
        self._dns_query_tracker: Dict[str, List[tuple]] = defaultdict(list)
        self._known_devices: Set[str] = set()
        self._last_cleanup = time.time()
        
    def _generate_alert_id(self) -> str:
        """Generate unique alert ID."""
        self._alert_counter += 1
        return f"ALERT-{int(time.time())}-{self._alert_counter:06d}"
    
    def _create_alert(
        self,
        alert_type: AlertType,
        severity: AlertSeverity,
        source_mac: Optional[str],
        source_ip: Optional[str],
        description: str,
        target_ip: Optional[str] = None,
        target_port: Optional[int] = None,
        details: dict = None
    ) -> SecurityAlert:
        """Create and store a new security alert."""
        alert = SecurityAlert(
            alert_id=self._generate_alert_id(),
            alert_type=alert_type,
            severity=severity,
            timestamp=time.time(),
            source_mac=source_mac,
            source_ip=source_ip,
            target_ip=target_ip,
            target_port=target_port,
            description=description,
            details=details or {}
        )
        
        with self._lock:
            self._alerts.append(alert)
            # Keep only recent alerts
            cutoff = time.time() - (self.config.security.get("alert_retention_days", 7) * 86400
                                    if hasattr(self.config.security, "get") 
                                    else 7 * 86400)
            self._alerts = [a for a in self._alerts if a.timestamp > cutoff]
        
        logger.warning(f"Security Alert [{severity.value}]: {description}")
        return alert
    
    def check_new_device(self, mac: str, ip: str, is_authorized: bool) -> Optional[SecurityAlert]:
        """Check for new or unauthorized devices."""
        mac = mac.upper()
        
        with self._lock:
            is_new = mac not in self._known_devices
            self._known_devices.add(mac)
        
        if is_new:
            if not is_authorized:
                return self._create_alert(
                    AlertType.UNAUTHORIZED_DEVICE,
                    AlertSeverity.HIGH,
                    mac, ip,
                    f"Unauthorized device detected: {mac} ({ip})",
                    details={"mac": mac, "ip": ip}
                )
            else:
                return self._create_alert(
                    AlertType.NEW_DEVICE,
                    AlertSeverity.INFO,
                    mac, ip,
                    f"New device connected: {mac} ({ip})",
                    details={"mac": mac, "ip": ip}
                )
        return None
    
    def check_port_scan(self, source_ip: str, target_ip: str, target_port: int,
                        source_mac: Optional[str] = None) -> Optional[SecurityAlert]:
        """Detect port scanning activity."""
        current_time = time.time()
        threshold = self.config.security.port_scan_threshold
        
        with self._lock:
            # Track the port access
            self._port_scan_tracker[source_ip][target_ip].add(target_port)
            
            # Clean old entries periodically
            if current_time - self._last_cleanup > 60:
                self._cleanup_trackers()
                self._last_cleanup = current_time
            
            ports_accessed = len(self._port_scan_tracker[source_ip][target_ip])
            
            if ports_accessed >= threshold:
                # Reset tracker to avoid repeated alerts
                self._port_scan_tracker[source_ip][target_ip].clear()
                
                return self._create_alert(
                    AlertType.PORT_SCAN,
                    AlertSeverity.HIGH,
                    source_mac, source_ip,
                    f"Port scan detected from {source_ip} to {target_ip}",
                    target_ip=target_ip,
                    details={
                        "ports_scanned": ports_accessed,
                        "threshold": threshold
                    }
                )
        return None
    
    def check_suspicious_port(self, source_ip: str, target_ip: str, target_port: int,
                               source_mac: Optional[str] = None) -> Optional[SecurityAlert]:
        """Check for connections to suspicious ports."""
        if target_port in self.config.security.suspicious_ports:
            return self._create_alert(
                AlertType.SUSPICIOUS_PORT,
                AlertSeverity.MEDIUM,
                source_mac, source_ip,
                f"Connection to suspicious port {target_port} from {source_ip}",
                target_ip=target_ip,
                target_port=target_port,
                details={"port_description": self._get_port_description(target_port)}
            )
        return None
    
    def check_bandwidth_anomaly(self, mac: str, ip: str, bytes_per_second: float) -> Optional[SecurityAlert]:
        """Detect unusual bandwidth usage."""
        threshold_bps = self.config.security.bandwidth_alert_mbps * 1_000_000 / 8
        
        with self._lock:
            # Store sample
            self._bandwidth_samples[mac].append((time.time(), bytes_per_second))
            
            # Keep last 5 minutes of samples
            cutoff = time.time() - 300
            self._bandwidth_samples[mac] = [
                (t, b) for t, b in self._bandwidth_samples[mac] if t > cutoff
            ]
            
            if bytes_per_second > threshold_bps:
                return self._create_alert(
                    AlertType.HIGH_BANDWIDTH,
                    AlertSeverity.MEDIUM,
                    mac, ip,
                    f"High bandwidth usage detected from {ip}: {bytes_per_second / 1_000_000:.2f} MB/s",
                    details={
                        "bytes_per_second": bytes_per_second,
                        "threshold_mbps": self.config.security.bandwidth_alert_mbps
                    }
                )
        return None
    
    def check_arp_spoofing(self, ip: str, mac: str) -> Optional[SecurityAlert]:
        """Detect potential ARP spoofing attacks."""
        mac = mac.upper()
        
        with self._lock:
            if ip in self._arp_table and self._arp_table[ip] != mac:
                old_mac = self._arp_table[ip]
                self._arp_table[ip] = mac
                
                return self._create_alert(
                    AlertType.ARP_SPOOFING,
                    AlertSeverity.CRITICAL,
                    mac, ip,
                    f"Possible ARP spoofing: IP {ip} changed from {old_mac} to {mac}",
                    details={
                        "old_mac": old_mac,
                        "new_mac": mac
                    }
                )
            else:
                self._arp_table[ip] = mac
        return None
    
    def check_known_malicious_ip(self, ip: str, source_mac: Optional[str] = None,
                                  source_ip: Optional[str] = None) -> Optional[SecurityAlert]:
        """Check if IP is in known malicious IP list."""
        if ip in self.config.security.known_malicious_ips:
            return self._create_alert(
                AlertType.KNOWN_MALICIOUS_IP,
                AlertSeverity.CRITICAL,
                source_mac, source_ip,
                f"Connection to known malicious IP: {ip}",
                target_ip=ip,
                details={"malicious_ip": ip}
            )
        return None
    
    def check_connection_rate(self, mac: str, ip: str) -> Optional[SecurityAlert]:
        """Detect rapid connection attempts."""
        current_time = time.time()
        
        with self._lock:
            self._connection_rate[mac].append(current_time)
            
            # Keep last minute of connections
            cutoff = current_time - 60
            self._connection_rate[mac] = [
                t for t in self._connection_rate[mac] if t > cutoff
            ]
            
            connections = len(self._connection_rate[mac])
            
            # Alert if more than 100 connections per minute
            if connections > 100:
                self._connection_rate[mac].clear()
                return self._create_alert(
                    AlertType.DEVICE_RAPID_CONNECTIONS,
                    AlertSeverity.MEDIUM,
                    mac, ip,
                    f"Rapid connection rate from {ip}: {connections} connections/minute",
                    details={"connections_per_minute": connections}
                )
        return None
    
    def analyze_packet(self, packet_info: dict) -> List[SecurityAlert]:
        """Analyze a packet and return any generated alerts."""
        alerts = []
        
        source_mac = packet_info.get("src_mac")
        source_ip = packet_info.get("src_ip")
        target_ip = packet_info.get("dst_ip")
        target_port = packet_info.get("dst_port")
        
        # Check for suspicious port access
        if target_port:
            alert = self.check_suspicious_port(source_ip, target_ip, target_port, source_mac)
            if alert:
                alerts.append(alert)
            
            # Check for port scanning
            alert = self.check_port_scan(source_ip, target_ip, target_port, source_mac)
            if alert:
                alerts.append(alert)
        
        # Check for known malicious IPs
        if target_ip:
            alert = self.check_known_malicious_ip(target_ip, source_mac, source_ip)
            if alert:
                alerts.append(alert)
        
        return alerts
    
    def get_alerts(self, severity: Optional[AlertSeverity] = None,
                   alert_type: Optional[AlertType] = None,
                   limit: int = 100,
                   unacknowledged_only: bool = False) -> List[SecurityAlert]:
        """Retrieve alerts with optional filtering."""
        with self._lock:
            alerts = self._alerts.copy()
        
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        if unacknowledged_only:
            alerts = [a for a in alerts if not a.acknowledged]
        
        # Sort by timestamp descending
        alerts.sort(key=lambda a: a.timestamp, reverse=True)
        return alerts[:limit]
    
    def acknowledge_alert(self, alert_id: str) -> bool:
        """Mark an alert as acknowledged."""
        with self._lock:
            for alert in self._alerts:
                if alert.alert_id == alert_id:
                    alert.acknowledged = True
                    return True
        return False
    
    def get_alert_summary(self) -> dict:
        """Get summary of alerts by severity and type."""
        with self._lock:
            alerts = self._alerts.copy()
        
        by_severity = defaultdict(int)
        by_type = defaultdict(int)
        unacknowledged = 0
        
        for alert in alerts:
            by_severity[alert.severity.value] += 1
            by_type[alert.alert_type.value] += 1
            if not alert.acknowledged:
                unacknowledged += 1
        
        return {
            "total": len(alerts),
            "unacknowledged": unacknowledged,
            "by_severity": dict(by_severity),
            "by_type": dict(by_type),
            "recent": [a.to_dict() for a in self.get_alerts(limit=5)]
        }
    
    def _cleanup_trackers(self):
        """Clean up old tracking data."""
        cutoff = time.time() - 60
        
        # Clean port scan tracker
        for source_ip in list(self._port_scan_tracker.keys()):
            if not self._port_scan_tracker[source_ip]:
                del self._port_scan_tracker[source_ip]
        
        # Clean connection rate tracker
        for mac in list(self._connection_rate.keys()):
            self._connection_rate[mac] = [
                t for t in self._connection_rate[mac] if t > cutoff
            ]
            if not self._connection_rate[mac]:
                del self._connection_rate[mac]
    
    def _get_port_description(self, port: int) -> str:
        """Get description for suspicious ports."""
        descriptions = {
            23: "Telnet - unencrypted remote access",
            2323: "Alternative Telnet - commonly targeted by IoT botnets",
            5555: "Android Debug Bridge - often exploited",
            7547: "TR-069 - ISP management protocol, frequently attacked",
            37215: "Huawei router exploit port",
            52869: "Realtek SDK vulnerability port",
        }
        return descriptions.get(port, "Suspicious service port")
