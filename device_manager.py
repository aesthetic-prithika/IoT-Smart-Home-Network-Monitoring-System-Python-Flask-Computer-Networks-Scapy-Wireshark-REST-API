"""Device tracking and management for IoT network monitoring."""

import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from collections import defaultdict
from datetime import datetime
import socket
import struct


@dataclass
class DeviceInfo:
    """Information about a detected network device."""
    mac_address: str
    ip_address: str
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: str = "unknown"
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    is_authorized: bool = False
    bytes_sent: int = 0
    bytes_received: int = 0
    packets_sent: int = 0
    packets_received: int = 0
    open_ports: List[int] = field(default_factory=list)
    connection_count: int = 0
    
    def to_dict(self) -> dict:
        """Convert device info to dictionary for API responses."""
        return {
            "mac_address": self.mac_address,
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "vendor": self.vendor,
            "device_type": self.device_type,
            "first_seen": datetime.fromtimestamp(self.first_seen).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen).isoformat(),
            "is_authorized": self.is_authorized,
            "bandwidth": {
                "bytes_sent": self.bytes_sent,
                "bytes_received": self.bytes_received,
                "packets_sent": self.packets_sent,
                "packets_received": self.packets_received,
            },
            "open_ports": self.open_ports,
            "connection_count": self.connection_count,
            "status": "online" if time.time() - self.last_seen < 300 else "offline"
        }


# Common OUI (Organizationally Unique Identifier) prefixes for device identification
OUI_DATABASE = {
    "00:1A:2B": "Vendor A",
    "B8:27:EB": "Raspberry Pi Foundation",
    "DC:A6:32": "Raspberry Pi Foundation",
    "18:FE:34": "Espressif Systems",
    "24:0A:C4": "Espressif Systems",
    "AC:67:B2": "Espressif Systems",
    "60:01:94": "Espressif Systems",
    "50:02:91": "Amazon Technologies",
    "68:54:FD": "Amazon Technologies",
    "44:65:0D": "Amazon Technologies",
    "F0:27:2D": "Amazon Technologies",
    "74:C6:3B": "Amazon Technologies",
    "00:17:88": "Philips Lighting",
    "00:1F:5B": "Apple",
    "3C:06:30": "Apple",
    "F0:B4:29": "Google",
    "54:60:09": "Google",
    "30:FD:38": "Google",
    "A4:77:33": "Google (Nest)",
    "64:16:66": "Google (Nest)",
    "18:B4:30": "Nest Labs",
    "00:11:22": "Sonos",
    "B8:E9:37": "Sonos",
    "5C:AA:FD": "Sonos",
    "78:28:CA": "Sonos",
    "00:04:20": "Roku",
    "B0:A7:37": "Roku",
    "D8:31:34": "Roku",
    "00:0D:4B": "Roku",
    "00:50:C2": "TP-Link",
    "54:C8:0F": "TP-Link",
    "60:32:B1": "TP-Link",
    "70:4F:57": "TP-Link",
    "98:DA:C4": "TP-Link",
    "B0:BE:76": "TP-Link",
}

# Common IoT device type detection based on hostname patterns
DEVICE_TYPE_PATTERNS = {
    "camera": ["cam", "ipcam", "camera", "dvr", "nvr", "hikvision", "dahua", "reolink", "wyze"],
    "smart_speaker": ["echo", "alexa", "google-home", "homepod", "sonos"],
    "smart_tv": ["tv", "roku", "firetv", "chromecast", "appletv", "samsung-tv", "lg-tv"],
    "thermostat": ["nest", "ecobee", "thermostat", "hvac"],
    "smart_plug": ["plug", "switch", "outlet", "wemo", "kasa", "tplink"],
    "smart_light": ["hue", "lifx", "bulb", "light", "lamp"],
    "router": ["router", "gateway", "ap", "access-point"],
    "phone": ["iphone", "android", "phone", "mobile"],
    "computer": ["desktop", "laptop", "pc", "macbook", "imac"],
    "printer": ["printer", "print", "epson", "hp-", "canon", "brother"],
    "gaming": ["playstation", "xbox", "nintendo", "switch", "ps4", "ps5"],
}


class DeviceManager:
    """Manages device detection, tracking, and classification."""
    
    def __init__(self, whitelist_macs: set = None):
        self._devices: Dict[str, DeviceInfo] = {}
        self._lock = threading.RLock()
        self._whitelist_macs = whitelist_macs or set()
        self._traffic_history: Dict[str, list] = defaultdict(list)
        
    @property
    def devices(self) -> Dict[str, DeviceInfo]:
        """Thread-safe access to devices dictionary."""
        with self._lock:
            return dict(self._devices)
    
    def update_device(self, mac: str, ip: str, hostname: Optional[str] = None) -> DeviceInfo:
        """Update or create device entry."""
        mac = mac.upper()
        
        with self._lock:
            if mac in self._devices:
                device = self._devices[mac]
                device.ip_address = ip
                device.last_seen = time.time()
                if hostname:
                    device.hostname = hostname
            else:
                device = DeviceInfo(
                    mac_address=mac,
                    ip_address=ip,
                    hostname=hostname,
                    vendor=self._lookup_vendor(mac),
                    is_authorized=mac in self._whitelist_macs
                )
                device.device_type = self._classify_device(device)
                self._devices[mac] = device
            
            return device
    
    def record_traffic(self, mac: str, bytes_sent: int = 0, bytes_received: int = 0,
                       packets_sent: int = 0, packets_received: int = 0):
        """Record traffic statistics for a device."""
        mac = mac.upper()
        
        with self._lock:
            if mac in self._devices:
                device = self._devices[mac]
                device.bytes_sent += bytes_sent
                device.bytes_received += bytes_received
                device.packets_sent += packets_sent
                device.packets_received += packets_received
                device.last_seen = time.time()
                
                # Store for historical analysis
                self._traffic_history[mac].append({
                    "timestamp": time.time(),
                    "bytes_sent": bytes_sent,
                    "bytes_received": bytes_received
                })
                
                # Keep only last hour of granular data
                cutoff = time.time() - 3600
                self._traffic_history[mac] = [
                    t for t in self._traffic_history[mac]
                    if t["timestamp"] > cutoff
                ]
    
    def increment_connections(self, mac: str):
        """Increment connection count for a device."""
        mac = mac.upper()
        with self._lock:
            if mac in self._devices:
                self._devices[mac].connection_count += 1
    
    def authorize_device(self, mac: str, authorized: bool = True):
        """Set device authorization status."""
        mac = mac.upper()
        with self._lock:
            if mac in self._devices:
                self._devices[mac].is_authorized = authorized
                if authorized:
                    self._whitelist_macs.add(mac)
                elif mac in self._whitelist_macs:
                    self._whitelist_macs.discard(mac)
    
    def get_device(self, mac: str) -> Optional[DeviceInfo]:
        """Get device by MAC address."""
        with self._lock:
            return self._devices.get(mac.upper())
    
    def get_device_by_ip(self, ip: str) -> Optional[DeviceInfo]:
        """Get device by IP address."""
        with self._lock:
            for device in self._devices.values():
                if device.ip_address == ip:
                    return device
        return None
    
    def get_all_devices(self) -> List[DeviceInfo]:
        """Get list of all tracked devices."""
        with self._lock:
            return list(self._devices.values())
    
    def get_online_devices(self, timeout: int = 300) -> List[DeviceInfo]:
        """Get devices seen within timeout seconds."""
        cutoff = time.time() - timeout
        with self._lock:
            return [d for d in self._devices.values() if d.last_seen > cutoff]
    
    def get_unauthorized_devices(self) -> List[DeviceInfo]:
        """Get list of unauthorized devices."""
        with self._lock:
            return [d for d in self._devices.values() if not d.is_authorized]
    
    def get_traffic_stats(self) -> dict:
        """Get aggregate traffic statistics."""
        with self._lock:
            total_sent = sum(d.bytes_sent for d in self._devices.values())
            total_received = sum(d.bytes_received for d in self._devices.values())
            
            # Top talkers
            top_by_traffic = sorted(
                self._devices.values(),
                key=lambda d: d.bytes_sent + d.bytes_received,
                reverse=True
            )[:10]
            
            return {
                "total_bytes_sent": total_sent,
                "total_bytes_received": total_received,
                "total_devices": len(self._devices),
                "online_devices": len(self.get_online_devices()),
                "unauthorized_devices": len(self.get_unauthorized_devices()),
                "top_talkers": [
                    {
                        "mac": d.mac_address,
                        "ip": d.ip_address,
                        "hostname": d.hostname,
                        "bytes_total": d.bytes_sent + d.bytes_received
                    }
                    for d in top_by_traffic
                ]
            }
    
    def _lookup_vendor(self, mac: str) -> Optional[str]:
        """Look up vendor from MAC address OUI."""
        oui = mac[:8].upper()
        return OUI_DATABASE.get(oui)
    
    def _classify_device(self, device: DeviceInfo) -> str:
        """Classify device type based on available information."""
        search_strings = []
        
        if device.hostname:
            search_strings.append(device.hostname.lower())
        if device.vendor:
            search_strings.append(device.vendor.lower())
        
        combined = " ".join(search_strings)
        
        for device_type, patterns in DEVICE_TYPE_PATTERNS.items():
            for pattern in patterns:
                if pattern in combined:
                    return device_type
        
        return "unknown"
    
    def resolve_hostname(self, ip: str) -> Optional[str]:
        """Attempt to resolve hostname for an IP address."""
        try:
            hostname, _, _ = socket.gethostbyaddr(ip)
            return hostname
        except (socket.herror, socket.gaierror):
            return None
    
    def clear_offline_devices(self, timeout: int = 86400):
        """Remove devices not seen for timeout seconds."""
        cutoff = time.time() - timeout
        with self._lock:
            to_remove = [
                mac for mac, device in self._devices.items()
                if device.last_seen < cutoff
            ]
            for mac in to_remove:
                del self._devices[mac]
                if mac in self._traffic_history:
                    del self._traffic_history[mac]
        return len(to_remove)
