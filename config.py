"""Configuration settings for the IoT monitoring system."""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class NetworkConfig:
    """Network monitoring configuration."""
    interface: str = "eth0"  # Network interface to monitor
    subnet: str = "192.168.1.0/24"  # Local network subnet
    gateway_ip: str = "192.168.1.1"
    scan_interval: int = 30  # Seconds between network scans
    packet_buffer_size: int = 1000  # Max packets to keep in memory


@dataclass
class SecurityConfig:
    """Security and intrusion detection settings."""
    max_new_devices_per_minute: int = 5
    port_scan_threshold: int = 15  # Ports hit in 60 seconds
    bandwidth_alert_mbps: float = 100.0
    suspicious_ports: list = field(default_factory=lambda: [
        23, 2323,  # Telnet (common IoT attack vector)
        5555,      # Android Debug Bridge
        7547,      # TR-069 (ISP management, often exploited)
        37215,     # Huawei router exploit
        52869,     # Realtek SDK exploit
    ])
    known_malicious_ips: set = field(default_factory=set)
    whitelist_macs: set = field(default_factory=set)


@dataclass
class Config:
    """Main application configuration."""
    network: NetworkConfig = field(default_factory=NetworkConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    
    # Flask settings
    debug: bool = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    host: str = os.getenv("FLASK_HOST", "0.0.0.0")
    port: int = int(os.getenv("FLASK_PORT", 5000))
    secret_key: str = os.getenv("SECRET_KEY", os.urandom(24).hex())
    
    # Data retention
    traffic_history_hours: int = 24
    alert_retention_days: int = 7


config = Config()
