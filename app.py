"""Flask application with REST API and web dashboard for IoT network monitoring."""

import os
import time
import logging
from functools import wraps
from flask import Flask, render_template, jsonify, request
from flask_cors import CORS

from config import config
from device_manager import DeviceManager
from intrusion_detector import IntrusionDetector, AlertSeverity, AlertType
from network_monitor import NetworkMonitor

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.config["SECRET_KEY"] = config.secret_key
CORS(app)

# Initialize components
device_manager = DeviceManager(whitelist_macs=config.security.whitelist_macs)
intrusion_detector = IntrusionDetector(config)
network_monitor = NetworkMonitor(config, device_manager, intrusion_detector)

# Store for real-time updates (in production, use Redis or similar)
recent_alerts = []


def alert_callback(alert):
    """Callback for new security alerts."""
    recent_alerts.append(alert.to_dict())
    # Keep only last 100 alerts in memory
    while len(recent_alerts) > 100:
        recent_alerts.pop(0)


network_monitor.register_alert_callback(alert_callback)


# ==================== API Routes ====================

@app.route("/")
def dashboard():
    """Serve the main dashboard."""
    return render_template("dashboard.html")


@app.route("/api/status")
def api_status():
    """Get system status."""
    return jsonify({
        "status": "running" if network_monitor.is_running else "stopped",
        "interface": config.network.interface,
        "subnet": config.network.subnet,
        "uptime": time.time() - network_monitor._stats.start_time if network_monitor._stats.start_time else 0,
        "packet_stats": network_monitor.get_stats()
    })


@app.route("/api/devices")
def api_devices():
    """Get all devices."""
    devices = device_manager.get_all_devices()
    return jsonify({
        "count": len(devices),
        "devices": [d.to_dict() for d in devices]
    })


@app.route("/api/devices/online")
def api_online_devices():
    """Get online devices."""
    devices = device_manager.get_online_devices()
    return jsonify({
        "count": len(devices),
        "devices": [d.to_dict() for d in devices]
    })


@app.route("/api/devices/<mac>")
def api_device_detail(mac):
    """Get device details."""
    device = device_manager.get_device(mac)
    if device:
        return jsonify(device.to_dict())
    return jsonify({"error": "Device not found"}), 404


@app.route("/api/devices/<mac>/authorize", methods=["POST"])
def api_authorize_device(mac):
    """Authorize or unauthorize a device."""
    data = request.get_json() or {}
    authorized = data.get("authorized", True)
    
    device = device_manager.get_device(mac)
    if device:
        device_manager.authorize_device(mac, authorized)
        return jsonify({
            "success": True,
            "mac": mac,
            "authorized": authorized
        })
    return jsonify({"error": "Device not found"}), 404


@app.route("/api/traffic")
def api_traffic_stats():
    """Get traffic statistics."""
    return jsonify(device_manager.get_traffic_stats())


@app.route("/api/traffic/protocols")
def api_protocol_stats():
    """Get protocol distribution."""
    return jsonify(network_monitor.get_protocol_stats())


@app.route("/api/traffic/ports")
def api_port_stats():
    """Get top ports."""
    top_n = request.args.get("limit", 20, type=int)
    return jsonify(network_monitor.get_port_stats(top_n))


@app.route("/api/alerts")
def api_alerts():
    """Get security alerts."""
    severity = request.args.get("severity")
    alert_type = request.args.get("type")
    limit = request.args.get("limit", 100, type=int)
    unacknowledged = request.args.get("unacknowledged", "false").lower() == "true"
    
    severity_enum = AlertSeverity(severity) if severity else None
    type_enum = AlertType(alert_type) if alert_type else None
    
    alerts = intrusion_detector.get_alerts(
        severity=severity_enum,
        alert_type=type_enum,
        limit=limit,
        unacknowledged_only=unacknowledged
    )
    
    return jsonify({
        "count": len(alerts),
        "alerts": [a.to_dict() for a in alerts]
    })


@app.route("/api/alerts/summary")
def api_alerts_summary():
    """Get alerts summary."""
    return jsonify(intrusion_detector.get_alert_summary())


@app.route("/api/alerts/<alert_id>/acknowledge", methods=["POST"])
def api_acknowledge_alert(alert_id):
    """Acknowledge an alert."""
    success = intrusion_detector.acknowledge_alert(alert_id)
    return jsonify({"success": success})


@app.route("/api/packets/recent")
def api_recent_packets():
    """Get recent packets."""
    limit = request.args.get("limit", 50, type=int)
    return jsonify(network_monitor.get_recent_packets(limit))


@app.route("/api/scan", methods=["POST"])
def api_network_scan():
    """Trigger a network scan."""
    devices = network_monitor.perform_network_scan()
    return jsonify({
        "success": True,
        "discovered": len(devices),
        "devices": devices
    })


@app.route("/api/monitor/start", methods=["POST"])
def api_start_monitor():
    """Start packet capture."""
    success = network_monitor.start()
    return jsonify({"success": success})


@app.route("/api/monitor/stop", methods=["POST"])
def api_stop_monitor():
    """Stop packet capture."""
    network_monitor.stop()
    return jsonify({"success": True})


@app.route("/api/dashboard/summary")
def api_dashboard_summary():
    """Get summary data for dashboard."""
    traffic_stats = device_manager.get_traffic_stats()
    alert_summary = intrusion_detector.get_alert_summary()
    packet_stats = network_monitor.get_stats()
    
    return jsonify({
        "devices": {
            "total": traffic_stats["total_devices"],
            "online": traffic_stats["online_devices"],
            "unauthorized": traffic_stats["unauthorized_devices"]
        },
        "traffic": {
            "bytes_sent": traffic_stats["total_bytes_sent"],
            "bytes_received": traffic_stats["total_bytes_received"],
            "packets_per_second": packet_stats["packets_per_second"],
            "bytes_per_second": packet_stats["bytes_per_second"]
        },
        "alerts": {
            "total": alert_summary["total"],
            "unacknowledged": alert_summary["unacknowledged"],
            "by_severity": alert_summary["by_severity"]
        },
        "top_talkers": traffic_stats["top_talkers"][:5],
        "recent_alerts": alert_summary["recent"]
    })


# ==================== Error Handlers ====================

@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(e):
    logger.error(f"Internal error: {e}")
    return jsonify({"error": "Internal server error"}), 500


# ==================== Main Entry Point ====================

def main():
    """Main entry point."""
    logger.info("Starting IoT Smart Home Network Monitoring System")
    
    # Start network monitoring
    network_monitor.start()
    
    # Perform initial network scan
    logger.info("Performing initial network scan...")
    network_monitor.perform_network_scan()
    
    # Run Flask app
    try:
        app.run(
            host=config.host,
            port=config.port,
            debug=config.debug,
            threaded=True
        )
    finally:
        network_monitor.stop()


if __name__ == "__main__":
    main()
