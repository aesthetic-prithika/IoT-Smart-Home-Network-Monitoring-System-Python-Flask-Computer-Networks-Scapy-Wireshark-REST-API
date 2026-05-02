/**
 * IoT Network Monitor Dashboard
 * Real-time dashboard for monitoring IoT devices and network security
 */

class Dashboard {
    constructor() {
        this.apiBase = '/api';
        this.refreshInterval = 5000;
        this.isMonitoring = false;
        
        this.init();
    }
    
    async init() {
        this.bindEvents();
        await this.checkStatus();
        this.startPolling();
    }
    
    bindEvents() {
        // Scan button
        document.getElementById('btn-scan').addEventListener('click', () => this.scanNetwork());
        
        // Toggle monitor button
        document.getElementById('btn-toggle-monitor').addEventListener('click', () => this.toggleMonitor());
        
        // Device search
        document.getElementById('device-search').addEventListener('input', (e) => this.filterDevices(e.target.value));
        
        // Alert filter
        document.getElementById('alert-filter').addEventListener('change', (e) => this.loadAlerts(e.target.value));
        
        // Modal close
        document.querySelector('.modal-close').addEventListener('click', () => this.closeModal());
        document.getElementById('device-modal').addEventListener('click', (e) => {
            if (e.target.classList.contains('modal')) this.closeModal();
        });
    }
    
    async checkStatus() {
        try {
            const response = await fetch(`${this.apiBase}/status`);
            const data = await response.json();
            
            this.isMonitoring = data.status === 'running';
            this.updateStatusBadge();
            this.updateToggleButton();
        } catch (error) {
            console.error('Failed to check status:', error);
        }
    }
    
    updateStatusBadge() {
        const badge = document.getElementById('status-badge');
        if (this.isMonitoring) {
            badge.textContent = 'Monitoring';
            badge.className = 'status-badge status-online';
        } else {
            badge.textContent = 'Offline';
            badge.className = 'status-badge status-offline';
        }
    }
    
    updateToggleButton() {
        const btn = document.getElementById('btn-toggle-monitor');
        btn.textContent = this.isMonitoring ? 'Stop Monitor' : 'Start Monitor';
        btn.className = this.isMonitoring ? 'btn btn-danger' : 'btn btn-success';
    }
    
    async toggleMonitor() {
        const endpoint = this.isMonitoring ? 'stop' : 'start';
        try {
            await fetch(`${this.apiBase}/monitor/${endpoint}`, { method: 'POST' });
            this.isMonitoring = !this.isMonitoring;
            this.updateStatusBadge();
            this.updateToggleButton();
        } catch (error) {
            console.error('Failed to toggle monitor:', error);
        }
    }
    
    async scanNetwork() {
        const btn = document.getElementById('btn-scan');
        btn.disabled = true;
        btn.textContent = '🔄 Scanning...';
        
        try {
            const response = await fetch(`${this.apiBase}/scan`, { method: 'POST' });
            const data = await response.json();
            
            btn.textContent = `✅ Found ${data.discovered} devices`;
            await this.loadDevices();
            
            setTimeout(() => {
                btn.textContent = '🔍 Scan Network';
                btn.disabled = false;
            }, 2000);
        } catch (error) {
            console.error('Scan failed:', error);
            btn.textContent = '❌ Scan Failed';
            setTimeout(() => {
                btn.textContent = '🔍 Scan Network';
                btn.disabled = false;
            }, 2000);
        }
    }
    
    startPolling() {
        this.refreshData();
        setInterval(() => this.refreshData(), this.refreshInterval);
    }
    
    async refreshData() {
        await Promise.all([
            this.loadSummary(),
            this.loadDevices(),
            this.loadAlerts(),
            this.loadProtocols()
        ]);
    }
    
    async loadSummary() {
        try {
            const response = await fetch(`${this.apiBase}/dashboard/summary`);
            const data = await response.json();
            
            // Update stats
            document.getElementById('stat-devices').textContent = data.devices.total;
            document.getElementById('stat-online').textContent = data.devices.online;
            document.getElementById('stat-unauthorized').textContent = data.devices.unauthorized;
            document.getElementById('stat-alerts').textContent = data.alerts.unacknowledged;
            
            // Update traffic stats
            document.getElementById('traffic-sent').textContent = this.formatBytes(data.traffic.bytes_sent);
            document.getElementById('traffic-received').textContent = this.formatBytes(data.traffic.bytes_received);
            document.getElementById('traffic-pps').textContent = Math.round(data.traffic.packets_per_second);
            document.getElementById('traffic-bandwidth').textContent = this.formatBytes(data.traffic.bytes_per_second) + '/s';
            
            // Update top talkers
            this.renderTopTalkers(data.top_talkers);
        } catch (error) {
            console.error('Failed to load summary:', error);
        }
    }
    
    async loadDevices() {
        try {
            const response = await fetch(`${this.apiBase}/devices`);
            const data = await response.json();
            
            this.renderDevices(data.devices);
        } catch (error) {
            console.error('Failed to load devices:', error);
        }
    }
    
    renderDevices(devices) {
        const tbody = document.getElementById('devices-tbody');
        
        if (devices.length === 0) {
            tbody.innerHTML = `
                <tr>
                    <td colspan="6" style="text-align: center; color: var(--text-secondary);">
                        No devices found. Click "Scan Network" to discover devices.
                    </td>
                </tr>
            `;
            return;
        }
        
        tbody.innerHTML = devices.map(device => `
            <tr data-mac="${device.mac_address}">
                <td>
                    <span class="device-status ${device.status}"></span>
                </td>
                <td>
                    <div class="device-info">
                        <span class="device-name">${device.hostname || device.device_type}</span>
                        <span class="device-vendor">${device.vendor || 'Unknown vendor'}</span>
                    </div>
                </td>
                <td>${device.ip_address}</td>
                <td><code>${device.mac_address}</code></td>
                <td>${this.formatBytes(device.bandwidth.bytes_sent + device.bandwidth.bytes_received)}</td>
                <td>
                    <button class="btn btn-sm btn-secondary" onclick="dashboard.showDeviceDetails('${device.mac_address}')">
                        Details
                    </button>
                    ${!device.is_authorized ? `
                        <button class="btn btn-sm btn-success" onclick="dashboard.authorizeDevice('${device.mac_address}', true)">
                            Authorize
                        </button>
                    ` : ''}
                </td>
            </tr>
        `).join('');
    }
    
    filterDevices(query) {
        const rows = document.querySelectorAll('#devices-tbody tr');
        const lowerQuery = query.toLowerCase();
        
        rows.forEach(row => {
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(lowerQuery) ? '' : 'none';
        });
    }
    
    async loadAlerts(severity = '') {
        try {
            const url = severity 
                ? `${this.apiBase}/alerts?severity=${severity}&limit=50`
                : `${this.apiBase}/alerts?limit=50`;
            
            const response = await fetch(url);
            const data = await response.json();
            
            this.renderAlerts(data.alerts);
        } catch (error) {
            console.error('Failed to load alerts:', error);
        }
    }
    
    renderAlerts(alerts) {
        const container = document.getElementById('alerts-list');
        
        if (alerts.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; color: var(--text-secondary); padding: 20px;">
                    No security alerts
                </div>
            `;
            return;
        }
        
        container.innerHTML = alerts.map(alert => `
            <div class="alert-item severity-${alert.severity}">
                <div class="alert-header">
                    <span class="alert-type">${this.formatAlertType(alert.type)}</span>
                    <span class="alert-time">${this.formatTime(alert.timestamp)}</span>
                </div>
                <div class="alert-description">${alert.description}</div>
                ${!alert.acknowledged ? `
                    <div class="alert-actions">
                        <button class="btn btn-sm btn-secondary" onclick="dashboard.acknowledgeAlert('${alert.alert_id}')">
                            Acknowledge
                        </button>
                    </div>
                ` : ''}
            </div>
        `).join('');
    }
    
    async loadProtocols() {
        try {
            const response = await fetch(`${this.apiBase}/traffic/protocols`);
            const data = await response.json();
            
            this.renderProtocols(data);
        } catch (error) {
            console.error('Failed to load protocols:', error);
        }
    }
    
    renderProtocols(protocols) {
        const container = document.getElementById('protocol-stats');
        const entries = Object.entries(protocols);
        
        if (entries.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; color: var(--text-secondary);">
                    No protocol data yet
                </div>
            `;
            return;
        }
        
        // Sort by count
        entries.sort((a, b) => b[1].count - a[1].count);
        
        container.innerHTML = entries.slice(0, 5).map(([proto, stats]) => `
            <div class="protocol-item">
                <span class="protocol-name">${proto}</span>
                <div class="protocol-bar">
                    <div class="protocol-fill" style="width: ${stats.percentage}%">
                        ${stats.percentage.toFixed(1)}%
                    </div>
                </div>
            </div>
        `).join('');
    }
    
    renderTopTalkers(talkers) {
        const container = document.getElementById('top-talkers');
        
        if (talkers.length === 0) {
            container.innerHTML = `
                <div style="text-align: center; color: var(--text-secondary);">
                    No traffic data yet
                </div>
            `;
            return;
        }
        
        container.innerHTML = talkers.map(talker => `
            <div class="talker-item">
                <div class="talker-info">
                    <span class="talker-ip">${talker.ip}</span>
                    <span class="talker-hostname">${talker.hostname || 'Unknown'}</span>
                </div>
                <span class="talker-traffic">${this.formatBytes(talker.bytes_total)}</span>
            </div>
        `).join('');
    }
    
    async showDeviceDetails(mac) {
        try {
            const response = await fetch(`${this.apiBase}/devices/${mac}`);
            const device = await response.json();
            
            document.getElementById('modal-device-name').textContent = 
                device.hostname || device.device_type || 'Unknown Device';
            
            document.getElementById('modal-body').innerHTML = `
                <div class="detail-row">
                    <span class="detail-label">MAC Address</span>
                    <span class="detail-value"><code>${device.mac_address}</code></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">IP Address</span>
                    <span class="detail-value">${device.ip_address}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Vendor</span>
                    <span class="detail-value">${device.vendor || 'Unknown'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Device Type</span>
                    <span class="detail-value">${device.device_type}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Status</span>
                    <span class="detail-value">${device.status}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Authorized</span>
                    <span class="detail-value">${device.is_authorized ? '✅ Yes' : '❌ No'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">First Seen</span>
                    <span class="detail-value">${this.formatTime(device.first_seen)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Last Seen</span>
                    <span class="detail-value">${this.formatTime(device.last_seen)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Data Sent</span>
                    <span class="detail-value">${this.formatBytes(device.bandwidth.bytes_sent)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Data Received</span>
                    <span class="detail-value">${this.formatBytes(device.bandwidth.bytes_received)}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Packets Sent</span>
                    <span class="detail-value">${device.bandwidth.packets_sent.toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Packets Received</span>
                    <span class="detail-value">${device.bandwidth.packets_received.toLocaleString()}</span>
                </div>
                ${device.open_ports.length > 0 ? `
                    <div class="detail-row">
                        <span class="detail-label">Open Ports</span>
                        <span class="detail-value">${device.open_ports.join(', ')}</span>
                    </div>
                ` : ''}
            `;
            
            document.getElementById('device-modal').classList.add('active');
        } catch (error) {
            console.error('Failed to load device details:', error);
        }
    }
    
    closeModal() {
        document.getElementById('device-modal').classList.remove('active');
    }
    
    async authorizeDevice(mac, authorized) {
        try {
            await fetch(`${this.apiBase}/devices/${mac}/authorize`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ authorized })
            });
            
            await this.loadDevices();
        } catch (error) {
            console.error('Failed to authorize device:', error);
        }
    }
    
    async acknowledgeAlert(alertId) {
        try {
            await fetch(`${this.apiBase}/alerts/${alertId}/acknowledge`, {
                method: 'POST'
            });
            
            await this.loadAlerts(document.getElementById('alert-filter').value);
            await this.loadSummary();
        } catch (error) {
            console.error('Failed to acknowledge alert:', error);
        }
    }
    
    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
    }
    
    formatTime(timestamp) {
        const date = new Date(timestamp);
        return date.toLocaleString();
    }
    
    formatAlertType(type) {
        return type.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
    }
}

// Initialize dashboard
const dashboard = new Dashboard();
