from flask import Flask, render_template, jsonify, request
import json
import pandas as pd
from datetime import datetime, timedelta
import threading
import time
import sqlite3
from collections import deque

app = Flask(__name__)

class NIDSDashboard:
    def __init__(self, alert_file='alerts.jsonl', stats_interval=5):
        self.alert_file = alert_file
        self.stats_interval = stats_interval
        self.recent_alerts = deque(maxlen=1000)
        self.stats = {
            'total_alerts': 0,
            'alerts_by_severity': {'low': 0, 'medium': 0, 'high': 0},
            'alerts_by_type': {},
            'top_source_ips': {},
            'top_destination_ips': {}
        }
        self.last_update = datetime.now()
        
    def load_alerts(self):
        """Load alerts from JSONL file"""
        try:
            with open(self.alert_file, 'r') as f:
                for line in f:
                    if line.strip():
                        alert = json.loads(line.strip())
                        self.recent_alerts.append(alert)
                        self._update_stats(alert)
        except FileNotFoundError:
            print("Alert file not found - starting fresh")
    
    def _update_stats(self, alert):
        """Update statistics with new alert"""
        self.stats['total_alerts'] += 1
        
        # Update severity counts
        severity = alert.get('severity', 'low')
        self.stats['alerts_by_severity'][severity] = self.stats['alerts_by_severity'].get(severity, 0) + 1
        
        # Update alert type counts
        alert_type = alert.get('rule', 'unknown')
        self.stats['alerts_by_type'][alert_type] = self.stats['alerts_by_type'].get(alert_type, 0) + 1
        
        # Update top IPs
        src_ip = alert.get('source_ip', 'unknown')
        dst_ip = alert.get('destination_ip', 'unknown')
        
        self.stats['top_source_ips'][src_ip] = self.stats['top_source_ips'].get(src_ip, 0) + 1
        self.stats['top_destination_ips'][dst_ip] = self.stats['top_destination_ips'].get(dst_ip, 0) + 1
    
    def get_recent_alerts(self, limit=50):
        """Get most recent alerts"""
        return list(self.recent_alerts)[-limit:]
    
    def get_stats(self):
        """Get current statistics"""
        return self.stats
    
    def get_alerts_by_time(self, hours=24):
        """Get alerts from the last N hours"""
        cutoff = datetime.now() - timedelta(hours=hours)
        recent = []
        
        for alert in self.recent_alerts:
            alert_time = datetime.fromisoformat(alert['timestamp'])
            if alert_time >= cutoff:
                recent.append(alert)
        
        return recent

# Initialize dashboard
dashboard = NIDSDashboard()
dashboard.load_alerts()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/alerts/recent')
def get_recent_alerts():
    """API endpoint for recent alerts"""
    limit = request.args.get('limit', 50, type=int)
    alerts = dashboard.get_recent_alerts(limit)
    return jsonify(alerts)

@app.route('/api/stats')
def get_stats():
    """API endpoint for statistics"""
    return jsonify(dashboard.get_stats())

@app.route('/api/alerts/time-based')
def get_time_based_alerts():
    """API endpoint for time-based alerts"""
    hours = request.args.get('hours', 24, type=int)
    alerts = dashboard.get_alerts_by_time(hours)
    return jsonify(alerts)

@app.route('/api/alerts/severity-distribution')
def get_severity_distribution():
    """API endpoint for severity distribution"""
    return jsonify(dashboard.stats['alerts_by_severity'])

@app.route('/api/alerts/type-distribution')
def get_type_distribution():
    """API endpoint for alert type distribution"""
    return jsonify(dashboard.stats['alerts_by_type'])

def background_alert_loader():
    """Background thread to continuously load new alerts"""
    while True:
        dashboard.load_alerts()
        time.sleep(5)  # Update every 5 seconds

if __name__ == '__main__':
    # Start background thread for alert loading
    loader_thread = threading.Thread(target=background_alert_loader, daemon=True)
    loader_thread.start()
    
    # Start Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)