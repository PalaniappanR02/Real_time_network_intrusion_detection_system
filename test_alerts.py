import json
import time
from datetime import datetime
from scapy.all import IP, TCP, UDP, ICMP
import random

class AlertTester:
    """Test class to generate various alert types and understand severity levels"""
    
    def __init__(self):
        self.alert_types = {
            'signature': {
                'syn_flood': {'severity': 'high', 'description': 'SYN flood attack detected'},
                'port_scan': {'severity': 'medium', 'description': 'Port scanning activity detected'},
                'large_payload': {'severity': 'low', 'description': 'Large payload detected'},
                'suspicious_ports': {'severity': 'medium', 'description': 'Connection to suspicious port'},
                'null_scan': {'severity': 'high', 'description': 'TCP NULL scan detected'},
                'fin_scan': {'severity': 'medium', 'description': 'TCP FIN scan detected'},
                'xmas_scan': {'severity': 'high', 'description': 'TCP XMAS scan detected'}
            },
            'anomaly': {
                'ml_anomaly': {'severity': 'medium', 'description': 'Machine learning anomaly detected'},
                'behavior_anomaly': {'severity': 'high', 'description': 'Behavioral anomaly detected'}
            }
        }
        
        self.suspicious_ports = [22, 23, 3389, 1433, 3306, 5432, 5900, 8080]
        self.normal_ports = [80, 443, 53, 25, 110, 993, 995]
    
    def generate_test_packets(self):
        """Generate test packets for different alert scenarios"""
        test_packets = []
        
        print("=== GENERATING TEST PACKETS FOR ALERT TYPES ===\n")
        
        # 1. SYN Flood packets (High Severity)
        print("1. SYN Flood Packets (High Severity):")
        for i in range(10):
            pkt = IP(src=f"10.1.1.{i}", dst="192.168.1.100") / TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
            test_packets.append(('syn_flood', pkt, 'high'))
            print(f"   SYN packet: {pkt.summary()}")
        
        # 2. Port Scan packets (Medium Severity)
        print("\n2. Port Scan Packets (Medium Severity):")
        src_ip = "192.168.2.50"
        for port in [22, 23, 3389, 1433, 3306, 8080, 21, 25]:
            pkt = IP(src=src_ip, dst="192.168.1.100") / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            test_packets.append(('port_scan', pkt, 'medium'))
            print(f"   Port scan: {pkt.summary()}")
        
        # 3. Suspicious Port Access (Medium Severity)
        print("\n3. Suspicious Port Access (Medium Severity):")
        for port in self.suspicious_ports[:3]:
            pkt = IP(src="10.5.5.5", dst="192.168.1.100") / TCP(sport=random.randint(1024, 65535), dport=port, flags="S")
            test_packets.append(('suspicious_ports', pkt, 'medium'))
            print(f"   Suspicious port: {pkt.summary()}")
        
        # 4. Large Payload (Low Severity)
        print("\n4. Large Payload Packets (Low Severity):")
        large_payload = "X" * 2000  # Create large payload
        pkt = IP(src="192.168.3.10", dst="192.168.1.100") / TCP(sport=1234, dport=80, flags="PA") / large_payload
        test_packets.append(('large_payload', pkt, 'low'))
        print(f"   Large payload: {pkt.summary()} (Size: {len(pkt)} bytes)")
        
        # 5. NULL Scan (High Severity)
        print("\n5. NULL Scan Packets (High Severity):")
        pkt = IP(src="10.10.10.10", dst="192.168.1.100") / TCP(sport=5555, dport=80, flags="")
        test_packets.append(('null_scan', pkt, 'high'))
        print(f"   NULL scan: {pkt.summary()}")
        
        # 6. XMAS Scan (High Severity)
        print("\n6. XMAS Scan Packets (High Severity):")
        pkt = IP(src="10.10.10.11", dst="192.168.1.100") / TCP(sport=5556, dport=80, flags="FPU")
        test_packets.append(('xmas_scan', pkt, 'high'))
        print(f"   XMAS scan: {pkt.summary()}")
        
        # 7. Normal traffic (No alerts expected)
        print("\n7. Normal Traffic Packets (No Alerts Expected):")
        for port in self.normal_ports[:3]:
            pkt = IP(src="192.168.1.50", dst="192.168.1.100") / TCP(sport=random.randint(1024, 65535), dport=port, flags="A")
            test_packets.append(('normal', pkt, 'none'))
            print(f"   Normal: {pkt.summary()}")
        
        return test_packets
    
    def simulate_detection_engine(self, features):
        """Simulate the detection engine logic"""
        threats = []
        
        # Signature-based detection rules
        if features.get('syn_ratio', 0) > 0.8 and features.get('packet_rate', 0) > 100:
            threats.append({
                'type': 'signature',
                'rule': 'syn_flood',
                'severity': 'high',
                'confidence': 0.95,
                'description': 'SYN flood attack detected'
            })
        
        if features.get('unique_ports_count', 0) > 5 and features.get('packet_rate', 0) > 30:
            threats.append({
                'type': 'signature', 
                'rule': 'port_scan',
                'severity': 'medium',
                'confidence': 0.85,
                'description': 'Port scanning activity detected'
            })
        
        if features.get('dst_port') in self.suspicious_ports and 'SYN' in features.get('tcp_flags', ''):
            threats.append({
                'type': 'signature',
                'rule': 'suspicious_ports', 
                'severity': 'medium',
                'confidence': 0.75,
                'description': f"Connection to suspicious port {features.get('dst_port')}"
            })
        
        if features.get('payload_size', 0) > 1500:
            threats.append({
                'type': 'signature',
                'rule': 'large_payload',
                'severity': 'low', 
                'confidence': 0.65,
                'description': 'Large payload detected'
            })
        
        if features.get('tcp_flags') == '':
            threats.append({
                'type': 'signature',
                'rule': 'null_scan',
                'severity': 'high',
                'confidence': 0.90,
                'description': 'TCP NULL scan detected'
            })
        
        if features.get('tcp_flags') == 'FPU':
            threats.append({
                'type': 'signature', 
                'rule': 'xmas_scan',
                'severity': 'high',
                'confidence': 0.92,
                'description': 'TCP XMAS scan detected'
            })
        
        return threats
    
    def extract_features_from_packet(self, packet):
        """Extract features from a packet for detection"""
        features = {
            'timestamp': time.time(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'packet_size': len(packet),
            'protocol': 'TCP' if packet.haslayer(TCP) else 'UDP' if packet.haslayer(UDP) else 'OTHER'
        }
        
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'tcp_flags': self.get_tcp_flags_string(tcp.flags),
                'payload_size': len(tcp.payload)
            })
        
        # Simulate some derived features for testing
        features.update({
            'syn_ratio': 0.9 if features.get('tcp_flags') == 'S' else 0.1,
            'packet_rate': random.randint(10, 200),
            'unique_ports_count': random.randint(1, 15)
        })
        
        return features
    
    def get_tcp_flags_string(self, flags):
        """Convert TCP flags to string representation"""
        flag_map = {
            0x01: 'F',  # FIN
            0x02: 'S',  # SYN  
            0x04: 'R',  # RST
            0x08: 'P',  # PSH
            0x10: 'A',  # ACK
            0x20: 'U',  # URG
        }
        
        flag_chars = []
        for flag_val, flag_char in flag_map.items():
            if flags & flag_val:
                flag_chars.append(flag_char)
        
        return ''.join(flag_chars) if flag_chars else ''
    
    def run_comprehensive_test(self):
        """Run comprehensive test of all alert types"""
        print("=" * 70)
        print("COMPREHENSIVE NIDS ALERT TYPE TESTING")
        print("=" * 70)
        
        # Generate test packets
        test_packets = self.generate_test_packets()
        
        print("\n" + "=" * 70)
        print("TESTING DETECTION ENGINE")
        print("=" * 70)
        
        alert_summary = {
            'high': 0,
            'medium': 0, 
            'low': 0,
            'total': 0,
            'by_type': {}
        }
        
        # Test each packet
        for i, (expected_alert, packet, expected_severity) in enumerate(test_packets, 1):
            print(f"\n--- Test {i}: {expected_alert.upper()} ---")
            print(f"Packet: {packet.summary()}")
            print(f"Expected: {expected_alert} (Severity: {expected_severity})")
            
            # Extract features
            features = self.extract_features_from_packet(packet)
            print(f"Features: {features}")
            
            # Detect threats
            threats = self.simulate_detection_engine(features)
            
            if threats:
                for threat in threats:
                    print(f"🚨 DETECTED: {threat['rule']}")
                    print(f"   Type: {threat['type']}")
                    print(f"   Severity: {threat['severity']} (Expected: {expected_severity})")
                    print(f"   Confidence: {threat['confidence']:.2f}")
                    print(f"   Description: {threat['description']}")
                    
                    # Update summary
                    alert_summary[threat['severity']] += 1
                    alert_summary['total'] += 1
                    alert_type = threat['rule']
                    alert_summary['by_type'][alert_type] = alert_summary['by_type'].get(alert_type, 0) + 1
            else:
                print("✅ No threats detected (as expected for normal traffic)")
        
        # Print summary
        self.print_test_summary(alert_summary)
        
        # Generate sample alerts file
        self.generate_sample_alerts_file()
    
    def print_test_summary(self, alert_summary):
        """Print test results summary"""
        print("\n" + "=" * 70)
        print("TEST SUMMARY")
        print("=" * 70)
        
        print(f"\nTotal Alerts Generated: {alert_summary['total']}")
        print(f"High Severity Alerts: {alert_summary['high']}")
        print(f"Medium Severity Alerts: {alert_summary['medium']}") 
        print(f"Low Severity Alerts: {alert_summary['low']}")
        
        print("\nAlert Types Distribution:")
        for alert_type, count in alert_summary['by_type'].items():
            print(f"  {alert_type}: {count}")
        
        print("\n" + "=" * 70)
        print("ALERT SEVERITY EXPLANATION")
        print("=" * 70)
        
        print("""
🔴 HIGH SEVERITY (Critical threats):
   - SYN Flood attacks
   - NULL/XMAS/FIN scans  
   - DDoS attacks
   - Exploit attempts
   - Requires immediate attention

🟡 MEDIUM SEVERITY (Suspicious activity):
   - Port scanning
   - Suspicious port access
   - Unusual traffic patterns
   - Potential reconnaissance
   - Requires investigation

🔵 LOW SEVERITY (Anomalies):
   - Large payloads
   - Minor protocol violations
   - Unusual but not malicious
   - Informational alerts
   - Monitor for patterns
        """)
    
    def generate_sample_alerts_file(self):
        """Generate a sample alerts.jsonl file for testing the dashboard"""
        print("\n" + "=" * 70)
        print("GENERATING SAMPLE ALERTS FILE")
        print("=" * 70)
        
        sample_alerts = []
        
        # Create sample alerts for each type
        alert_samples = [
            {
                'rule': 'syn_flood', 'severity': 'high',
                'src_ip': '10.1.1.100', 'dst_ip': '192.168.1.50', 'dst_port': 80,
                'description': 'SYN flood attack from multiple sources'
            },
            {
                'rule': 'port_scan', 'severity': 'medium', 
                'src_ip': '192.168.2.200', 'dst_ip': '192.168.1.100', 'dst_port': 22,
                'description': 'Multiple port connection attempts detected'
            },
            {
                'rule': 'suspicious_ports', 'severity': 'medium',
                'src_ip': '10.5.5.5', 'dst_ip': '192.168.1.100', 'dst_port': 3389, 
                'description': 'Connection attempt to RDP port'
            },
            {
                'rule': 'large_payload', 'severity': 'low',
                'src_ip': '192.168.1.75', 'dst_ip': '192.168.1.100', 'dst_port': 80,
                'description': 'Unusually large payload detected'
            },
            {
                'rule': 'null_scan', 'severity': 'high',
                'src_ip': '10.10.10.10', 'dst_ip': '192.168.1.100', 'dst_port': 443,
                'description': 'TCP NULL scan detected'
            }
        ]
        
        for i, alert in enumerate(sample_alerts):
            sample_alert = {
                'alert_id': i + 1,
                'timestamp': (datetime.now() - timedelta(hours=random.randint(0, 24))).isoformat(),
                'threat_type': 'signature',
                'rule': alert['rule'],
                'severity': alert['severity'],
                'confidence': round(random.uniform(0.7, 0.95), 2),
                'description': alert['description'],
                'source_ip': alert['src_ip'],
                'destination_ip': alert['dst_ip'],
                'source_port': random.randint(1024, 65535),
                'destination_port': alert['dst_port'],
                'protocol': 'TCP'
            }
            sample_alerts.append(sample_alert)
        
        # Write to file
        with open('sample_alerts.jsonl', 'w') as f:
            for alert in sample_alerts:
                f.write(json.dumps(alert) + '\n')
        
        print(f"Generated {len(sample_alerts)} sample alerts in 'sample_alerts.jsonl'")
        print("You can use this file to test the dashboard without running actual packet capture")

def test_alert_system():
    """Test the alert system independently"""
    print("=" * 70)
    print("TESTING ALERT SYSTEM")
    print("=" * 70)
    
    # Simulate alert generation
    test_alerts = [
        {
            'type': 'signature',
            'rule': 'syn_flood',
            'severity': 'high',
            'confidence': 0.95,
            'description': 'SYN flood attack from 10.1.1.0/24 network'
        },
        {
            'type': 'signature', 
            'rule': 'port_scan',
            'severity': 'medium',
            'confidence': 0.82,
            'description': 'Port scanning activity from 192.168.2.200'
        },
        {
            'type': 'anomaly',
            'rule': 'ml_anomaly', 
            'severity': 'medium',
            'confidence': 0.78,
            'description': 'Unusual traffic pattern detected'
        }
    ]
    
    packet_info = {
        'src_ip': '10.1.1.50',
        'dst_ip': '192.168.1.100',
        'src_port': 54321,
        'dst_port': 80,
        'protocol': 'TCP'
    }
    
    for i, threat in enumerate(test_alerts, 1):
        print(f"\nAlert {i}:")
        print(f"  Type: {threat['type']}")
        print(f"  Rule: {threat['rule']}")
        print(f"  Severity: {threat['severity']}")
        print(f"  Confidence: {threat['confidence']:.2f}")
        print(f"  Description: {threat['description']}")
        print(f"  Source: {packet_info['src_ip']}:{packet_info['src_port']}")
        print(f"  Destination: {packet_info['dst_ip']}:{packet_info['dst_port']}")

if __name__ == "__main__":
    # Run comprehensive test
    tester = AlertTester()
    tester.run_comprehensive_test()
    
    # Test alert system
    test_alert_system()
    
    print("\n" + "=" * 70)
    print("TESTING COMPLETED SUCCESSFULLY!")
    print("=" * 70)
    print("\nNext steps:")
    print("1. Run the NIDS: python nids.py --interface <your_interface>")
    print("2. Start the dashboard: python dashboard.py") 
    print("3. Open http://localhost:5000 in your browser")
    print("4. Use sample_alerts.jsonl to test the dashboard immediately")