import logging
import queue
import threading
import time
import json
from datetime import datetime
from collections import defaultdict, deque
import numpy as np
from scapy.all import AsyncSniffer, IP, TCP
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('nids.log'),
        logging.StreamHandler()
    ]
)

class PacketCapture:
    """Real-time packet capture using Scapy"""
    
    def __init__(self, max_queue_size=10000):
        self.packet_queue = queue.Queue(maxsize=max_queue_size)
        self.sniffer = None
        self.running = False
        self.interface = None
        
    def _packet_callback(self, packet):
        """Callback for each captured packet"""
        try:
            if packet.haslayer(IP):
                self.packet_queue.put(packet, block=False)
        except queue.Full:
            logging.warning("Packet queue full - dropping packet")
        except Exception as e:
            logging.error(f"Error processing packet: {e}")
    
    def start_capture(self, interface=None):
        """Start packet capture on specified interface"""
        if self.running:
            logging.warning("Capture already running")
            return
            
        self.interface = interface
        self.running = True
        
        try:
            self.sniffer = AsyncSniffer(
                iface=interface,
                prn=self._packet_callback,
                store=False
            )
            self.sniffer.start()
            logging.info(f"Packet capture started on interface: {interface or 'default'}")
        except Exception as e:
            logging.error(f"Failed to start packet capture: {e}")
            self.running = False
    
    def stop(self):
        """Stop packet capture"""
        if self.sniffer and self.running:
            self.sniffer.stop()
            self.running = False
            logging.info("Packet capture stopped")

class TrafficAnalyzer:
    """Analyze network traffic and extract features"""
    
    def __init__(self):
        self.connections = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'start_time': None,
            'last_time': None,
            'syn_count': 0,
            'flags_history': deque(maxlen=100)
        })
        self.host_stats = defaultdict(lambda: {
            'sent_packets': 0,
            'received_packets': 0,
            'sent_bytes': 0,
            'received_bytes': 0,
            'unique_ports': set()
        })
        
    def analyze_packet(self, packet):
        """Extract features from packet"""
        if not packet.haslayer(IP):
            return None
            
        ip = packet[IP]
        features = {
            'timestamp': time.time(),
            'src_ip': ip.src,
            'dst_ip': ip.dst,
            'protocol': ip.proto,
            'packet_size': len(packet),
            'ip_len': ip.len
        }
        
        # TCP-specific features
        if packet.haslayer(TCP):
            tcp = packet[TCP]
            features.update({
                'src_port': tcp.sport,
                'dst_port': tcp.dport,
                'tcp_flags': self._parse_tcp_flags(tcp.flags),
                'window_size': tcp.window,
                'payload_size': len(tcp.payload)
            })
            
            # Update connection statistics
            self._update_connection_stats(features)
            self._update_host_stats(features)
            
            # Add derived features
            features.update(self._get_derived_features(features))
            
        return features
    
    def _parse_tcp_flags(self, flags):
        """Parse TCP flags to string representation"""
        flag_names = []
        if flags & 0x01: flag_names.append('FIN')
        if flags & 0x02: flag_names.append('SYN')
        if flags & 0x04: flag_names.append('RST')
        if flags & 0x08: flag_names.append('PSH')
        if flags & 0x10: flag_names.append('ACK')
        if flags & 0x20: flag_names.append('URG')
        return ','.join(flag_names) if flag_names else 'NONE'
    
    def _update_connection_stats(self, features):
        """Update connection-level statistics"""
        conn_key = (features['src_ip'], features['dst_ip'], features.get('src_port', 0))
        stats = self.connections[conn_key]
        
        current_time = features['timestamp']
        if not stats['start_time']:
            stats['start_time'] = current_time
            
        stats['packet_count'] += 1
        stats['byte_count'] += features['packet_size']
        stats['last_time'] = current_time
        
        if 'SYN' in features.get('tcp_flags', ''):
            stats['syn_count'] += 1
            
        stats['flags_history'].append(features.get('tcp_flags', ''))
    
    def _update_host_stats(self, features):
        """Update host-level statistics"""
        src_ip, dst_ip = features['src_ip'], features['dst_ip']
        
        # Update source host stats
        self.host_stats[src_ip]['sent_packets'] += 1
        self.host_stats[src_ip]['sent_bytes'] += features['packet_size']
        if 'src_port' in features:
            self.host_stats[src_ip]['unique_ports'].add(features['src_port'])
            
        # Update destination host stats
        self.host_stats[dst_ip]['received_packets'] += 1
        self.host_stats[dst_ip]['received_bytes'] += features['packet_size']
        if 'dst_port' in features:
            self.host_stats[dst_ip]['unique_ports'].add(features['dst_port'])
    
    def _get_derived_features(self, features):
        """Calculate derived features for detection"""
        conn_key = (features['src_ip'], features['dst_ip'], features.get('src_port', 0))
        host_key = features['src_ip']
        
        conn_stats = self.connections[conn_key]
        host_stats = self.host_stats[host_key]
        
        duration = conn_stats['last_time'] - conn_stats['start_time']
        
        return {
            'conn_duration': duration if duration > 0 else 0.001,
            'packet_rate': conn_stats['packet_count'] / duration if duration > 0 else 0,
            'byte_rate': conn_stats['byte_count'] / duration if duration > 0 else 0,
            'syn_ratio': conn_stats['syn_count'] / conn_stats['packet_count'] if conn_stats['packet_count'] > 0 else 0,
            'unique_ports_count': len(host_stats['unique_ports']),
            'avg_packet_size': host_stats['sent_bytes'] / host_stats['sent_packets'] if host_stats['sent_packets'] > 0 else 0
        }

class DetectionEngine:
    """Hybrid detection engine with signature-based and ML-based detection"""
    
    def __init__(self):
        # Signature-based rules
        self.signature_rules = {
            'syn_flood': {
                'condition': lambda f: f.get('syn_ratio', 0) > 0.8 and f.get('packet_rate', 0) > 100,
                'severity': 'high'
            },
            'port_scan': {
                'condition': lambda f: f.get('unique_ports_count', 0) > 10 and f.get('packet_rate', 0) > 50,
                'severity': 'medium'
            },
            'large_payload': {
                'condition': lambda f: f.get('payload_size', 0) > 1500,
                'severity': 'low'
            },
            'suspicious_ports': {
                'condition': lambda f: f.get('dst_port') in [22, 23, 3389, 1433, 3306] and 'SYN' in f.get('tcp_flags', ''),
                'severity': 'medium'
            },
            'null_scan': {
                'condition': lambda f: f.get('tcp_flags') == 'NONE',
                'severity': 'high'
            }
        }
        
        # ML-based anomaly detection
        self.anomaly_detector = IsolationForest(
            n_estimators=100,
            contamination=0.1,
            random_state=42
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.training_data = []
        
    def train(self, normal_traffic_data):
        """Train the ML model on normal traffic data"""
        if len(normal_traffic_data) < 100:
            logging.warning("Insufficient training data")
            return
            
        try:
            # Convert to numpy array and scale
            X = np.array([[f['packet_rate'], f['byte_rate'], f['syn_ratio'], 
                          f['unique_ports_count'], f['avg_packet_size']] 
                         for f in normal_traffic_data])
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.anomaly_detector.fit(X_scaled)
            self.is_trained = True
            logging.info("Anomaly detection model trained successfully")
        except Exception as e:
            logging.error(f"Error training model: {e}")
    
    def detect_threats(self, features):
        """Detect threats using both signature-based and ML-based approaches"""
        threats = []
        
        # Signature-based detection
        for rule_name, rule in self.signature_rules.items():
            try:
                if rule['condition'](features):
                    threats.append({
                        'type': 'signature',
                        'rule': rule_name,
                        'severity': rule['severity'],
                        'confidence': 0.9,
                        'description': f"Signature match: {rule_name}"
                    })
            except Exception as e:
                logging.error(f"Error in signature rule {rule_name}: {e}")
        
        # ML-based anomaly detection
        if self.is_trained and all(k in features for k in ['packet_rate', 'byte_rate', 'syn_ratio', 'unique_ports_count', 'avg_packet_size']):
            try:
                X = np.array([[features['packet_rate'], features['byte_rate'], 
                             features['syn_ratio'], features['unique_ports_count'], 
                             features['avg_packet_size']]])
                X_scaled = self.scaler.transform(X)
                
                anomaly_score = self.anomaly_detector.decision_function(X_scaled)[0]
                if anomaly_score < -0.1:  # Adjust threshold as needed
                    threats.append({
                        'type': 'anomaly',
                        'rule': 'ml_anomaly',
                        'severity': 'medium',
                        'confidence': min(1.0, abs(anomaly_score)),
                        'description': f"Anomalous behavior detected (score: {anomaly_score:.3f})"
                    })
            except Exception as e:
                logging.error(f"Error in ML detection: {e}")
        
        return threats

class AlertSystem:
    """Comprehensive alerting system with multiple outputs"""
    
    def __init__(self):
        self.alert_count = 0
        self.setup_logging()
        
    def setup_logging(self):
        """Setup alert-specific logging"""
        self.alert_logger = logging.getLogger('NIDS_Alerts')
        self.alert_logger.setLevel(logging.WARNING)
        
        # File handler for alerts
        file_handler = logging.FileHandler('alerts.jsonl')
        file_handler.setFormatter(logging.Formatter('%(message)s'))
        self.alert_logger.addHandler(file_handler)
        
    def generate_alert(self, threat, packet_info):
        """Generate and log security alerts"""
        self.alert_count += 1
        
        alert = {
            'alert_id': self.alert_count,
            'timestamp': datetime.now().isoformat(),
            'threat_type': threat['type'],
            'rule': threat['rule'],
            'severity': threat['severity'],
            'confidence': threat['confidence'],
            'description': threat['description'],
            'source_ip': packet_info.get('src_ip', 'unknown'),
            'destination_ip': packet_info.get('dst_ip', 'unknown'),
            'source_port': packet_info.get('src_port', 'unknown'),
            'destination_port': packet_info.get('dst_port', 'unknown'),
            'protocol': packet_info.get('protocol', 'unknown')
        }
        
        # Log to JSONL file
        self.alert_logger.warning(json.dumps(alert))
        
        # Console output for high severity alerts
        if threat['severity'] in ['high', 'critical']:
            logging.critical(
                f"HIGH SEVERITY ALERT - {threat['rule']}: "
                f"{packet_info.get('src_ip', 'unknown')} -> {packet_info.get('dst_ip', 'unknown')} "
                f"({threat['description']})"
            )
        
        return alert

class RealTimeNIDS:
    """Main NIDS class integrating all components"""
    
    def __init__(self, interface=None, training_mode=False):
        self.interface = interface
        self.training_mode = training_mode
        self.running = False
        
        # Initialize components
        self.packet_capture = PacketCapture()
        self.traffic_analyzer = TrafficAnalyzer()
        self.detection_engine = DetectionEngine()
        self.alert_system = AlertSystem()
        
        # Statistics
        self.stats = {
            'total_packets': 0,
            'analyzed_packets': 0,
            'alerts_generated': 0,
            'start_time': None
        }
        
        # Training data collection
        self.training_samples = []
        
    def start(self):
        """Start the NIDS"""
        self.running = True
        self.stats['start_time'] = time.time()
        
        logging.info("Starting Real-Time NIDS...")
        logging.info(f"Interface: {self.interface or 'default'}")
        logging.info(f"Training mode: {self.training_mode}")
        
        # Start packet capture
        self.packet_capture.start_capture(self.interface)
        
        # Main processing loop
        try:
            while self.running:
                self._process_packets()
                time.sleep(0.01)  # Small delay to prevent CPU overload
                
        except KeyboardInterrupt:
            logging.info("Shutdown signal received...")
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
        finally:
            self.stop()
    
    def _process_packets(self):
        """Process packets from the capture queue"""
        try:
            while True:
                packet = self.packet_capture.packet_queue.get_nowait()
                self.stats['total_packets'] += 1
                
                # Analyze packet
                features = self.traffic_analyzer.analyze_packet(packet)
                if not features:
                    continue
                    
                self.stats['analyzed_packets'] += 1
                
                # Collect training data or detect threats
                if self.training_mode:
                    self.training_samples.append(features)
                    if len(self.training_samples) >= 1000:
                        self._train_model()
                else:
                    self._detect_and_alert(features, packet)
                    
        except queue.Empty:
            pass
    
    def _train_model(self):
        """Train the ML model with collected data"""
        if self.training_samples:
            logging.info(f"Training model with {len(self.training_samples)} samples...")
            self.detection_engine.train(self.training_samples)
            self.training_mode = False
            self.training_samples.clear()
    
    def _detect_and_alert(self, features, packet):
        """Detect threats and generate alerts"""
        threats = self.detection_engine.detect_threats(features)
        
        if threats:
            self.stats['alerts_generated'] += len(threats)
            
            # Prepare packet info for alerting
            packet_info = {
                'src_ip': features.get('src_ip'),
                'dst_ip': features.get('dst_ip'),
                'src_port': features.get('src_port'),
                'dst_port': features.get('dst_port'),
                'protocol': features.get('protocol')
            }
            
            # Generate alerts for all detected threats
            for threat in threats:
                alert = self.alert_system.generate_alert(threat, packet_info)
                
                # Log detection
                logging.warning(
                    f"THREAT DETECTED - {threat['rule']} "
                    f"(Severity: {threat['severity']}, Confidence: {threat['confidence']:.2f})"
                )
    
    def stop(self):
        """Stop the NIDS"""
        self.running = False
        self.packet_capture.stop()
        
        # Print final statistics
        duration = time.time() - self.stats['start_time']
        logging.info("\n=== NIDS Statistics ===")
        logging.info(f"Runtime: {duration:.2f} seconds")
        logging.info(f"Total packets: {self.stats['total_packets']}")
        logging.info(f"Analyzed packets: {self.stats['analyzed_packets']}")
        logging.info(f"Alerts generated: {self.stats['alerts_generated']}")
        logging.info(f"Alert rate: {self.stats['alerts_generated']/duration:.2f} alerts/sec")
        
        logging.info("NIDS stopped successfully")

def main():
    """Main function to run the NIDS"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Real-Time Network Intrusion Detection System')
    parser.add_argument('--interface', '-i', help='Network interface to monitor')
    parser.add_argument('--train', '-t', action='store_true', help='Enable training mode')
    parser.add_argument('--train-file', help='Training data file')
    
    args = parser.parse_args()
    
    # Create and start NIDS
    nids = RealTimeNIDS(interface=args.interface, training_mode=args.train)
    
    try:
        nids.start()
    except Exception as e:
        logging.error(f"Failed to start NIDS: {e}")

if __name__ == "__main__":
    main()