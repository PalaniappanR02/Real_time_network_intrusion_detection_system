
"""
Quick test to understand NIDS alert types and severity levels
"""

def explain_alert_system():
    """Explain the NIDS alert system in simple terms"""
    
    print("🚀 NIDS ALERT SYSTEM - QUICK GUIDE")
    print("=" * 50)
    
    # Alert Types
    print("\n📊 ALERT TYPES:")
    print("  ├── Signature-based: Known attack patterns")
    print("  └── Anomaly-based: ML-detected unusual behavior")
    
    # Severity Levels
    print("\n🔴 SEVERITY LEVELS:")
    
    print("\n  HIGH SEVERITY (Immediate Action Required):")
    high_threats = [
        "SYN Flood attacks",
        "DDoS attacks", 
        "NULL/XMAS/FIN scans",
        "Exploit attempts",
        "Brute force attacks"
    ]
    for threat in high_threats:
        print(f"    • {threat}")
    
    print("\n  MEDIUM SEVERITY (Investigation Needed):")
    medium_threats = [
        "Port scanning",
        "Suspicious port access",
        "Reconnaissance activity", 
        "Policy violations",
        "Unusual geographic access"
    ]
    for threat in medium_threats:
        print(f"    • {threat}")
    
    print("\n  LOW SEVERITY (Monitoring):")
    low_threats = [
        "Large payloads",
        "Protocol anomalies",
        "Minor policy violations",
        "Informational events"
    ]
    for threat in low_threats:
        print(f"    • {threat}")
    
    # Common Alert Examples
    print("\n🎯 COMMON ALERT EXAMPLES:")
    examples = [
        ("SYN Flood", "High", "Multiple SYN packets from single source"),
        ("Port Scan", "Medium", "Connection attempts to multiple ports"),
        ("Suspicious RDP", "Medium", "Access to port 3389 from external"),
        ("Large FTP Transfer", "Low", "Unusually large file transfer"),
        ("NULL Scan", "High", "TCP packet with no flags set")
    ]
    
    for rule, severity, description in examples:
        print(f"  {severity:6} | {rule:15} | {description}")
    
    # Confidence Scores
    print("\n💯 CONFIDENCE SCORES:")
    print("  0.9-1.0: Very High - Almost certain malicious activity")
    print("  0.7-0.9: High - Strong evidence of malicious activity") 
    print("  0.5-0.7: Medium - Suspicious activity, needs verification")
    print("  0.3-0.5: Low - Possibly benign, monitor for patterns")
    print("  0.0-0.3: Very Low - Likely false positive")
    
    print("\n" + "=" * 50)
    print("To test the system, run: python test_alerts.py")

if __name__ == "__main__":
    explain_alert_system()