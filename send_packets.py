from scapy.all import *

# Send SYN flood packets
def send_syn_flood(target_ip, target_port):
    print("Sending SYN flood packets...")
    for i in range(20):
        pkt = IP(src=f"10.0.0.{i}", dst=target_ip) / TCP(sport=RandShort(), dport=target_port, flags="S")
        send(pkt, verbose=False)
    print("Done.")

# Send port scan packets
def port_scan(target_ip):
    print("Sending port scan packets...")
    for port in [21, 22, 23, 25, 80, 443]:
        pkt = IP(src="192.168.1.50", dst=target_ip) / TCP(sport=1234, dport=port, flags="S")
        send(pkt, verbose=False)
    print("Done.")

if __name__ == "__main__":
    target = "192.168.1.6"  # CHANGE THIS to your laptop's IP
    send_syn_flood(target, 80)
    port_scan(target)
