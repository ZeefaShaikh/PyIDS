from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# -------------------------------
# CONFIGURATION
# -------------------------------

PROTOCOL_MAP = {
    6: "TCP",
    17: "UDP",
    1: "ICMP"
}

COMMON_PORTS = [80, 443, 53, 22, 25, 110]

PORT_SCAN_THRESHOLD = 6
SYN_FLOOD_THRESHOLD = 20
HIGH_TRAFFIC_THRESHOLD = 100

LOG_FILE = "traffic_log.txt"

# -------------------------------
# TRACKING STRUCTURES
# -------------------------------

port_activity = defaultdict(set)
syn_count = defaultdict(int)
packet_count = defaultdict(int)

# -------------------------------
# HELPER FUNCTIONS
# -------------------------------

def log_to_file(text):
    with open(LOG_FILE, "a") as f:
        f.write(text + "\n")

def alert_message(text):
    print("\n================ ALERT ================\n")
    print(text)
    print("\n=======================================\n")
    log_to_file(text)

# -------------------------------
# PACKET ANALYSIS FUNCTION
# -------------------------------

def analyze(packet):

    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst
    proto_num = packet[IP].proto
    protocol = PROTOCOL_MAP.get(proto_num, "OTHER")

    sport = packet.sport if hasattr(packet, "sport") else "-"
    dport = packet.dport if hasattr(packet, "dport") else "-"

    # Log normal traffic
    log_line = f"{src}:{sport} -> {dst}:{dport} | Protocol: {protocol}"
    print(log_line)
    log_to_file(log_line)

    # -------------------------------
    # PACKET COUNT (ANOMALY)
    # -------------------------------
    packet_count[src] += 1
    if packet_count[src] == HIGH_TRAFFIC_THRESHOLD:
        alert_message(
            f"⚠ High Traffic Anomaly: {src} sent more than {HIGH_TRAFFIC_THRESHOLD} packets"
        )

    # -------------------------------
    # PORT SCAN DETECTION
    # -------------------------------
    if protocol in ["TCP", "UDP"] and dport != "-":
        port_activity[src].add(dport)
        if len(port_activity[src]) == PORT_SCAN_THRESHOLD:
            alert_message(
                f"⚠ Possible Port Scan Detected from {src}"
            )

    # -------------------------------
    # UNUSUAL PORT DETECTION
    # -------------------------------
    if dport != "-" and isinstance(dport, int):
        if dport not in COMMON_PORTS and dport > 1024:
            alert_message(
                f"ALERT : Unusual Port Access: {src} communicating on port {dport}"
            )

    # -------------------------------
    # SYN FLOOD DETECTION
    # -------------------------------
    if packet.haslayer(TCP):
        tcp_layer = packet[TCP]
        if tcp_layer.flags == 2:  # SYN flag
            syn_count[src] += 1
            if syn_count[src] == SYN_FLOOD_THRESHOLD:
                alert_message(
                    f"⚠ Possible SYN Flood Attack Detected from {src}"
                )

# -------------------------------
# START SNIFFING
# -------------------------------

print("\n🔍 PyIDS started...")
print("📡 Monitoring network traffic")
print("⛔ Press CTRL + C to stop\n")

try:
    sniff(prn=analyze, store=False)
except KeyboardInterrupt:
    print("\n🛑 PyIDS stopped safely.")
