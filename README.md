# PyIDS – Python Intrusion Detection System

PyIDS is a Python-based Network Intrusion Detection System (IDS) developed to monitor live network traffic and detect suspicious activities using rule-based and anomaly-based detection techniques.

This project is created for learning purposes to understand how network monitoring and basic threat detection work in real-world cybersecurity environments.

---

## Features

- Live packet sniffing using Scapy  
- Protocol identification (TCP, UDP, ICMP)  
- Detection of port scanning activity  
- Detection of SYN flood attack attempts  
- High traffic anomaly detection  
- Unusual port access detection  
- Network traffic logging for monitoring and basic forensic analysis  

---

## Technologies Used

- Python  
- Scapy  
- Networking concepts (TCP/IP, Ports, Protocols)  

---

## Use Case

This project demonstrates the core working of a Network Intrusion Detection System and helps in understanding:

- Network traffic flow  
- Packet-level analysis  
- SOC-style monitoring and alerting  
- Basic attack detection techniques  

It is suitable for learning cybersecurity fundamentals and SOC analyst concepts.

---

## How to Run

1. Install dependencies:

```bash
pip install scapy
```

2. Run the program with administrator/root privileges:

```bash
python main.py
```

Note: Packet sniffing requires elevated permissions.

---

## Disclaimer

This project is intended strictly for educational purposes.  
It only monitors network traffic on the local system and does not perform any offensive or malicious actions.

---

## Author

Zeefa Shaikh
