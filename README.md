# CodeAlpha Basic Network Sniffer

**Organization:** CodeAlpha Cyber Security Internship  
**Internship ID:** CA/DF1/324898  
**Student:** Chipasha Cosmas  
**Degree:** Bachelor of Science in Cybersecurity — Kwame Nkrumah University (KMU), Zambia  
**Task 01:** Basic Network Sniffer  

---

## 1. Project Overview

A robust, cross-platform Python network packet analyzer and sniffer built using the **Scapy** library. The tool performs real-time promiscuous/packet-capture operations across network interfaces, decodes network and transport layer protocols, sanitizes and previews payload contents, logs structured session data to CSV, and generates end-of-session protocol analytics.

This project was developed in compliance with **CodeAlpha Cyber Security Internship Task 1** requirements:
- Build a Python program to capture network traffic packets.
- Analyze captured packets to understand structure and content.
- Learn data flow dynamics and protocol fundamentals.
- Utilize packet capture libraries (`scapy`).
- Display useful information: Source/Destination IPs, Protocols, Ports, and Payloads.

---

## 2. Key Features

- **Dynamic Interface Discovery:** Automatically lists available hardware and virtual network interfaces along with their active IPv4 bindings.
- **Dual-Stack IP Support:** Seamlessly captures and parses both **IPv4** and **IPv6** packets.
- **Protocol Decoding:** Identifies transport and network layer protocols including **TCP**, **UDP**, and **ICMP**.
- **Port Identification:** Extracts Source and Destination port numbers for transport layer traffic.
- **Payload Inspection & Sanitization:** Safely inspects raw packet payloads (`Raw` layer), calculates payload length, and generates a printable ASCII preview (masking unprintable binary control bytes as `.`) and hex representation.
- **Session Analytics:** Computes live capture statistics including total packets captured, total data volume (KB/Bytes), and percentage-based protocol distribution.
- **Structured CSV Export:** Persists all packet metadata and payload previews to `captured_packets.csv` for forensic review or security auditing.
- **Controlled Capture:** Supports both indefinite capture (terminated cleanly via `Ctrl+C`) and packet count limits.

---

## 3. Project Architecture

```text
CodeAlpha_BasicNetworkSniffer/
├── sniffer.py              # Main packet sniffer & analysis engine
├── requirements.txt        # Python dependency manifest (scapy)
├── README.md               # Complete project documentation & audit guide
├── .gitignore              # Ignores runtime bytecode & local packet captures
└── captured_packets.csv    # Generated forensic log (CSV format)
```

---

## 4. Technical Prerequisites

1. **Python 3.10+** (Tested on Python 3.12)
2. **Npcap (Windows)** or **libpcap (Linux/macOS)**:
   - On Windows, install [Npcap](https://npcap.com/) with the option **"Install Npcap in WinPcap API-compatible Mode"** enabled.
3. **Administrator / Root Privileges**:
   - Raw packet capture requires elevated privileges to access socket drivers.

---

## 5. Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/chipashacosmas/CodeAlpha_BasicNetworkSniffer.git
   cd CodeAlpha_BasicNetworkSniffer
   ```

2. **Install dependencies:**
   ```bash
   python -m pip install -r requirements.txt
   ```

---

## 6. Execution & Usage

Launch the sniffer with Administrator privileges:

### Windows (Run Command Prompt or PowerShell as Administrator):
```powershell
python sniffer.py
```

### Linux / macOS:
```bash
sudo python3 sniffer.py
```

### Interactive Workflow:
1. The tool prints a numbered table of all available interfaces and active IPv4 addresses.
2. Enter the number corresponding to your active network interface (e.g. Wi-Fi, Ethernet, or VirtualBox Host-Only).
3. Optionally specify a packet count limit or press Enter for continuous monitoring.
4. Press `Ctrl+C` at any time to stop monitoring and review session statistics.

---

## 7. Sample Output

### Terminal Live Stream
```text
  ==============================================================
   CodeAlpha Cybersecurity Internship — Task 01
   Basic Network Sniffer & Packet Analyzer
   Student: Chipasha Cosmas | ID: CA/DF1/324898
  ==============================================================

============================================================
           AVAILABLE NETWORK INTERFACES
============================================================
 [ 1] \Device\NPF_{195D84...}              | IPv4: 10.149.236.79
 [ 2] \Device\NPF_{8824FA...}              | IPv4: 192.168.56.1
 [ 3] \Device\NPF_Loopback                 | IPv4: 127.0.0.1
============================================================

Select interface number to monitor: 1
Enter packet count limit (press Enter for unlimited / Ctrl+C to stop): 

---------------------------------------------------------------------------
[*] Bound Interface : \Device\NPF_{195D84...}
[*] Capture Filter   : ip or ip6 (All IPv4 & IPv6 traffic)
[*] Packet Limit     : Unlimited (Ctrl+C to stop)
[*] CSV Log File     : C:\Users\365\CodeAlpha_BasicNetworkSniffer\captured_packets.csv
---------------------------------------------------------------------------
[*] Starting live packet capture...

[2026-10-26T14:10:05+02:00] 10.149.236.79:51240        -> 142.251.47.206:443         | TCP   | Len:   74B | Payload:   32B [....G...google.com.]
[2026-10-26T14:10:06+02:00] 10.149.236.79:58210        -> 8.8.8.8:53                 | UDP   | Len:   68B | Payload:   28B [....1.0.0.127.in-ad]
[2026-10-26T14:10:07+02:00] 10.149.236.79              -> 8.8.8.8                    | ICMP  | Len:   84B | Payload:   56B [!"#$%&'()*+,-./0123]

^C
[*] Capture terminated by user (KeyboardInterrupt).

============================================================
                 CAPTURE SESSION SUMMARY
============================================================
 Total Packets Captured : 152
 Total Data Volume      : 114.82 KB (117576 Bytes)

 Protocol Distribution:
   - TCP      :   128 packets ( 84.2%)
   - UDP      :    20 packets ( 13.2%)
   - ICMP     :     4 packets (  2.6%)
------------------------------------------------------------
 CSV Output Saved to    : C:\Users\365\CodeAlpha_BasicNetworkSniffer\captured_packets.csv
============================================================
```

### CSV Output Structure
The generated `captured_packets.csv` contains the following columns:
| Column Header | Description |
|---|---|
| `Timestamp` | ISO-8601 formatted local timestamp |
| `IP Version` | `IPv4` or `IPv6` |
| `Source IP` | Originating IP address |
| `Source Port` | Originating transport port (TCP/UDP) |
| `Destination IP` | Target IP address |
| `Destination Port` | Target transport port (TCP/UDP) |
| `Protocol` | Transport/network protocol (`TCP`, `UDP`, `ICMP`, etc.) |
| `Packet Length (Bytes)` | Entire packet wire length |
| `Payload Size (Bytes)` | Length of application/raw payload |
| `Payload Preview (ASCII)` | Sanitized printable ASCII preview |
| `Payload Hex Preview` | Space-delimited hex bytes of payload head |

---

## 8. Responsible Use & Security Disclaimer

This packet sniffer is created strictly for academic and defensive security analysis purposes within authorized networks. It is designed to inspect traffic headers and diagnostic payload segments. It must not be deployed on unauthorized networks or utilized for non-consensual packet eavesdropping.

---
*Maintained by Chipasha Cosmas — Cybersecurity Student, KMU Zambia.*
