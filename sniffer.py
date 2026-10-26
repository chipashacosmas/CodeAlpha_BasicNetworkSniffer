#!/usr/bin/env python3
"""
CodeAlpha Task 01: Basic Network Sniffer
Author: Chipasha Cosmas
Internship ID: CA/DF1/324898
Organization: CodeAlpha Cyber Security Internship

Description:
A cross-platform Python network sniffer built with Scapy that captures real-time
network traffic, extracts packet headers (Source/Destination IP, Protocol, Ports),
inspects and safely previews payload contents, logs data to CSV, and generates
capture statistics.
"""

import csv
import os
import sys
from datetime import datetime
from collections import Counter

try:
    from scapy.all import (
        sniff,
        IP,
        IPv6,
        TCP,
        UDP,
        ICMP,
        Raw,
        get_if_list,
        get_if_addr,
    )
except ImportError:
    print("Error: Scapy is not installed. Run: pip install scapy")
    sys.exit(1)

OUTPUT_FILE = "captured_packets.csv"


def list_interfaces():
    """Display available network interfaces with their bound IPv4 addresses."""
    print("\n" + "=" * 60)
    print("           AVAILABLE NETWORK INTERFACES")
    print("=" * 60)
    interfaces = get_if_list()
    for index, interface in enumerate(interfaces, start=1):
        try:
            address = get_if_addr(interface)
        except Exception:
            address = "No IP / Unassigned"

        print(f" [{index:2d}] {interface:<36} | IPv4: {address}")
    print("=" * 60)
    return interfaces


def get_addresses(packet):
    """Extract source and destination IP addresses from IPv4 or IPv6 layers."""
    if IP in packet:
        return packet[IP].src, packet[IP].dst, "IPv4"
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst, "IPv6"
    return "Non-IP", "Non-IP", "Unknown"


def get_protocol(packet):
    """Identify the transport or network protocol and extract port numbers."""
    if TCP in packet:
        return "TCP", packet[TCP].sport, packet[TCP].dport
    if UDP in packet:
        return "UDP", packet[UDP].sport, packet[UDP].dport
    if ICMP in packet:
        return "ICMP", "-", "-"
    if IPv6 in packet:
        return "IPv6", "-", "-"
    if IP in packet:
        return "IP", "-", "-"
    return "Other", "-", "-"


def get_payload_info(packet, max_preview=32):
    """
    Extract payload size and a sanitized, human-readable ASCII preview.
    Non-printable characters are masked as '.' to prevent terminal control injection.
    """
    if Raw in packet:
        raw_bytes = bytes(packet[Raw].load)
        payload_len = len(raw_bytes)
        # Convert printable ASCII (32-126); mask others as '.'
        preview_chars = [
            chr(b) if 32 <= b <= 126 else "." for b in raw_bytes[:max_preview]
        ]
        preview_str = "".join(preview_chars)
        hex_preview = raw_bytes[:16].hex(" ")
        return payload_len, preview_str, hex_preview
    return 0, "<No Raw Payload>", ""


def prepare_csv(filepath=OUTPUT_FILE):
    """Create the CSV output file and write column headers if file is empty."""
    file_exists = os.path.exists(filepath) and os.path.getsize(filepath) > 0
    if not file_exists:
        with open(filepath, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp",
                "IP Version",
                "Source IP",
                "Source Port",
                "Destination IP",
                "Destination Port",
                "Protocol",
                "Packet Length (Bytes)",
                "Payload Size (Bytes)",
                "Payload Preview (ASCII)",
                "Payload Hex Preview",
            ])


def main():
    print("""
  ==============================================================
   CodeAlpha Cybersecurity Internship — Task 01
   Basic Network Sniffer & Packet Analyzer
   Student: Chipasha Cosmas | ID: CA/DF1/324898
  ==============================================================
    """)

    interfaces = list_interfaces()
    if not interfaces:
        print("[!] No packet capture network interfaces detected.")
        return

    try:
        selection = input("\nSelect interface number to monitor: ").strip()
        choice = int(selection)
        if not 1 <= choice <= len(interfaces):
            print(f"[!] Invalid selection. Please choose 1 to {len(interfaces)}.")
            return
    except ValueError:
        print("[!] Invalid input. Numeric interface ID required.")
        return

    interface = interfaces[choice - 1]

    # Optional packet capture count
    count_input = input("Enter packet count limit (press Enter for unlimited / Ctrl+C to stop): ").strip()
    max_packets = int(count_input) if count_input.isdigit() and int(count_input) > 0 else 0

    print("\n" + "-" * 75)
    print(f"[*] Bound Interface : {interface}")
    print(f"[*] Capture Filter   : ip or ip6 (All IPv4 & IPv6 traffic)")
    print(f"[*] Packet Limit     : {'Unlimited (Ctrl+C to stop)' if max_packets == 0 else max_packets}")
    print(f"[*] CSV Log File     : {os.path.abspath(OUTPUT_FILE)}")
    print("-" * 75)
    print("[*] Starting live packet capture...\n")

    prepare_csv(OUTPUT_FILE)

    stats = {
        "total_packets": 0,
        "total_bytes": 0,
        "protocols": Counter(),
    }

    def process_packet(packet):
        stats["total_packets"] += 1
        pkt_len = len(packet)
        stats["total_bytes"] += pkt_len

        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        src_ip, dst_ip, ip_ver = get_addresses(packet)
        protocol, sport, dport = get_protocol(packet)
        payload_len, ascii_preview, hex_preview = get_payload_info(packet)

        stats["protocols"][protocol] += 1

        # Format source and destination with ports
        src_str = f"{src_ip}:{sport}" if sport != "-" else src_ip
        dst_str = f"{dst_ip}:{dport}" if dport != "-" else dst_ip

        # Clean terminal output line
        print(
            f"[{timestamp}] {src_str:<26} -> {dst_str:<26} | "
            f"{protocol:<5} | Len: {pkt_len:4d}B | "
            f"Payload: {payload_len:4d}B [{ascii_preview[:20]}]"
        )

        # Append structured row to CSV
        with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                ip_ver,
                src_ip,
                sport,
                dst_ip,
                dport,
                protocol,
                pkt_len,
                payload_len,
                ascii_preview,
                hex_preview,
            ])

    try:
        sniff(
            iface=interface,
            filter="ip or ip6",
            prn=process_packet,
            store=False,
            count=max_packets,
        )
    except KeyboardInterrupt:
        print("\n\n[*] Capture terminated by user (KeyboardInterrupt).")
    except PermissionError:
        print("\n[!] Permission Error: Raw socket capture requires Administrator privileges.")
        print("[!] Please run Command Prompt or PowerShell as Administrator.")
    except Exception as error:
        print(f"\n[!] Unexpected capture error: {error}")
        print("[!] Ensure Npcap is installed in 'WinPcap API-compatible Mode'.")
    finally:
        total = stats["total_packets"]
        bytes_kb = stats["total_bytes"] / 1024.0

        print("\n" + "=" * 60)
        print("                 CAPTURE SESSION SUMMARY")
        print("=" * 60)
        print(f" Total Packets Captured : {total}")
        print(f" Total Data Volume      : {bytes_kb:.2f} KB ({stats['total_bytes']} Bytes)")
        print("\n Protocol Distribution:")
        if total > 0:
            for proto, count in stats["protocols"].most_common():
                pct = (count / total) * 100
                print(f"   - {proto:<8} : {count:5d} packets ({pct:5.1f}%)")
        else:
            print("   - No packets captured.")
        print("-" * 60)
        print(f" CSV Output Saved to    : {os.path.abspath(OUTPUT_FILE)}")
        print("=" * 60 + "\n")


if __name__ == "__main__":
    main()
