
#!/usr/bin/env python3
"""
CodeAlpha Task 01: Basic Network Sniffer
Captures packet metadata on a selected network interface.
"""

import csv
import os
from datetime import datetime

from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, get_if_list, get_if_addr

OUTPUT_FILE = "captured_packets.csv"


def list_interfaces():
    """Display available network interfaces."""
    print("\nAvailable network interfaces:")
    for index, interface in enumerate(get_if_list(), start=1):
        try:
            address = get_if_addr(interface)
        except Exception:
            address = "Unknown"

        print(f"{index}. {interface}  |  IPv4: {address}")


def get_protocol(packet):
    """Identify the packet's transport or network protocol."""
    if TCP in packet:
        return "TCP", packet[TCP].sport, packet[TCP].dport
    if UDP in packet:
        return "UDP", packet[UDP].sport, packet[UDP].dport
    if ICMP in packet:
        return "ICMP", "", ""
    if IPv6 in packet:
        return "IPv6", "", ""
    if IP in packet:
        return "IP", "", ""
    return "Other", "", ""


def get_addresses(packet):
    """Extract source and destination IP addresses."""
    if IP in packet:
        return packet[IP].src, packet[IP].dst
    if IPv6 in packet:
        return packet[IPv6].src, packet[IPv6].dst
    return "Non-IP", "Non-IP"


def prepare_csv():
    """Create the CSV file and write its header if needed."""
    if not os.path.exists(OUTPUT_FILE) or os.path.getsize(OUTPUT_FILE) == 0:
        with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                "Timestamp",
                "Source IP",
                "Destination IP",
                "Protocol",
                "Source Port",
                "Destination Port",
                "Packet Length",
            ])


def main():
    interfaces = get_if_list()
    if not interfaces:
        print("No packet-capture interfaces found.")
        return

    list_interfaces()

    try:
        choice = int(input("\nSelect interface number: "))
        if not 1 <= choice <= len(interfaces):
            print("Invalid interface selection.")
            return
    except ValueError:
        print("Enter a valid number.")
        return

    interface = interfaces[choice - 1]

    print(f"\nSelected interface: {interface}")
    print("Capturing packet metadata. Press Ctrl+C to stop.")
    print(f"CSV output: {os.path.abspath(OUTPUT_FILE)}\n")

    prepare_csv()
    packet_count = 0

    def process_packet(packet):
        nonlocal packet_count
        packet_count += 1

        timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
        source, destination = get_addresses(packet)
        protocol, source_port, destination_port = get_protocol(packet)
        length = len(packet)

        print(
            f"[{timestamp}] {source} -> {destination} | "
            f"{protocol} | {source_port} -> {destination_port} | "
            f"{length} bytes"
        )

        with open(OUTPUT_FILE, "a", newline="", encoding="utf-8") as file:
            writer = csv.writer(file)
            writer.writerow([
                timestamp,
                source,
                destination,
                protocol,
                source_port,
                destination_port,
                length,
            ])

    try:
        sniff(
            iface=interface,
            filter="ip or ip6",
            prn=process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCapture stopped by user.")
    except Exception as error:
        print(f"\nCapture error: {error}")
        print("Check that CMD is running as Administrator and Npcap is installed.")
    finally:
        print(f"Total packets captured: {packet_count}")
        print(f"Metadata saved to: {os.path.abspath(OUTPUT_FILE)}")


if __name__ == "__main__":
    main()
