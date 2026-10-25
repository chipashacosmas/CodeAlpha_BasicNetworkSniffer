# CodeAlpha Basic Network Sniffer

A Python-based network sniffer developed for **CodeAlpha Cybersecurity Internship — Task 01**. The tool uses Scapy to capture network packets and display useful metadata for basic network traffic analysis.

## Features

- Live packet capture on a selected network interface.
- Source and destination IP address identification.
- TCP, UDP, and ICMP protocol identification.
- Source and destination port display when available.
- Packet timestamps and packet lengths.
- Export of captured metadata to CSV.
- Graceful shutdown using `Ctrl+C`.

## Technologies

- Python 3.12
- Scapy 2.8.0
- Npcap on Windows

## Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
├── sniffer.py
├── requirements.txt
├── README.md
├── .gitignore
└── captured_packets.csv  # Generated at runtime; excluded from Git
```

## Requirements

- Python 3.12 or a compatible Python version.
- Scapy.
- Npcap installed on Windows.
- Administrator privileges may be required for packet capture.

## Installation

Open CMD in the project directory and run:

```bash
python -m pip install -r requirements.txt
```

## Usage

Run the sniffer:

```bash
python sniffer.py
```

Select the network interface you are authorized to monitor. The program displays packet metadata and writes records to `captured_packets.csv`.

Press `Ctrl+C` to stop the capture.

## CSV Output

The CSV file contains these columns:

- `Timestamp`
- `Source IP`
- `Destination IP`
- `Protocol`
- `Source Port`
- `Destination Port`
- `Packet Length`

## Testing

The initial test on a personal USB-tethered connection successfully captured live IP traffic and wrote packet metadata to CSV. The generated CSV was inspected to confirm the expected columns and record structure.

## Responsible Use

Use this tool only on devices and networks you own or have explicit authorization to monitor. Packet metadata can reveal information about network activity, so protect captured logs and avoid publishing sensitive traffic records.

This project focuses on metadata and does not intentionally extract application payloads, passwords, or message contents.

## Internship Task

**Program:** CodeAlpha Cybersecurity Internship  
**Task:** Task 01 — Basic Network Sniffer  
**Status:** Core capture and CSV logging implemented; further testing and documentation review pending.
