# AirRecon

A command-line tool for discovering nearby WiFi networks and reviewing their security configuration. Built for use on your own network(s) or in environments where you have explicit authorization to perform wireless security assessments.

**Version:** 1.0
**Author:** paul.l

## ⚠️ Authorized Use Only

Only scan networks you own or have explicit written permission to assess. Unauthorized wireless network scanning or analysis may violate local laws and regulations (e.g. the Computer Fraud and Abuse Act in the US, or equivalent laws elsewhere).

## Features

Current / planned menu options:

1. **List Wireless Interfaces** — Enumerate wireless network interfaces available on the host.
2. **Scan for WiFi Networks** — Run a scan on a chosen interface, parse results, save them, and display a table.
3. **Analyze Selected Network** — Inspect a specific discovered network in more detail, with basic security and channel-congestion warnings.
4. **Generate Report (CSV)** — Export the current or last-saved scan results to a timestamped CSV report in `reports/`.
5. **View Saved Results** — Load and display the most recently saved scan results from `data/wifi_scan_results.json`.
6. **Exit**

## Requirements

- Linux (uses `/sys/class/net/` for interface discovery and `iwlist` for scanning)
- Python 3
- Root/sudo privileges (required for `iwlist scan` on most systems)
- `iwlist` (part of `wireless-tools`, e.g. `sudo apt install wireless-tools`)

### Python dependencies

```
scapy
tabulate
```

Install with:

```bash
pip install -r requirements.txt
```

## Project Structure

The tool creates the following folders on startup:

```
data/       # Saved scan results (wifi_scan_results.json)
logs/       # Log output (wifi_scan.log)
reports/    # Generated CSV reports
```

## Usage

```bash
sudo python3 wifi_recon.py
```

You'll be presented with a menu:

```
============================================================
AirRecon - Version 1.0
============================================================
1. List Wireless Interfaces
2. Scan for WiFi Networks
3. Analyze Selected Network
4. Generate Report (CSV)
5. View Saved Results
6. Exit
============================================================
```

Select an option by entering its number.

## Current Status

The tool is now functional end-to-end. Run it with:

```bash
sudo python3 airrecon.py
```

Implemented:

- Project folder/log setup
- Full menu loop — all 6 options are wired to real functions
- Wireless interface listing (`get_wireless_interfaces`)
- Scan flow (`scan_wifi`) that shells out to `iwlist`, writes raw output to `scan_output.txt`, and splits it by cell for parsing
- Cell parsing (`parse_network_info`) — extracts BSSID, ESSID, channel, and frequency via regex
- Encryption detection (`detect_encryption`) — classifies networks as Open / WEP / WPA / WPA2 / WPA3
- Signal quality calculation (`calculate_signal`) — converts `iwlist`'s Quality value into a percentage
- Signal analysis (`analyze_signal`), channel analysis (`analyze_channels`)
- Filtering (`filter_networks`) by encryption, SSID substring, or minimum quality (available as a function; not yet exposed in the menu)
- CSV export (`save_to_csv`) — written to `reports/` with a timestamped filename
- Console table display (`display_results`)
- Persisting scan results to `data/wifi_scan_results.json` and logging actions to `logs/wifi_scan.log`
- Per-network deep-dive (option 3) with basic security warnings for Open/WEP networks and channel-congestion notes

**Not yet implemented / possible next steps:**

- Exposing `filter_networks` in the menu (e.g. "search by SSID" or "show only WPA3 networks")
- More detailed vulnerability analysis beyond Open/WEP warnings

## Roadmap Ideas

- Encryption type detection (Open / WEP / WPA / WPA2 / WPA3)
- Signal strength and channel reporting
- Table-formatted console output via `tabulate`
- JSON persistence of scan history for trend comparison over time

## Disclaimer

This tool is provided for educational and authorized security assessment purposes only. The author is not responsible for misuse of this software.