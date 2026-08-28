# AirRecon

A command-line tool for discovering nearby WiFi networks and reviewing their security configuration. Built for use on your own network(s) or in environments where you have explicit authorization to perform wireless security assessments.

**Version:** 1.0
**Author:** paul.l

## ⚠️ Authorized Use Only

Only scan networks you own or have explicit written permission to assess. Unauthorized wireless network scanning or analysis may violate local laws and regulations (e.g. the Computer Fraud and Abuse Act in the US, or equivalent laws elsewhere).

## Features

Current / planned menu options:

1. **List Wireless Interfaces** — Enumerate wireless network interfaces available on the host.
2. **Scan for WiFi Networks** — Run a scan on a chosen interface and parse the results (SSID, and other cell info from `iwlist`).
3. **Analyze Selected Network** — Inspect a specific discovered network in more detail. *(not yet implemented)*
4. **Generate Report (CSV)** — Export scan results to a CSV report. *(not yet implemented)*
5. **View Saved Results** — Load and display previously saved scan results from disk. *(not yet implemented)*
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
pip install scapy tabulate
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

This project is a work in progress. Implemented so far:

- Project folder/log setup
- Menu display
- Wireless interface listing (`get_wireless_interfaces`)
- Basic scan flow (`scan_wifi`) that shells out to `iwlist`, writes raw output to `scan_output.txt`, and splits it by cell for parsing

**Not yet implemented** (referenced but missing from the current script):

- `parse_network_info()` — parsing individual cell blocks into structured network data
- Menu wiring — connecting `show_menu()` selections to the actual functions
- Network analysis (option 3)
- CSV report generation (option 4)
- Saved results viewer (option 5)
- Writing results to `RESULTS_FILE` / `LOG_FILE`

## Roadmap Ideas

- Encryption type detection (Open / WEP / WPA / WPA2 / WPA3)
- Signal strength and channel reporting
- Table-formatted console output via `tabulate`
- JSON persistence of scan history for trend comparison over time

## Disclaimer

This tool is provided for educational and authorized security assessment purposes only. The author is not responsible for misuse of this software.