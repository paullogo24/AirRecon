# AirRecon

AirRecon is a Linux command-line WiFi discovery tool. It reads `iw` scan output,
shows advertised network settings, saves the latest results, and exports CSV reports.
Use it on your own networks or in environments where you have permission to assess WiFi.

**Version:** 1.1 · **Author:** paul.l

## Requirements

- Python 3.9 or newer; no third-party Python packages or virtual environment needed.
- For live scans: Linux, a WiFi adapter with a working driver, and `iw`.
- Live scans usually require root privileges. Offline mode needs neither `iw` nor sudo.

Install `iw` if necessary:

```bash
# Fedora
sudo dnf install iw

# Debian / Ubuntu
sudo apt install iw
```

## Setup on another computer

AirRecon calls `iw` internally. You can keep using NetworkManager, `nmcli`, or your
desktop WiFi menu to manage connections; `iw` only needs to be installed alongside
them. You do not need to change your normal WiFi manager or edit AirRecon's code.

1. Check that the computer runs Linux and has a working WiFi adapter.
2. Install Python 3.9 or newer and `iw` using your distribution's package manager.
   The `iw` installation commands for Fedora and Debian/Ubuntu are listed above.
3. Confirm the tools and adapter are available:

   ```bash
   python3 --version
   iw --version
   sudo iw dev
   ```

   The last command should list a wireless interface. If none appears, check that
   the adapter is connected, its driver is installed, and WiFi is enabled.
4. Open your copy of the AirRecon folder and follow **Run a live scan** below.
   Select the adapter listed on your computer. Names such as `wlo1`, `wlan0`, and
   `wlp2s0` are examples; you do not need to match the author's adapter name.

**Alternative scanners:** live scanning currently supports only Linux with `iw`.
There is no backend setting or automatic fallback to `nmcli`, `iwlist`, Windows,
or macOS scanning tools. Supporting those tools would require additional scanner
implementations. If you cannot install or use `iw`, try the offline sample below.
The `--input` option accepts plain-text **iw scan output only**, not output from
other scanners.

## Run a live scan

Replace `/path/to/AirRecon` with the location of your copy of the project in each
example below.

```bash
cd /path/to/AirRecon
sudo python3 AirRecon.py
```

The filename `AirRecon.py` is case-sensitive.

1. Choose **1** to list wireless adapters. Ethernet and loopback devices are excluded.
2. Choose **2**, then enter the number of the adapter to scan (for example, `wlo1`).
3. Read the table of network names, BSSIDs, channels, frequencies, signal levels,
   estimated quality, and security labels.
4. Choose **3**, then a network number, for details and basic configuration warnings.
5. Choose **4** to export the full scan to CSV, or **5** to view saved results.
6. Choose **7** to filter the displayed results by name, exact security label, and
   minimum quality. Filtering does not change saved results or the full-scan report.
7. Choose **6** to exit. Ctrl+C and end-of-input also exit cleanly.

## Try it without scanning

The included sample contains four fictional networks: WPA2, WPA2/WPA3 transition,
an open network named `SAE Guest`, and a hidden WPA3 network on 6 GHz.

```bash
cd /path/to/AirRecon
python3 AirRecon.py --input tests/fixtures/sample_scan.txt --output-dir /tmp/airrecon-demo
```

Choose **2** to load the sample, then use the other menu options as above.
The banner says **OFFLINE**. Keeping a separate output directory prevents sample data
from replacing your real saved scan. You can also pass a previously captured plain-text
`iw dev INTERFACE scan` transcript to `--input`.

## How it works

1. Live mode discovers wireless adapters through `/sys/class/net` and runs
   `iw dev INTERFACE scan`, with a 25-second timeout. It does not change adapter mode,
   connect to a network, or change router settings. The driver may send probe requests.
2. Each `BSS` block becomes a network record, including hidden SSIDs. The parser reads
   frequencies, dBm signal values, and RSN/WPA security fields. Network names cannot
   change the security classification.
3. Quality is an estimate: `clamp(2 × (dBm + 100), 0, 100)`. For example, −75 dBm becomes
   50%. It is not a throughput measurement. Missing measurements display as `—`.
4. Security labels include `Open`, `WPA`, `WPA2`, `WPA3`, `WPA2/WPA3`, and
   `Enhanced Open (OWE)`. Privacy without WPA/RSN is labeled `WEP/unknown`, because the
   scan alone is insufficient to confirm WEP. Enterprise modes can remain ambiguous:
   generic 802.1X is labeled `WPA2/3-Enterprise`; unrecognized authentication stays unknown.
   These labels describe advertised settings, not proof that a network is secure.
5. Channel analysis counts BSS entries on the same center frequency. It keeps the
   2.4, 5, and 6 GHz bands separate. It does not measure airtime, channel-width overlap,
   interference, or the number of physical routers.
6. Successful scans replace the last saved JSON snapshot using an atomic file replacement.
   Failed scans preserve previous results. A successful scan finding zero networks saves
   an empty snapshot. If saving fails, the new results remain available in the session.

## Files and storage

By default, output is stored next to `AirRecon.py`, regardless of the launch directory:

```text
data/wifi_scan_results.json   Latest successful scan (not a history)
data/scan_output.txt          Latest available raw live scan output
logs/wifi_scan.log            Timestamped scan and export events
reports/wifi_report_*.csv     Timestamped CSV exports
```

Folders are created as needed. Use `--output-dir /path/to/folder` to choose a different
parent for these directories. Live mode attempts to save raw output before the JSON
snapshot; if a file write fails, the raw output and snapshot can differ. The JSON snapshot
is what **View Saved Results** reads.

Files created with sudo may require sudo to read or update. Use a separate output directory
for unprivileged demo runs. Reports include the full scan and protect text cells beginning
with spreadsheet formula characters by prefixing an apostrophe. JSON retains the original
name as represented by `iw`; `iw` escape sequences are not decoded.

Generated data, logs, reports, Python caches, and virtual environments are ignored by Git.
The existing `myenv/` and `venv/` directories are not needed and can be removed if you no
longer use them for other work.

## Troubleshooting

- **`iw` not found:** install it with the command above.
- **Operation not permitted:** run live mode with sudo from your terminal.
- **No wireless interfaces:** confirm the adapter and driver are available. Containers
  and virtual machines may not expose the host WiFi device.
- **Failed to connect to generic netlink:** the environment may restrict kernel network
  access. Run from the host terminal, or use offline mode.
- **Network is down / rfkill / device busy:** enable WiFi, check airplane mode with
  `rfkill list`, wait for any other scan to finish, and retry.
- **Cannot save results:** choose a writable `--output-dir` and check ownership.
- **Cannot load saved results:** the file is unreadable or malformed. The app reports the
  problem and leaves the file untouched; a later successful scan can replace it.

## Tests

```bash
cd /path/to/AirRecon
python3 -m unittest discover -s tests -v
```

Tests use synthetic scan output, temporary directories, and mocked `iw` calls. They cover
parsing, failure recovery, storage, input validation, filtering, CSV export, and a complete
offline menu session. They do not run wireless scans. Live scanning still depends on your
adapter, driver, privileges, and environment.
