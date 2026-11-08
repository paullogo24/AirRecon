# AirRecon

AirRecon is a Linux command-line WiFi discovery tool. It reads `iw` scan output,
shows advertised network settings, saves the latest results, and exports CSV reports.
Use it on your own networks or in environments where you have permission to assess WiFi.

**Version:** 1.2 · **Author:** paul.l

## Requirements

- Python 3.9 or newer; no third-party Python packages or virtual environment needed.
- For live scans: Linux, a WiFi adapter with a working driver, and `iw`.
- A direct live scan usually requires root privileges. Without sudo, AirRecon falls back
  to a NetworkManager rescan if available, otherwise to cached results (see
  **How it works**). Offline mode needs neither `iw`
  nor sudo.

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
`nmcli` is used only to trigger a rescan when running without sudo; results are always
read through `iw`. There is no support for `iwlist`, Windows, or macOS scanning tools.
Supporting those would require additional scanner implementations. If you cannot install or use `iw`, try the offline sample below.
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

1. Choose **2** to scan. With one WiFi adapter it is used automatically; with several,
   you are asked once and the choice is remembered (shown as `Adapter:` in the menu).
   Choose **1** to pick a different adapter. Ethernet and loopback devices are excluded.
2. If you run without sudo, see the fallback in **How it works**: results come from a
   NetworkManager rescan instead of a direct scan.
3. Read the table of network names, BSSIDs, channels, frequencies, signal levels,
   estimated quality, and security labels, strongest signal first.
   Networks with configuration warnings are marked, e.g. `[2 warnings]`. Below the table,
   names broadcast by several access points are summarised (see **Shared network names**).
4. Choose **3**, then a network number, for details and configuration warnings
   (see **Configuration warnings** below).
5. Choose **4** to export the full scan to CSV, or **5** to view saved results.
6. Choose **6** to filter the displayed results by name, exact security label, and
   minimum quality. Filtering does not change saved results or the full-scan report.
7. Choose **7** (or `0` / `q`) to exit. Ctrl+C and end-of-input also exit cleanly.

## Run without the menu

Passing `--interface`, `--json`, or `--csv` runs one scan, saves it like a menu scan,
and exits. Results (a table, or JSON with `--json`) go to stdout; progress and errors
go to stderr, so JSON can be piped into other tools. Exit status is 0 on success, 1 if
the scan or CSV export fails, and 2 for invalid options.

```bash
sudo python3 AirRecon.py --interface wlo1                    # print the table
sudo python3 AirRecon.py --interface wlo1 --json > scan.json # machine-readable
sudo python3 AirRecon.py --interface wlo1 --csv reports/today.csv
python3 AirRecon.py --input tests/fixtures/sample_scan.txt --json --output-dir /tmp/airrecon-demo
```

JSON output includes a `Warnings` list for each network; the saved snapshot does not.
For cron, put the command in root's crontab (`sudo crontab -e`).

## Try it without scanning

The included sample contains four fictional networks: WPA2 with WPS and no PMF,
WPA2/WPA3 transition, an open network named `SAE Guest`, and a hidden WPA3 network on 6 GHz.

```bash
cd /path/to/AirRecon
python3 AirRecon.py --input tests/fixtures/sample_scan.txt --output-dir /tmp/airrecon-demo
```

Choose **2** to load the sample, then use the other menu options as above.

To see shared-name warnings, load `tests/fixtures/twin_scan.txt` instead. It contains
a fictional cafe network imitated by an Open access point and a lookalike name, plus a
library with two normal access points:

```bash
python3 AirRecon.py --input tests/fixtures/twin_scan.txt --output-dir /tmp/airrecon-demo --csv /tmp/airrecon-demo/twins.csv
```
The banner says **OFFLINE**. Keeping a separate output directory prevents sample data
from replacing your real saved scan. You can also pass a previously captured plain-text
`iw dev INTERFACE scan` transcript to `--input`.

## How it works

1. Live mode discovers wireless adapters through `/sys/class/net` and runs
   `iw dev INTERFACE scan`, with a 25-second timeout. It does not change adapter mode,
   connect to a network, or change router settings. The driver may send probe requests.
   If the fresh scan is refused (no sudo, or another program is scanning), AirRecon asks
   NetworkManager to rescan (`nmcli device wifi list ifname INTERFACE --rescan yes`,
   normally allowed for a logged-in user, about 10 seconds) and then reads the kernel's
   results with `iw dev INTERFACE scan dump`, which works without root. Both steps are
   best effort: without NetworkManager, the dump holds whatever the system last saw and
   may list only a few networks, often just the one you are connected to. If it is empty,
   the original error is reported and saved results are kept. The log records which
   path was used.
2. Each `BSS` block becomes a network record, including hidden SSIDs. Names broadcast
   as all zero bytes (`\x00\x00…`) are treated as hidden. The parser reads
   frequencies, dBm signal values, and RSN/WPA security fields. Network names cannot
   change the security classification.
3. Quality is an estimate: `clamp(2 × (dBm + 100), 0, 100)`. For example, −75 dBm becomes
   50%. It is not a throughput measurement. Missing measurements display as `—`.
4. Security labels include `Open`, `WPA`, `WPA2`, `WPA3`, `WPA2/WPA3`, and
   `Enhanced Open (OWE)`. Privacy without WPA/RSN is labeled `WEP/unknown`, because the
   scan alone is insufficient to confirm WEP. Enterprise modes can remain ambiguous:
   generic 802.1X is labeled `WPA2/3-Enterprise`; unrecognized authentication stays unknown.
   These labels describe advertised settings, not proof that a network is secure.
5. Results are shown and exported strongest signal first (unmeasured last). Analysis
   numbers follow the table. The saved JSON snapshot keeps scan order.
6. Configuration details are read from the same RSN/WPA/WPS sections: protected
   management frames (`PMF`: Required, Optional, or Disabled), WPS presence, and group
   and pairwise ciphers. See **Configuration warnings**.
7. Channel analysis counts BSS entries on the same center frequency. It keeps the
   2.4, 5, and 6 GHz bands separate. It does not measure airtime, channel-width overlap,
   interference, or the number of physical routers.
8. Successful scans replace the last saved JSON snapshot using an atomic file replacement.
   Failed scans preserve previous results. A successful scan finding zero networks saves
   an empty snapshot. If saving fails, the new results remain available in the session.

## Configuration warnings

Warnings are derived only from what the access point advertises:

| Warning | Trigger |
|---|---|
| No encryption | Open network (not OWE) |
| Possibly WEP | Privacy bit without WPA/RSN |
| Legacy WPA | WPA (v1) advertised, alone or alongside WPA2 |
| TKIP | TKIP listed as group or pairwise cipher |
| PMF not required | WPA3, OWE, or 192-bit Enterprise without `MFP-required` |
| PMF not supported | RSN network with neither `MFP-capable` nor `MFP-required` |
| WPS advertised | A WPS section is present |

WPA2/WPA3 transition networks are expected to have PMF optional and are not warned for
it. Results saved by version 1.1 lack these fields and receive no PMF/WPS/cipher warnings
until rescanned.

## Shared network names

Access points are grouped by network name. Names are compared the way a person sees them:
`iw` escapes such as `\x20` are decoded, and case, surrounding spaces, and invisible
(zero-width) characters are ignored. Hidden networks are not grouped.

| Situation | Result |
|---|---|
| Several access points, same name, same security | Information only: normal for dual-band routers, mesh systems, and repeaters |
| Same name, but one access point is Open and others are encrypted | Warning: devices may join the open one; a common evil-twin setup |
| Same name with different encrypted security (e.g. WPA2 and WPA3) | Warning: misconfiguration or imitation |
| Names that only look identical (`Cafe` vs `Cafe\x20` or `CAFE`) | Warning: one may imitate the other |

Name warnings are added to every access point in the group: in the table count, option 3,
CSV, and JSON. Option 3 also lists the other access points broadcasting the same name.
In a filtered view, names are still compared against the full scan. These are hints to
check the BSSIDs, not proof of an attack.

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

When run with sudo, AirRecon hands the files and folders it creates back to the user who
ran sudo (`SUDO_UID`/`SUDO_GID`), so saved results and reports stay readable without sudo.
Files left root-owned by version 1.1 are replaced on the next sudo scan, or fix them at once
with `sudo chown -R $USER: data logs reports`. Use a separate output directory for
unprivileged demo runs. Reports include the full scan and include PMF, WPS, cipher, and warning columns, and protect text cells beginning
with spreadsheet formula characters by prefixing an apostrophe. JSON retains the original
name as represented by `iw`; `iw` escape sequences are not decoded. The exception is a name
made only of `\x00` escapes, which is stored as an empty (hidden) name.

Generated data, logs, reports, Python caches, and virtual environments are ignored by Git.
No virtual environment is needed, since AirRecon uses only the Python standard library.

## Troubleshooting

- **`iw` not found:** install it with the command above.
- **Operation not permitted:** without sudo AirRecon uses the NetworkManager fallback. If
  that shows few networks (NetworkManager not running or not permitted), run with sudo.
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

Tests use synthetic scan output, an anonymised real scan, temporary directories, and
mocked `iw` calls. `tests/fixtures/real_scan.txt` is a 16-network `iw` 6.17 scan with
network names, MAC addresses, WPS device details, and the country code replaced; a test
checks that no identifying values remain. They cover parsing, configuration warnings,
sorting, shared-name analysis, failure recovery, storage, sudo file ownership, input
validation, filtering, CSV export, non-interactive mode, and a complete offline menu
session. They do not run wireless scans. Live scanning still depends on your adapter,
driver, privileges, and environment.
