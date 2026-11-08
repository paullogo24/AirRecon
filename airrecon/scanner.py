"""Run `iw` (and `nmcli` for unprivileged rescans) to scan wireless adapters."""

import subprocess
from pathlib import Path

from . import parser, storage


NET_DIR = Path('/sys/class/net')
SCAN_TIMEOUT = 25


def get_wireless_interfaces():
    if not NET_DIR.is_dir():
        return []
    return sorted(p.name for p in NET_DIR.iterdir()
                  if (p / 'wireless').is_dir() or (p / 'phy80211').exists())


def run_iw(interface, command, timeout):
    try:
        return subprocess.run(['iw', 'dev', interface, *command],
                              capture_output=True, text=True, errors='replace',
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise parser.ScanError('Install iw: sudo dnf install iw (Fedora), '
                               'or sudo apt install iw (Debian/Ubuntu).') from exc
    except subprocess.TimeoutExpired as exc:
        raise parser.ScanError(f'Scan timed out after {timeout} seconds. Try again.') from exc
    except OSError as exc:
        raise parser.ScanError(f'Cannot run iw: {exc}') from exc


def request_rescan(interface, timeout=SCAN_TIMEOUT):
    """Ask NetworkManager to rescan and wait for it; usually allowed without sudo.

    Best effort: returns False if nmcli is missing, refuses, or times out.
    """
    try:
        result = subprocess.run(['nmcli', 'device', 'wifi', 'list', 'ifname', interface,
                                 '--rescan', 'yes'], capture_output=True, text=True,
                                errors='replace', timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0


def scan_wifi(interface, timeout=SCAN_TIMEOUT):
    """Trigger a fresh scan; if iw refuses, fall back to the kernel's cached results.

    `iw scan` needs root and fails while another program is scanning, but
    NetworkManager can usually rescan for a normal user, and `iw scan dump`
    then returns the refreshed kernel cache without sudo. An empty cache is not treated as a success,
    so a failed scan never replaces saved results with nothing.
    """
    print(f'[*] Scanning on {interface}...')
    result = run_iw(interface, ['scan'], timeout)
    networks = None
    if result.returncode:
        detail = result.stderr.strip() or f'iw exited with status {result.returncode}'
        print(f'[*] Fresh scan unavailable ({detail}); asking NetworkManager to rescan...')
        refreshed = request_rescan(interface, timeout)
        cached = run_iw(interface, ['scan', 'dump'], timeout)
        if not cached.returncode:
            try:
                networks = parser.parse_scan_output(cached.stdout)
            except parser.ScanError:
                networks = None
        if not networks:
            raise parser.ScanError(f'{detail}. Check permissions, WiFi/rfkill, and whether '
                                   'another scan is running. Live scans usually need sudo.')
        result = cached
        if refreshed:
            print('[*] Showing results from the NetworkManager rescan. '
                  'Run with sudo for a direct scan.')
        else:
            print('[*] NetworkManager rescan unavailable; showing cached results from the '
                  'last system scan. These may be incomplete; run with sudo for a full scan.')
        how = 'NetworkManager rescan' if refreshed else 'stale cache'
        storage.log_message(f'Fresh scan on {interface} failed ({detail}); used cached scan dump ({how}).')
    else:
        networks = parser.parse_scan_output(result.stdout)
    try:
        storage.atomic_write(storage.RAW_FILE, result.stdout)
    except OSError as exc:
        print(f'[!] Could not save raw scan output: {exc}')
    return networks
