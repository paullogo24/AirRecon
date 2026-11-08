#!/usr/bin/env python3
"""Inspect Linux WiFi scan results using iw or a saved iw scan transcript."""

import argparse
import contextlib
import csv
import json
import math
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parent
NET_DIR = Path('/sys/class/net')
SCAN_TIMEOUT = 25
TOOL_NAME = 'AirRecon'
TOOL_VERSION = '1.2'
MAC = r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'


def configure_storage(directory):
    """Resolve storage paths without creating files during import."""
    global DATA_DIR, LOGS_DIR, REPORTS_DIR, LOG_FILE, RESULTS_FILE, RAW_FILE
    directory = Path(directory).expanduser().resolve()
    DATA_DIR = directory / 'data'
    LOGS_DIR = directory / 'logs'
    REPORTS_DIR = directory / 'reports'
    LOG_FILE = LOGS_DIR / 'wifi_scan.log'
    RESULTS_FILE = DATA_DIR / 'wifi_scan_results.json'
    RAW_FILE = DATA_DIR / 'scan_output.txt'


configure_storage(BASE_DIR)


class ScanError(Exception):
    """A failed scan, distinct from a successful scan with no networks."""


def get_wireless_interfaces():
    if not NET_DIR.is_dir():
        return []
    return sorted(p.name for p in NET_DIR.iterdir()
                  if (p / 'wireless').is_dir() or (p / 'phy80211').exists())


def freq_to_channel(freq_mhz):
    if freq_mhz == 2484:
        return 14
    if freq_mhz == 5935:
        return 2
    if freq_mhz is None:
        return None
    for low, high, offset in ((2412, 2472, 2407), (4910, 4980, 4000),
                              (5005, 5895, 5000), (5955, 7115, 5950)):
        if low <= freq_mhz <= high and (freq_mhz - offset) % 5 == 0:
            return (freq_mhz - offset) // 5
    return None


def security_sections(cell):
    # iw prints an RSN/WPA/WPS header followed by indented '*' property lines.
    # Restrict matching to these sections so SSIDs cannot affect the result.
    sections = {}
    pattern = r'^[ \t]*(RSN|WPA|WPS):[^\n]*(?:\n[ \t]+\*[^\n]*)*'
    for match in re.finditer(pattern, cell, re.MULTILINE):
        sections.setdefault(match.group(1), []).append(match.group(0))
    return {name: '\n'.join(parts) for name, parts in sections.items()}


def cipher_list(text, field):
    """Unique cipher names from '* Group cipher:' style lines, ignoring '(default)' notes."""
    names = []
    for value in re.findall(r'\*[ \t]*' + field + r':[ \t]*([^\n]*)', text):
        for token in value.split():
            if not token.startswith('(') and token not in names:
                names.append(token)
    return ' '.join(names) or None


def security_details(cell):
    sections = security_sections(cell)
    rsn = sections.get('RSN')
    ciphers_from = '\n'.join(sections.get(name, '') for name in ('RSN', 'WPA'))
    pmf = None
    if rsn is not None:
        capabilities = ' '.join(re.findall(r'\*[ \t]*Capabilities:[ \t]*([^\n]*)', rsn))
        if 'MFP-required' in capabilities:
            pmf = 'Required'
        elif 'MFP-capable' in capabilities:
            pmf = 'Optional'
        else:
            pmf = 'Disabled'
    return {
        'PMF': pmf,
        'WPS': 'WPS' in sections,
        'Group Cipher': cipher_list(ciphers_from, 'Group cipher'),
        'Pairwise Ciphers': cipher_list(ciphers_from, 'Pairwise ciphers'),
    }


STRICT_PMF_LABELS = ('WPA3', 'Enhanced Open (OWE)', 'WPA3-Enterprise (192-bit)')


def security_warnings(net):
    """Configuration warnings derived from advertised settings only."""
    enc = net.get('Encryption') or ''
    warnings = []
    if enc == 'Open':
        warnings.append('No WiFi link encryption is advertised.')
    elif enc.startswith('WEP'):
        warnings.append('Privacy is advertised without WPA/RSN; possibly legacy WEP. Verify manually.')
    if 'WPA' in enc.split('/'):
        warnings.append('Legacy WPA is advertised. Review the router security configuration.')
    ciphers = f"{net.get('Group Cipher') or ''} {net.get('Pairwise Ciphers') or ''}".split()
    if 'TKIP' in ciphers:
        warnings.append('TKIP cipher is advertised; it is deprecated. Use CCMP (AES) only.')
    # Records saved before PMF parsing existed have no PMF key; do not guess for them.
    pmf = net.get('PMF')
    if pmf is not None and pmf != 'Required' and enc in STRICT_PMF_LABELS:
        warnings.append(f'{enc} requires protected management frames (PMF), '
                        'but this network does not advertise PMF as required.')
    elif pmf == 'Disabled':
        warnings.append('Protected management frames (PMF/802.11w) are not supported; '
                        'deauthentication frames are unprotected.')
    if net.get('WPS'):
        warnings.append('WPS is advertised. PIN-based WPS is open to brute-force attacks; '
                        'disable WPS if it is not needed.')
    return warnings


def detect_encryption(cell):
    sections = security_sections(cell)
    labels = []
    if 'WPA' in sections:
        labels.append('WPA')
    if 'RSN' in sections:
        rsn = sections['RSN']
        auth = ' '.join(re.findall(r'Authentication suites:[ \t]*([^\n]*)', rsn))
        if re.search(r'\bSAE\b', auth):
            labels.append('WPA2/WPA3' if re.search(r'\bPSK\b', auth) else 'WPA3')
        elif re.search(r'\bOWE\b', auth):
            labels.append('Enhanced Open (OWE)')
        elif 'SUITE-B-192' in auth.upper():
            labels.append('WPA3-Enterprise (192-bit)')
        elif '802.1X' in auth:
            labels.append('WPA2/3-Enterprise')
        elif re.search(r'\bPSK\b', auth):
            labels.append('WPA2')
        else:
            labels.append('RSN (unknown authentication)')
    if labels:
        return '/'.join(labels)
    capability = re.search(r'^[ \t]*capability:[ \t]*([^\n]*)', cell, re.MULTILINE)
    if capability:
        return 'WEP/unknown' if re.search(r'\bPrivacy\b', capability.group(1)) else 'Open'
    return 'Unknown'


def calculate_signal(signal_match):
    if signal_match is None:
        return None
    dbm = float(signal_match.group(1))
    return int(max(0, min(100, 2 * (dbm + 100))))


def normalize_ssid(raw):
    # Hidden networks often broadcast a zero-filled name, which iw prints as \x00 escapes.
    return '' if re.fullmatch(r'(?:\\x00)+', raw.strip()) else raw


def parse_network_info(cell):
    bssid = re.search(r'^BSS (' + MAC + r')(?=[(\s]|$)', cell, re.MULTILINE)
    if not bssid:
        return None
    # Only horizontal whitespace is allowed here; a hidden SSID has no value.
    ssid = re.search(r'^[ \t]*SSID:[ \t]?([^\r\n]*)', cell, re.MULTILINE)
    freq = re.search(r'^[ \t]*freq:[ \t]*(\d+)', cell, re.MULTILINE)
    signal = re.search(r'^[ \t]*signal:[ \t]*(-?\d+(?:\.\d+)?)[ \t]*dBm',
                       cell, re.MULTILINE)
    mhz = int(freq.group(1)) if freq else None
    channel = freq_to_channel(mhz)
    quality = calculate_signal(signal)
    return {
        'BSSID': bssid.group(1).lower(),
        'ESSID': normalize_ssid(ssid.group(1)) if ssid else '',
        'Frequency': f'{mhz / 1000:.3f} GHz' if mhz is not None else None,
        'Channel': str(channel) if channel is not None else None,
        'Encryption': detect_encryption(cell),
        'Signal (dBm)': float(signal.group(1)) if signal else None,
        'Quality(%)': quality,
        **security_details(cell),
    }


def parse_scan_output(output):
    blocks = re.split(r'(?=^BSS ' + MAC + r'(?=[(\s]|$))', output, flags=re.MULTILINE)
    networks = [network for block in blocks if (network := parse_network_info(block))]
    if output.strip() and not networks:
        raise ScanError('No recognizable BSS records in the scan output.')
    return networks


def sudo_owner():
    """The invoking user's (uid, gid) when running as root via sudo, else None."""
    if os.geteuid() != 0:
        return None
    try:
        return int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID'])
    except (KeyError, ValueError):
        return None


def give_to_user(path):
    """Under sudo, hand a created file back to the invoking user so it stays readable."""
    owner = sudo_owner()
    if owner:
        try:
            os.chown(path, *owner)
        except OSError:
            pass


def make_dirs(directory):
    """Create a directory and its parents; under sudo, newly created ones go to the user."""
    directory = Path(directory)
    missing = []
    for candidate in (directory, *directory.parents):
        if candidate.exists():
            break
        missing.append(candidate)
    directory.mkdir(parents=True, exist_ok=True)
    for created in missing:
        give_to_user(created)


def atomic_write(path, content):
    """Replace a complete file only after its new contents are written."""
    path = Path(path)
    make_dirs(path.parent)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', encoding='utf-8',
                                         dir=path.parent, delete=False) as handle:
            temporary = Path(handle.name)
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        give_to_user(temporary)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def run_iw(interface, command, timeout):
    try:
        return subprocess.run(['iw', 'dev', interface, *command],
                              capture_output=True, text=True, errors='replace',
                              timeout=timeout)
    except FileNotFoundError as exc:
        raise ScanError('Install iw: sudo dnf install iw (Fedora), '
                        'or sudo apt install iw (Debian/Ubuntu).') from exc
    except subprocess.TimeoutExpired as exc:
        raise ScanError(f'Scan timed out after {timeout} seconds. Try again.') from exc
    except OSError as exc:
        raise ScanError(f'Cannot run iw: {exc}') from exc


def scan_wifi(interface, timeout=SCAN_TIMEOUT):
    """Trigger a fresh scan; if iw refuses, fall back to the kernel's cached results.

    `iw scan` needs root and fails while another program is scanning, but
    `iw scan dump` returns what the system (e.g. NetworkManager) last found and
    usually works without sudo. An empty cache is not treated as a success,
    so a failed scan never replaces saved results with nothing.
    """
    print(f'[*] Scanning on {interface}...')
    result = run_iw(interface, ['scan'], timeout)
    networks = None
    if result.returncode:
        detail = result.stderr.strip() or f'iw exited with status {result.returncode}'
        cached = run_iw(interface, ['scan', 'dump'], timeout)
        if not cached.returncode:
            try:
                networks = parse_scan_output(cached.stdout)
            except ScanError:
                networks = None
        if not networks:
            raise ScanError(f'{detail}. Check permissions, WiFi/rfkill, and whether '
                            'another scan is running. Live scans usually need sudo.')
        result = cached
        print(f'[*] Fresh scan unavailable ({detail}); showing cached results from the '
              'last system scan. These may be incomplete; run with sudo for a full scan.')
        log_message(f'Fresh scan on {interface} failed ({detail}); used cached scan dump.')
    else:
        networks = parse_scan_output(result.stdout)
    try:
        atomic_write(RAW_FILE, result.stdout)
    except OSError as exc:
        print(f'[!] Could not save raw scan output: {exc}')
    return networks


def analyze_channels(networks):
    # Center frequency distinguishes identical channel numbers in different bands.
    counts = {}
    for net in networks:
        frequency = net.get('Frequency')
        if frequency:
            counts[frequency] = counts.get(frequency, 0) + 1
    return counts


def filter_networks(networks, security=None, ssid=None, min_quality=0):
    return [net for net in networks
            if (not security or net.get('Encryption', '').casefold() == security.casefold())
            and (not ssid or ssid.casefold() in (net.get('ESSID') or '').casefold())
            and (not min_quality or (net.get('Quality(%)') is not None
                                     and net['Quality(%)'] >= min_quality))]


def safe_text(value, fallback='—'):
    if value is None:
        return fallback
    # Do not interpret control characters received in names or saved files.
    return ''.join(char if char.isprintable() else repr(char)[1:-1] for char in str(value))


def save_to_csv(networks, filename='wifi_results.csv'):
    fields = ['ESSID', 'BSSID', 'Channel', 'Frequency', 'Signal (dBm)', 'Quality(%)', 'Encryption',
              'PMF', 'WPS', 'Group Cipher', 'Pairwise Ciphers', 'Warnings']
    path = Path(filename)
    make_dirs(path.parent)
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for net in networks:
            row = {}
            for field in fields:
                if field == 'Warnings':
                    value = '; '.join(security_warnings(net))
                elif field == 'WPS':
                    value = {True: 'Yes', False: 'No'}.get(net.get('WPS'), '')
                else:
                    value = net.get(field)
                if isinstance(value, str):
                    value = safe_text(value)
                    # Names are untrusted spreadsheet data, not formulas.
                    if value.lstrip().startswith(('=', '+', '-', '@')):
                        value = "'" + value
                row[field] = value
            writer.writerow(row)
    give_to_user(path)


def display_results(networks):
    if not networks:
        print('[!] No networks found.')
        return
    print(f'{"No.":<4} {"ESSID":<26} {"BSSID":<18} {"Ch":<4} {"Frequency":<11} {"dBm":<7} {"Quality%":<9} Security')
    print('-' * 110)
    for i, net in enumerate(networks, 1):
        name = safe_text(net.get('ESSID') or '(hidden)')
        if len(name) > 25:
            name = name[:24] + '…'
        values = [safe_text(net.get(key)) for key in
                  ('BSSID', 'Channel', 'Frequency', 'Signal (dBm)', 'Quality(%)', 'Encryption')]
        count = len(security_warnings(net))
        flag = f'  [{count} warning{"s" if count > 1 else ""}]' if count else ''
        print(f'{i:<4} {name:<26} {values[0]:<18} {values[1]:<4} {values[2]:<11} '
              f'{values[3]:<7} {values[4]:<9} {values[5]}{flag}')


def log_message(message):
    try:
        make_dirs(LOG_FILE.parent)
        with LOG_FILE.open('a', encoding='utf-8') as handle:
            handle.write(f'[{datetime.now().isoformat(timespec="seconds")}] {safe_text(message)}\n')
        give_to_user(LOG_FILE)
    except OSError as exc:
        print(f'[!] Could not write log: {exc}')


def save_results(networks):
    atomic_write(RESULTS_FILE, json.dumps(networks, indent=2, allow_nan=False) + '\n')


def validate_results(networks):
    if not isinstance(networks, list):
        raise ValueError('Expected a list of network records.')
    for net in networks:
        if not isinstance(net, dict) or not re.fullmatch(MAC, str(net.get('BSSID', ''))):
            raise ValueError('A network record has an invalid or missing BSSID.')
        for field in ('ESSID', 'Channel', 'Frequency', 'Encryption',
                      'PMF', 'Group Cipher', 'Pairwise Ciphers'):
            if net.get(field) is not None and not isinstance(net[field], str):
                raise ValueError(f'Invalid {field} in a network record.')
        if net.get('WPS') is not None and not isinstance(net['WPS'], bool):
            raise ValueError('Invalid WPS in a network record.')
        net['ESSID'] = net.get('ESSID') or ''
        net['Encryption'] = net.get('Encryption') or 'Unknown'
        net.setdefault('Quality(%)', net.get('Signal Level'))
        for field in ('Signal Level', 'Quality(%)', 'Signal (dBm)'):
            value = net.get(field)
            if value is not None and (type(value) not in (int, float)
                                      or (isinstance(value, float) and not math.isfinite(value))):
                raise ValueError(f'Invalid {field} in a network record.')
            if field != 'Signal (dBm)' and value is not None and not 0 <= value <= 100:
                raise ValueError(f'{field} must be between 0 and 100.')
        net.pop('Signal Level', None)  # pre-1.2 duplicate of Quality(%)
    return networks


def load_results():
    try:
        return validate_results(json.loads(RESULTS_FILE.read_text(encoding='utf-8')))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        print(f'[!] Cannot load saved results: {exc}')
        return []


def choose_interface():
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print('[!] No wireless interfaces found. A Linux WiFi adapter is required for live scans.')
        return None
    print('\nAvailable wireless interfaces:')
    for i, interface in enumerate(interfaces, 1):
        print(f'  {i}. {interface}')
    try:
        idx = int(input('Select interface number: ').strip()) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
    except ValueError:
        pass
    print('[!] Invalid selection.')
    return None


def current_results(state):
    return load_results() if state.get('networks') is None else state['networks']


def acquire_networks(source=None, interface=None):
    """Parse a saved iw transcript when source is given, otherwise scan the interface."""
    if source is not None:
        networks = parse_scan_output(Path(source).read_text(encoding='utf-8'))
        print(f'[*] Loaded offline scan: {source}')
        return networks
    return scan_wifi(interface)


def export_records(networks):
    return [dict(net, Warnings=security_warnings(net)) for net in networks]


def run_batch(args):
    """Non-interactive run: scan once, save, optionally export, then exit.

    Results (table or JSON) go to stdout; progress and errors go to stderr,
    so `--json` output can be piped straight into other tools.
    """
    with contextlib.redirect_stdout(sys.stderr):
        try:
            networks = acquire_networks(args.input, args.interface)
        except (ScanError, OSError, UnicodeError) as exc:
            print(f'[!] Scan failed: {exc}\nPrevious results were preserved.')
            log_message(f'Scan failed: {exc}')
            return 1
        try:
            save_results(networks)
        except OSError as exc:
            print(f'[!] Could not save results: {exc}')
        log_message(f'Scanned {args.input or args.interface}; found {len(networks)} networks.')
        print(f'[+] Found {len(networks)} networks.')
        if args.csv:
            try:
                save_to_csv(networks, args.csv)
            except OSError as exc:
                print(f'[!] Could not write CSV report: {exc}')
                return 1
            log_message(f'Saved CSV report to {args.csv}')
            print(f'[+] Report saved to {args.csv}')
    if args.json:
        print(json.dumps(export_records(networks), indent=2, allow_nan=False))
    else:
        display_results(networks)
    return 0


def handle_scan(state):
    source = state.get('input_file')
    interface = None
    if source is None:
        interface = choose_interface()
        if interface is None:
            return
    try:
        networks = acquire_networks(source, interface)
    except (ScanError, OSError, UnicodeError) as exc:
        print(f'[!] Scan failed: {exc}\nPrevious results were preserved.')
        log_message(f'Scan failed: {exc}')
        return
    state['networks'] = networks
    try:
        save_results(networks)
    except OSError as exc:
        print(f'[!] Could not save results: {exc}. Results remain available in this session.')
    log_message(f'Scanned {source or interface}; found {len(networks)} networks.')
    print(f'\n[+] Found {len(networks)} networks.\n')
    display_results(networks)


def handle_analyze(state):
    networks = current_results(state)
    if not networks:
        print('[!] No scan data available. Run a scan first (option 2).')
        return
    display_results(networks)
    choice = input('\nEnter network number to analyze (or blank to cancel): ').strip()
    if not choice:
        return
    try:
        idx = int(choice) - 1
        if not 0 <= idx < len(networks):
            raise ValueError
    except ValueError:
        print('[!] Invalid selection.')
        return
    net = networks[idx]
    print(f'\nNetwork: {safe_text(net.get("ESSID") or "(hidden)")}')
    for field in ('BSSID', 'Channel', 'Frequency', 'Encryption', 'Signal (dBm)', 'Quality(%)',
                  'PMF', 'Group Cipher', 'Pairwise Ciphers'):
        print(f'  {field}: {safe_text(net.get(field))}')
    if 'WPS' in net:
        print(f'  WPS: {"Advertised" if net["WPS"] else "Not advertised"}')
    for warning in security_warnings(net):
        print(f'  [!] {warning}')
    frequency = net.get('Frequency')
    count = analyze_channels(networks).get(frequency, 0)
    if count > 1:
        print(f'  Note: {count} BSS entries share {safe_text(frequency)}. '
              'This count does not measure traffic or interference.')
    print('  Security labels describe advertised settings, not a vulnerability assessment.')


def handle_report(state):
    networks = current_results(state)
    if not networks:
        print('[!] No scan data available to report on.')
        return
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    filename = REPORTS_DIR / f'wifi_report_{timestamp}.csv'
    save_to_csv(networks, filename)
    log_message(f'Saved CSV report to {filename}')
    print(f'[+] Report saved to {filename}')


def handle_filter(state):
    networks = current_results(state)
    if not networks:
        print('[!] No scan data available. Run a scan first (option 2).')
        return
    ssid = input('SSID contains (blank for any): ').strip()
    print('Security labels present: ' + ', '.join(sorted({n['Encryption'] for n in networks})))
    security = input('Exact security label (blank for any): ').strip()
    try:
        quality = int(input('Minimum quality 0–100 (blank for any): ').strip() or '0')
        if not 0 <= quality <= 100:
            raise ValueError
    except ValueError:
        print('[!] Quality must be a whole number from 0 to 100.')
        return
    display_results(filter_networks(networks, security, ssid, quality))
    print('Filter applies to this view; reports use the full scan.')


def show_menu(offline=False):
    print('\n' + '=' * 60)
    print(f'{TOOL_NAME} — Version {TOOL_VERSION}' + (' [OFFLINE]' if offline else ''))
    print('=' * 60)
    print('1. List Wireless Interfaces')
    print('2. ' + ('Load Offline Scan' if offline else 'Scan for WiFi Networks'))
    print('3. Analyze Selected Network')
    print('4. Generate Report (CSV)')
    print('5. View Saved Results')
    print('6. Filter Networks')
    print('7. Exit')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input', type=Path, help='Read saved iw scan output instead of scanning hardware.')
    parser.add_argument('--output-dir', type=Path, default=BASE_DIR,
                        help='Parent of data/, logs/, and reports/ (default: script directory).')
    batch = parser.add_argument_group(
        'non-interactive mode',
        'Any of these options runs one scan without the menu, then exits '
        '(status 0 on success, 1 if the scan or CSV export fails).')
    batch.add_argument('--interface', metavar='IFACE',
                       help='Scan this wireless adapter (e.g. wlo1) without the menu.')
    batch.add_argument('--json', action='store_true',
                       help='Print results, including warnings, as JSON on stdout.')
    batch.add_argument('--csv', type=Path, metavar='PATH', help='Write a CSV report to PATH.')
    args = parser.parse_args(argv)
    if args.input is not None and args.interface:
        parser.error('use either --input or --interface, not both')
    configure_storage(args.output_dir)
    if args.interface or args.json or args.csv:
        if args.input is None and not args.interface:
            parser.error('--json and --csv need --interface IFACE or --input FILE')
        return run_batch(args)
    state = {'networks': None, 'input_file': args.input}
    print(f'Results directory: {DATA_DIR.parent}')
    try:
        while True:
            show_menu(args.input is not None)
            choice = input('Select an option: ').strip()
            if choice in ('7', '0', 'q', 'Q'):
                print('Goodbye!')
                return 0
            try:
                if choice == '1':
                    interfaces = get_wireless_interfaces()
                    print('Wireless interfaces: ' + (', '.join(interfaces) or '(none found)'))
                elif choice == '2':
                    handle_scan(state)
                elif choice == '3':
                    handle_analyze(state)
                elif choice == '4':
                    handle_report(state)
                elif choice == '5':
                    display_results(load_results())
                elif choice == '6':
                    handle_filter(state)
                else:
                    print('[!] Invalid option.')
            except (OSError, UnicodeError) as exc:
                print(f'[!] File operation failed: {exc}')
            input('\nPress Enter to continue...')
    except (KeyboardInterrupt, EOFError):
        print('\nGoodbye!')
        return 0


if __name__ == '__main__':
    sys.exit(main())
