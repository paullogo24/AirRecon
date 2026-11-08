"""Inspect Linux WiFi scan results using iw or a saved iw scan transcript."""

import argparse
import contextlib
import json
import sys
from datetime import datetime
from pathlib import Path

from . import analysis, display, hosts, parser, scanner, storage, util


TOOL_NAME = 'AirRecon'
TOOL_VERSION = '1.3'


def choose_interface(interfaces=None):
    interfaces = scanner.get_wireless_interfaces() if interfaces is None else interfaces
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


def resolve_interface(state):
    """Reuse the selected adapter, use the only one present, or ask the user."""
    interfaces = scanner.get_wireless_interfaces()
    remembered = state.get('interface')
    if remembered in interfaces:
        return remembered
    if remembered:
        print(f'[!] Adapter {remembered} is no longer available.')
        state['interface'] = None
    if len(interfaces) == 1:
        print(f'[*] Using the only wireless adapter: {interfaces[0]}')
        chosen = interfaces[0]
    else:
        chosen = choose_interface(interfaces)
    if chosen:
        state['interface'] = chosen
    return chosen


def current_results(state):
    return storage.load_results() if state.get('networks') is None else state['networks']


def acquire_networks(source=None, interface=None):
    """Parse a saved iw transcript when source is given, otherwise scan the interface."""
    if source is not None:
        networks = parser.parse_scan_output(Path(source).read_text(encoding='utf-8'))
        print(f'[*] Loaded offline scan: {source}')
        return networks
    return scanner.scan_wifi(interface)


def run_batch(args):
    """Non-interactive run: scan once, save, optionally export, then exit.

    Results (table or JSON) go to stdout; progress and errors go to stderr,
    so `--json` output can be piped straight into other tools.
    """
    with contextlib.redirect_stdout(sys.stderr):
        try:
            networks = acquire_networks(args.input, args.interface)
        except (parser.ScanError, OSError, UnicodeError) as exc:
            print(f'[!] Scan failed: {exc}\nPrevious results were preserved.')
            storage.log_message(f'Scan failed: {exc}')
            return 1
        try:
            storage.save_results(networks)
        except OSError as exc:
            print(f'[!] Could not save results: {exc}')
        storage.log_message(f'Scanned {args.input or args.interface}; found {len(networks)} networks.')
        print(f'[+] Found {len(networks)} networks.')
        if args.csv:
            try:
                storage.save_to_csv(networks, args.csv)
            except OSError as exc:
                print(f'[!] Could not write CSV report: {exc}')
                return 1
            storage.log_message(f'Saved CSV report to {args.csv}')
            print(f'[+] Report saved to {args.csv}')
    if args.json:
        print(json.dumps(storage.export_records(networks), indent=2, allow_nan=False))
    else:
        display.display_results(networks)
        display.display_findings(networks)
    return 0


def finish_host_scan(found, info, csv_path=None):
    """Save and log a successful device discovery. Returns False if the CSV failed."""
    try:
        storage.save_hosts(found, info)
    except OSError as exc:
        print(f'[!] Could not save device results: {exc}')
    where = info.get('network') or 'saved nmap file'
    storage.log_message(f'Device discovery on {where}; {len(found)} devices up.')
    print(f'[+] Found {len(found)} devices.')
    if csv_path:
        try:
            storage.save_hosts_csv(found, csv_path)
        except OSError as exc:
            print(f'[!] Could not write CSV report: {exc}')
            return False
        storage.log_message(f'Saved device CSV report to {csv_path}')
        print(f'[+] Report saved to {csv_path}')
    return True


def acquire_hosts(hosts_input, interface):
    if hosts_input is not None:
        print(f'[*] Loaded offline nmap results: {hosts_input}')
        return hosts.load_hosts_file(hosts_input)
    return hosts.discover_hosts(interface)


def run_hosts_batch(args):
    """Non-interactive device discovery (--hosts): same stdout/stderr rules as WiFi scans."""
    with contextlib.redirect_stdout(sys.stderr):
        try:
            found, info = acquire_hosts(args.hosts_input, args.interface)
        except (parser.ScanError, OSError, UnicodeError) as exc:
            print(f'[!] Device discovery failed: {exc}\nPrevious results were preserved.')
            storage.log_message(f'Device discovery failed: {exc}')
            return 1
        if not finish_host_scan(found, info, args.csv):
            return 1
    if args.json:
        print(json.dumps({'network': str(info['network']) if info.get('network') else None,
                          'interface': info.get('interface'), 'gateway': info.get('gateway'),
                          'hosts': found}, indent=2))
    else:
        display.display_hosts(found, info)
    return 0


def handle_hosts(state):
    """Menu option 7: find devices on the network the adapter is connected to."""
    if state.get('hosts_input') is None:
        if state.get('input_file') is not None:
            print('[!] Offline mode: pass --hosts-input FILE (saved `nmap -sn -oX` output) '
                  'to load device results.')
            return
        interface = resolve_interface(state)
        if interface is None:
            return
        try:
            info = hosts.connected_network(interface)
            hosts.check_scannable(info['network'])
        except parser.ScanError as exc:
            print(f'[!] {exc}')
            return
        print(f"\nThis sends ping/ARP probes to every address in {info['network']} "
              f'({info["network"].num_addresses - 2} hosts). No ports are scanned.')
        print('Only scan networks you own or have permission to test.')
        if input('Continue? [y/N]: ').strip().lower() not in ('y', 'yes'):
            print('Cancelled.')
            return
    try:
        found, info = acquire_hosts(state.get('hosts_input'), state.get('interface'))
    except (parser.ScanError, OSError, UnicodeError) as exc:
        print(f'[!] Device discovery failed: {exc}\nPrevious results were preserved.')
        storage.log_message(f'Device discovery failed: {exc}')
        return
    finish_host_scan(found, info)
    print()
    display.display_hosts(found, info)


def handle_scan(state):
    source = state.get('input_file')
    interface = None
    if source is None:
        interface = resolve_interface(state)
        if interface is None:
            return
    try:
        networks = acquire_networks(source, interface)
    except (parser.ScanError, OSError, UnicodeError) as exc:
        print(f'[!] Scan failed: {exc}\nPrevious results were preserved.')
        storage.log_message(f'Scan failed: {exc}')
        return
    state['networks'] = networks
    try:
        storage.save_results(networks)
    except OSError as exc:
        print(f'[!] Could not save results: {exc}. Results remain available in this session.')
    storage.log_message(f'Scanned {source or interface}; found {len(networks)} networks.')
    print(f'\n[+] Found {len(networks)} networks.\n')
    display.display_results(networks)
    display.display_findings(networks)


def handle_analyze(state):
    networks = current_results(state)
    if not networks:
        print('[!] No scan data available. Run a scan first (option 2).')
        return
    networks = analysis.sort_networks(networks)  # numbering matches the displayed table
    display.display_results(networks)
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
    print(f'\nNetwork: {util.safe_text(net.get("ESSID") or "(hidden)")}')
    for field in ('BSSID', 'Channel', 'Frequency', 'Encryption', 'Signal (dBm)', 'Quality(%)',
                  'PMF', 'Group Cipher', 'Pairwise Ciphers'):
        print(f'  {field}: {util.safe_text(net.get(field))}')
    if 'WPS' in net:
        print(f'  WPS: {"Advertised" if net["WPS"] else "Not advertised"}')
    findings = analysis.name_findings(networks)
    for warning in analysis.network_warnings(net, findings):
        print(f'  [!] {warning}')
    others = [n for n in findings['groups'].get(net['BSSID'], []) if n is not net]
    if others:
        print(f'  Same name also broadcast by {len(others)} other access point'
              f'{"s" if len(others) > 1 else ""}:')
        for other in others:
            print(f'    {util.safe_text(other.get("BSSID"))}  {util.safe_text(other.get("Encryption"))}, '
                  f'{util.safe_text(analysis.band(other))}, {util.safe_text(other.get("Signal (dBm)"))} dBm')
    frequency = net.get('Frequency')
    count = analysis.analyze_channels(networks).get(frequency, 0)
    if count > 1:
        print(f'  Note: {count} BSS entries share {util.safe_text(frequency)}. '
              'This count does not measure traffic or interference.')
    print('  Security labels describe advertised settings, not a vulnerability assessment.')


def handle_report(state):
    networks = current_results(state)
    if not networks:
        print('[!] No scan data available to report on.')
        return
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
    filename = storage.REPORTS_DIR / f'wifi_report_{timestamp}.csv'
    storage.save_to_csv(networks, filename)
    storage.log_message(f'Saved CSV report to {filename}')
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
    display.display_results(analysis.filter_networks(networks, security, ssid, quality), context=networks)
    print('Filter applies to this view; reports use the full scan.')


def show_menu(offline=False, interface=None):
    print('\n' + '=' * 60)
    print(f'{TOOL_NAME} — Version {TOOL_VERSION}' + (' [OFFLINE]' if offline else ''))
    if interface:
        print(f'Adapter: {interface}')
    print('=' * 60)
    print('1. ' + ('List Wireless Interfaces' if offline else 'Select Wireless Interface'))
    print('2. ' + ('Load Offline Scan' if offline else 'Scan for WiFi Networks'))
    print('3. Analyze Selected Network')
    print('4. Generate Report (CSV)')
    print('5. View Saved Results')
    print('6. Filter Networks')
    print('7. Find Devices on My Network (nmap)')
    print('8. Exit')


def main(argv=None):
    arg_parser = argparse.ArgumentParser(description=__doc__)
    arg_parser.add_argument('--input', type=Path, help='Read saved iw scan output instead of scanning hardware.')
    arg_parser.add_argument('--output-dir', type=Path, default=storage.BASE_DIR,
                            help='Parent of data/, logs/, and reports/ (default: script directory).')
    batch = arg_parser.add_argument_group(
        'non-interactive mode',
        'Any of these options runs one scan without the menu, then exits '
        '(status 0 on success, 1 if the scan or CSV export fails).')
    batch.add_argument('--interface', metavar='IFACE',
                       help='Scan this wireless adapter (e.g. wlo1) without the menu.')
    batch.add_argument('--json', action='store_true',
                       help='Print results, including warnings, as JSON on stdout.')
    batch.add_argument('--csv', type=Path, metavar='PATH', help='Write a CSV report to PATH.')
    batch.add_argument('--hosts', action='store_true',
                       help='Find devices on the network IFACE is connected to (nmap -sn, no '
                            'port scan) instead of scanning WiFi. Needs --interface or '
                            '--hosts-input.')
    arg_parser.add_argument('--hosts-input', type=Path, metavar='FILE',
                            help='Read saved `nmap -sn -oX` output instead of running nmap.')
    args = arg_parser.parse_args(argv)
    if args.input is not None and args.interface:
        arg_parser.error('use either --input or --interface, not both')
    if args.hosts_input is not None and args.interface and args.hosts:
        arg_parser.error('use either --hosts-input or --interface with --hosts, not both')
    storage.configure_storage(args.output_dir)
    if args.hosts:
        if args.hosts_input is None and not args.interface:
            arg_parser.error('--hosts needs --interface IFACE or --hosts-input FILE')
        return run_hosts_batch(args)
    if args.interface or args.json or args.csv:
        if args.input is None and not args.interface:
            arg_parser.error('--json and --csv need --interface IFACE or --input FILE')
        return run_batch(args)
    state = {'networks': None, 'input_file': args.input, 'interface': None,
             'hosts_input': args.hosts_input}
    print(f'Results directory: {storage.DATA_DIR.parent}')
    try:
        while True:
            show_menu(args.input is not None, state['interface'])
            choice = input('Select an option: ').strip()
            if choice in ('8', '0', 'q', 'Q'):
                print('Goodbye!')
                return 0
            try:
                if choice == '1' and args.input is not None:
                    interfaces = scanner.get_wireless_interfaces()
                    print('Wireless interfaces: ' + (', '.join(interfaces) or '(none found)'))
                elif choice == '1':
                    chosen = choose_interface()
                    if chosen:
                        state['interface'] = chosen
                        print(f'[+] Option 2 will scan {chosen}.')
                elif choice == '2':
                    handle_scan(state)
                elif choice == '3':
                    handle_analyze(state)
                elif choice == '4':
                    handle_report(state)
                elif choice == '5':
                    saved = storage.load_results()
                    display.display_results(saved)
                    display.display_findings(saved)
                elif choice == '6':
                    handle_filter(state)
                elif choice == '7':
                    handle_hosts(state)
                else:
                    print('[!] Invalid option.')
            except (OSError, UnicodeError) as exc:
                print(f'[!] File operation failed: {exc}')
            input('\nPress Enter to continue...')
    except (KeyboardInterrupt, EOFError):
        print('\nGoodbye!')
        return 0
