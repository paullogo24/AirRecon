import os
import sys
import re
import time
import csv
import json
import subprocess
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import *
from tabulate import tabulate

#PROJECT FOLDERS
DATA_DIR = 'data'
LOGS_DIR = 'logs'
REPORTS_DIR = 'reports'
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

#Config
DEFAULT_INTERFACE = None
SCAN_TIMEOUT = 10
LOG_FILE = os.path.join(LOGS_DIR, "wifi_scan.log")
RESULTS_FILE = os.path.join(DATA_DIR, "wifi_scan_results.json")

#Tool Info
TOOL_NAME = "AirRecon"
TOOL_VERSION = "1.0"
AUTHOR = "paul.l"
DESCRIPTION = "Discover nearby wifi networks analyze their security details"

#Main menu
def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 60)
    print(f"{TOOL_NAME} - Version {TOOL_VERSION}")
    print("=" *60)
    print("1. List Wireless Interfaces")
    print("2. Scan for WiFi Networks")
    print("3. Analyze Selected Network")
    print("4. Generate Report (CSV)")
    print("5. View Saved Results")
    print("6. Exit")
    print("=" * 60)

#Get wifi interfaces
def get_wireless_interfaces():
    interfaces = []
    for iface in os.listdir('/sys/class/net/'):
        if iface != 'lo':
            interfaces.append(iface)
    return interfaces

#Scan wifi networks (uses `iw`, since `iwlist`/wireless-tools is deprecated
#and unavailable on many modern distros, including Fedora)
def scan_wifi(interface, timeout=5):
    print(f'[*] Scanning on {interface}...')
    try:
        result = subprocess.run(
            ['iw', 'dev', interface, 'scan'],
            capture_output=True, text=True, timeout=timeout + 15
        )
    except FileNotFoundError:
        print('[!] `iw` command not found. Install it with your package manager '
              '(e.g. `sudo dnf install iw` / `sudo apt install iw`).')
        return []
    except subprocess.TimeoutExpired:
        print('[!] Scan timed out.')
        return []

    if result.returncode != 0:
        print(f'[!] Scan failed: {result.stderr.strip()}')
        return []

    with open('scan_output.txt', 'w') as f:
        f.write(result.stdout)

    networks = []
    # Each network's block starts with a line like "BSS aa:bb:cc:dd:ee:ff(on wlan0)"
    blocks = re.findall(
        r'BSS [0-9A-Fa-f:]{17}.*?(?=\nBSS [0-9A-Fa-f:]{17}|\Z)',
        result.stdout, re.DOTALL
    )
    for block in blocks:
        network = parse_network_info(block)
        if network and network.get('ESSID'):
            networks.append(network)
    return networks

#parse network info from an `iw scan` block
def parse_network_info(cell):
    network = {}

    bssid_match = re.search(r'BSS ([0-9A-Fa-f:]{17})', cell)
    ssid_match = re.search(r'SSID:\s*(.*)', cell)
    freq_match = re.search(r'freq:\s*(\d+)', cell)
    signal_match = re.search(r'signal:\s*(-?\d+(?:\.\d+)?)\s*dBm', cell)

    freq_mhz = int(freq_match.group(1)) if freq_match else None

    network['BSSID'] = bssid_match.group(1) if bssid_match else None
    network['ESSID'] = ssid_match.group(1).strip() if ssid_match else None
    network['Frequency'] = f'{freq_mhz / 1000:.3f} GHz' if freq_mhz else None
    network['Channel'] = str(freq_to_channel(freq_mhz)) if freq_mhz else None
    network['Encryption'] = detect_encryption(cell)
    network['Signal Level'] = calculate_signal(signal_match)

    return network

#convert a frequency in MHz to a WiFi channel number
def freq_to_channel(freq_mhz):
    if freq_mhz is None:
        return None
    if freq_mhz == 2484:
        return 14
    if 2412 <= freq_mhz <= 2472:
        return (freq_mhz - 2407) // 5
    if 5000 <= freq_mhz < 5900:
        return (freq_mhz - 5000) // 5
    if 5955 <= freq_mhz <= 7115:  # 6 GHz band (WiFi 6E / 7)
        return (freq_mhz - 5950) // 5
    return None

#detect encryption type from an `iw scan` block
def detect_encryption(cell):
    if 'SAE' in cell:                          return "WPA3"
    elif 'RSN:' in cell:                        return "WPA2"
    elif 'WPA:' in cell:                        return "WPA"
    elif 'capability' in cell and 'Privacy' in cell: return "WEP"
    else:                                       return "Open"

#calculate signal quality as a percentage from a dBm reading
def calculate_signal(signal_match):
    if not signal_match:
        return 0
    try:
        dbm = float(signal_match.group(1))
        return int(max(0, min(100, 2 * (dbm + 100))))
    except ValueError:
        return 0

#signal strength
def analyze_signal(networks):
    # 'Signal Level' is already a 0-100% quality score from calculate_signal().
    # Copy it into 'Quality(%)' so filter/save/display functions have a
    # consistent field to work with.
    for net in networks:
        net['Quality(%)'] = net.get('Signal Level', 0)

#channel analysis
def analyze_channels(networks):
    channel_count = {}
    for net in networks:
        channel = net.get('Channel')
        if channel:
            channel_count[channel] = channel_count.get(channel, 0) + 1
    return channel_count

#filter networks by encryption
def filter_networks(networks, security=None, ssid=None, min_quality=0):
    filtered = []
    for net in networks:
        if security and net.get('Encryption', '') != security:
            continue
        if ssid and ssid.lower() not in (net.get('ESSID') or '').lower():
            continue
        if int(net.get('Quality(%)', 0)) < min_quality:
            continue
        filtered.append(net)
    return filtered

#save results to csv
def save_to_csv(networks, filename= 'wifi_results.csv'):
    if not networks:
        print('[!]No data to save.')
        return
    fields = ['ESSID','BSSID','Channel','Frequency','Quality(%)','Encryption']
    with open(filename, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for net in networks:
            writer.writerow({field: net.get(field, '') for field in fields})

#display results table
def display_results(networks):
    if not networks:
        print('[!]No networks found.')
        return
    headers = ['No.','ESSID','BSSID','Ch','Frequency','Quality(%)','Enc']
    print('_' * 100)
    print(f'{headers[0]:<3} {headers[1]:<25} {headers[2]:<20} {headers[3]:<4} {headers[4]:<12} {headers[5]:<8} {headers[6]:<10}')
    print('_' * 100)
    for i, net in enumerate(networks, 1):
        print(f'{i:<3} {net.get("ESSID",""):<25} {net.get("BSSID",""):<20} {net.get("Channel",""):<4} {net.get("Frequency",""):<12} {net.get("Quality(%)",""):<8} {net.get("Encryption",""):<10}')

#log a message with a timestamp
def log_message(message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with open(LOG_FILE, 'a') as f:
        f.write(f'[{timestamp}] {message}\n')

#persist scan results to disk as JSON
def save_results(networks):
    with open(RESULTS_FILE, 'w') as f:
        json.dump(networks, f, indent=2)

#load previously saved scan results from disk
def load_results():
    if not os.path.exists(RESULTS_FILE):
        return []
    with open(RESULTS_FILE, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []

#prompt the user to pick a wireless interface
def choose_interface():
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print('[!] No wireless interfaces found.')
        return None
    print('\nAvailable interfaces:')
    for i, iface in enumerate(interfaces, 1):
        print(f'  {i}. {iface}')
    choice = input('Select interface number: ').strip()
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(interfaces):
            return interfaces[idx]
    except ValueError:
        pass
    print('[!] Invalid selection.')
    return None

#--- Menu option handlers ---

def handle_list_interfaces():
    interfaces = get_wireless_interfaces()
    if not interfaces:
        print('[!] No wireless interfaces found.')
    else:
        print('\nWireless interfaces:')
        for iface in interfaces:
            print(f'  - {iface}')
    input('\nPress Enter to continue...')

def handle_scan(state):
    interface = choose_interface()
    if not interface:
        input('\nPress Enter to continue...')
        return
    networks = scan_wifi(interface, SCAN_TIMEOUT)
    analyze_signal(networks)
    state['networks'] = networks
    save_results(networks)
    log_message(f'Scanned {interface}, found {len(networks)} networks.')
    print(f'\n[+] Found {len(networks)} networks.\n')
    display_results(networks)
    input('\nPress Enter to continue...')

def handle_analyze(state):
    networks = state.get('networks') or load_results()
    if not networks:
        print('[!] No scan data available. Run a scan first (option 2).')
        input('\nPress Enter to continue...')
        return
    display_results(networks)
    choice = input('\nEnter network number to analyze (or blank to cancel): ').strip()
    if not choice:
        return
    try:
        idx = int(choice) - 1
        net = networks[idx]
    except (ValueError, IndexError):
        print('[!] Invalid selection.')
        input('\nPress Enter to continue...')
        return

    print('\n' + '=' * 40)
    print(f'Network: {net.get("ESSID") or "(hidden)"}')
    print(f'  BSSID:       {net.get("BSSID")}')
    print(f'  Channel:     {net.get("Channel")}')
    print(f'  Frequency:   {net.get("Frequency")}')
    print(f'  Encryption:  {net.get("Encryption")}')
    print(f'  Quality:     {net.get("Quality(%)", net.get("Signal Level", 0))}%')

    enc = net.get('Encryption')
    if enc == 'Open':
        print('  [!] Warning: This network has no encryption.')
    elif enc == 'WEP':
        print('  [!] Warning: WEP is outdated and easily broken.')

    channel_counts = analyze_channels(networks)
    ch = net.get('Channel')
    if ch and channel_counts.get(ch, 0) > 1:
        print(f'  Note: {channel_counts[ch]} networks detected on channel {ch} (possible congestion).')
    print('=' * 40)
    input('\nPress Enter to continue...')

def handle_report(state):
    networks = state.get('networks') or load_results()
    if not networks:
        print('[!] No scan data available to report on.')
        input('\nPress Enter to continue...')
        return
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    filename = os.path.join(REPORTS_DIR, f'wifi_report_{timestamp}.csv')
    save_to_csv(networks, filename)
    log_message(f'Saved CSV report to {filename}')
    print(f'[+] Report saved to {filename}')
    input('\nPress Enter to continue...')

def handle_view_saved():
    networks = load_results()
    if not networks:
        print('[!] No saved results found.')
    else:
        display_results(networks)
    input('\nPress Enter to continue...')

#--- Main loop ---

def main():
    state = {'networks': []}
    while True:
        show_menu()
        choice = input('Select an option: ').strip()
        if choice == '1':
            handle_list_interfaces()
        elif choice == '2':
            handle_scan(state)
        elif choice == '3':
            handle_analyze(state)
        elif choice == '4':
            handle_report(state)
        elif choice == '5':
            handle_view_saved()
        elif choice == '6':
            print('Goodbye!')
            break
        else:
            print('[!] Invalid option.')
            input('\nPress Enter to continue...')

if __name__ == '__main__':
    main()S