"""Find devices on the network a wireless adapter is connected to, using nmap.

Only host discovery (`nmap -sn`): which addresses answer, plus MAC address and
vendor when run with sudo. No ports are scanned. The target is never typed by
the user; it is the adapter's own IPv4 subnet, and only private subnets of a
home-network size are accepted.
"""

import ipaddress
import json
import subprocess
import xml.etree.ElementTree as ET

from . import parser, storage


HOSTS_TIMEOUT = 180
# A /22 is 1,024 addresses. Home networks are usually /24 (256). Anything larger
# is typically a school, office or provider network that is not ours to scan.
MIN_PREFIXLEN = 22


def run_tool(command, timeout, missing):
    try:
        result = subprocess.run(command, capture_output=True, text=True, errors='replace',
                                timeout=timeout)
    except FileNotFoundError as exc:
        raise parser.ScanError(missing) from exc
    except subprocess.TimeoutExpired as exc:
        raise parser.ScanError(f'{command[0]} timed out after {timeout} seconds.') from exc
    except OSError as exc:
        raise parser.ScanError(f'Cannot run {command[0]}: {exc}') from exc
    if result.returncode:
        detail = result.stderr.strip() or f'{command[0]} exited with status {result.returncode}'
        raise parser.ScanError(detail)
    return result.stdout


def connected_network(interface):
    """The adapter's IPv4 address, subnet and default gateway, from `ip -j`."""
    missing = 'The ip command (iproute2) is required to find the connected network.'
    try:
        addresses = json.loads(run_tool(['ip', '-j', '-4', 'addr', 'show', 'dev', interface],
                                        10, missing))
        routes = json.loads(run_tool(['ip', '-j', '-4', 'route', 'show', 'default',
                                      'dev', interface], 10, missing) or '[]')
    except ValueError as exc:
        raise parser.ScanError(f'Unexpected output from ip: {exc}') from exc
    infos = [a for entry in addresses for a in entry.get('addr_info', [])
             if a.get('family') == 'inet' and a.get('scope') == 'global']
    if not infos:
        raise parser.ScanError(f'{interface} has no IPv4 address. Connect to a WiFi network first.')
    address = ipaddress.ip_interface(f"{infos[0]['local']}/{infos[0]['prefixlen']}")
    gateways = [r['gateway'] for r in routes if r.get('gateway')]
    return {'interface': interface, 'address': str(address.ip),
            'network': address.network, 'gateway': gateways[0] if gateways else None}


def check_scannable(network):
    """Refuse targets that are not a private, home-sized network."""
    if not network.is_private or network.is_loopback or network.is_link_local:
        raise parser.ScanError(f'{network} is not a private local network; AirRecon will not scan it.')
    if network.prefixlen < MIN_PREFIXLEN:
        raise parser.ScanError(
            f'{network} has {network.num_addresses:,} addresses, larger than a home network '
            f'(limit /{MIN_PREFIXLEN}). Networks this size usually belong to a school, workplace '
            'or provider; AirRecon will not scan them.')


def parse_nmap_xml(text):
    """Hosts reported as up in `nmap -oX` output, sorted by IP address."""
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise parser.ScanError(f'Not valid nmap XML output: {exc}') from exc
    if root.tag != 'nmaprun':
        raise parser.ScanError('Not nmap XML output (expected <nmaprun>).')
    hosts = []
    for host in root.iter('host'):
        status = host.find('status')
        if status is None or status.get('state') != 'up':
            continue
        record = {'IP': None, 'MAC': None, 'Vendor': None, 'Hostname': None}
        for address in host.findall('address'):
            if address.get('addrtype') == 'ipv4':
                record['IP'] = address.get('addr')
            elif address.get('addrtype') == 'mac':
                record['MAC'] = (address.get('addr') or '').lower() or None
                record['Vendor'] = address.get('vendor')
        names = [h.get('name') for h in host.iter('hostname') if h.get('name')]
        record['Hostname'] = names[0] if names else None
        if record['IP']:
            hosts.append(record)
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h['IP']))


def label_hosts(hosts, info):
    """Mark this computer and the router so they are easy to spot."""
    for host in hosts:
        if host['IP'] == info.get('address'):
            host['Role'] = 'this device'
        elif host['IP'] == info.get('gateway'):
            host['Role'] = 'router'
        else:
            host['Role'] = None
    return hosts


def discover_hosts(interface, timeout=HOSTS_TIMEOUT):
    """Run host discovery on the adapter's connected network. Returns (hosts, info)."""
    info = connected_network(interface)
    check_scannable(info['network'])
    print(f"[*] Looking for devices on {info['network']} via {interface} (no ports scanned)...")
    output = run_tool(['nmap', '-sn', '-oX', '-', str(info['network'])], timeout,
                      'Install nmap: sudo dnf install nmap (Fedora), '
                      'or sudo apt install nmap (Debian/Ubuntu).')
    hosts = label_hosts(parse_nmap_xml(output), info)
    try:
        storage.atomic_write(storage.HOSTS_RAW_FILE, output)
    except OSError as exc:
        print(f'[!] Could not save raw nmap output: {exc}')
    return hosts, info


def load_hosts_file(path):
    """Offline mode: hosts from a saved `nmap -sn -oX` file (no network access)."""
    with open(path, encoding='utf-8') as handle:
        hosts = parse_nmap_xml(handle.read())
    return label_hosts(hosts, {}), {'interface': None, 'address': None,
                                    'network': None, 'gateway': None}
