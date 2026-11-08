"""Turn `iw dev INTERFACE scan` output into network records."""

import re


MAC = r'(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}'


class ScanError(Exception):
    """A failed scan, distinct from a successful scan with no networks."""


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
