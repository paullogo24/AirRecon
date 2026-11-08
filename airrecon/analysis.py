"""Security warnings, sorting, shared-name checks, and filtering."""

import re
import unicodedata

from . import util


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


def analyze_channels(networks):
    # Center frequency distinguishes identical channel numbers in different bands.
    counts = {}
    for net in networks:
        frequency = net.get('Frequency')
        if frequency:
            counts[frequency] = counts.get(frequency, 0) + 1
    return counts


def sort_networks(networks):
    """Strongest signal first; networks without a measurement go last."""
    def key(net):
        dbm = net.get('Signal (dBm)')
        if dbm is None and net.get('Quality(%)') is not None:
            dbm = net['Quality(%)'] / 2 - 100  # records saved without dBm
        return (dbm is None, -(dbm or 0))
    return sorted(networks, key=key)


def decode_iw_name(name):
    r"""Undo iw's \xNN escapes (used for comparing names, never for display)."""
    raw, pos = bytearray(), 0
    for match in re.finditer(r'\\x([0-9A-Fa-f]{2})', name):
        raw += name[pos:match.start()].encode('utf-8') + bytes([int(match.group(1), 16)])
        pos = match.end()
    raw += name[pos:].encode('utf-8')
    return raw.decode('utf-8', errors='replace')


def name_key(name):
    """Names that look identical to a person map to the same key."""
    text = unicodedata.normalize('NFKC', decode_iw_name(name))
    text = ''.join(char for char in text if unicodedata.category(char) != 'Cf')  # zero-width
    return text.strip().casefold()


def band(net):
    try:
        ghz = float(str(net.get('Frequency')).split()[0])
    except ValueError:
        return None
    return '2.4 GHz' if ghz < 3 else '5 GHz' if ghz < 5.9 else '6 GHz'


def name_findings(networks):
    """Compare access points that broadcast the same (or a lookalike) name.

    Several access points sharing a name and security is normal: dual-band
    routers, mesh systems and repeaters. Different security under one name,
    or names that only look identical, are typical of misconfiguration or of
    an imitation ("evil twin"), so those become warnings on every member.
    Returns {'warnings': {bssid: [text]}, 'entries': [...], 'groups': {bssid: [nets]}}.
    """
    groups = {}
    for net in networks:
        if net.get('ESSID'):
            groups.setdefault(name_key(net['ESSID']), []).append(net)
    findings = {'warnings': {}, 'entries': [], 'groups': {}}
    for key in sorted(groups):
        members = sort_networks(groups[key])
        if len(members) < 2:
            continue
        for net in members:
            findings['groups'][net['BSSID']] = members
        names = sorted({net['ESSID'] for net in members})
        labels = sorted({net.get('Encryption') or 'Unknown' for net in members})
        shown = ', '.join(f"'{util.safe_text(name)}'" for name in names)
        problems = []
        if len(names) > 1:
            problems.append(f'Names {shown} look the same but differ in spacing, case or hidden '
                            'characters; one may be imitating the other.')
        if 'Open' in labels and len(labels) > 1:
            problems.append(f'{shown} has an Open access point alongside encrypted ones '
                            f'({", ".join(l for l in labels if l != "Open")}). Devices may join the '
                            'open one automatically; this is a common evil-twin setup.')
        elif len(labels) > 1:
            problems.append(f'{shown} is broadcast with different security ({", ".join(labels)}); '
                            'this can be a misconfigured access point or an imitation.')
        if problems:
            for net in members:
                findings['warnings'].setdefault(net['BSSID'], []).extend(problems)
            findings['entries'].append({'level': 'warning', 'messages': problems,
                                        'members': members})
        else:
            bands = sorted({b for b in map(band, members) if b}, key=lambda b: float(b.split()[0]))
            findings['entries'].append({'level': 'info', 'members': members, 'messages': [
                f"'{util.safe_text(names[0])}': {len(members)} access points, same security "
                f"({labels[0]})" + (f", {' + '.join(bands)}" if bands else '') +
                '. Normal for dual-band routers, mesh systems or repeaters.']})
    return findings


def network_warnings(net, findings):
    return security_warnings(net) + findings['warnings'].get(net.get('BSSID'), [])


def filter_networks(networks, security=None, ssid=None, min_quality=0):
    return [net for net in networks
            if (not security or net.get('Encryption', '').casefold() == security.casefold())
            and (not ssid or ssid.casefold() in (net.get('ESSID') or '').casefold())
            and (not min_quality or (net.get('Quality(%)') is not None
                                     and net['Quality(%)'] >= min_quality))]
