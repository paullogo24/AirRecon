"""Output paths, file ownership under sudo, saved results, CSV export, and logging."""

import csv
import json
import math
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path

from . import analysis, parser, util


# Project folder (the one containing AirRecon.py); default parent of data/, logs/, reports/.
BASE_DIR = Path(__file__).resolve().parent.parent


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


def save_to_csv(networks, filename='wifi_results.csv'):
    fields = ['ESSID', 'BSSID', 'Channel', 'Frequency', 'Signal (dBm)', 'Quality(%)', 'Encryption',
              'PMF', 'WPS', 'Group Cipher', 'Pairwise Ciphers', 'Warnings']
    path = Path(filename)
    make_dirs(path.parent)
    findings = analysis.name_findings(networks)
    with path.open('w', newline='', encoding='utf-8') as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for net in analysis.sort_networks(networks):
            row = {}
            for field in fields:
                if field == 'Warnings':
                    value = '; '.join(analysis.network_warnings(net, findings))
                elif field == 'WPS':
                    value = {True: 'Yes', False: 'No'}.get(net.get('WPS'), '')
                else:
                    value = net.get(field)
                if isinstance(value, str):
                    value = util.safe_text(value)
                    # Names are untrusted spreadsheet data, not formulas.
                    if value.lstrip().startswith(('=', '+', '-', '@')):
                        value = "'" + value
                row[field] = value
            writer.writerow(row)
    give_to_user(path)


def log_message(message):
    try:
        make_dirs(LOG_FILE.parent)
        with LOG_FILE.open('a', encoding='utf-8') as handle:
            handle.write(f'[{datetime.now().isoformat(timespec="seconds")}] {util.safe_text(message)}\n')
        give_to_user(LOG_FILE)
    except OSError as exc:
        print(f'[!] Could not write log: {exc}')


def save_results(networks):
    atomic_write(RESULTS_FILE, json.dumps(networks, indent=2, allow_nan=False) + '\n')


def validate_results(networks):
    if not isinstance(networks, list):
        raise ValueError('Expected a list of network records.')
    for net in networks:
        if not isinstance(net, dict) or not re.fullmatch(parser.MAC, str(net.get('BSSID', ''))):
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


def export_records(networks):
    findings = analysis.name_findings(networks)
    return [dict(net, Warnings=analysis.network_warnings(net, findings)) for net in analysis.sort_networks(networks)]
