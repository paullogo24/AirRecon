"""Console tables and summaries."""

from . import analysis, util


def display_findings(networks):
    entries = analysis.name_findings(networks)['entries']
    if not entries:
        return
    print('\nNetwork names shared by several access points:')
    for entry in sorted(entries, key=lambda e: e['level'] != 'warning'):
        for message in entry['messages']:
            print(f'  [!] {message}' if entry['level'] == 'warning' else f'  {message}')
        if entry['level'] == 'warning':
            for net in entry['members']:
                print(f'      {util.safe_text(net.get("BSSID"))}  {util.safe_text(net.get("Encryption")):<18} '
                      f'{util.safe_text(analysis.band(net)):<8} {util.safe_text(net.get("Signal (dBm)"))} dBm  '
                      f'{util.safe_text(net.get("ESSID"))}')


def display_results(networks, context=None):
    """Print a table, strongest first. `context` is the full scan when showing a
    filtered subset, so name comparisons still see every access point."""
    if not networks:
        print('[!] No networks found.')
        return
    findings = analysis.name_findings(context if context is not None else networks)
    print(f'{"No.":<4} {"ESSID":<26} {"BSSID":<18} {"Ch":<4} {"Frequency":<11} {"dBm":<7} {"Quality%":<9} Security')
    print('-' * 110)
    for i, net in enumerate(analysis.sort_networks(networks), 1):
        name = util.safe_text(net.get('ESSID') or '(hidden)')
        if len(name) > 25:
            name = name[:24] + '…'
        values = [util.safe_text(net.get(key)) for key in
                  ('BSSID', 'Channel', 'Frequency', 'Signal (dBm)', 'Quality(%)', 'Encryption')]
        count = len(analysis.network_warnings(net, findings))
        flag = f'  [{count} warning{"s" if count > 1 else ""}]' if count else ''
        print(f'{i:<4} {name:<26} {values[0]:<18} {values[1]:<4} {values[2]:<11} '
              f'{values[3]:<7} {values[4]:<9} {values[5]}{flag}')
