"""Regression and offline integration tests; no wireless hardware or sudo needed."""
import argparse
import contextlib
import csv
import io
import json
import os
import re
from collections import Counter
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import ipaddress

from airrecon import analysis, cli, display, hosts, parser, scanner, storage


FIXTURE = Path(__file__).parent / 'fixtures' / 'sample_scan.txt'
TWIN_FIXTURE = Path(__file__).parent / 'fixtures' / 'twin_scan.txt'
# A real iw 6.17 scan (16 networks), anonymised: names, MACs, WPS identity, country.
REAL_FIXTURE = Path(__file__).parent / 'fixtures' / 'real_scan.txt'
# Synthetic nmap 7.92 `-sn -oX` output: router, this laptop, a phone, one host down.
NMAP_FIXTURE = Path(__file__).parent / 'fixtures' / 'nmap_hosts.xml'


class AirReconTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(storage.configure_storage, storage.BASE_DIR)
        self.root = Path(self.directory.name)
        storage.configure_storage(self.root)
        self.raw = FIXTURE.read_text(encoding='utf-8')
        self.networks = parser.parse_scan_output(self.raw)
        self.console = io.StringIO()
        self.redirect = contextlib.redirect_stdout(self.console)
        self.redirect.__enter__()
        self.addCleanup(self.redirect.__exit__, None, None, None)

    def test_sample_includes_hidden_and_accurate_security(self):
        self.assertEqual(len(self.networks), 4)
        self.assertEqual([n['Encryption'] for n in self.networks],
                         ['WPA2', 'WPA2/WPA3', 'Open', 'WPA3'])
        self.assertEqual(self.networks[3]['ESSID'], '')
        self.assertEqual(self.networks[0]['Signal (dBm)'], -54)
        self.assertEqual(self.networks[0]['Quality(%)'], 92)

    def test_ssid_cannot_spoof_security_sections(self):
        for name in ('SAE', 'RSN:', 'WPA:', 'Privacy', 'Authentication suites: SAE'):
            with self.subTest(name=name):
                cell = f'BSS 02:00:00:00:00:01(on wlan0)\n\tSSID: {name}\n\tcapability: ESS (0x0001)\n'
                self.assertEqual(parser.parse_network_info(cell)['Encryption'], 'Open')

    def test_security_authentication_modes(self):
        for auth, expected in [('PSK', 'WPA2'), ('SAE', 'WPA3'),
                               ('PSK SAE', 'WPA2/WPA3'), ('FT/SAE', 'WPA3'),
                               ('OWE', 'Enhanced Open (OWE)'),
                               ('IEEE 802.1X', 'WPA2/3-Enterprise'),
                               ('IEEE 802.1X/Suite-B-192', 'WPA3-Enterprise (192-bit)'),
                               ('IEEE 802.1X/SUITE-B-192', 'WPA3-Enterprise (192-bit)'),
                               ('unrecognized', 'RSN (unknown authentication)')]:
            with self.subTest(auth=auth):
                cell = f'\tRSN: * Version: 1\n\t\t * Authentication suites: {auth}\n'
                self.assertEqual(parser.detect_encryption(cell), expected)
        self.assertEqual(parser.detect_encryption('\tWPA: * Version: 1\n'), 'WPA')
        self.assertEqual(parser.detect_encryption('\tcapability: ESS Privacy\n'), 'WEP/unknown')
        self.assertEqual(parser.detect_encryption(''), 'Unknown')
        mixed = '\tWPA: * Version: 1\n\tRSN: * Version: 1\n\t\t * Authentication suites: PSK\n'
        self.assertEqual(parser.detect_encryption(mixed), 'WPA/WPA2')

    def test_empty_and_unrecognized_scan_are_distinct(self):
        self.assertEqual(parser.parse_scan_output(' \n'), [])
        with self.assertRaises(parser.ScanError):
            parser.parse_scan_output('this is not iw scan output')

    def test_missing_optional_fields_are_displayable(self):
        network = parser.parse_network_info('BSS 02:00:00:00:00:01(on wlan0)\n')
        self.assertIsNone(network['Channel'])
        self.assertIsNone(network['Quality(%)'])
        display.display_results([network])
        self.assertIn('(hidden)', self.console.getvalue())

    def test_frequency_conversion_and_invalid_values(self):
        for frequency, expected in [(2412, 1), (2484, 14), (5180, 36), (5955, 1),
                                     (5935, 2), (7115, 233), (4910, 182),
                                     (2413, None), (8000, None), (None, None)]:
            with self.subTest(frequency=frequency):
                self.assertEqual(parser.freq_to_channel(frequency), expected)

    def test_signal_clamps_and_missing_signal_is_unknown(self):
        for dbm, expected in [(-120, 0), (-100, 0), (-75, 50), (-50, 100), (-20, 100)]:
            cell = f'BSS 02:00:00:00:00:01(on wlan0)\n\tsignal: {dbm} dBm\n'
            self.assertEqual(parser.parse_network_info(cell)['Quality(%)'], expected)
        self.assertIsNone(parser.calculate_signal(None))

    def test_channel_counts_do_not_merge_frequency_bands(self):
        self.assertEqual(analysis.analyze_channels(self.networks),
                         {'2.412 GHz': 2, '5.180 GHz': 1, '5.955 GHz': 1})

    def test_only_wireless_interfaces_are_listed(self):
        for name in ('lo', 'eth0', 'wlan0', 'wlan1'):
            (self.root / name).mkdir()
        (self.root / 'wlan0' / 'wireless').mkdir()
        (self.root / 'wlan1' / 'phy80211').mkdir()
        with patch.object(scanner, 'NET_DIR', self.root):
            self.assertEqual(scanner.get_wireless_interfaces(), ['wlan0', 'wlan1'])
        with patch.object(scanner, 'NET_DIR', self.root / 'absent'):
            self.assertEqual(scanner.get_wireless_interfaces(), [])

    def test_invalid_interface_selection(self):
        for answer in ('0', '-1', '3', 'abc'):
            with self.subTest(answer=answer), patch.object(scanner, 'get_wireless_interfaces', return_value=['wlan0']), patch('builtins.input', return_value=answer):
                self.assertIsNone(cli.choose_interface())

    def test_scan_success_uses_argument_list_and_saves_raw_output(self):
        result = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(subprocess, 'run', return_value=result) as run:
            self.assertEqual(scanner.scan_wifi('wlan0'), self.networks)
        self.assertEqual(run.call_args.args[0], ['iw', 'dev', 'wlan0', 'scan'])
        self.assertEqual(run.call_args.kwargs['timeout'], scanner.SCAN_TIMEOUT)
        self.assertEqual(storage.RAW_FILE.read_text(), self.raw)

    def test_scan_errors_are_not_empty_successes(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired('iw', 25), PermissionError()):
            with self.subTest(error=type(error)), patch.object(subprocess, 'run', side_effect=error):
                with self.assertRaises(parser.ScanError):
                    scanner.scan_wifi('wlan0')
        with patch.object(subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'Operation not permitted')):
            with self.assertRaisesRegex(parser.ScanError, 'Operation not permitted'):
                scanner.scan_wifi('wlan0')

    def test_raw_output_write_failure_does_not_discard_scan(self):
        result = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(subprocess, 'run', return_value=result), patch.object(storage, 'atomic_write', side_effect=PermissionError('read only')):
            self.assertEqual(scanner.scan_wifi('wlan0'), self.networks)
        self.assertIn('Could not save raw scan output', self.console.getvalue())

    def test_failed_scan_preserves_memory_and_saved_results(self):
        storage.save_results(self.networks)
        previous_bytes = storage.RESULTS_FILE.read_bytes()
        state = {'networks': self.networks}
        with patch.object(cli, 'resolve_interface', return_value='wlan0'), patch.object(scanner, 'scan_wifi', side_effect=parser.ScanError('failed')):
            cli.handle_scan(state)
        self.assertIs(state['networks'], self.networks)
        self.assertEqual(storage.RESULTS_FILE.read_bytes(), previous_bytes)
        self.assertIn('Previous results were preserved', self.console.getvalue())
        self.assertNotIn('Found 0 networks', self.console.getvalue())

    def test_successful_empty_scan_replaces_previous_results(self):
        storage.save_results(self.networks)
        state = {'networks': self.networks}
        with patch.object(cli, 'resolve_interface', return_value='wlan0'), patch.object(scanner, 'scan_wifi', return_value=[]):
            cli.handle_scan(state)
        self.assertEqual(state['networks'], [])
        self.assertEqual(storage.load_results(), [])
        with patch.object(storage, 'load_results', side_effect=AssertionError('must not load stale results')):
            self.assertEqual(cli.current_results(state), [])

    def test_offline_read_error_preserves_results(self):
        state = {'networks': self.networks, 'input_file': self.root / 'missing'}
        cli.handle_scan(state)
        self.assertIs(state['networks'], self.networks)
        self.assertIn('Scan failed', self.console.getvalue())

    def test_write_failure_keeps_session_results(self):
        state = {'networks': None, 'input_file': FIXTURE}
        with patch.object(storage, 'save_results', side_effect=PermissionError('read only')):
            cli.handle_scan(state)
        self.assertEqual(state['networks'], self.networks)
        self.assertIn('remain available in this session', self.console.getvalue())

    def test_failed_atomic_replace_preserves_original_file(self):
        storage.save_results(self.networks)
        original = storage.RESULTS_FILE.read_bytes()
        with patch.object(os, 'replace', side_effect=OSError('write failure')):
            with self.assertRaises(OSError):
                storage.save_results([])
        self.assertEqual(storage.RESULTS_FILE.read_bytes(), original)
        self.assertEqual(list(storage.DATA_DIR.iterdir()), [storage.RESULTS_FILE])

    def test_saved_results_round_trip_and_legacy_records(self):
        storage.save_results(self.networks)
        self.assertEqual(storage.load_results(), self.networks)
        old = {'BSSID': '02:00:00:00:00:01', 'ESSID': None, 'Signal Level': 75}
        storage.save_results([old])
        loaded = storage.load_results()[0]
        self.assertEqual(loaded['Quality(%)'], 75)
        self.assertEqual(loaded['ESSID'], '')
        self.assertEqual(loaded['Encryption'], 'Unknown')
        self.assertNotIn('Signal Level', loaded)
        display.display_results([loaded])

    def test_invalid_saved_data_is_reported_without_crashing(self):
        for data in ('{', '{}', '[null]', '[{}]', '[{"BSSID":"02:00:00:00:00:01","Quality(%)":"high"}]',
                     '[{"BSSID":"02:00:00:00:00:01","Quality(%)":NaN}]',
                     '[{"BSSID":"02:00:00:00:00:01","Quality(%)":101}]'):
            with self.subTest(data=data):
                storage.atomic_write(storage.RESULTS_FILE, data)
                self.assertEqual(storage.load_results(), [])
        self.assertIn('Cannot load saved results', self.console.getvalue())

    def test_network_selection_rejects_zero_negative_and_out_of_range(self):
        for choice in ('0', '-1', '5', 'abc'):
            self.console.truncate(0)
            self.console.seek(0)
            with self.subTest(choice=choice), patch('builtins.input', return_value=choice):
                cli.handle_analyze({'networks': self.networks})
            self.assertIn('Invalid selection', self.console.getvalue())
            self.assertNotIn('\nNetwork:', self.console.getvalue())

    def test_filtering_combines_conditions_and_handles_unknown_signal(self):
        self.assertEqual(analysis.filter_networks(self.networks, 'wpa2', 'HOME', 90), [self.networks[0]])
        self.assertEqual(analysis.filter_networks(self.networks, min_quality=99), [])
        hidden = dict(self.networks[3], **{'Quality(%)': None})
        self.assertEqual(analysis.filter_networks([hidden]), [hidden])
        self.assertEqual(analysis.filter_networks([hidden], min_quality=1), [])

    def test_csv_keeps_numeric_signal_and_quotes_untrusted_names(self):
        network = dict(self.networks[0], ESSID='=1+1')
        filename = self.root / 'report.csv'
        storage.save_to_csv([network], filename)
        with filename.open(newline='') as handle:
            row = next(csv.DictReader(handle))
        self.assertEqual(row['ESSID'], "'=1+1")
        self.assertEqual(row['Signal (dBm)'], '-54.0')
        self.assertEqual(row['BSSID'], network['BSSID'])

    def test_terminal_control_characters_are_escaped(self):
        network = dict(self.networks[0], ESSID='bad\x1b[2Jname')
        display.display_results([network])
        self.assertNotIn('\x1b', self.console.getvalue())
        self.assertIn('\\x1b', self.console.getvalue())

    def test_log_write_error_does_not_crash(self):
        with patch.object(Path, 'mkdir', side_effect=PermissionError('read only')):
            storage.log_message('test')
        self.assertIn('Could not write log', self.console.getvalue())

    def test_full_offline_menu_from_another_directory(self):
        # Scan, analyze, export, reload, filter, then exit in a separate process.
        commands = '2\n\n3\n1\n\n4\n\n5\n\n6\nExample\nWPA2\n80\n\n8\n'
        result = subprocess.run([sys.executable, str(storage.BASE_DIR / 'AirRecon.py'),
                                 '--input', str(FIXTURE.resolve()), '--output-dir', str(self.root)],
                                input=commands, capture_output=True, text=True,
                                cwd=self.root, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertIn('Found 4 networks', result.stdout)
        self.assertIn('Network: Example Home', result.stdout)
        self.assertIn('Report saved to', result.stdout)
        self.assertIn('Goodbye!', result.stdout)
        self.assertEqual(len(json.loads(storage.RESULTS_FILE.read_text())), 4)
        reports = list(storage.REPORTS_DIR.glob('*.csv'))
        self.assertEqual(len(reports), 1)
        with reports[0].open(newline='') as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 4)

    def test_eof_exits_without_traceback(self):
        result = subprocess.run([sys.executable, str(storage.BASE_DIR / 'AirRecon.py'),
                                 '--output-dir', str(self.root)], input='', capture_output=True,
                                text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stderr, '')
        self.assertIn('Goodbye!', result.stdout)

    def test_zero_filled_ssid_is_hidden(self):
        for raw, expected in [('\\x00', ''), ('\\x00\\x00\\x00\\x00', ''),
                              ('a\\x00', 'a\\x00'), ('\\x01', '\\x01')]:
            with self.subTest(raw=raw):
                cell = f'BSS 02:00:00:00:00:01(on wlan0)\n\tSSID: {raw}\n'
                self.assertEqual(parser.parse_network_info(cell)['ESSID'], expected)
        display.display_results([parser.parse_network_info(
            'BSS 02:00:00:00:00:01(on wlan0)\n\tSSID: \\x00\\x00\n')])
        self.assertIn('(hidden)', self.console.getvalue())

    def test_new_records_have_no_duplicate_signal_level(self):
        self.assertNotIn('Signal Level', self.networks[0])

    def test_menu_exit_aliases(self):
        for exit_choice in ('8', '0', 'q'):
            with self.subTest(choice=exit_choice), patch('builtins.input', side_effect=[exit_choice]):
                self.assertEqual(cli.main(['--output-dir', str(self.root)]), 0)

    # --- Cached scan fallback -----------------------------------------------------

    def test_failed_fresh_scan_falls_back_to_cached_dump(self):
        refused = subprocess.CompletedProcess([], 255, '', 'command failed: Operation not permitted (-1)')
        cached = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(subprocess, 'run', side_effect=[refused, cached]) as run, \
             patch.object(scanner, 'request_rescan', return_value=False) as rescan:
            self.assertEqual(scanner.scan_wifi('wlan0'), self.networks)
        rescan.assert_called_once_with('wlan0', scanner.SCAN_TIMEOUT)
        self.assertEqual([c.args[0] for c in run.call_args_list],
                         [['iw', 'dev', 'wlan0', 'scan'], ['iw', 'dev', 'wlan0', 'scan', 'dump']])
        self.assertIn('cached results', self.console.getvalue())
        self.assertEqual(storage.RAW_FILE.read_text(), self.raw)
        self.assertIn('used cached scan dump (stale cache)', storage.LOG_FILE.read_text())

    def test_empty_or_failed_cache_reports_original_error(self):
        refused = subprocess.CompletedProcess([], 240, '', 'command failed: Device or resource busy (-16)')
        for dump in (subprocess.CompletedProcess([], 0, '', ''),
                     subprocess.CompletedProcess([], 0, 'garbage', ''),
                     subprocess.CompletedProcess([], 1, '', 'nope')):
            with self.subTest(dump=dump.stdout or dump.stderr), \
                 patch.object(subprocess, 'run', side_effect=[refused, dump]), \
                 patch.object(scanner, 'request_rescan', return_value=True):
                with self.assertRaisesRegex(parser.ScanError, 'resource busy'):
                    scanner.scan_wifi('wlan0')
        self.assertFalse(storage.RAW_FILE.exists())

    def test_networkmanager_rescan_is_reported(self):
        refused = subprocess.CompletedProcess([], 255, '', 'Operation not permitted (-1)')
        cached = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(subprocess, 'run', side_effect=[refused, cached]), \
             patch.object(scanner, 'request_rescan', return_value=True):
            self.assertEqual(scanner.scan_wifi('wlan0'), self.networks)
        self.assertIn('results from the NetworkManager rescan', self.console.getvalue())
        self.assertIn('(NetworkManager rescan)', storage.LOG_FILE.read_text())

    def test_request_rescan_is_best_effort(self):
        ok = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(subprocess, 'run', return_value=ok) as run:
            self.assertTrue(scanner.request_rescan('wlan0'))
        self.assertEqual(run.call_args.args[0], ['nmcli', 'device', 'wifi', 'list',
                                                 'ifname', 'wlan0', '--rescan', 'yes'])
        for outcome in (FileNotFoundError(), subprocess.TimeoutExpired('nmcli', 25),
                        subprocess.CompletedProcess([], 10, '', 'not authorized')):
            kwargs = ({'side_effect': outcome} if isinstance(outcome, BaseException)
                      else {'return_value': outcome})
            with self.subTest(outcome=type(outcome)), patch.object(subprocess, 'run', **kwargs):
                self.assertFalse(scanner.request_rescan('wlan0'))

    # --- Adapter selection --------------------------------------------------------

    def test_single_adapter_is_used_automatically(self):
        state = {'interface': None}
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlo1']), \
             patch('builtins.input', side_effect=AssertionError('must not prompt')):
            self.assertEqual(cli.resolve_interface(state), 'wlo1')
        self.assertEqual(state['interface'], 'wlo1')

    def test_selected_adapter_is_remembered(self):
        state = {'interface': None}
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlan0', 'wlan1']):
            with patch('builtins.input', return_value='2'):
                self.assertEqual(cli.resolve_interface(state), 'wlan1')
            with patch('builtins.input', side_effect=AssertionError('must not prompt again')):
                self.assertEqual(cli.resolve_interface(state), 'wlan1')

    def test_unplugged_adapter_prompts_again(self):
        state = {'interface': 'wlan1'}
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlan0', 'wlan2']), \
             patch('builtins.input', return_value='2'):
            self.assertEqual(cli.resolve_interface(state), 'wlan2')
        self.assertIn('wlan1 is no longer available', self.console.getvalue())

    def test_menu_option_1_selects_adapter_for_scanning(self):
        answers = iter(['1', '2', '', '2', '', '8'])
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlan0', 'wlan1']), \
             patch.object(scanner, 'scan_wifi', return_value=self.networks) as scan, \
             patch('builtins.input', side_effect=lambda prompt='': next(answers)):
            self.assertEqual(cli.main(['--output-dir', str(self.root)]), 0)
        scan.assert_called_once_with('wlan1')
        self.assertIn('Adapter: wlan1', self.console.getvalue())

    def test_successful_fresh_scan_does_not_dump(self):
        result = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(subprocess, 'run', return_value=result) as run:
            self.assertEqual(scanner.scan_wifi('wlan0'), [])
        self.assertEqual(run.call_count, 1)

    # --- Security configuration details -------------------------------------------

    def test_sample_security_details(self):
        home, modern, guest, hidden = self.networks
        self.assertEqual((home['PMF'], home['WPS']), ('Disabled', True))
        self.assertEqual((home['Group Cipher'], home['Pairwise Ciphers']), ('CCMP', 'CCMP'))
        self.assertEqual(modern['PMF'], 'Optional')
        self.assertEqual((guest['PMF'], guest['WPS'], guest['Group Cipher']), (None, False, None))
        self.assertEqual(hidden['PMF'], 'Required')
        self.assertEqual(analysis.security_warnings(hidden), [])

    def test_ssid_cannot_spoof_wps_or_pmf(self):
        cell = ('BSS 02:00:00:00:00:01(on wlan0)\n\tSSID: WPS: MFP-required\n'
                '\tcapability: ESS (0x0001)\n')
        network = parser.parse_network_info(cell)
        self.assertFalse(network['WPS'])
        self.assertIsNone(network['PMF'])

    def test_tkip_and_wpa_ciphers_are_flagged(self):
        cell = ('BSS 02:00:00:00:00:01(on wlan0)\n\tcapability: ESS Privacy (0x0011)\n'
                '\tWPA:\t * Version: 1\n\t\t * Group cipher: TKIP\n'
                '\t\t * Pairwise ciphers: TKIP (default)\n\t\t * Authentication suites: PSK\n'
                '\tRSN:\t * Version: 1\n\t\t * Group cipher: TKIP\n'
                '\t\t * Pairwise ciphers: CCMP TKIP\n\t\t * Authentication suites: PSK\n')
        network = parser.parse_network_info(cell)
        self.assertEqual(network['Encryption'], 'WPA/WPA2')
        self.assertEqual(network['Group Cipher'], 'TKIP')
        self.assertEqual(network['Pairwise Ciphers'], 'CCMP TKIP')
        text = ' '.join(analysis.security_warnings(network))
        self.assertIn('Legacy WPA', text)
        self.assertIn('TKIP', text)
        self.assertIn('not supported', text)

    def test_wpa3_without_required_pmf_is_flagged(self):
        for label in ('WPA3', 'Enhanced Open (OWE)'):
            for pmf in ('Optional', 'Disabled'):
                with self.subTest(label=label, pmf=pmf):
                    warnings = analysis.security_warnings({'Encryption': label, 'PMF': pmf})
                    self.assertEqual(len(warnings), 1)
                    self.assertIn('requires protected management frames', warnings[0])
        self.assertEqual(analysis.security_warnings({'Encryption': 'WPA2/WPA3', 'PMF': 'Optional'}), [])

    def test_legacy_records_without_pmf_get_no_pmf_guess(self):
        self.assertEqual(analysis.security_warnings({'Encryption': 'WPA3'}), [])
        old = {'BSSID': '02:00:00:00:00:01', 'Encryption': 'WPA3', 'Signal Level': 75}
        storage.save_results([old])
        self.assertEqual(analysis.security_warnings(storage.load_results()[0]), [])

    def test_invalid_security_fields_in_saved_data_are_rejected(self):
        for data in ('[{"BSSID":"02:00:00:00:00:01","WPS":"yes"}]',
                     '[{"BSSID":"02:00:00:00:00:01","PMF":1}]'):
            with self.subTest(data=data):
                storage.atomic_write(storage.RESULTS_FILE, data)
                self.assertEqual(storage.load_results(), [])

    def test_analyze_and_csv_show_warnings(self):
        with patch('builtins.input', return_value='1'):
            cli.handle_analyze({'networks': self.networks})
        output = self.console.getvalue()
        self.assertIn('WPS: Advertised', output)
        self.assertIn('[!] WPS is advertised', output)
        filename = self.root / 'report.csv'
        storage.save_to_csv(self.networks, filename)
        with filename.open(newline='') as handle:
            rows = list(csv.DictReader(handle))
        rows = {row['BSSID']: row for row in rows}
        home, hidden = rows['02:00:00:00:00:01'], rows['02:00:00:00:00:04']
        self.assertEqual(home['WPS'], 'Yes')
        self.assertEqual(home['PMF'], 'Disabled')
        self.assertIn('WPS is advertised', home['Warnings'])
        self.assertEqual(hidden['Warnings'], '')

    # --- Ownership of files created under sudo -----------------------------------

    def test_sudo_runs_return_created_files_to_invoking_user(self):
        root_owned = self.root / 'fresh'
        storage.configure_storage(root_owned)
        env = {'SUDO_UID': '1000', 'SUDO_GID': '1001'}
        with patch.object(os, 'geteuid', return_value=0), \
             patch.dict(os.environ, env), patch.object(os, 'chown') as chown:
            storage.save_results(self.networks)
            storage.log_message('test')
            storage.save_to_csv(self.networks, storage.REPORTS_DIR / 'r.csv')
        chowned = {Path(call.args[0]) for call in chown.call_args_list}
        self.assertTrue({root_owned, storage.DATA_DIR, storage.LOGS_DIR, storage.REPORTS_DIR,
                         storage.LOG_FILE, storage.REPORTS_DIR / 'r.csv'} <= chowned)
        self.assertTrue(all(call.args[1:] == (1000, 1001) for call in chown.call_args_list))
        # The results file is chowned as its temporary name, before the atomic rename.
        self.assertTrue(any(p.parent == storage.DATA_DIR and p != storage.RESULTS_FILE for p in chowned))
        self.assertNotIn(self.root, chowned)  # pre-existing directories are left alone

    def test_no_chown_without_sudo(self):
        for euid, env in ((1000, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}), (0, {})):
            with self.subTest(euid=euid), patch.object(os, 'geteuid', return_value=euid), \
                 patch.dict(os.environ, env, clear=True), \
                 patch.object(os, 'chown') as chown:
                storage.save_results(self.networks)
                chown.assert_not_called()

    def test_chown_failure_does_not_break_saving(self):
        with patch.object(os, 'geteuid', return_value=0), \
             patch.dict(os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}), \
             patch.object(os, 'chown', side_effect=PermissionError('nope')):
            storage.save_results(self.networks)
        self.assertEqual(storage.load_results(), self.networks)

    # --- Non-interactive mode -----------------------------------------------------

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(storage.BASE_DIR / 'AirRecon.py'),
                               '--output-dir', str(self.root), *args],
                              input='', capture_output=True, text=True, cwd=self.root, timeout=10)

    def test_batch_json_goes_to_stdout_and_progress_to_stderr(self):
        result = self.run_cli('--input', str(FIXTURE.resolve()), '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        records = json.loads(result.stdout)
        self.assertEqual([r['BSSID'] for r in records],  # strongest signal first
                         [n['BSSID'] for n in analysis.sort_networks(self.networks)])
        self.assertIn('WPS is advertised', ' '.join(records[0]['Warnings']))
        self.assertIn('Found 4 networks', result.stderr)
        self.assertNotIn('Select an option', result.stdout + result.stderr)
        self.assertEqual(len(json.loads(storage.RESULTS_FILE.read_text())), 4)
        self.assertNotIn('Warnings', json.loads(storage.RESULTS_FILE.read_text())[0])

    def test_batch_csv_and_table(self):
        report = self.root / 'out' / 'scan.csv'
        result = self.run_cli('--input', str(FIXTURE.resolve()), '--csv', str(report))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Example Home', result.stdout)
        self.assertIn('Report saved to', result.stderr)
        with report.open(newline='') as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 4)

    def test_batch_failures_and_usage_errors(self):
        result = self.run_cli('--input', str(self.root / 'missing'), '--json')
        self.assertEqual(result.returncode, 1)
        self.assertEqual(result.stdout, '')
        self.assertIn('Scan failed', result.stderr)
        self.assertEqual(self.run_cli('--json').returncode, 2)
        self.assertEqual(self.run_cli('--input', str(FIXTURE), '--interface', 'wlan0').returncode, 2)

    def test_batch_live_scan_uses_interface(self):
        args = argparse.Namespace(input=None, interface='wlan0', json=True, csv=None)
        errors = io.StringIO()
        with patch.object(scanner, 'scan_wifi', return_value=self.networks) as scan, \
             patch.object(sys, 'stderr', errors):
            self.assertEqual(cli.run_batch(args), 0)
        scan.assert_called_once_with('wlan0')
        self.assertIn('Found 4 networks', errors.getvalue())
        self.assertEqual(len(json.loads(self.console.getvalue())), 4)


    # --- Sorting ------------------------------------------------------------------

    def test_sort_strongest_first_unknown_last(self):
        nets = [{'BSSID': 'a', 'Signal (dBm)': -80.0}, {'BSSID': 'b', 'Signal (dBm)': None},
                {'BSSID': 'c', 'Signal (dBm)': -40.0}, {'BSSID': 'd', 'Quality(%)': 70},
                {'BSSID': 'e', 'Signal (dBm)': -40.0}]
        self.assertEqual([n['BSSID'] for n in analysis.sort_networks(nets)], ['c', 'e', 'd', 'a', 'b'])
        self.assertEqual([n['BSSID'] for n in nets], ['a', 'b', 'c', 'd', 'e'])  # input untouched

    def test_table_and_analysis_numbers_follow_sorted_order(self):
        weak_first = [dict(self.networks[0], **{'Signal (dBm)': -90.0}),
                      dict(self.networks[1], **{'Signal (dBm)': -30.0})]
        display.display_results(weak_first)
        rows = [l for l in self.console.getvalue().splitlines() if l[:1].isdigit()]
        self.assertIn('Example Modern', rows[0])
        with patch('builtins.input', return_value='1'):
            cli.handle_analyze({'networks': weak_first})
        self.assertIn('Network: Example Modern', self.console.getvalue())

    # --- Network-name groups ------------------------------------------------------

    def twins(self):
        return parser.parse_scan_output(TWIN_FIXTURE.read_text(encoding='utf-8'))

    def test_decode_and_name_key(self):
        self.assertEqual(analysis.decode_iw_name(r'Cafe\x20'), 'Cafe ')
        self.assertEqual(analysis.decode_iw_name(r'Caf\xc3\xa9'), 'Café')
        self.assertEqual(analysis.decode_iw_name(r'\x5cx41'), r'\x41')
        for lookalike in (r'Home\x20', 'HOME', r'Home\xe2\x80\x8b', r'\x20home'):
            with self.subTest(name=lookalike):
                self.assertEqual(analysis.name_key(lookalike), analysis.name_key('Home'))
        self.assertNotEqual(analysis.name_key('Home-5G'), analysis.name_key('Home'))

    def test_same_name_same_security_is_information_only(self):
        findings = analysis.name_findings([n for n in self.twins() if n['ESSID'] == 'Town Library'])
        self.assertEqual(findings['warnings'], {})
        [entry] = findings['entries']
        self.assertEqual(entry['level'], 'info')
        self.assertIn('2 access points, same security (WPA3), 2.4 GHz + 5 GHz', entry['messages'][0])

    def test_open_twin_and_lookalike_name_are_flagged(self):
        nets = self.twins()
        findings = analysis.name_findings(nets)
        cafe = [n for n in nets if n['ESSID'].startswith('Cafe')]
        self.assertEqual(len(cafe), 4)
        for net in cafe:
            text = ' '.join(findings['warnings'][net['BSSID']])
            self.assertIn('look the same', text)
            self.assertIn('Open access point alongside encrypted ones (WPA2)', text)
        library = [n for n in nets if n['ESSID'] == 'Town Library']
        self.assertTrue(all(n['BSSID'] not in findings['warnings'] for n in library))

    def test_mixed_security_without_open(self):
        nets = [{'BSSID': 'a', 'ESSID': 'Office', 'Encryption': 'WPA2'},
                {'BSSID': 'b', 'ESSID': 'Office', 'Encryption': 'WPA3'}]
        warnings = analysis.name_findings(nets)['warnings']['a']
        self.assertEqual(len(warnings), 1)
        self.assertIn('different security (WPA2, WPA3)', warnings[0])

    def test_hidden_and_unique_names_are_not_grouped(self):
        findings = analysis.name_findings(self.networks)  # sample: unique names + one hidden
        self.assertEqual(findings, {'warnings': {}, 'entries': [], 'groups': {}})
        display.display_findings(self.networks)
        self.assertEqual(self.console.getvalue(), '')

    def test_group_warnings_reach_table_csv_json_and_analysis(self):
        nets = self.twins()
        display.display_results(nets)
        display.display_findings(nets)
        output = self.console.getvalue()
        self.assertIn('[2 warnings]', output)  # lookalike + open twin
        self.assertIn('common evil-twin setup', output)
        self.assertIn("'Town Library': 2 access points", output)
        report = self.root / 'twins.csv'
        storage.save_to_csv(nets, report)
        with report.open(newline='') as handle:
            first = next(csv.DictReader(handle))
        self.assertEqual(first['BSSID'], '02:00:00:00:0e:01')  # strongest (-41 dBm) first
        self.assertIn('evil-twin', first['Warnings'])
        records = storage.export_records(nets)
        self.assertIn('evil-twin', ' '.join(records[0]['Warnings']))
        self.console.truncate(0)
        self.console.seek(0)
        with patch('builtins.input', return_value='1'):
            cli.handle_analyze({'networks': nets})
        self.assertIn('Same name also broadcast by 3 other access points', self.console.getvalue())

    def test_filtered_view_still_compares_against_full_scan(self):
        nets = self.twins()
        open_only = analysis.filter_networks(nets, security='Open')
        display.display_results(open_only, context=nets)
        self.assertIn('[3 warnings]', self.console.getvalue())  # no encryption + 2 name warnings

    def test_twin_fixture_through_cli(self):
        result = subprocess.run([sys.executable, str(storage.BASE_DIR / 'AirRecon.py'),
                                 '--input', str(TWIN_FIXTURE), '--output-dir', str(self.root)],
                                input='2\n\n8\n', capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Network names shared by several access points', result.stdout)
        self.assertIn('evil-twin', result.stdout)


class RealScanTests(unittest.TestCase):
    """Parser behaviour on real-world iw output rather than hand-written samples."""

    @classmethod
    def setUpClass(cls):
        cls.raw = REAL_FIXTURE.read_text(encoding='utf-8')
        cls.networks = parser.parse_scan_output(cls.raw)

    def test_every_bss_is_parsed_with_core_fields(self):
        self.assertEqual(len(self.networks), self.raw.count('\nBSS ') + self.raw.startswith('BSS '))
        self.assertEqual(len(self.networks), 16)
        self.assertEqual(len({n['BSSID'] for n in self.networks}), 16)
        for net in self.networks:
            with self.subTest(bssid=net['BSSID']):
                self.assertIsNotNone(net['Channel'])
                self.assertIsNotNone(net['Signal (dBm)'])
                self.assertRegex(net['Frequency'], r'^\d\.\d{3} GHz$')

    def test_associated_suffix_and_decimal_frequency(self):
        # Real output: 'BSS <mac>(on wlo1) -- associated' and 'freq: 5500.0'.
        first = self.networks[0]
        self.assertEqual(first['BSSID'], '02:00:00:00:10:01')
        self.assertEqual(first['ESSID'], 'Network A')
        self.assertEqual(first['Frequency'], '5.500 GHz')
        self.assertEqual(first['Channel'], '100')

    def test_hidden_networks(self):
        self.assertEqual(sum(not n['ESSID'] for n in self.networks), 5)

    def test_security_labels_and_details(self):
        count = lambda key: sorted(Counter(str(n[key]) for n in self.networks).items())
        self.assertEqual(count('Encryption'), [('Open', 2), ('WPA2', 9),
                                               ('WPA2/3-Enterprise', 2), ('WPA2/WPA3', 3)])
        self.assertEqual(count('PMF'), [('Disabled', 9), ('None', 2), ('Optional', 5)])
        self.assertEqual(sum(n['WPS'] for n in self.networks), 2)
        self.assertFalse(any('TKIP' in f"{n['Group Cipher']} {n['Pairwise Ciphers']}"
                             for n in self.networks))

    def test_bands_and_channel_counts(self):
        self.assertEqual(sorted(Counter(analysis.band(n) for n in self.networks).items()),
                         [('2.4 GHz', 10), ('5 GHz', 6)])
        self.assertEqual(analysis.analyze_channels(self.networks),
                         {'2.412 GHz': 4, '2.437 GHz': 1, '2.462 GHz': 5, '5.200 GHz': 1,
                          '5.220 GHz': 1, '5.500 GHz': 2, '5.765 GHz': 2})

    def test_real_shared_names_are_not_false_alarms(self):
        findings = analysis.name_findings(self.networks)
        self.assertEqual(findings['warnings'], {})
        self.assertEqual([(e['level'], len(e['members'])) for e in findings['entries']],
                         [('info', 2), ('info', 2), ('info', 3)])

    def test_real_warning_totals(self):
        findings = analysis.name_findings(self.networks)
        warnings = Counter(w.split('.')[0] for n in self.networks
                           for w in analysis.network_warnings(n, findings))
        self.assertEqual(warnings, Counter({
            'No WiFi link encryption is advertised': 2,
            'Protected management frames (PMF/802': 9,
            'WPS is advertised': 2}))

    def test_fixture_contains_no_identifying_data(self):
        self.assertEqual(set(re.findall(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', self.raw)),
                         {f'02:00:00:00:10:{i:02x}' for i in range(1, 17)})
        names = set(re.findall(r'^\s*SSID: (.*)$', self.raw, re.MULTILINE))
        self.assertTrue(all(re.fullmatch(r'Network [A-Z]', name) for name in names), names)
        for field in ('Device name', 'Manufacturer', 'Model', 'Serial Number', 'UUID'):
            values = set(re.findall(r'\* ' + field + r':\s*(.*)$', self.raw, re.MULTILINE))
            with self.subTest(field=field):
                self.assertTrue(values <= {'Example Router', 'Example Corp', 'Model X',
                                           '0000000000', '00000000-0000-0000-0000-000000000000'})
        self.assertEqual(set(re.findall(r'Country: (\S+)', self.raw)), {'XX'})


def ip_reply(local='192.168.50.2', prefix=24, gateway='192.168.50.1'):
    """Fake `ip -j` replies: address first, then default route."""
    addr = json.dumps([{'ifname': 'wlo1', 'addr_info': [
        {'family': 'inet', 'local': local, 'prefixlen': prefix, 'scope': 'global'}]}])
    route = json.dumps([{'dst': 'default', 'gateway': gateway}] if gateway else [])
    return [subprocess.CompletedProcess([], 0, addr, ''), subprocess.CompletedProcess([], 0, route, '')]


class HostDiscoveryTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(storage.configure_storage, storage.BASE_DIR)
        self.root = Path(self.directory.name)
        storage.configure_storage(self.root)
        self.xml = NMAP_FIXTURE.read_text(encoding='utf-8')
        self.console = io.StringIO()
        redirect = contextlib.redirect_stdout(self.console)
        redirect.__enter__()
        self.addCleanup(redirect.__exit__, None, None, None)

    def test_parse_up_hosts_sorted_numerically(self):
        found = hosts.parse_nmap_xml(self.xml)
        self.assertEqual([h['IP'] for h in found], ['192.168.50.1', '192.168.50.2', '192.168.50.10'])
        router = found[0]
        self.assertEqual((router['MAC'], router['Vendor'], router['Hostname']),
                         ('02:00:00:aa:00:01', 'Example Networks', 'router.lan'))
        self.assertIsNone(found[1]['MAC'])  # nmap does not report the scanning machine's MAC

    def test_invalid_or_foreign_xml_is_an_error(self):
        for text in ('not xml', '<other/>', ''):
            with self.subTest(text=text), self.assertRaises(parser.ScanError):
                hosts.parse_nmap_xml(text)
        self.assertEqual(hosts.parse_nmap_xml('<nmaprun></nmaprun>'), [])

    def test_connected_network_reads_address_and_gateway(self):
        with patch.object(subprocess, 'run', side_effect=ip_reply()) as run:
            info = hosts.connected_network('wlo1')
        self.assertEqual(info['network'], ipaddress.ip_network('192.168.50.0/24'))
        self.assertEqual((info['address'], info['gateway']), ('192.168.50.2', '192.168.50.1'))
        self.assertEqual(run.call_args_list[0].args[0], ['ip', '-j', '-4', 'addr', 'show', 'dev', 'wlo1'])

    def test_not_connected_is_reported(self):
        empty = subprocess.CompletedProcess([], 0, json.dumps([{'addr_info': []}]), '')
        with patch.object(subprocess, 'run', side_effect=[empty, empty]):
            with self.assertRaisesRegex(parser.ScanError, 'no IPv4 address'):
                hosts.connected_network('wlo1')

    def test_only_private_home_sized_networks_are_scannable(self):
        for allowed in ('192.168.1.0/24', '10.0.0.0/22', '172.16.5.0/25'):
            with self.subTest(allowed=allowed):
                hosts.check_scannable(ipaddress.ip_network(allowed))
        for refused, reason in (('10.20.0.0/16', 'school, workplace'), ('192.168.0.0/21', 'larger'),
                                ('8.8.8.0/24', 'not a private'), ('127.0.0.0/24', 'not a private'),
                                ('169.254.0.0/24', 'not a private')):
            with self.subTest(refused=refused), self.assertRaisesRegex(parser.ScanError, reason):
                hosts.check_scannable(ipaddress.ip_network(refused))

    def test_discover_runs_ping_scan_only_and_saves_raw_xml(self):
        nmap = subprocess.CompletedProcess([], 0, self.xml, '')
        with patch.object(subprocess, 'run', side_effect=ip_reply() + [nmap]) as run:
            found, info = hosts.discover_hosts('wlo1')
        self.assertEqual(run.call_args_list[2].args[0], ['nmap', '-sn', '-oX', '-', '192.168.50.0/24'])
        self.assertEqual(run.call_args_list[2].kwargs['timeout'], hosts.HOSTS_TIMEOUT)
        self.assertEqual([h['Role'] for h in found], ['router', 'this device', None])
        self.assertEqual(storage.HOSTS_RAW_FILE.read_text(), self.xml)

    def test_large_network_is_refused_before_nmap_runs(self):
        with patch.object(subprocess, 'run', side_effect=ip_reply('10.20.30.40', 16, '10.20.0.1')) as run:
            with self.assertRaisesRegex(parser.ScanError, '65,536 addresses'):
                hosts.discover_hosts('wlo1')
        self.assertEqual(run.call_count, 2)  # only the two `ip` calls

    def test_nmap_missing_or_failing(self):
        with patch.object(subprocess, 'run', side_effect=ip_reply() + [FileNotFoundError()]):
            with self.assertRaisesRegex(parser.ScanError, 'Install nmap'):
                hosts.discover_hosts('wlo1')
        failed = subprocess.CompletedProcess([], 1, '', 'Failed to resolve')
        with patch.object(subprocess, 'run', side_effect=ip_reply() + [failed]):
            with self.assertRaisesRegex(parser.ScanError, 'Failed to resolve'):
                hosts.discover_hosts('wlo1')
        self.assertFalse(storage.HOSTS_RAW_FILE.exists())

    def test_table_escapes_untrusted_hostnames_and_explains_missing_macs(self):
        found = hosts.label_hosts(hosts.parse_nmap_xml(self.xml), {})
        display.display_hosts(found, {})
        output = self.console.getvalue()
        self.assertNotIn('‮', output)
        self.assertIn('\\u202e', output)
        self.assertNotIn('need sudo', output)
        self.console.truncate(0)
        self.console.seek(0)
        display.display_hosts([dict(h, MAC=None) for h in found], {})
        self.assertIn('MAC addresses and vendors need sudo', self.console.getvalue())

    def test_snapshot_and_csv(self):
        found, info = hosts.load_hosts_file(NMAP_FIXTURE)
        storage.save_hosts(found, info)
        snapshot = json.loads(storage.HOSTS_FILE.read_text())
        self.assertEqual(len(snapshot['hosts']), 3)
        report = self.root / 'devices.csv'
        storage.save_hosts_csv(found, report)
        with report.open(newline='') as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[2]['Hostname'][:2], "'=")  # formula neutralised
        self.assertNotIn('‮', rows[2]['Hostname'])

    def run_cli(self, *args, stdin=''):
        return subprocess.run([sys.executable, str(storage.BASE_DIR / 'AirRecon.py'),
                               '--output-dir', str(self.root), *args],
                              input=stdin, capture_output=True, text=True, timeout=15)

    def test_batch_hosts_json_and_csv_offline(self):
        report = self.root / 'out' / 'devices.csv'
        result = self.run_cli('--hosts', '--hosts-input', str(NMAP_FIXTURE), '--json', '--csv', str(report))
        self.assertEqual(result.returncode, 0, result.stderr)
        data = json.loads(result.stdout)
        self.assertEqual([h['IP'] for h in data['hosts']], ['192.168.50.1', '192.168.50.2', '192.168.50.10'])
        self.assertIn('Found 3 devices', result.stderr)
        self.assertTrue(report.exists())
        self.assertIn('Device discovery', storage.LOG_FILE.read_text())

    def test_batch_hosts_usage_and_failure(self):
        self.assertEqual(self.run_cli('--hosts').returncode, 2)
        result = self.run_cli('--hosts', '--hosts-input', str(self.root / 'missing.xml'))
        self.assertEqual(result.returncode, 1)
        self.assertIn('Device discovery failed', result.stderr)
        self.assertEqual(result.stdout, '')

    def test_batch_hosts_live_path(self):
        args = argparse.Namespace(hosts_input=None, interface='wlo1', json=False, csv=None)
        info = {'interface': 'wlo1', 'address': '192.168.50.2', 'gateway': '192.168.50.1',
                'network': ipaddress.ip_network('192.168.50.0/24')}
        found = hosts.label_hosts(hosts.parse_nmap_xml(self.xml), info)
        errors = io.StringIO()
        with patch.object(hosts, 'discover_hosts', return_value=(found, info)) as discover, \
             patch.object(sys, 'stderr', errors):
            self.assertEqual(cli.run_hosts_batch(args), 0)
        discover.assert_called_once_with('wlo1')
        self.assertIn('Network: 192.168.50.0/24 on wlo1, router 192.168.50.1', self.console.getvalue())

    def test_menu_asks_before_scanning(self):
        state = {'interface': 'wlo1', 'input_file': None, 'hosts_input': None}
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlo1']), \
             patch.object(subprocess, 'run', side_effect=ip_reply()), \
             patch.object(hosts, 'discover_hosts') as discover, \
             patch('builtins.input', return_value='n'):
            cli.handle_hosts(state)
        discover.assert_not_called()
        self.assertIn('Only scan networks you own', self.console.getvalue())
        self.assertIn('Cancelled', self.console.getvalue())
        info = {'interface': 'wlo1', 'address': '192.168.50.2', 'gateway': '192.168.50.1',
                'network': ipaddress.ip_network('192.168.50.0/24')}
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlo1']), \
             patch.object(subprocess, 'run', side_effect=ip_reply()), \
             patch.object(hosts, 'discover_hosts', return_value=([], info)) as discover, \
             patch('builtins.input', return_value='y'):
            cli.handle_hosts(state)
        discover.assert_called_once_with('wlo1')
        self.assertTrue(storage.HOSTS_FILE.exists())

    def test_menu_refuses_large_network_without_prompting(self):
        state = {'interface': 'wlo1', 'input_file': None, 'hosts_input': None}
        with patch.object(scanner, 'get_wireless_interfaces', return_value=['wlo1']), \
             patch.object(subprocess, 'run', side_effect=ip_reply('10.20.30.40', 16)), \
             patch('builtins.input', side_effect=AssertionError('must not prompt')):
            cli.handle_hosts(state)
        self.assertIn('will not scan', self.console.getvalue())

    def test_menu_offline_without_hosts_file(self):
        cli.handle_hosts({'interface': None, 'input_file': FIXTURE, 'hosts_input': None})
        self.assertIn('--hosts-input', self.console.getvalue())

    def test_menu_offline_with_hosts_file(self):
        result = self.run_cli('--input', str(FIXTURE), '--hosts-input', str(NMAP_FIXTURE),
                              stdin='7\n\n8\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('7. Find Devices on My Network', result.stdout)
        self.assertIn('192.168.50.10', result.stdout)


if __name__ == '__main__':
    unittest.main()
