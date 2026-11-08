"""Regression and offline integration tests; no wireless hardware or sudo needed."""
import contextlib
import csv
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import AirRecon as app


FIXTURE = Path(__file__).parent / 'fixtures' / 'sample_scan.txt'


class AirReconTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.addCleanup(app.configure_storage, app.BASE_DIR)
        self.root = Path(self.directory.name)
        app.configure_storage(self.root)
        self.raw = FIXTURE.read_text(encoding='utf-8')
        self.networks = app.parse_scan_output(self.raw)
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
                self.assertEqual(app.parse_network_info(cell)['Encryption'], 'Open')

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
                self.assertEqual(app.detect_encryption(cell), expected)
        self.assertEqual(app.detect_encryption('\tWPA: * Version: 1\n'), 'WPA')
        self.assertEqual(app.detect_encryption('\tcapability: ESS Privacy\n'), 'WEP/unknown')
        self.assertEqual(app.detect_encryption(''), 'Unknown')
        mixed = '\tWPA: * Version: 1\n\tRSN: * Version: 1\n\t\t * Authentication suites: PSK\n'
        self.assertEqual(app.detect_encryption(mixed), 'WPA/WPA2')

    def test_empty_and_unrecognized_scan_are_distinct(self):
        self.assertEqual(app.parse_scan_output(' \n'), [])
        with self.assertRaises(app.ScanError):
            app.parse_scan_output('this is not iw scan output')

    def test_missing_optional_fields_are_displayable(self):
        network = app.parse_network_info('BSS 02:00:00:00:00:01(on wlan0)\n')
        self.assertIsNone(network['Channel'])
        self.assertIsNone(network['Quality(%)'])
        app.display_results([network])
        self.assertIn('(hidden)', self.console.getvalue())

    def test_frequency_conversion_and_invalid_values(self):
        for frequency, expected in [(2412, 1), (2484, 14), (5180, 36), (5955, 1),
                                     (5935, 2), (7115, 233), (4910, 182),
                                     (2413, None), (8000, None), (None, None)]:
            with self.subTest(frequency=frequency):
                self.assertEqual(app.freq_to_channel(frequency), expected)

    def test_signal_clamps_and_missing_signal_is_unknown(self):
        for dbm, expected in [(-120, 0), (-100, 0), (-75, 50), (-50, 100), (-20, 100)]:
            cell = f'BSS 02:00:00:00:00:01(on wlan0)\n\tsignal: {dbm} dBm\n'
            self.assertEqual(app.parse_network_info(cell)['Quality(%)'], expected)
        self.assertIsNone(app.calculate_signal(None))

    def test_channel_counts_do_not_merge_frequency_bands(self):
        self.assertEqual(app.analyze_channels(self.networks),
                         {'2.412 GHz': 2, '5.180 GHz': 1, '5.955 GHz': 1})

    def test_only_wireless_interfaces_are_listed(self):
        for name in ('lo', 'eth0', 'wlan0', 'wlan1'):
            (self.root / name).mkdir()
        (self.root / 'wlan0' / 'wireless').mkdir()
        (self.root / 'wlan1' / 'phy80211').mkdir()
        with patch.object(app, 'NET_DIR', self.root):
            self.assertEqual(app.get_wireless_interfaces(), ['wlan0', 'wlan1'])
        with patch.object(app, 'NET_DIR', self.root / 'absent'):
            self.assertEqual(app.get_wireless_interfaces(), [])

    def test_invalid_interface_selection(self):
        for answer in ('0', '-1', '3', 'abc'):
            with self.subTest(answer=answer), patch.object(app, 'get_wireless_interfaces', return_value=['wlan0']), patch('builtins.input', return_value=answer):
                self.assertIsNone(app.choose_interface())

    def test_scan_success_uses_argument_list_and_saves_raw_output(self):
        result = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(app.subprocess, 'run', return_value=result) as run:
            self.assertEqual(app.scan_wifi('wlan0'), self.networks)
        self.assertEqual(run.call_args.args[0], ['iw', 'dev', 'wlan0', 'scan'])
        self.assertEqual(run.call_args.kwargs['timeout'], app.SCAN_TIMEOUT)
        self.assertEqual(app.RAW_FILE.read_text(), self.raw)

    def test_scan_errors_are_not_empty_successes(self):
        for error in (FileNotFoundError(), subprocess.TimeoutExpired('iw', 25), PermissionError()):
            with self.subTest(error=type(error)), patch.object(app.subprocess, 'run', side_effect=error):
                with self.assertRaises(app.ScanError):
                    app.scan_wifi('wlan0')
        with patch.object(app.subprocess, 'run', return_value=subprocess.CompletedProcess([], 1, '', 'Operation not permitted')):
            with self.assertRaisesRegex(app.ScanError, 'Operation not permitted'):
                app.scan_wifi('wlan0')

    def test_raw_output_write_failure_does_not_discard_scan(self):
        result = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(app.subprocess, 'run', return_value=result), patch.object(app, 'atomic_write', side_effect=PermissionError('read only')):
            self.assertEqual(app.scan_wifi('wlan0'), self.networks)
        self.assertIn('Could not save raw scan output', self.console.getvalue())

    def test_failed_scan_preserves_memory_and_saved_results(self):
        app.save_results(self.networks)
        previous_bytes = app.RESULTS_FILE.read_bytes()
        state = {'networks': self.networks}
        with patch.object(app, 'choose_interface', return_value='wlan0'), patch.object(app, 'scan_wifi', side_effect=app.ScanError('failed')):
            app.handle_scan(state)
        self.assertIs(state['networks'], self.networks)
        self.assertEqual(app.RESULTS_FILE.read_bytes(), previous_bytes)
        self.assertIn('Previous results were preserved', self.console.getvalue())
        self.assertNotIn('Found 0 networks', self.console.getvalue())

    def test_successful_empty_scan_replaces_previous_results(self):
        app.save_results(self.networks)
        state = {'networks': self.networks}
        with patch.object(app, 'choose_interface', return_value='wlan0'), patch.object(app, 'scan_wifi', return_value=[]):
            app.handle_scan(state)
        self.assertEqual(state['networks'], [])
        self.assertEqual(app.load_results(), [])
        with patch.object(app, 'load_results', side_effect=AssertionError('must not load stale results')):
            self.assertEqual(app.current_results(state), [])

    def test_offline_read_error_preserves_results(self):
        state = {'networks': self.networks, 'input_file': self.root / 'missing'}
        app.handle_scan(state)
        self.assertIs(state['networks'], self.networks)
        self.assertIn('Scan failed', self.console.getvalue())

    def test_write_failure_keeps_session_results(self):
        state = {'networks': None, 'input_file': FIXTURE}
        with patch.object(app, 'save_results', side_effect=PermissionError('read only')):
            app.handle_scan(state)
        self.assertEqual(state['networks'], self.networks)
        self.assertIn('remain available in this session', self.console.getvalue())

    def test_failed_atomic_replace_preserves_original_file(self):
        app.save_results(self.networks)
        original = app.RESULTS_FILE.read_bytes()
        with patch.object(app.os, 'replace', side_effect=OSError('write failure')):
            with self.assertRaises(OSError):
                app.save_results([])
        self.assertEqual(app.RESULTS_FILE.read_bytes(), original)
        self.assertEqual(list(app.DATA_DIR.iterdir()), [app.RESULTS_FILE])

    def test_saved_results_round_trip_and_legacy_records(self):
        app.save_results(self.networks)
        self.assertEqual(app.load_results(), self.networks)
        old = {'BSSID': '02:00:00:00:00:01', 'ESSID': None, 'Signal Level': 75}
        app.save_results([old])
        loaded = app.load_results()[0]
        self.assertEqual(loaded['Quality(%)'], 75)
        self.assertEqual(loaded['ESSID'], '')
        self.assertEqual(loaded['Encryption'], 'Unknown')
        self.assertNotIn('Signal Level', loaded)
        app.display_results([loaded])

    def test_invalid_saved_data_is_reported_without_crashing(self):
        for data in ('{', '{}', '[null]', '[{}]', '[{"BSSID":"02:00:00:00:00:01","Quality(%)":"high"}]',
                     '[{"BSSID":"02:00:00:00:00:01","Quality(%)":NaN}]',
                     '[{"BSSID":"02:00:00:00:00:01","Quality(%)":101}]'):
            with self.subTest(data=data):
                app.atomic_write(app.RESULTS_FILE, data)
                self.assertEqual(app.load_results(), [])
        self.assertIn('Cannot load saved results', self.console.getvalue())

    def test_network_selection_rejects_zero_negative_and_out_of_range(self):
        for choice in ('0', '-1', '5', 'abc'):
            self.console.truncate(0)
            self.console.seek(0)
            with self.subTest(choice=choice), patch('builtins.input', return_value=choice):
                app.handle_analyze({'networks': self.networks})
            self.assertIn('Invalid selection', self.console.getvalue())
            self.assertNotIn('\nNetwork:', self.console.getvalue())

    def test_filtering_combines_conditions_and_handles_unknown_signal(self):
        self.assertEqual(app.filter_networks(self.networks, 'wpa2', 'HOME', 90), [self.networks[0]])
        self.assertEqual(app.filter_networks(self.networks, min_quality=99), [])
        hidden = dict(self.networks[3], **{'Quality(%)': None})
        self.assertEqual(app.filter_networks([hidden]), [hidden])
        self.assertEqual(app.filter_networks([hidden], min_quality=1), [])

    def test_csv_keeps_numeric_signal_and_quotes_untrusted_names(self):
        network = dict(self.networks[0], ESSID='=1+1')
        filename = self.root / 'report.csv'
        app.save_to_csv([network], filename)
        with filename.open(newline='') as handle:
            row = next(csv.DictReader(handle))
        self.assertEqual(row['ESSID'], "'=1+1")
        self.assertEqual(row['Signal (dBm)'], '-54.0')
        self.assertEqual(row['BSSID'], network['BSSID'])

    def test_terminal_control_characters_are_escaped(self):
        network = dict(self.networks[0], ESSID='bad\x1b[2Jname')
        app.display_results([network])
        self.assertNotIn('\x1b', self.console.getvalue())
        self.assertIn('\\x1b', self.console.getvalue())

    def test_log_write_error_does_not_crash(self):
        with patch.object(Path, 'mkdir', side_effect=PermissionError('read only')):
            app.log_message('test')
        self.assertIn('Could not write log', self.console.getvalue())

    def test_full_offline_menu_from_another_directory(self):
        # Scan, analyze, export, reload, filter, then exit in a separate process.
        commands = '2\n\n3\n1\n\n4\n\n5\n\n6\nExample\nWPA2\n80\n\n7\n'
        result = subprocess.run([sys.executable, str(app.BASE_DIR / 'AirRecon.py'),
                                 '--input', str(FIXTURE.resolve()), '--output-dir', str(self.root)],
                                input=commands, capture_output=True, text=True,
                                cwd=self.root, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')
        self.assertIn('Found 4 networks', result.stdout)
        self.assertIn('Network: Example Home', result.stdout)
        self.assertIn('Report saved to', result.stdout)
        self.assertIn('Goodbye!', result.stdout)
        self.assertEqual(len(json.loads(app.RESULTS_FILE.read_text())), 4)
        reports = list(app.REPORTS_DIR.glob('*.csv'))
        self.assertEqual(len(reports), 1)
        with reports[0].open(newline='') as handle:
            self.assertEqual(len(list(csv.DictReader(handle))), 4)

    def test_eof_exits_without_traceback(self):
        result = subprocess.run([sys.executable, str(app.BASE_DIR / 'AirRecon.py'),
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
                self.assertEqual(app.parse_network_info(cell)['ESSID'], expected)
        app.display_results([app.parse_network_info(
            'BSS 02:00:00:00:00:01(on wlan0)\n\tSSID: \\x00\\x00\n')])
        self.assertIn('(hidden)', self.console.getvalue())

    def test_new_records_have_no_duplicate_signal_level(self):
        self.assertNotIn('Signal Level', self.networks[0])

    def test_menu_exit_aliases(self):
        for exit_choice in ('7', '0', 'q'):
            with self.subTest(choice=exit_choice), patch('builtins.input', side_effect=[exit_choice]):
                self.assertEqual(app.main(['--output-dir', str(self.root)]), 0)

    # --- Cached scan fallback -----------------------------------------------------

    def test_failed_fresh_scan_falls_back_to_cached_dump(self):
        refused = subprocess.CompletedProcess([], 255, '', 'command failed: Operation not permitted (-1)')
        cached = subprocess.CompletedProcess([], 0, self.raw, '')
        with patch.object(app.subprocess, 'run', side_effect=[refused, cached]) as run:
            self.assertEqual(app.scan_wifi('wlan0'), self.networks)
        self.assertEqual([c.args[0] for c in run.call_args_list],
                         [['iw', 'dev', 'wlan0', 'scan'], ['iw', 'dev', 'wlan0', 'scan', 'dump']])
        self.assertIn('cached results', self.console.getvalue())
        self.assertEqual(app.RAW_FILE.read_text(), self.raw)
        self.assertIn('used cached scan dump', app.LOG_FILE.read_text())

    def test_empty_or_failed_cache_reports_original_error(self):
        refused = subprocess.CompletedProcess([], 240, '', 'command failed: Device or resource busy (-16)')
        for dump in (subprocess.CompletedProcess([], 0, '', ''),
                     subprocess.CompletedProcess([], 0, 'garbage', ''),
                     subprocess.CompletedProcess([], 1, '', 'nope')):
            with self.subTest(dump=dump.stdout or dump.stderr), \
                 patch.object(app.subprocess, 'run', side_effect=[refused, dump]):
                with self.assertRaisesRegex(app.ScanError, 'resource busy'):
                    app.scan_wifi('wlan0')
        self.assertFalse(app.RAW_FILE.exists())

    def test_successful_fresh_scan_does_not_dump(self):
        result = subprocess.CompletedProcess([], 0, '', '')
        with patch.object(app.subprocess, 'run', return_value=result) as run:
            self.assertEqual(app.scan_wifi('wlan0'), [])
        self.assertEqual(run.call_count, 1)

    # --- Security configuration details -------------------------------------------

    def test_sample_security_details(self):
        home, modern, guest, hidden = self.networks
        self.assertEqual((home['PMF'], home['WPS']), ('Disabled', True))
        self.assertEqual((home['Group Cipher'], home['Pairwise Ciphers']), ('CCMP', 'CCMP'))
        self.assertEqual(modern['PMF'], 'Optional')
        self.assertEqual((guest['PMF'], guest['WPS'], guest['Group Cipher']), (None, False, None))
        self.assertEqual(hidden['PMF'], 'Required')
        self.assertEqual(app.security_warnings(hidden), [])

    def test_ssid_cannot_spoof_wps_or_pmf(self):
        cell = ('BSS 02:00:00:00:00:01(on wlan0)\n\tSSID: WPS: MFP-required\n'
                '\tcapability: ESS (0x0001)\n')
        network = app.parse_network_info(cell)
        self.assertFalse(network['WPS'])
        self.assertIsNone(network['PMF'])

    def test_tkip_and_wpa_ciphers_are_flagged(self):
        cell = ('BSS 02:00:00:00:00:01(on wlan0)\n\tcapability: ESS Privacy (0x0011)\n'
                '\tWPA:\t * Version: 1\n\t\t * Group cipher: TKIP\n'
                '\t\t * Pairwise ciphers: TKIP (default)\n\t\t * Authentication suites: PSK\n'
                '\tRSN:\t * Version: 1\n\t\t * Group cipher: TKIP\n'
                '\t\t * Pairwise ciphers: CCMP TKIP\n\t\t * Authentication suites: PSK\n')
        network = app.parse_network_info(cell)
        self.assertEqual(network['Encryption'], 'WPA/WPA2')
        self.assertEqual(network['Group Cipher'], 'TKIP')
        self.assertEqual(network['Pairwise Ciphers'], 'CCMP TKIP')
        text = ' '.join(app.security_warnings(network))
        self.assertIn('Legacy WPA', text)
        self.assertIn('TKIP', text)
        self.assertIn('not supported', text)

    def test_wpa3_without_required_pmf_is_flagged(self):
        for label in ('WPA3', 'Enhanced Open (OWE)'):
            for pmf in ('Optional', 'Disabled'):
                with self.subTest(label=label, pmf=pmf):
                    warnings = app.security_warnings({'Encryption': label, 'PMF': pmf})
                    self.assertEqual(len(warnings), 1)
                    self.assertIn('requires protected management frames', warnings[0])
        self.assertEqual(app.security_warnings({'Encryption': 'WPA2/WPA3', 'PMF': 'Optional'}), [])

    def test_legacy_records_without_pmf_get_no_pmf_guess(self):
        self.assertEqual(app.security_warnings({'Encryption': 'WPA3'}), [])
        old = {'BSSID': '02:00:00:00:00:01', 'Encryption': 'WPA3', 'Signal Level': 75}
        app.save_results([old])
        self.assertEqual(app.security_warnings(app.load_results()[0]), [])

    def test_invalid_security_fields_in_saved_data_are_rejected(self):
        for data in ('[{"BSSID":"02:00:00:00:00:01","WPS":"yes"}]',
                     '[{"BSSID":"02:00:00:00:00:01","PMF":1}]'):
            with self.subTest(data=data):
                app.atomic_write(app.RESULTS_FILE, data)
                self.assertEqual(app.load_results(), [])

    def test_analyze_and_csv_show_warnings(self):
        with patch('builtins.input', return_value='1'):
            app.handle_analyze({'networks': self.networks})
        output = self.console.getvalue()
        self.assertIn('WPS: Advertised', output)
        self.assertIn('[!] WPS is advertised', output)
        filename = self.root / 'report.csv'
        app.save_to_csv(self.networks, filename)
        with filename.open(newline='') as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(rows[0]['WPS'], 'Yes')
        self.assertEqual(rows[0]['PMF'], 'Disabled')
        self.assertIn('WPS is advertised', rows[0]['Warnings'])
        self.assertEqual(rows[3]['Warnings'], '')

    # --- Ownership of files created under sudo -----------------------------------

    def test_sudo_runs_return_created_files_to_invoking_user(self):
        root_owned = self.root / 'fresh'
        app.configure_storage(root_owned)
        env = {'SUDO_UID': '1000', 'SUDO_GID': '1001'}
        with patch.object(app.os, 'geteuid', return_value=0), \
             patch.dict(app.os.environ, env), patch.object(app.os, 'chown') as chown:
            app.save_results(self.networks)
            app.log_message('test')
            app.save_to_csv(self.networks, app.REPORTS_DIR / 'r.csv')
        chowned = {Path(call.args[0]) for call in chown.call_args_list}
        self.assertTrue({root_owned, app.DATA_DIR, app.LOGS_DIR, app.REPORTS_DIR,
                         app.LOG_FILE, app.REPORTS_DIR / 'r.csv'} <= chowned)
        self.assertTrue(all(call.args[1:] == (1000, 1001) for call in chown.call_args_list))
        # The results file is chowned as its temporary name, before the atomic rename.
        self.assertTrue(any(p.parent == app.DATA_DIR and p != app.RESULTS_FILE for p in chowned))
        self.assertNotIn(self.root, chowned)  # pre-existing directories are left alone

    def test_no_chown_without_sudo(self):
        for euid, env in ((1000, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}), (0, {})):
            with self.subTest(euid=euid), patch.object(app.os, 'geteuid', return_value=euid), \
                 patch.dict(app.os.environ, env, clear=True), \
                 patch.object(app.os, 'chown') as chown:
                app.save_results(self.networks)
                chown.assert_not_called()

    def test_chown_failure_does_not_break_saving(self):
        with patch.object(app.os, 'geteuid', return_value=0), \
             patch.dict(app.os.environ, {'SUDO_UID': '1000', 'SUDO_GID': '1000'}), \
             patch.object(app.os, 'chown', side_effect=PermissionError('nope')):
            app.save_results(self.networks)
        self.assertEqual(app.load_results(), self.networks)

    # --- Non-interactive mode -----------------------------------------------------

    def run_cli(self, *args):
        return subprocess.run([sys.executable, str(app.BASE_DIR / 'AirRecon.py'),
                               '--output-dir', str(self.root), *args],
                              input='', capture_output=True, text=True, cwd=self.root, timeout=10)

    def test_batch_json_goes_to_stdout_and_progress_to_stderr(self):
        result = self.run_cli('--input', str(FIXTURE.resolve()), '--json')
        self.assertEqual(result.returncode, 0, result.stderr)
        records = json.loads(result.stdout)
        self.assertEqual([r['BSSID'] for r in records], [n['BSSID'] for n in self.networks])
        self.assertIn('WPS is advertised', ' '.join(records[0]['Warnings']))
        self.assertIn('Found 4 networks', result.stderr)
        self.assertNotIn('Select an option', result.stdout + result.stderr)
        self.assertEqual(len(json.loads(app.RESULTS_FILE.read_text())), 4)
        self.assertNotIn('Warnings', json.loads(app.RESULTS_FILE.read_text())[0])

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
        args = app.argparse.Namespace(input=None, interface='wlan0', json=True, csv=None)
        errors = io.StringIO()
        with patch.object(app, 'scan_wifi', return_value=self.networks) as scan, \
             patch.object(app.sys, 'stderr', errors):
            self.assertEqual(app.run_batch(args), 0)
        scan.assert_called_once_with('wlan0')
        self.assertIn('Found 4 networks', errors.getvalue())
        self.assertEqual(len(json.loads(self.console.getvalue())), 4)


if __name__ == '__main__':
    unittest.main()
