"""Behavioral regressions for native coverage report admission."""
import importlib.util
import unittest
import sys
from pathlib import Path

sys.dont_write_bytecode = True

spec = importlib.util.spec_from_file_location('coverage_gate', Path(__file__).with_name('check-native-coverage.py'))
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)

WINDOWS = 'crates/tinysecurity-audit/src/windows.rs'
ACL = 'crates/tinysecurity-audit/src/windows_acl.rs'
ROOT = 'D:/a/tinysecurity/tinysecurity'


def report(*entries):
    return {'data': [{'files': [
        {'filename': ROOT + '/' + name, 'summary': {'lines': {'count': count, 'covered': covered}}}
        for name, count, covered in entries
    ]}]}


class NativeCoverageAdmission(unittest.TestCase):
    def test_accepts_native_drive_paths_and_backslashes(self):
        data = report((WINDOWS, 10, 9), (ACL, 10, 10))
        data['data'][0]['files'][0]['filename'] = ('d:/a/tinysecurity/tinysecurity/' + WINDOWS).replace('/', '\\')
        files = gate.check_files(data, ROOT, 90)
        self.assertEqual(files[WINDOWS], (9, 10))

    def test_missing_windows_engine_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'missing.*windows.rs'):
            gate.check_files(report((ACL, 10, 10)), ROOT, 90)

    def test_zero_executable_windows_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'executable.*windows.rs'):
            gate.check_files(report((WINDOWS, 0, 0), (ACL, 10, 10)), ROOT, 90)

    def test_low_per_file_coverage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'below 90'):
            gate.check_files(report((WINDOWS, 10, 8), (ACL, 10, 10)), ROOT, 90)

    def test_checkout_substring_and_path_escape_do_not_admit_sources(self):
        self.assertIsNone(gate.relative_source('X:/other/' + ROOT + '/' + WINDOWS, ROOT))
        self.assertIsNone(gate.relative_source(ROOT + '/../outside/' + WINDOWS, ROOT))
        self.assertIsNone(gate.relative_source(ROOT + '-other/' + WINDOWS, ROOT))

    def test_conflicting_duplicate_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'conflicting'):
            gate.check_files(report((WINDOWS, 10, 9), (WINDOWS, 10, 10), (ACL, 10, 10)), ROOT, 90)

    def test_lcov_normalizes_windows_paths_and_admits_changed_lines(self):
        lcov = 'SF:' + (ROOT + '/' + WINDOWS).replace('/', '\\') + '\nDA:3,1\nend_of_record\nSF:' + ROOT + '/' + ACL + '\nDA:4,1\nend_of_record\n'
        lines = gate.parse_lcov(lcov, ROOT)
        self.assertEqual(gate.check_changed(lines, {WINDOWS: {3}, ACL: {4}}, 80), (2, 2))

    def test_zero_windows_changed_denominator_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no measured changed.*windows.rs'):
            gate.check_changed({ACL: {4: 1}}, {WINDOWS: {3}, ACL: {4}}, 80)

    def test_uninstrumented_changed_windows_source_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'no measured changed.*windows_acl.rs'):
            gate.check_changed({WINDOWS: {3: 1}}, {WINDOWS: {3}, ACL: {4}}, 80)

    def test_low_changed_line_coverage_is_rejected(self):
        with self.assertRaisesRegex(ValueError, 'below 80'):
            gate.check_changed({WINDOWS: {3: 0}, ACL: {4: 1}}, {WINDOWS: {3}, ACL: {4}}, 80)

    def test_no_production_changes_skip_only_changed_line_gate(self):
        self.assertIsNone(gate.check_changed({WINDOWS: {3: 1}, ACL: {4: 1}}, {}, 80))
        self.assertEqual(gate.changed_lines('+++ b/crates/a/src/sink_tests.rs\n@@ -0,0 +1 @@\n+x\n'), {})

    def test_missing_lcov_source_fails_even_without_production_changes(self):
        with self.assertRaisesRegex(ValueError, 'executable LCOV lines'):
            gate.check_changed({}, {}, 80)

    def test_unknown_diff_path_is_not_silently_no_changes(self):
        with self.assertRaisesRegex(ValueError, 'unrecognized git diff source path'):
            gate.changed_lines('+++ "b/crates/a/src/unknown.rs"\n@@ -0,0 +1 @@\n+x\n')

    def test_added_and_modified_line_ranges_come_from_zero_context_diff(self):
        diff = '+++ b/' + WINDOWS + '\n@@ -1,2 +3,2 @@\n+x\n+y\n+++ b/' + ACL + '\n@@ -0,0 +4 @@\n+z\n'
        self.assertEqual(gate.changed_lines(diff), {WINDOWS: {3, 4}, ACL: {4}})


if __name__ == '__main__':
    unittest.main()
