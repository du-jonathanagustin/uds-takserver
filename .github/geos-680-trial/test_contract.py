# Copyright 2026 uds-takserver authors
# SPDX-License-Identifier: GPL-3.0-only
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('hosted_geos_trial', HERE/'run.py')
TRIAL = importlib.util.module_from_spec(spec)
spec.loader.exec_module(TRIAL)


class Contract(unittest.TestCase):
    def test_four_implementation_and_existing_recipe_helpers_are_exact(self):
        lock = json.loads((HERE/'lock.json').read_text())
        self.assertEqual(len(lock['source_sha256']), 10)
        for path, expected in lock['source_sha256'].items():
            self.assertEqual(TRIAL.sha((TRIAL.ROOT/path).read_bytes()), expected, path)
        self.assertEqual(lock['source_commit'],'7de0765783b130e202fa57067692c8a00ed42b6f')

    def test_current_package_records_must_match_every_retained_identity_field(self):
        expected = json.loads((HERE/'lock.json').read_text())['packages']['make']
        raw = ('\n'.join(k+': '+v for k,v in expected.items())+'\n').encode()
        self.assertEqual(TRIAL.package_matches(raw,expected),expected)
        for key in expected:
            with self.subTest(key=key), self.assertRaises(TRIAL.Rejected):
                TRIAL.package_matches(raw.replace((key+': '+expected[key]).encode(),(key+': changed').encode()),expected)

    def test_all_printed_payloads_are_hash_bounded_and_official(self):
        raw = b"'http://deb.debian.org/debian/pool/main/m/make-dfsg/make_4.4.1-2_amd64.deb' make_4.4.1-2_amd64.deb 463104 SHA256:"+b'a'*64+b'\n'
        self.assertEqual(TRIAL.download_plan(raw,463104)[0]['bytes'],463104)
        for value in (b'',raw+raw,raw.replace(b'deb.debian.org',b'foreign.invalid'),raw.replace(b'SHA256:',b'MD5Sum:'),raw.replace(b'make_4.4.1-2_amd64.deb 463104',b'../escape.deb 463104')):
            with self.subTest(value=value), self.assertRaises(TRIAL.Rejected):
                TRIAL.download_plan(value,463104)
        with self.assertRaises(TRIAL.Rejected):
            TRIAL.download_plan(raw,463103)

    def test_signed_release_envelope_and_current_date_expiry_are_required(self):
        raw = b'-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nOrigin: Debian\nCodename: trixie-security\nDate: Tue, 17 Nov 2026 05:44:28 UTC\nValid-Until: Tue, 24 Nov 2026 05:44:28 UTC\n\n-----BEGIN PGP SIGNATURE-----\n'
        now = 1794897900
        self.assertEqual(TRIAL.release_identity(raw,now)['codename'],'trixie-security')
        for value,when in ((raw.replace(b'Origin: Debian',b'Origin: Foreign'),now),
                           (raw.replace(b'Valid-Until: Tue, 24 Nov 2026 05:44:28 UTC\n',b''),now),
                           (raw,now+8*86400),(raw,now-86400),(raw.replace(b'PGP SIGNED MESSAGE',b'INVALID'),now)):
            with self.subTest(value=value,when=when), self.assertRaises(TRIAL.Rejected):
                TRIAL.release_identity(value,when)

    def test_identity_embedded_script_parses_and_tab_split_is_actual_tab(self):
        compile(TRIAL.IDENTITY,'builder-identity','exec')
        self.assertIn('line.split(chr(9))',TRIAL.IDENTITY)
        self.assertNotIn('Check-Valid-Until=false',' '.join(TRIAL.APT_OPTIONS))
        self.assertNotIn('snapshot.debian',TRIAL.SOURCES)
        self.assertIn('Acquire::Check-Valid-Until=true',TRIAL.APT_OPTIONS)

    def test_failure_facts_are_allowlisted_without_retaining_child_payloads(self):
        raw = (b'Historical GEOS 3.4.3 source-built PIC and geometry/error controls passed\n'
               b'test_only_active_true_definitions_count (test_build.IntegerFeatureGuards.test_only_active_true_definitions_count) ... FAIL\n'
               b'test_foreign (test_build.Foreign.test_foreign) ... ERROR\n'
               b'ValueError: integer configuration qualification changed\n'
               b'ValueError: SECRET_PAYLOAD\nFileNotFoundError: SECRET_PAYLOAD\n'
               b'Ran 18 tests in 2.3s\n\nFAILED (failures=1)\n')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'commands.json').write_text('[{"name":"int64-after-arithmetic","args":["SECRET_PAYLOAD"]}]')
            (root/'int64-after-arithmetic.log').write_text('SECRET_PAYLOAD')
            (root/'complete.json').write_text('{"unqualified":true}')
            result = TRIAL.failure_metadata(raw,root,'profile-unit-tests')
        self.assertNotIn('SECRET_PAYLOAD',json.dumps(result))
        self.assertEqual(result['reported_test_count'],18)
        self.assertEqual(len(result['test_statuses']),1)
        self.assertEqual(result['recipe_failure_codes'],['integer_qualification_changed'])
        self.assertEqual(result['last_producer_command'],'int64-after-arithmetic')
        self.assertTrue(result['producer_completion']['present'])
        self.assertEqual(result['producer_completion']['qualification'],'unqualified_failure_evidence')
        self.assertFalse(result['qualified_component_result'])

    def test_unknown_commands_bounds_and_symlinks_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'commands.json').write_text('[{"name":"untrusted-payload"}]')
            result = TRIAL.failure_metadata(b'',root,'profile-build')
            self.assertEqual(result['last_producer_command'],'unknown')
            self.assertNotIn('untrusted-payload',json.dumps(result))
            self.assertFalse(result['producer_completion']['present'])
            (root/'commands.json').unlink()
            (root/'commands.json').symlink_to(HERE/'lock.json')
            with self.assertRaises(TRIAL.Rejected):TRIAL.failure_metadata(b'',root,'profile-build')
            with self.assertRaises(TRIAL.Rejected):TRIAL.failure_metadata(b'x'*(16*1024**2+1),root,'profile-build')


if __name__ == '__main__':
    unittest.main()
