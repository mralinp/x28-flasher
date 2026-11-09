#!/usr/bin/env python3
"""Offline tests of the entry gates; no hardware, SSH, USB or private data."""
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import sys

import slot_entry as e
import slot_session

IDENT = {'target': 'rootfs_a', 'original': 'o' * 64, 'candidate': 'c' * 64, 'rootfs_a': 'c' * 64, 'da': 'd' * 64,
         'host': 'h' * 64, 'tools': 't' * 64, 'unit': 'u' * 64}
SPEC = slot_session.Spec('rootfs_a', 0x13600000, 0x4000000, 'o' * 64, (), lambda o, c: None, 'c' * 64, ())


class PriorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make(self, mode='identical', status='VERIFIED', attempts=None, final='TARGET_AND_GUARDS_VERIFIED', age=0,
             ident=IDENT, header=None, ack=True, sha=None):
        self.n = getattr(self, 'n', 0) + 1
        run = (self.root / f'run-{self.n}').resolve()
        (run / 'inner').mkdir(parents=True)
        head = header or {'mode': mode, 'target': 'rootfs_a', 'target_offset': SPEC.addr, 'target_length': SPEC.size,
                          'candidate_sha256': SPEC.candidate_sha if mode == 'write' else None}
        image = sha or (SPEC.candidate_sha if mode == 'write' else SPEC.original_sha)
        attempts = [mode] if attempts is None else attempts
        events = [head] + [{'write_attempt': a, 'sha256': image} for a in attempts]
        if attempts:
            events.append({'write_result': mode, 'acknowledged': ack})
        events.append({'status': final})
        journal = run / 'inner' / 'journal.jsonl'
        journal.write_text(''.join(json.dumps(x) + '\n' for x in events))
        receipt = {'schema': 2, 'run': str(run), 'target': 'rootfs_a', 'mode': mode, 'status': status, 'identity': ident,
                   'created': time.time() - age, 'journal': 'inner/journal.jsonl', 'journal_hash': e.digest(journal.read_bytes())}
        (run / 'receipt.json').write_text(json.dumps(receipt))
        return run

    def test_good_verified_prior_is_accepted(self):
        e.load_prior(self.make(), IDENT, SPEC, 'identical', True)
        e.load_prior(self.make('write'), IDENT, SPEC, 'write', True)

    def test_each_binding_failure_is_refused(self):
        cases = {
            'stale': dict(age=90000),
            'unverified': dict(status='STOP_UNVERIFIED'),
            'other image': dict(ident={**IDENT, 'candidate': 'x' * 64}),
            'other unit': dict(ident={**IDENT, 'unit': 'x' * 64}),
            'other host': dict(ident={**IDENT, 'host': 'x' * 64}),
            'other rootfs_a': dict(ident={**IDENT, 'rootfs_a': 'x' * 64}),
            'two writes': dict(attempts=['identical', 'identical']),
            'wrong write': dict(attempts=['write']),
            'wrong bytes written': dict(sha='x' * 64),
            'wrong offset': dict(header={'mode': 'identical', 'target': 'rootfs_a', 'target_offset': 0x700000,
                                         'target_length': SPEC.size, 'candidate_sha256': None}),
            'unacknowledged': dict(ack=False),
            'no final verify': dict(final='STOP_UNVERIFIED_NO_RETRY_OR_REBOOT'),
        }
        for name, kw in cases.items():
            with self.assertRaises(ValueError, msg=name):
                e.load_prior(self.make(**kw), IDENT, SPEC, 'identical', True)

    def test_edited_journal_or_wrong_mode_or_target_is_refused(self):
        run = self.make()
        (run / 'inner' / 'journal.jsonl').write_text('{"tampered": 1}\n')
        with self.assertRaises(ValueError):
            e.load_prior(run, IDENT, SPEC, 'identical', True)
        run = self.make()
        with self.assertRaises(ValueError):
            e.load_prior(run, IDENT, SPEC, 'write', True)
        with self.assertRaises(ValueError):
            e.load_prior(run, IDENT, SPEC._replace(name='misc'), 'identical', True)

    def test_a_claimed_run_is_spent_even_as_a_verified_prior(self):
        run = self.make('write')
        (run / 'restore-claim.json').write_text('{}')
        for verified in (True, False):
            with self.assertRaises(ValueError):
                e.load_prior(run, IDENT, SPEC, 'write', verified)

    def test_resume_accepts_a_stopped_write_once(self):
        run = self.make('write', status='STOP_UNVERIFIED', final='STOP_UNVERIFIED_NO_RETRY_OR_REBOOT')
        e.load_prior(run, IDENT, SPEC, 'write', False)
        run = self.make('write', status='RESTORE_ATTEMPTED', final='STOP_UNVERIFIED_NO_RETRY_OR_REBOOT')
        with self.assertRaises(ValueError):
            e.load_prior(run, IDENT, SPEC, 'write', False)

    def test_a_write_that_never_started_has_nothing_to_resume(self):
        run = self.make('write', status='STOP_UNVERIFIED', attempts=[], final='STOP_UNVERIFIED_NO_RETRY_OR_REBOOT')
        with self.assertRaises(ValueError):
            e.load_prior(run, IDENT, SPEC, 'write', False)


class GateTests(unittest.TestCase):
    def run_main(self, *argv):
        with patch.object(sys, 'argv', ['slot_entry.py', *argv]):
            e.main()

    def test_sequencing_table(self):
        flags = lambda t, m: [p[0] for p in e.PRIOR[(t, m)]]
        self.assertEqual(flags('rootfs_a', 'identical'), [])
        self.assertEqual(flags('rootfs_a', 'write'), [])  # the rehearsal is optional here...
        self.assertEqual([o[0] for o in e.OPTIONAL_PRIOR[('rootfs_a', 'write')]], ['prior_identical'])  # ...and checked like a required one when given
        self.assertEqual(sorted(flags('misc', 'write')), ['prior_identical', 'prior_rootfs_a'])
        self.assertEqual(flags('misc', 'identical'), ['prior_rootfs_a'])
        self.assertEqual((flags('rootfs_a', 'restore'), flags('misc', 'restore')), (['resume'], ['resume']))
        self.assertEqual((flags('rootfs_b', 'identical'), flags('rootfs_b', 'write'), flags('rootfs_b', 'restore')), ([], [], ['resume']))  # #89
        self.assertEqual([o[0] for o in e.OPTIONAL_PRIOR[('rootfs_b', 'write')]], ['prior_identical'])
        self.assertTrue(all(p[3] for k, v in e.PRIOR.items() if k[1] != 'restore' for p in v))
        self.assertTrue(all(not p[3] for k, v in e.PRIOR.items() if k[1] == 'restore' for p in v))

    def test_missing_or_misplaced_prior_flags_refuse_before_touching_data(self):
        for argv in (('rootfs_a', 'write'), ('misc', 'write', '--prior-identical', '/x'), ('misc', 'restore'),
                     ('rootfs_a', 'identical', '--resume', '/x'), ('rootfs_a', 'write', '--prior-identical', '/x', '--prior-rootfs-a', '/y'),
                     ('misc', 'identical', '--resume', '/x', '--prior-rootfs-a', '/y'), ('rootfs_a', 'identical')):
            with self.assertRaises(ValueError, msg=argv):
                self.run_main(*argv)

    def test_phrase_names_the_bytes_that_land_and_the_rootfs_a_misc_may_select(self):
        a, m = slot_session.rootfs_a_spec('abcdef1234567890' * 4), slot_session.misc_spec('abcdef1234567890' * 4)
        self.assertEqual(e.phrase(a, 'write', a.candidate_sha, False), 'WRITE write rootfs_a abcdef123456')
        self.assertEqual(e.phrase(a, 'restore', a.candidate_sha, False), 'WRITE restore rootfs_a 5f0c997ddbc0')
        self.assertIn('SAME-DISK', e.phrase(a, 'write', a.candidate_sha, True))
        text = e.phrase(m, 'write', 'abcdef1234567890' * 4, False)
        self.assertEqual(text, 'WRITE write misc cd512c873dd4 ROOTFS-A abcdef123456 BROM-ROUTE-PROVEN')
        self.assertIn('d8a5b852d233', e.phrase(m, 'identical', 'a' * 64, False))
        self.assertNotIn('BROM', e.phrase(a, 'identical', 'a' * 64, False))


    def test_base_phrase_names_the_base_and_that_misc_selects_a(self):
        b = slot_session.rootfs_a_spec('abcdef1234567890' * 4, '0123456789ab' * 5 + '0123', 0x40000)
        self.assertEqual(e.phrase(b, 'write', b.candidate_sha, False), 'WRITE write rootfs_a abcdef123456 BASE 0123456789ab MISC-SELECTS-A')
        self.assertEqual(e.phrase(b, 'identical', 'a' * 64, False), 'WRITE identical rootfs_a 0123456789ab BASE 0123456789ab MISC-SELECTS-A')
        self.assertEqual(e.phrase(b, 'restore', 'a' * 64, False), 'WRITE restore rootfs_a 5f0c997ddbc0')

    def test_prior_identical_of_a_base_run_must_name_the_base(self):
        base = slot_session.rootfs_a_spec('c' * 64, 'b' * 64, 0x40000)
        t = PriorTests('test_good_verified_prior_is_accepted')
        t.setUp()
        self.addCleanup(t.tmp.cleanup)
        ident = {**IDENT, 'base': 'b' * 64}
        e.load_prior(t.make(sha='b' * 64, ident=ident), ident, base, 'identical', True)
        with self.assertRaises(ValueError):
            e.load_prior(t.make(sha=base.original_sha, ident=ident), ident, base, 'identical', True)
        with self.assertRaises(ValueError):
            e.load_prior(t.make(sha='b' * 64, ident=IDENT), ident, base, 'identical', True)  # receipt without the base


    def test_main_never_rebinds_the_base_image(self):
        # Once shadowed by the usb-probe directory, run_session got a Path as the base and every --write failed after the claim.
        import ast
        main = next(n for n in ast.parse(Path(e.__file__).read_text()).body if isinstance(n, ast.FunctionDef) and n.name == 'main')
        stores = [n for n in ast.walk(main) if isinstance(n, ast.Name) and n.id == 'base' and isinstance(n.ctx, ast.Store)]
        self.assertEqual(len(stores), 1)


    def test_base_head_is_layout_plus_rootfs_lebs_and_refuses_overlay_blocks(self):
        peb = 0x40000
        manifest = {'peb_bytes': peb, 'layout_copies': 2, 'populated_lebs': [3, 1], 'volumes': ['rootfs', 'rootfs_data']}
        def vid(vol):
            return b'UBI!' + b'\0' * 4 + vol.to_bytes(4, 'big')
        image = bytearray(b'\xff' * (8 * peb))
        for n, vol in enumerate((0x7fffefff, 0x7fffefff, 0, 0, 0, 1, 1, 1)):
            image[n * peb + 4096:n * peb + 4108] = vid(vol)
        self.assertEqual(e.base_head(bytes(image), manifest), 5 * peb)
        image[4 * peb + 4096:4 * peb + 4108] = vid(1)  # overlay block inside the claimed head
        with self.assertRaises(ValueError):
            e.base_head(bytes(image), manifest)
        for bad in ({**manifest, 'volumes': ['rootfs_data', 'rootfs']}, {**manifest, 'populated_lebs': [30, 1]}, {**manifest, 'peb_bytes': 4096}):
            with self.assertRaises(ValueError):
                e.base_head(bytes(8 * peb), bad)

    def test_base_head_of_the_real_first_native_image(self):
        base = Path(e.__file__).resolve().parents[2] / 'private/build/native-ubi-104'
        if not base.is_dir():
            self.skipTest('private build output not present')
        head = e.base_head((base / 'rootfs-a-experimental.bin').read_bytes(), json.loads((base / 'manifest.json').read_text()))
        self.assertEqual(head, 33 * 0x40000)


class RootfsBEntryTests(unittest.TestCase):
    def test_phrase_names_rootfs_b_and_the_bytes_that_land(self):
        b = slot_session.rootfs_b_spec('abcdef1234567890' * 4)
        self.assertEqual(e.phrase(b, 'write', b.candidate_sha, False), 'WRITE write rootfs_b abcdef123456')
        self.assertEqual(e.phrase(b, 'restore', b.candidate_sha, False), 'WRITE restore rootfs_b c4e3f3d25b3a')  # the backup's stock rootfs_b
        self.assertNotIn('MISC-SELECTS-A', e.phrase(b, 'write', b.candidate_sha, False))

    def test_no_ssh_and_no_uart_are_allowed_for_rootfs_b_but_not_restore(self):
        b = slot_session.rootfs_b_spec('c' * 64)
        e.check_no_ssh(True, 'rootfs_b', 'write', b)
        e.check_no_uart(True, 'rootfs_b', None)
        with self.assertRaises(ValueError):
            e.check_no_ssh(True, 'rootfs_b', 'restore', b)


class NoSshTests(unittest.TestCase):
    def test_phrase_names_the_missing_ssh_check(self):
        a = slot_session.rootfs_a_spec('abcdef1234567890' * 4)
        self.assertEqual(e.phrase(a, 'write', a.candidate_sha, False, True), 'WRITE write rootfs_a abcdef123456 NO-SSH')
        self.assertEqual(e.phrase(a, 'write', a.candidate_sha, True, True), 'WRITE write rootfs_a abcdef123456 NO-SSH SAME-DISK')
        self.assertNotIn('NO-SSH', e.phrase(a, 'write', a.candidate_sha, False))

    def test_no_ssh_only_for_rootfs_a_from_stock_b(self):
        plain = slot_session.rootfs_a_spec('c' * 64)
        based = slot_session.rootfs_a_spec('c' * 64, 'b' * 64, 0x40000)
        e.check_no_ssh(True, 'rootfs_a', 'write', plain)
        e.check_no_ssh(True, 'rootfs_a', 'identical', plain)
        e.check_no_ssh(False, 'misc', 'restore', based)
        for args in (('misc', 'write', plain), ('rootfs_a', 'restore', plain), ('rootfs_a', 'write', based), ('rootfs_a', 'identical', based)):
            with self.assertRaises(ValueError, msg=args[:2]):
                e.check_no_ssh(True, *args)


class NoUartTests(unittest.TestCase):
    def test_phrase_names_the_missing_uart(self):
        a = slot_session.rootfs_a_spec('abcdef1234567890' * 4)
        self.assertEqual(e.phrase(a, 'write', a.candidate_sha, False, False, True), 'WRITE write rootfs_a abcdef123456 NO-UART')
        self.assertEqual(e.phrase(a, 'write', a.candidate_sha, True, True, True), 'WRITE write rootfs_a abcdef123456 NO-SSH NO-UART SAME-DISK')
        self.assertNotIn('NO-UART', e.phrase(a, 'write', a.candidate_sha, False, True))

    def test_no_uart_only_for_rootfs_a_and_not_with_a_log(self):
        e.check_no_uart(True, 'rootfs_a', None)
        e.check_no_uart(False, 'misc', Path('u.log'))
        for target, log in (('misc', None), ('rootfs_a', Path('u.log'))):
            with self.assertRaises(ValueError, msg=target):
                e.check_no_uart(True, target, log)


if __name__ == '__main__':
    unittest.main()
