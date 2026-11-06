#!/usr/bin/env python3
"""Offline entry gates; no real SSH, USB or vendor module imports."""
import json
import os
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import restore_entry as e


class EntryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in ('DEFAULT_BACKUP', 'VENDOR_DA'):
            patcher = patch.object(e, name, self.root / ('absent-' + name))
            patcher.start()
            self.addCleanup(patcher.stop)
        self.identity = {'source': 'original', 'da': 'pinned', 'host': 'patched', 'tools': 'current', 'unit': 'this-unit'}

    def receipt(self, mode='identical', status='VERIFIED'):
        run = self.root / 'run'
        run.mkdir(exist_ok=True)
        receipt = {'schema': 1, 'run': str(run.resolve()), 'mode': mode, 'status': status,
                   'identity': self.identity, 'created': e.time.time(), 'slot': 'b'}
        (run / 'receipt.json').write_text(json.dumps(receipt))
        return run, receipt

    def test_missing_or_truncated_receipt_is_rejected(self):
        with self.assertRaises((ValueError, OSError)):
            e.load_receipt(self.root, self.identity, 'identical')
        (self.root / 'receipt.json').write_text('{')
        with self.assertRaises(ValueError):
            e.load_receipt(self.root, self.identity, 'identical')

    def test_wrong_receipt_mode_status_identity_slot_path_schema_rejected(self):
        run, receipt = self.receipt()
        for key, value in [('schema', 2), ('mode', 'test'), ('status', 'STARTED'), ('slot', 'a'),
                           ('run', str(self.root)), ('identity', {})]:
            bad = {**receipt, key: value}
            (run / 'receipt.json').write_text(json.dumps(bad))
            with self.subTest(key=key), self.assertRaises(ValueError):
                e.load_receipt(run, self.identity, 'identical')

    def test_identical_requires_complete_journal_not_receipt_claim(self):
        run, _ = self.receipt()
        with self.assertRaises((ValueError, OSError)):
            e.load_receipt(run, self.identity, 'identical')

    def test_restore_rejects_successful_test_and_consumed_run(self):
        for status in ('VERIFIED', 'RESTORE_ATTEMPTED', 'STARTED'):
            run, _ = self.receipt('test', status)
            with self.assertRaises(ValueError):
                e.load_receipt(run, self.identity, 'restore')

    def complete_journal(self, run, receipt, mode='identical'):
        folder = run / 'bounded-restore-test'
        folder.mkdir(exist_ok=True)
        events = [{'mode': mode, 'target_offset': e.engine.ADDRESS, 'target_length': e.engine.SIZE}]
        expected = [('rootfs_sig_a', e.engine.ADDRESS, e.engine.SIZE, e.engine.ORIGINAL), *e.engine.GUARDS]
        if mode == 'identical':
            for label in ('before', 'after-original'):
                if label == 'after-original':
                    events += [{'write_attempt': 'original', 'sha256': e.engine.ORIGINAL},
                               {'write_result': 'original', 'acknowledged': True}]
                events += [{'read': label, 'name': name, 'acknowledged': True, 'length': size, 'sha256': sha}
                           for name, _, size, sha in expected]
            events.append({'status': 'ORIGINAL_AND_GUARDS_VERIFIED'})
        else:
            events += [{'write_attempt': 'staged', 'sha256': e.engine.STAGED},
                       {'status': 'STOP_UNVERIFIED_NO_RETRY_OR_REBOOT'}]
        raw = ''.join(json.dumps(event)+'\n' for event in events).encode()
        (folder / 'journal.jsonl').write_bytes(raw)
        receipt.update(journal='bounded-restore-test/journal.jsonl', journal_hash=e.digest(raw))
        (run / 'receipt.json').write_text(json.dumps(receipt))
        return events

    def test_complete_identical_evidence_is_accepted_but_tampering_is_not(self):
        run, receipt = self.receipt()
        self.complete_journal(run, receipt)
        e.load_receipt(run, self.identity, 'identical')
        journal = run / receipt['journal']
        journal.write_bytes(journal.read_bytes()+b'{}\n')
        with self.assertRaises(ValueError):
            e.load_receipt(run, self.identity, 'identical')

    def test_read_claim_wrong_hash_false_ack_missing_or_stale_is_rejected(self):
        run, receipt = self.receipt()
        for kind in ('hash', 'ack', 'missing', 'stale'):
            events = self.complete_journal(run, receipt)
            if kind == 'hash':
                events[1]['sha256'] = 'wrong'
            elif kind == 'ack':
                events[1]['acknowledged'] = False
            elif kind == 'missing':
                events.pop(1)
            else:
                receipt['created'] = 0
            raw = ''.join(json.dumps(v)+'\n' for v in events).encode()
            (run / receipt['journal']).write_bytes(raw)
            receipt['journal_hash'] = e.digest(raw)
            (run / 'receipt.json').write_text(json.dumps(receipt))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                e.load_receipt(run, self.identity, 'identical')

    def test_stopped_staged_run_is_restore_eligible_but_restore_attempt_is_not(self):
        run, receipt = self.receipt('test', 'STOP_UNVERIFIED')
        self.complete_journal(run, receipt, 'test')
        e.load_receipt(run, self.identity, 'restore')
        receipt['status'] = 'RESTORE_ATTEMPTED'
        (run / 'receipt.json').write_text(json.dumps(receipt))
        with self.assertRaises(ValueError):
            e.load_receipt(run, self.identity, 'restore')

    def test_restore_claim_is_exclusive_and_receipt_cannot_reenable_it(self):
        run, receipt = self.receipt('test', 'STOP_UNVERIFIED')
        self.complete_journal(run, receipt, 'test')
        e.claim_restore(run, self.root)
        with self.assertRaises(FileExistsError):
            e.claim_restore(run, self.root / 'second')
        with self.assertRaises(ValueError):
            e.load_receipt(run, self.identity, 'restore')

    def test_uart_must_be_existing_nonempty_and_recent(self):
        path = self.root / 'uart.log'
        with self.assertRaises((ValueError, OSError)):
            e.check_uart(path)
        path.write_bytes(b'')
        with self.assertRaises(ValueError):
            e.check_uart(path)
        path.write_bytes(b'boot')
        e.check_uart(path)
        with patch.object(e.time, 'time', return_value=e.time.time()+120), self.assertRaises(ValueError):
            e.check_uart(path)

    def test_false_or_wrong_unit_read_cannot_pass(self):
        part = {'offset': 0, 'size': 4, 'sha256': e.digest(b'unit')}
        def read(**kw):
            Path(kw['filename']).write_bytes(b'unit')
            return False
        with self.assertRaises(ValueError):
            e.check_unit(Mock(readflash=read), part, self.root)

    def test_dry_run_never_uses_ssh_or_hardware(self):
        loader = self.root / 'loader'
        loader.write_bytes(b'synthetic DA')
        with patch.object(e.sys, 'argv', ['restore_entry.py', 'identical', '--backup', str(self.root), '--loader', str(loader)]), patch.object(e, 'local_inputs', return_value=({}, [], b'', {})), patch.object(e, 'active_slot', side_effect=AssertionError('SSH forbidden')), patch.object(e, 'open_da', side_effect=AssertionError('USB forbidden')):
            e.main()


class ExecutionTests(unittest.TestCase):
    def setUp(self):
        import types
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.archive = self.root / 'complete-captured-partitions.tar'
        self.archive.write_bytes(b'verified synthetic archive')
        (self.root / 'ARCHIVE.sha256').write_text(e.sha256_file(self.archive))
        self.copy = self.root / 'copy.tar'
        self.copy.write_bytes(self.archive.read_bytes())
        self.uart = self.root / 'uart.log'
        self.uart.write_bytes(b'RX')
        self.loader = self.root / 'loader'
        self.loader.write_bytes(b'not an actual DA')
        self.xml = self.root / 'xml.py'
        self.xml.write_bytes(b'synthetic host')
        self.identity = {'host': e.sha256_file(self.xml)}
        self.mtk = types.SimpleNamespace(daloader=Mock(), port=Mock())
        self.engine = Mock()
        patches = [patch.object(e, 'local_inputs', return_value=({'proinfo': {}}, [], b'original', self.identity)),
                   patch.object(e, 'PRIVATE', self.root / 'private'),
                   patch.object(e, 'active_slot', return_value='b'),
                   patch.object(e, 'open_da', return_value=self.mtk),
                   patch.object(e, 'check_unit'),
                   patch.object(e.sys, 'prefix', str(e.MTK_HOME / 'venv')),  # ensure_venv compares sys.prefix (#8)
                   patch.object(e.engine, 'run_session', self.engine),
                   patch.dict(e.sys.modules, {'mtkclient.Library.DA.xmlflash.xml_lib': types.SimpleNamespace(__file__=str(self.xml))}),
                   patch('builtins.input', return_value='WRITE identical rootfs_sig_a SAME-DISK')]
        self.mocks = [p.start() for p in patches]
        for p in patches:
            self.addCleanup(p.stop)
        self.argv = ['restore_entry.py', 'identical', '--write', '--backup', str(self.root),
                     '--loader', str(self.loader), '--backup-copy', str(self.copy), '--uart-log', str(self.uart)]

    def run_main(self):
        with patch.object(e.sys, 'argv', self.argv), contextlib.redirect_stdout(io.StringIO()):
            e.main()

    def test_restore_reentry_avoids_ssh_and_second_claim_cannot_connect(self):
        self.argv[1] = 'restore'
        self.argv += ['--resume', str(self.root)]
        self.mocks[2].side_effect = AssertionError('SSH forbidden during recovery')
        with patch.object(e, 'load_receipt', return_value={'status': 'STOP_UNVERIFIED'}), patch('builtins.input', return_value='WRITE restore rootfs_sig_a SAME-DISK'):
            self.run_main()
            self.mocks[3].assert_called_once()
            self.engine.assert_called_once()
            with self.assertRaises(FileExistsError):
                self.run_main()
            self.mocks[3].assert_called_once()
            self.engine.assert_called_once()

    def test_live_slot_rejection_prevents_connection(self):
        self.mocks[2].return_value = 'a'
        with self.assertRaises(ValueError):
            self.run_main()
        self.mocks[3].assert_not_called()
        self.engine.assert_not_called()

    def test_refused_confirmation_prevents_connection(self):
        with patch('builtins.input', return_value='no'), self.assertRaises(ValueError):
            self.run_main()
        self.mocks[3].assert_not_called()

    def test_hardlinked_archive_is_not_a_second_copy(self):
        self.copy.unlink()
        os.link(self.archive, self.copy)
        with self.assertRaises(ValueError):
            self.run_main()
        self.mocks[3].assert_not_called()

    def test_wrong_loaded_host_stops_before_engine_and_closes_port(self):
        self.identity['host'] = 'wrong'
        with self.assertRaises(ValueError):
            self.run_main()
        self.engine.assert_not_called()
        self.mtk.port.close.assert_called_once()

    def test_unit_mismatch_stops_before_engine(self):
        self.mocks[4].side_effect = ValueError('wrong unit')
        with self.assertRaises(ValueError):
            self.run_main()
        self.engine.assert_not_called()
        self.mtk.port.close.assert_called_once()

    def test_execution_passes_only_fixed_mode_and_source_to_engine(self):
        self.run_main()
        self.engine.assert_called_once()
        self.assertEqual(self.engine.call_args.kwargs, {'mode': 'identical'})
        self.assertEqual(self.engine.call_args.args[:2], (self.mtk.daloader, b'original'))
        self.mtk.port.close.assert_called_once()


if __name__ == '__main__':
    unittest.main()
