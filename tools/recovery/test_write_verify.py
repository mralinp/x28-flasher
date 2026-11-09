#!/usr/bin/env python3
"""Host-only restore safety tests: fake DA, synthetic files, no SSH/USB or firmware imports."""
import contextlib
import hashlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
stub = types.ModuleType('read_by_name')
stub.connect = Mock(side_effect=AssertionError('real DA connection forbidden'))
stub.problems = Mock()
with patch.dict(sys.modules, {'read_by_name': stub}):
    spec = importlib.util.spec_from_file_location('restore', Path(__file__).with_name('write_verify.py'))
    restore = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(restore)


class RestoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.cwd = Path.cwd()
        self.backup_arg = self.root
        self.addCleanup(os.chdir, self.cwd)
        self.parts, self.data = [], {}
        for index, name in enumerate(['misc', 'mcupm_a', 'lk_a', 'tee_a', 'lk_b', 'boot_para']):
            data = bytes([index + 1]) * 8192
            image = self.root / (name + '.bin')
            image.write_bytes(data)
            self.parts.append(dict(index=index, name=name, offset=index * 8192, size=8192, erase_size=4096,
                                   image=image, sha256=hashlib.sha256(data).hexdigest()))
            self.data[index * 8192] = data
        self.target = self.parts[2]
        self.writes = 0
        self.write_result = self.read_result = True
        self.after_target = self.after_guard = self.read_shape = None
        self.source_seen = None
        self.write_error = self.fail_post_read = False
        self.loader = self.root / 'da.bin'
        self.loader.write_bytes(b'synthetic loader, never executed')
        self.da = types.SimpleNamespace(readflash=self.read, writeflash=self.write)
        self.mtk = types.SimpleNamespace(daloader=self.da, port=Mock())
        self.connect = Mock(return_value=self.mtk)
        self.problems = Mock()
        stub.connect, stub.problems = self.connect, self.problems
        self.patch('DEFAULT_BACKUP', self.root / 'absent-default-backup')
        self.patch('backup_table', lambda _: self.parts)
        self.patch('active_slot', lambda table: 'b')
        self.patch('probe_dir', lambda: self.root)
        self.addCleanup(patch.stopall)

    def patch(self, name, value, **kwargs):
        patch.object(restore, name, value, **kwargs).start()

    def read(self, addr, length, filename, **kwargs):
        data = self.data[addr]
        if self.writes and addr == self.target['offset'] and self.after_target:
            data = b'X' * length
        if self.writes and addr == self.parts[1]['offset'] and self.after_guard:
            data = b'X' * length
        if self.read_shape == 'short':
            data = data[:-1]
        elif self.read_shape == 'long':
            data += b'X'
        Path(filename).write_bytes(data)
        return self.read_result

    def write(self, addr, length, filename, **kwargs):
        self.writes += 1
        if self.write_error:
            raise OSError('simulated USB failure')
        if self.fail_post_read:
            self.read_result = False
        self.source_seen = Path(filename)
        if self.write_result:
            self.data[addr] = self.source_seen.read_bytes()
        return self.write_result

    def run_main(self, *args):
        argv = ['write_verify.py', 'lk_a', '--backup', str(self.backup_arg), '--loader', str(self.loader), *args]
        self.output = io.StringIO()
        with patch.dict(sys.modules, {'read_by_name': stub}), patch.object(sys, 'argv', argv), contextlib.redirect_stdout(self.output):
            try:
                restore.main()
            except SystemExit as error:
                return error.code
        return 0

    def test_dry_run_never_connects(self):
        self.assertEqual(self.run_main(), 0)
        self.connect.assert_not_called()
        self.assertEqual(self.writes, 0)

    def test_success_requires_write_and_all_readbacks(self):
        self.assertEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 1)
        self.mtk.port.close.assert_called_once()

    def test_failed_write_with_matching_data_is_not_success(self):
        self.write_result = False
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 1)
        self.assertNotIn("IDENTICAL REWRITE VERIFIED", self.output.getvalue())
        self.assertNotIn("boot it normally", self.output.getvalue())

    def test_read_failure_with_matching_file_blocks_write(self):
        self.read_result = False
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 0)

    def test_wrong_read_lengths_block_write(self):
        for shape in ['short', 'long']:
            with self.subTest(shape=shape):
                self.read_shape = shape
                self.assertNotEqual(self.run_main('--write'), 0)
                self.assertEqual(self.writes, 0)

    def test_target_mismatch_after_write_never_retries(self):
        self.after_target = True
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 1)

    def test_guard_change_after_write_never_retries(self):
        self.after_guard = True
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 1)

    def test_incomplete_or_duplicate_layout_blocks_connection(self):
        original = self.parts[:]
        for name in ['lk_b', 'misc', 'boot_para', 'mcupm_a', 'tee_a', 'duplicate']:
            with self.subTest(name=name):
                self.parts = (original + [original[0]]) if name == 'duplicate' else [p for p in original if p['name'] != name]
                self.assertNotEqual(self.run_main('--write'), 0)
                self.connect.assert_not_called()
        self.parts = original

    def test_relative_source_survives_probe_directory_change(self):
        os.chdir(self.root.parent)  # same drive as the temp files (Windows CI: checkout on D:, temp on C:)
        self.target['image'] = Path(os.path.relpath(self.target['image']))
        self.assertEqual(self.run_main('--write'), 0)
        self.assertTrue(self.source_seen.is_absolute())

    def test_wrong_active_slot_blocks_connection(self):
        self.patch('active_slot', lambda table: 'a')
        self.assertNotEqual(self.run_main('--write'), 0)
        self.connect.assert_not_called()

    def test_corrupt_backup_blocks_connection(self):
        self.target['image'].write_bytes(b'X' * 8192)
        self.assertNotEqual(self.run_main('--write'), 0)
        self.connect.assert_not_called()

    def test_refuses_non_slot_a_target(self):
        with patch.object(sys, 'argv', ['write_verify.py', 'misc', '--backup', str(self.root)]), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                restore.main()
        self.connect.assert_not_called()

    def test_relative_backup_keeps_guard_mismatch_diagnostics(self):
        os.chdir(self.root.parent)
        self.backup_arg = Path(os.path.relpath(self.root))
        self.patch('backup_table', lambda backup: [
            {**p, 'image': backup / Path(p['image']).name} for p in self.parts])
        self.after_guard = True
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertIn('post-mcupm_a.bin: DIFF', self.output.getvalue())
        self.assertNotIn('session error', self.output.getvalue())

    def test_import_and_dry_run_forbid_hardware_dependencies(self):
        real_import = __import__

        def deny_hardware(name, *args, **kwargs):
            if name == 'read_by_name' or name.startswith('mtkclient'):
                raise AssertionError('hardware import forbidden during dry-run')
            return real_import(name, *args, **kwargs)

        spec = importlib.util.spec_from_file_location('dry_restore', Path(__file__).with_name('write_verify.py'))
        fresh = importlib.util.module_from_spec(spec)
        with patch('builtins.__import__', side_effect=deny_hardware), contextlib.redirect_stdout(io.StringIO()):
            spec.loader.exec_module(fresh)
            fresh.backup_table = lambda _: self.parts
            fresh.active_slot = lambda table: 'b'
            with patch.object(sys, 'argv', ['write_verify.py', 'lk_a', '--backup', str(self.root)]):
                fresh.main()

    def test_missing_loader_blocks_connection(self):
        self.loader.unlink()
        self.assertNotEqual(self.run_main('--write'), 0)
        self.connect.assert_not_called()

    def test_source_change_during_connection_blocks_write(self):
        def connect(*args):
            self.target['image'].write_bytes(b'X' * 8192)
            return self.mtk
        stub.connect = Mock(side_effect=connect)
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 0)
        self.mtk.port.close.assert_called_once()

    def test_read_failure_after_write_is_not_success(self):
        self.fail_post_read = True
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 1)

    def test_write_exception_never_retries(self):
        self.write_error = True
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 1)
        self.mtk.port.close.assert_called_once()

    def test_preexisting_target_mismatch_still_blocks_write(self):
        self.data[self.target['offset']] = b'X' * 8192
        self.assertNotEqual(self.run_main('--write'), 0)
        self.assertEqual(self.writes, 0)


class SlotTests(unittest.TestCase):
    layout = 'dev:\nmtd0: 00002000 00001000 "lk_a"\nmtd1: 00002000 00001000 "lk_b"\n'

    def check(self, cmdline='bootslot=b', *, code=0, layout=None):
        result = subprocess.CompletedProcess([], code, stdout=cmdline + '\n' + (self.layout if layout is None else layout))
        with patch.object(restore.subprocess, 'run', return_value=result) as run:
            slot = restore.active_slot(restore.parse_mtd(self.layout))
        self.command = run.call_args.args[0]
        return slot

    def test_failed_ssh_output_is_not_trusted(self):
        self.assertIsNone(self.check(code=255))

    def test_ambiguous_or_invalid_slot_is_rejected(self):
        for line in ['bootslot=a bootslot=b', 'bootslot=b bootslot=b', 'bootslot=x', '']:
            with self.subTest(line=line):
                self.assertIsNone(self.check(line))

    def test_key_only_ssh_and_matching_layout(self):
        self.assertEqual(self.check('root=foo bootslot=b'), 'b')
        self.assertIn('BatchMode=yes', self.command)
        self.assertIn('StrictHostKeyChecking=yes', self.command)

    def test_swapped_or_changed_layout_is_rejected(self):
        for layout in [self.layout.replace('lk_a', 'tmp').replace('lk_b', 'lk_a').replace('tmp', 'lk_b'),
                       self.layout.replace('00002000', '00004000'), 'dev:\n', 'invalid']:
            with self.subTest(layout=layout):
                self.assertIsNone(self.check(layout=layout))

    def test_timeout_or_missing_ssh_is_rejected(self):
        for error in [subprocess.TimeoutExpired('ssh', 20), FileNotFoundError('ssh')]:
            with self.subTest(error=type(error)), patch.object(restore.subprocess, 'run', side_effect=error):
                self.assertIsNone(restore.active_slot(restore.parse_mtd(self.layout)))


if __name__ == '__main__':
    unittest.main()
