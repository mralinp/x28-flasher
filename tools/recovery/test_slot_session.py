#!/usr/bin/env python3
"""Fake-DA tests only: never import USB or connect to a device."""
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

import slot_session as s

H = lambda data: hashlib.sha256(data).hexdigest()


class FakeDA(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.out = Path(self.temp.name)
        self.original = b'\x11' * 64
        self.candidate = b'\x22' * 64
        self.guard = b'G' * 16
        guards = tuple((f'g{i}', 0x2000 + i * 0x100, 16, H(self.guard)) for i in range(3))
        # g2 may legitimately differ after a fallback repair, but only when restoring
        wide = guards[:2] + (('g2', 0x2200, 16, (H(self.guard), H(b'R' * 16))),)
        self.spec = s.Spec('t', 0x1000, 64, H(self.original), guards,
                           lambda o, c: None if c != o else (_ for _ in ()).throw(ValueError('same')),
                           H(self.candidate), wide)
        self.data = {0x1000: self.original, **{0x2000 + i * 0x100: self.guard for i in range(3)}}
        self.writes = []
        self.fail_write = self.fail_read = self.drift_guard = self.corrupt = self.exception = 0
        self.reads = 0

    def readflash(self, addr, length, filename, **kw):
        self.reads += 1
        Path(filename).write_bytes(self.data[addr])
        return False if self.fail_read == self.reads else True

    def writeflash(self, addr, length, filename, **kw):
        self.writes.append((addr, length))
        if self.exception:
            raise OSError('lost USB')
        self.data[addr] = Path(filename).read_bytes()
        if self.drift_guard:
            self.data[0x2000] = b'X' * 16
        if self.corrupt:
            self.data[addr] = b'X' * length
        return False if self.fail_write else True

    def run_(self, mode='write', **kw):
        return s.run_session(self, self.spec, kw.get('original', self.original), kw.get('candidate', self.candidate),
                             self.out, mode=mode)

    def journal(self):
        return [json.loads(l) for p in self.out.glob('*/journal.jsonl') for l in p.read_text().splitlines()]


class SessionTests(FakeDA):
    def test_identical_writes_original_once_and_verifies(self):
        self.run_('identical')
        self.assertEqual(self.writes, [(0x1000, 64)])
        self.assertEqual(self.data[0x1000], self.original)

    def test_write_puts_candidate_and_checks_everything_after(self):
        self.run_('write')
        self.assertEqual(self.data[0x1000], self.candidate)
        reads = [e for e in self.journal() if 'read' in e]
        self.assertEqual([e['read'] for e in reads], ['before'] * 4 + ['after'] * 4)

    def test_restore_works_from_candidate_or_a_half_written_target(self):
        for state in (self.candidate, b'\x33' * 64):
            self.data[0x1000] = state
            self.run_('restore', candidate=None)
            self.assertEqual(self.data[0x1000], self.original)

    def test_restore_still_stops_on_guard_drift(self):
        self.data[0x1000] = self.candidate
        self.data[0x2100] = b'X' * 16
        with self.assertRaises(ValueError):
            self.run_('restore', candidate=None)
        self.assertEqual(self.writes, [])

    def test_wrong_inputs_refuse_before_any_io(self):
        for kw in ({'original': b'\x00' * 64}, {'candidate': b'\x55' * 64}, {'candidate': self.original}):
            with self.assertRaises(ValueError):
                self.run_('write', **kw)
        with self.assertRaises(ValueError):
            self.run_('erase')
        self.assertEqual((self.writes, self.reads), ([], 0))

    def test_before_mismatch_target_or_guard_stops_without_writing(self):
        self.data[0x1000] = b'\x44' * 64
        with self.assertRaises(ValueError):
            self.run_('write')
        self.data[0x1000] = self.original
        self.data[0x2200] = b'X' * 16
        with self.assertRaises(ValueError):
            self.run_('write')
        self.assertEqual(self.writes, [])

    def test_failures_stop_and_journal_unverified_without_retry(self):
        for attr in ('fail_write', 'drift_guard', 'corrupt', 'exception'):
            self.setUp()
            setattr(self, attr, 1)
            with self.assertRaises((ValueError, OSError), msg=attr):
                self.run_('write')
            self.assertEqual(len(self.writes), 1, attr)
            self.assertEqual(self.journal()[-1]['status'], 'STOP_UNVERIFIED_NO_RETRY_OR_REBOOT')

    def test_read_failure_stops_before_the_write(self):
        self.fail_read = 2
        with self.assertRaises(ValueError):
            self.run_('write')
        self.assertEqual(self.writes, [])

    def test_restore_accepts_a_repaired_guard_but_write_does_not(self):
        self.data[0x2200] = b'R' * 16
        with self.assertRaises(ValueError):
            self.run_('write')
        self.assertEqual(self.writes, [])
        self.data[0x1000] = self.candidate
        self.run_('restore', candidate=None)
        self.assertEqual(self.data[0x1000], self.original)

    def test_write_intent_is_journaled_and_fsynced_before_the_write(self):
        order = []
        real_fsync = s.os.fsync
        s.os.fsync = lambda fd: (order.append('fsync'), real_fsync(fd))[1]
        self.addCleanup(setattr, s.os, 'fsync', real_fsync)
        real_write = self.writeflash
        self.writeflash = lambda **kw: (order.append('write'), real_write(**kw))[1]
        self.run_('write')
        attempt = [e for e in self.journal() if 'write_attempt' in e]
        self.assertEqual(len(attempt), 1)
        self.assertEqual(order[order.index('write') - 1], 'fsync')

    def test_source_file_is_read_only_and_new_run_dir_each_time(self):
        a = self.run_('identical')
        self.assertEqual((a / 'source.bin').stat().st_mode & 0o222, 0)
        self.assertNotEqual(a, self.run_('identical'))


class SpecTests(unittest.TestCase):
    def test_misc_candidate_must_be_exactly_the_four_copy_selection(self):
        original = bytearray(b'\xff' * 0x100000)
        for off in s.MISC_COPIES:
            original[off:off + 16] = s.MISC_BEFORE
        good = bytearray(original)
        for off in s.MISC_COPIES:
            good[off:off + 16] = s.MISC_AFTER
        s.validate_misc(bytes(original), bytes(good))
        for tweak in (lambda b: b.__setitem__(0x40800 + 8, 0x0e), lambda b: b.__setitem__(0x1000, 0), lambda b: b.__setitem__(slice(0xc0800, 0xc0810), s.MISC_BEFORE)):
            bad = bytearray(good)
            tweak(bad)
            with self.assertRaises(ValueError):
                s.validate_misc(bytes(original), bytes(bad))
        with self.assertRaises(ValueError):
            s.validate_misc(b'\xff' * 0x100000, bytes(good))

    def test_misc_selection_changes_four_bytes_per_copy(self):
        diff = [i for i, (a, b) in enumerate(zip(s.MISC_BEFORE, s.MISC_AFTER)) if a != b]
        self.assertEqual(diff, [8, 9, 10, 12])

    def test_rootfs_a_candidate_must_be_a_valid_different_ubi(self):
        with self.assertRaises(ValueError):
            s.validate_rootfs_a(b'\xff' * 0x4000000, b'\xff' * 0x4000000)
        with self.assertRaises(ValueError):
            s.validate_rootfs_a(b'\xff' * 0x4000000, b'\x00' * 0x4000000)
        with self.assertRaises(ValueError):
            s.validate_rootfs_a(b'\xff' * 0x4000000, b'short')

    def specs(self):
        return s.rootfs_a_spec('a' * 64), s.misc_spec('a' * 64)

    def test_real_specs_guard_both_slots_and_never_the_target(self):
        every = {'boot_a', 'rootfs_sig_a', 'rootfs_sig_b', 'boot_para', 'lk_a', 'tee_a', 'boot_b', 'rootfs_b', 'lk_b', 'tee_b',
                 'proinfo', 'md1dsp_a', 'md1dsp_b', 'mcf1_a', 'mcf1_b', 'mcf2_a', 'mcf2_b'}
        rootfs_a, misc = self.specs()
        self.assertEqual({g[0] for g in rootfs_a.guards}, every | {'misc'})
        self.assertEqual({g[0] for g in misc.guards}, every | {'rootfs_a'})
        for spec in (rootfs_a, misc):
            self.assertNotIn(spec.name, {g[0] for g in spec.guards})
            ranges = sorted((g[1], g[1] + g[2]) for g in (*spec.guards, (spec.name, spec.addr, spec.size)))
            for (a0, a1), (b0, b1) in zip(ranges, ranges[1:]):
                self.assertLessEqual(a1, b0, 'overlapping ranges')

    def test_hashes_are_pinned_and_a_new_rootfs_a_hash_is_required(self):
        rootfs_a, misc = self.specs()
        self.assertEqual((rootfs_a.candidate_sha, misc.candidate_sha), ('a' * 64, s.MISC_A_SHA))
        for bad in ('short', s.ROOTFS_A_SHA, s.ROOTFS_B_SHA):
            with self.assertRaises(ValueError):
                s.rootfs_a_spec(bad)
            with self.assertRaises(ValueError):
                s.misc_spec(bad)

    def test_rootfs_a_restore_needs_misc_on_b_but_misc_restore_tolerates_a_repaired_rootfs_a(self):
        rootfs_a, misc = self.specs()
        self.assertEqual(dict((g[0], g[3]) for g in rootfs_a.restore_guards)['misc'], s.MISC_SHA)
        accepted = dict((g[0], g[3]) for g in misc.restore_guards)['rootfs_a']
        self.assertEqual(set(accepted), {'a' * 64, s.ROOTFS_A_SHA, s.ROOTFS_B_SHA})
        self.assertEqual(dict((g[0], g[3]) for g in misc.guards)['rootfs_a'], 'a' * 64)

    def test_misc_candidate_hash_matches_the_selection_bytes(self):
        original = bytearray(b'\xff' * 0x100000)
        for off in s.MISC_COPIES:
            original[off:off + 16] = s.MISC_BEFORE
        for off in s.MISC_COPIES:
            original[off:off + 16] = s.MISC_AFTER
        # the real dump's other bytes are 0xff, so this reproduces the pinned hash
        self.assertEqual(H(bytes(original)), s.MISC_A_SHA)


class BaseModeTests(FakeDA):
    """#137: identical/write start from a named base image already on the target; misc only has to stay unchanged."""
    def setUp(self):
        super().setUp()
        self.base = b'\x33' * 64
        guards = self.spec.guards[:2] + (('misc', 0x2200, 16, None),)
        self.spec = self.spec._replace(guards=guards, restore_guards=guards, base_sha=H(self.base))
        self.data[0x1000] = self.base
        self.misc_a = b'A' * 16
        self.data[0x2200] = self.misc_a

    def run_(self, mode='write', **kw):
        return s.run_session(self, self.spec, self.original, self.candidate, self.out, mode=mode, base=kw.get('base', self.base))

    def test_write_starts_from_base_and_leaves_misc_alone(self):
        self.run_('write')
        self.assertEqual(self.data[0x1000], self.candidate)
        self.assertEqual(self.data[0x2200], self.misc_a)

    def test_identical_rewrites_the_base_not_the_original(self):
        self.run_('identical')
        self.assertEqual(self.data[0x1000], self.base)
        self.assertEqual(self.writes, [(0x1000, 64)])

    def test_only_the_static_head_of_the_base_is_compared_before_the_write(self):
        self.spec = self.spec._replace(base_head=32)
        self.data[0x1000] = self.base[:32] + b'\xee' * 32  # a booted slot rewrote its overlay tail
        self.run_('write')
        self.assertEqual(self.data[0x1000], self.candidate)  # the write still replaces all of it
        self.data[0x1000] = b'\xee' * 32 + self.base[32:]  # the head differs: not the base
        with self.assertRaises(ValueError):
            self.run_('write')
        self.assertEqual(len(self.writes), 1)

    def test_light_flash_writes_and_reads_back_only_the_target(self):
        spec = self.spec._replace(base_sha='', base_head=0)
        out = s.run_session(self, spec, self.original, self.candidate, self.out, mode='write', base=None, guards=False)
        self.assertEqual(self.data[0x1000], self.candidate)
        self.assertEqual((self.writes, self.reads), ([(0x1000, 64)], 1))  # one read: the target after the write
        events = [json.loads(l) for l in (out / 'journal.jsonl').read_text().splitlines()]
        self.assertEqual(events[-1], {'status': 'TARGET_VERIFIED'})

    def test_light_flash_stops_when_the_read_back_differs(self):
        spec = self.spec._replace(base_sha='', base_head=0)
        self.corrupt = 1
        with self.assertRaises(ValueError):
            s.run_session(self, spec, self.original, self.candidate, self.out, mode='write', base=None, guards=False)

    def test_light_checks_are_refused_for_a_restore_or_a_base_session(self):
        with self.assertRaises(ValueError):
            s.run_session(self, self.spec._replace(base_sha='', base_head=0), self.original, self.candidate, self.out, mode='restore', guards=False)
        with self.assertRaises(ValueError):
            s.run_session(self, self.spec, self.original, self.candidate, self.out, mode='write', base=self.base, guards=False)

    def test_original_on_target_is_not_a_valid_start(self):
        self.data[0x1000] = self.original
        with self.assertRaises(ValueError):
            self.run_('write')
        self.assertEqual(self.writes, [])

    def test_wrong_or_missing_base_refused_before_any_io(self):
        for base in (b'\x44' * 64, None):
            with self.assertRaises(ValueError):
                self.run_('write', base=base)
        self.assertEqual((self.writes, self.reads), ([], 0))

    def test_misc_changing_during_the_session_stops(self):
        orig = self.writeflash
        def drift(addr, length, filename, **kw):
            ack = orig(addr, length, filename, **kw)
            self.data[0x2200] = b'Z' * 16
            return ack
        self.writeflash = drift
        with self.assertRaises(ValueError):
            self.run_('write')

    def test_restore_returns_the_original_from_any_state(self):
        self.data[0x1000] = b'\x99' * 64
        self.run_('restore')
        self.assertEqual(self.data[0x1000], self.original)

    def test_base_given_without_a_base_spec_is_refused(self):
        with self.assertRaises(ValueError):
            s.run_session(self, self.spec._replace(base_sha=''), self.original, self.candidate, self.out, mode='write', base=self.base)

    def test_spec_rules(self):
        spec = s.rootfs_a_spec('a' * 64, 'b' * 64, 0x40000)
        self.assertEqual(dict((g[0], g[3]) for g in spec.guards)['misc'], None)
        self.assertEqual(dict((g[0], g[3]) for g in s.rootfs_a_spec('a' * 64).guards)['misc'], s.MISC_SHA)
        for cand, base in (('b' * 64, 'b' * 64), ('a' * 64, s.ROOTFS_A_SHA), ('a' * 64, 'short')):
            with self.assertRaises(ValueError):
                s.rootfs_a_spec(cand, base, 0x40000)
        for base, head in (('b' * 64, 0), ('b' * 64, 0x40001), ('b' * 64, 0x4000000), ('', 0x40000)):
            with self.assertRaises(ValueError):
                s.rootfs_a_spec('a' * 64, base, head)


class UnitPinTests(unittest.TestCase):
    """Per-unit pins come from a verified backup (#318); the boot chain stays pinned for every unit."""
    SECOND_UNIT_RECORD = bytes.fromhex('00414230ffffffff0e0001010f000101')  # the second unit's real stock misc record

    @staticmethod
    def misc_with(record, copies=s.MISC_COPIES):
        misc = bytearray(b'\xff' * 0x100000)
        for off in copies:
            misc[off:off + 16] = record
        return bytes(misc)

    def images(self, record):
        return {'misc': self.misc_with(record), 'rootfs_a': bytes(range(256)) * 0x40000, 'rootfs_b': b'UBI#' + (bytes(range(256)) * 0x40000)[4:],
                'boot_para': bytes(range(256)) * 0x2000}

    def test_pins_are_the_hashes_of_this_units_images(self):
        pins = s.unit_pins(self.images(self.SECOND_UNIT_RECORD))
        self.assertEqual(pins['rootfs_a'], s.digest(self.images(self.SECOND_UNIT_RECORD)['rootfs_a']))
        self.assertEqual(pins['rootfs_b_head'], s.digest(self.images(self.SECOND_UNIT_RECORD)['rootfs_b'][:0x2000000]))
        self.assertEqual(pins['misc'], s.digest(self.misc_with(self.SECOND_UNIT_RECORD)))
        self.assertEqual(s.unit_pins(self.images(s.MISC_BEFORE))['boot_para'], s.digest(self.images(s.MISC_BEFORE)['boot_para']))

    def test_misc_must_be_the_stock_b_selected_record_in_all_four_copies(self):
        for bad in (s.MISC_AFTER, bytes.fromhex('00414230ffffffff0e0001020f000100'), b'\xff' * 16):
            with self.assertRaises(ValueError, msg=bad.hex()):
                s.unit_pins(self.images(bad))
        mixed = self.images(s.MISC_BEFORE)
        mixed['misc'] = self.misc_with(self.SECOND_UNIT_RECORD, s.MISC_COPIES[:3])
        mixed['misc'] = mixed['misc'][:s.MISC_COPIES[3]] + s.MISC_BEFORE + mixed['misc'][s.MISC_COPIES[3] + 16:]
        with self.assertRaises(ValueError):
            s.unit_pins(mixed)
        short = self.images(s.MISC_BEFORE)
        short['misc'] = short['misc'][:-1]
        with self.assertRaises(ValueError):
            s.unit_pins(short)

    def test_a_flash_does_not_care_which_slot_misc_selects(self):
        a_selected = bytes.fromhex('00414230ffffffff0f0000000e000101')  # this unit's record: A first, tries 0
        pins = s.unit_pins(self.images(a_selected), boot_order=False)
        self.assertEqual(pins['misc'], s.digest(self.images(a_selected)['misc']))
        with self.assertRaises(ValueError):  # the boot-order step still needs the stock B-selected record
            s.unit_pins(self.images(a_selected))
        mixed = self.images(a_selected)
        mixed['misc'] = mixed['misc'][:s.MISC_COPIES[3]] + s.MISC_BEFORE + mixed['misc'][s.MISC_COPIES[3] + 16:]
        with self.assertRaises(ValueError):  # misc must still be one consistent record
            s.unit_pins(mixed, boot_order=False)

    def test_blank_short_or_non_ubi_images_are_refused(self):
        for name, bad in (('rootfs_a', b'\xff' * 0x4000000), ('rootfs_a', b'\0' * 0x4000000), ('rootfs_a', b'A' * 64),
                          ('boot_para', b'\xff' * 0x200000), ('rootfs_b', bytes(range(256)) * 0x40000), ('rootfs_b', b'UBI#')):
            images = self.images(s.MISC_BEFORE)
            images[name] = bad
            with self.assertRaises(ValueError, msg=name):
                s.unit_pins(images)

    def test_default_pins_are_the_first_unit_and_change_nothing(self):
        self.assertEqual(s.common_guards(), s.COMMON)
        self.assertEqual(s.rootfs_a_spec('a' * 64).original_sha, s.ROOTFS_A_SHA)

    def test_spec_uses_the_unit_pins_but_keeps_the_boot_chain_pinned(self):
        pins = s.unit_pins(self.images(self.SECOND_UNIT_RECORD))
        spec = s.rootfs_a_spec('c' * 64, pins=pins)
        guards = {g[0]: g[3] for g in spec.guards}
        self.assertEqual((spec.original_sha, guards['misc'], guards['boot_para'], guards['rootfs_b']),
                         (pins['rootfs_a'], pins['misc'], pins['boot_para'], pins['rootfs_b_head']))
        first = {g[0]: g[3] for g in s.rootfs_a_spec('c' * 64).guards}
        for name in ('boot_a', 'boot_b', 'lk_a', 'lk_b', 'tee_a', 'tee_b', 'rootfs_sig_a', 'rootfs_sig_b', 'proinfo'):
            self.assertEqual(guards[name], first[name], name)
        for name in ('misc', 'boot_para', 'rootfs_b'):
            self.assertNotEqual(guards[name], first[name], name)

    def test_candidate_may_not_be_this_units_own_stock_image(self):
        pins = s.unit_pins(self.images(self.SECOND_UNIT_RECORD))
        for bad in (pins['rootfs_a'], pins['rootfs_b']):
            with self.assertRaises(ValueError):
                s.rootfs_a_spec(bad, pins=pins)


if __name__ == '__main__':
    unittest.main()
