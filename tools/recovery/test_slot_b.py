#!/usr/bin/env python3
import json
import tempfile
import unittest
from pathlib import Path

import slot_b as b
import slot_b_entry as e
import slot_session as s
from stock_access import PEB, ec_header, vid_header

LEB = PEB - 8192
PINS = {'rootfs_a': 'a' * 64, 'rootfs_b': 'b' * 64, 'rootfs_b_head': 'c' * 64, 'misc': 'd' * 64, 'boot_para': 'e' * 64}


def block(lnum, first=b'\x31\x18\x10\x06'):
    raw = bytearray(ec_header(1, 4096, 8192, 5).ljust(PEB, b'\xff'))
    raw[4096:4160] = vid_header(lnum, 10 + lnum)
    raw[8192:8196] = first
    return bytes(raw)


def tail(*blocks):
    return b''.join(blocks).ljust(b.TAIL_SIZE, b'\xff')


class TailTests(unittest.TestCase):
    def test_a_ubifs_volume_from_leb_0_is_accepted(self):
        b.validate_tail(tail(), tail(block(0), block(1, b'\0' * 4)))

    def test_refused_when_empty_same_or_not_starting_at_leb_0(self):
        old = tail(block(0))
        for bad in (old, tail(block(1)), tail(block(0, b'hsqs')), b'\xff' * 10):
            with self.assertRaises(ValueError):
                b.validate_tail(old, bad)

    def test_a_block_of_another_volume_is_refused(self):
        other = bytearray(block(0))
        other[4096 + 11] = 0  # vol_id 1 -> 0 (the signed rootfs) ...
        other[4156:4160] = __import__('struct').pack('>I', __import__('stock_access').crc(bytes(other[4096:4156])))
        with self.assertRaises(ValueError):
            b.validate_tail(tail(), tail(bytes(other)))

    def test_spec_writes_the_tail_and_guards_the_rest(self):
        spec = b.rootfs_b_tail_spec('f' * 64, '1' * 64, PINS['rootfs_a'], PINS)
        self.assertEqual((spec.addr, spec.size), (0x21c00000, 0x2000000))
        names = {g[0] for g in spec.guards}
        self.assertTrue({'rootfs_a', 'misc', 'rootfs_b', 'rootfs_sig_b', 'boot_b', 'lk_b', 'boot_para'} <= names)
        head = next(g for g in spec.guards if g[0] == 'rootfs_b')
        self.assertEqual((head[1], head[2]), (0x1fc00000, s.ROOTFS_B_HEAD))  # head only, never overlapping the target
        self.assertLessEqual(head[1] + head[2], spec.addr)
        self.assertEqual(spec.guards, spec.restore_guards)

    def test_same_candidate_hash_is_refused(self):
        with self.assertRaises(ValueError):
            b.rootfs_b_tail_spec('1' * 64, '1' * 64, 'a' * 64, PINS)


class ChipTests(unittest.TestCase):
    def dirs(self, saved, live):
        root = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__('shutil').rmtree(root))
        (root / 'backup').mkdir(), (root / 'run').mkdir()
        (root / 'backup/hwparam.json').write_text(json.dumps(saved))
        if live is not None:
            (root / 'run/hwparam.json').write_text(json.dumps(live))
        return root / 'run', root / 'backup'

    def test_same_unit_passes_case_insensitively(self):
        e.check_chip(*self.dirs({'hwcode': '0x992', 'meid': 'AB12'}, {'hwcode': '0x992', 'meid': 'ab12'}))

    def test_other_unit_missing_or_empty_meid_stops(self):
        for saved, live in (({'hwcode': '0x992', 'meid': 'ab12'}, {'hwcode': '0x992', 'meid': 'cd34'}),
                            ({'hwcode': '0x992', 'meid': 'ab12'}, None), ({'hwcode': '0x992'}, {'hwcode': '0x992'})):
            with self.assertRaises(ValueError):
                e.check_chip(*self.dirs(saved, live))


if __name__ == '__main__':
    unittest.main()
