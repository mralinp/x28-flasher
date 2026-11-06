#!/usr/bin/env python3
import unittest
import stock_access as s

LEB = s.PEB - 8192


def peb(lnum=None, fill=0, sq=1):
    """A rootfs_data block holding LEB lnum, or an EC-only block."""
    b = bytearray(s.ec_header(7, 4096, 8192, 99).ljust(s.PEB, b"\xff"))
    if lnum is not None:
        b[4096:4160] = s.vid_header(lnum, sq)
        b[8192:] = bytes([fill]) * LEB
    return bytes(b)


class SpliceTests(unittest.TestCase):
    def test_overlay_blocks_are_replaced_and_unused_slots_emptied(self):
        raw = peb(0, 2, 5) + peb(1, 3, 6) + peb()
        new, changed = s.splice(raw, bytes([9]) * LEB, LEB)
        self.assertEqual(changed, [0, 1])
        parsed = s.parse(new)
        self.assertEqual([p[2:4] for p in parsed], [(s.ROOTFS_DATA, 0), (None, None), (None, None)])
        self.assertEqual(new[8192:s.PEB], bytes([9]) * LEB)
        self.assertEqual(new[2 * s.PEB:], raw[2 * s.PEB:])  # blocks outside the overlay are untouched
        self.assertGreater(parsed[0][4], 6)  # sqnum above every existing one

    def test_an_overlay_that_needs_more_blocks_is_refused(self):
        with self.assertRaises(AssertionError):
            s.splice(peb(0, 2, 5), bytes([9]) * LEB * 2, LEB)


if __name__ == "__main__":
    unittest.main()
