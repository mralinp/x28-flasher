import tempfile
import unittest
from pathlib import Path

import boot_order as b

THIS_UNIT = bytes.fromhex("00414230ffffffff" "0f000000" "0e000101")  # A first, B good
FIRST_UNIT = bytes.fromhex("00414230ffffffff" "0e000100" "0f000100")  # B first


def misc(rec=THIS_UNIT, filler=b"\xff"):
    out = bytearray(filler * b.MISC_SIZE)
    for off in b.COPIES:
        out[off:off + 16] = rec
    return bytes(out)


class RecordTests(unittest.TestCase):
    def test_which_slot_boots_first_is_read_from_the_priorities(self):
        self.assertEqual(b.first(THIS_UNIT), "a")
        self.assertEqual(b.first(FIRST_UNIT), "b")
        self.assertIn("slot A boots first", b.describe(THIS_UNIT))

    def test_choosing_swaps_only_the_two_priority_bytes_in_every_copy(self):
        before = misc()
        after = b.choose(before, "b")
        self.assertEqual(b.records(after), bytes.fromhex("00414230ffffffff" "0e000000" "0f000101"))
        changed = [i for i in range(len(before)) if before[i] != after[i]]
        self.assertEqual(changed, [o + d for o in b.COPIES for d in (8, 12)])
        self.assertEqual(b.choose(after, "a"), before)  # and back again is exact

    def test_it_refuses_what_it_does_not_know(self):
        with self.assertRaisesRegex(ValueError, "already boots first"):
            b.choose(misc(), "a")
        bad = bytearray(misc())
        bad[b.COPIES[2] + 8] = 0x0e  # one copy disagrees
        with self.assertRaisesRegex(ValueError, "differ"):
            b.records(bytes(bad))
        with self.assertRaisesRegex(ValueError, "not a boot-order record"):
            b.records(misc(bytes.fromhex("00414230ffffffff" "0f000000" "0f000000")))
        with self.assertRaisesRegex(ValueError, "not a boot-order record"):
            b.records(misc(b"\x00" * 16))
        with self.assertRaisesRegex(ValueError, "bytes"):
            b.records(misc()[:-1])


class FakeDa:
    def __init__(self, data, fail_block=None, corrupt_block=None):
        self.data, self.writes, self.fail_block, self.corrupt_block = bytearray(data), [], fail_block, corrupt_block

    def readflash(self, addr, length, filename, **kw):
        Path(filename).write_bytes(bytes(self.data[addr - b.MISC_ADDR:addr - b.MISC_ADDR + length]))
        return True

    def writeflash(self, addr, length, filename, **kw):
        k = (addr - b.MISC_ADDR) // b.BLOCK
        self.writes.append(k)
        if k == self.fail_block:
            return False
        body = Path(filename).read_bytes()
        self.data[addr - b.MISC_ADDR:addr - b.MISC_ADDR + length] = b"\x00" * length if k == self.corrupt_block else body
        return True


class WriteTests(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp())

    def test_blocks_are_written_last_to_first_and_the_result_is_the_candidate(self):
        before = misc()
        da = FakeDa(before)
        candidate = b.choose(before, "b")
        b.write_blocks(da, candidate, self.work, say=lambda *_: None)
        self.assertEqual(da.writes, [3, 2, 1, 0])
        self.assertEqual(bytes(da.data), candidate)

    def test_a_refused_block_stops_the_run_with_the_first_copy_untouched(self):
        before = misc()
        da = FakeDa(before, fail_block=2)
        with self.assertRaisesRegex(ValueError, "not acknowledged"):
            b.write_blocks(da, b.choose(before, "b"), self.work, say=lambda *_: None)
        self.assertEqual(da.writes, [3, 2])
        self.assertEqual(bytes(da.data)[:b.BLOCK], before[:b.BLOCK])  # block 0 never written

    def test_a_block_that_does_not_read_back_stops_the_run(self):
        before = misc()
        da = FakeDa(before, corrupt_block=3)
        with self.assertRaisesRegex(ValueError, "did not read back"):
            b.write_blocks(da, b.choose(before, "b"), self.work, say=lambda *_: None)
        self.assertEqual(da.writes, [3])

    def test_the_phrase_names_what_is_replaced_and_what_replaces_it(self):
        before = misc()
        self.assertRegex(b.phrase("b", before, b.choose(before, "b")), r"^BOOT-ORDER b [0-9a-f]{12} TO [0-9a-f]{12}$")


if __name__ == "__main__":
    unittest.main()
