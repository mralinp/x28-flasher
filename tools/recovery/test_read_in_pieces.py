import types
import unittest
from pathlib import Path

import os
import sys

from common import MTK_HOME

r = None
if os.path.realpath(sys.prefix) == os.path.realpath(MTK_HOME / "venv"):  # importing read_by_name elsewhere would re-exec into the venv
    import read_by_name as r


class FakeDaloader:
    def __init__(self, data, fail_at=None):
        self.data, self.fail_at, self.calls = data, fail_at, []

    def readflash(self, addr, length, filename, **kw):
        self.calls.append((addr, length))
        if self.fail_at is not None and len(self.calls) == self.fail_at:
            Path(filename).write_bytes(b"")  # a piece that came back empty
            return False
        Path(filename).write_bytes(self.data[addr:addr + length])
        return True


@unittest.skipIf(r is None, "needs the mtkclient venv")
class ReadInPiecesTests(unittest.TestCase):
    def setUp(self):
        r.CHUNK = 16
        self.addCleanup(setattr, r, "CHUNK", 4 << 20)
        self.data = bytes(range(256)) * 2

    def mtk(self, **kw):
        return types.SimpleNamespace(daloader=FakeDaloader(self.data, **kw))

    def test_whole_partition_in_chunk_sized_reads_from_its_start(self):
        mtk = self.mtk()
        got = r.read_in_pieces(mtk, 0x10, 40)
        self.assertEqual(got, self.data[0x10:0x10 + 40])
        self.assertEqual(mtk.daloader.calls, [(0x10, 16), (0x20, 16), (0x30, 8)])

    def test_a_failed_piece_keeps_the_whole_pieces_before_it(self):
        mtk = self.mtk(fail_at=2)
        self.assertEqual(r.read_in_pieces(mtk, 0, 48), self.data[:16])


if __name__ == "__main__":
    unittest.main()
