import tempfile
import unittest
from pathlib import Path

import boot_ssh as b

REC = "0f0000000e000101"  # A first; B good


class R:
    def __init__(self, out, rc=0):
        self.stdout, self.stderr, self.returncode = out, b"", rc


class BootTests(unittest.TestCase):
    def test_plan_swaps_only_the_priorities(self):
        self.assertEqual(b.plan(REC, "b").hex(), "0e0000000f")
        self.assertEqual(b.plan("0e0000000f000101", "a").hex(), "0f0000000e")
        self.assertEqual(b.plan("0e0102030f000101", "a").hex(), "0f0102030e")  # tries/success/flag stay

    def test_copies_that_differ_or_tie_are_refused(self):
        with self.assertRaises(b.BootError):
            b.parse("\n".join([REC] * 3 + ["0e0000000f000101"]))
        with self.assertRaises(b.BootError):
            b.boot_slot("0e0000000e000101")

    def test_set_slot_writes_last_copy_first_and_stops_on_a_bad_readback(self):
        calls, now = [], {"rec": REC, "bad": False}

        def fake(slot, cmd, stdin=None, timeout=60, pw=""):
            calls.append(cmd)
            if "dd-nand" in cmd:
                new = b.plan(now["rec"], "b").hex() + now["rec"][10:]
                return R(("0" * 16 if now["bad"] else new).encode())
            if "cat /dev/${M}ro" in cmd:
                return R(b"\0" * 0x100000)
            return R((now["rec"] + "\n").encode() * 4 + b"slot a\n")
        b.ssh = fake
        with tempfile.TemporaryDirectory() as d:
            b.BACKUPS = Path(d)
            now["bad"] = True
            with self.assertRaisesRegex(b.BootError, "copy 3"):
                b.set_slot("b")
            self.assertEqual(sum("dd-nand" in c for c in calls), 1)  # stopped at the first bad copy
            self.assertEqual(len(list(Path(d).iterdir())), 1)  # the whole partition was saved first
            now["bad"] = False
            calls.clear()
            b.set_slot("b")
            self.assertEqual([c.split("seek=")[1].split()[0] for c in calls if "dd-nand" in c], [str(2056 + 262144 * k) for k in (3, 2, 1, 0)])
            calls.clear()
            b.set_slot("a")  # already boots A: nothing written
            self.assertFalse(any("dd-nand" in c for c in calls))


if __name__ == "__main__":
    unittest.main()
