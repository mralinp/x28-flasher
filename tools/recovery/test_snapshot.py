"""A slot B snapshot (usb_backup.py --only): five partitions are enough for slot_b_entry, any damage or gap is refused."""
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import common
import slot_b_entry
import slot_entry
import usb_backup

NAMES = list(common.SLOT_B_SNAPSHOT)


def make(root, names=NAMES):
    parts = common.parse_mtd(usb_backup.LAYOUT.read_text())
    (root / "images").mkdir(parents=True)
    sums = []
    for p in parts:
        if p["name"] in names:
            path = root / "images" / common.image_name(p)
            with path.open("wb") as f:
                f.truncate(p["size"])  # sparse: right size, content is zeros
            sums.append((common.sha256_file(path), f"images/{common.image_name(p)}"))
    (root / "mtd.txt").write_text(usb_backup.LAYOUT.read_text())
    (root / "SHA256SUMS").write_text("".join(f"{d}  {r}\n" for d, r in sums))
    (root / "SNAPSHOT.json").write_text(json.dumps({"partitions": names}))
    return root


class SnapshotTests(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.loader = self.dir / "da"
        self.loader.write_bytes(b"da")
        patch = mock.patch.object(slot_entry, "DA_HASH", common.sha256_file(self.loader))
        patch.start()
        self.addCleanup(patch.stop)

    def test_the_five_partitions_load_and_the_others_have_no_hash(self):
        snap = make(self.dir / "s")
        _, by_name = slot_entry.verified_backup(snap, self.loader, slot_b_entry.snapshot_names(snap))
        self.assertTrue(all(by_name[n]["sha256"] for n in NAMES))
        self.assertIsNone(by_name["boot_a"]["sha256"])

    def test_a_snapshot_is_not_a_backup(self):
        with self.assertRaises(KeyError):
            slot_entry.verified_backup(make(self.dir / "s"), self.loader)

    def test_a_damaged_or_missing_image_is_refused(self):
        snap = make(self.dir / "s")
        victim = next((snap / "images").glob("*-misc.bin"))
        victim.write_bytes(b"x" * victim.stat().st_size)
        with self.assertRaisesRegex(ValueError, "misc"):
            slot_entry.verified_backup(snap, self.loader, slot_b_entry.snapshot_names(snap))
        victim.unlink()
        with self.assertRaisesRegex(ValueError, "misc"):
            slot_entry.verified_backup(snap, self.loader, slot_b_entry.snapshot_names(snap))

    def test_a_snapshot_with_other_partitions_is_refused(self):
        with self.assertRaisesRegex(ValueError, "exactly"):
            slot_b_entry.snapshot_names(make(self.dir / "s", NAMES[:-1]))


if __name__ == "__main__":
    unittest.main()
