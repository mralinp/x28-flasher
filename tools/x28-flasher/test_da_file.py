import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "recovery"))
import da_file  # noqa: E402
from restore_entry import DA_HASH  # noqa: E402


class DownloadAgent(unittest.TestCase):
    def test_the_copy_in_the_repo_is_the_agent_the_tools_expect(self):
        self.assertEqual(hashlib.sha256(da_file.REPO_DA.read_bytes()).hexdigest(), DA_HASH)
        self.assertEqual(da_file.default(), da_file.REPO_DA)

    def test_a_saved_path_that_exists_is_used_and_one_that_does_not_falls_back(self):
        with tempfile.TemporaryDirectory() as d:
            mine = Path(d) / "DA_BR.bin"
            mine.write_bytes(b"x")
            self.assertEqual(da_file.pick(str(mine)), mine)
            self.assertEqual(da_file.pick(str(Path(d) / "gone.bin")), da_file.default())
            self.assertEqual(da_file.pick(""), da_file.default())


if __name__ == "__main__":
    unittest.main()
