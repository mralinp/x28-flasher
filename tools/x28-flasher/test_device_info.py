"""Identity values from productinfo pages. Run: python3 tools/x28-flasher/test_device_info.py"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "recovery"))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import os  # noqa: E402

os.environ.setdefault("X28_MTKCLIENT", str(Path.cwd()))  # device_info runs ensure_venv at import
from unittest import mock  # noqa: E402

with mock.patch("common.ensure_venv"), mock.patch.dict(sys.modules, {"read_by_name": mock.MagicMock()}):
    import device_info  # noqa: E402


def page(text=b"", head=b""):
    return (head + text).ljust(0x1000, b"\xff")


class IdentityTests(unittest.TestCase):
    def test_values_are_told_apart_by_shape(self):
        data = page(b"\x00" * 10 + b"mac") + page(b"aa:bb:cc:00:11:22") + page(b"123456789012345") + page(b"A12345678901234567") + page(b"not an id")
        self.assertEqual(device_info.identity_values(data), [
            {"kind": "mac", "value": "aa:bb:cc:00:11:22"}, {"kind": "imei", "value": "123456789012345"},
            {"kind": "serial", "value": "A12345678901234567"}])

    def test_erased_and_key_pages_give_nothing(self):
        self.assertEqual(device_info.identity_values(b"\xff" * 0x3000 + page(b"imei", b"\x00" * 10)), [])


if __name__ == "__main__":
    unittest.main()
