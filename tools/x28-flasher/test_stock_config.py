import tempfile
import unittest
from pathlib import Path

import boot_ssh
import stock_config as sc

LOCKED = 'export A="1"\nexport SYS_LOCK_OPERATOR_SW="1"\nexport SYS_LOCK_OPERATOR_LIST="41601,41602"\nexport SYS_LOCK_SIM_SW="0"\nexport SYS_LOCK_SIM_INITIAL_PIN="1234"\nexport Z="x"\n'


class R:
    def __init__(self, out=b"", rc=0, err=b""):
        self.stdout, self.returncode, self.stderr = out, rc, err


class ConfigTests(unittest.TestCase):
    def test_only_the_two_operator_keys_change(self):
        new = sc.cleared(LOCKED)
        self.assertIn('export SYS_LOCK_OPERATOR_SW="0"', new)
        self.assertIn('export SYS_LOCK_OPERATOR_LIST=""', new)
        self.assertEqual(new.replace('SYS_LOCK_OPERATOR_SW="0"', 'SYS_LOCK_OPERATOR_SW="1"').replace('SYS_LOCK_OPERATOR_LIST=""', 'SYS_LOCK_OPERATOR_LIST="41601,41602"'), LOCKED)
        self.assertTrue(sc.unlocked(sc.values(new)))
        self.assertFalse(sc.unlocked(sc.values(LOCKED)))

    def test_a_config_without_exactly_one_of_each_key_is_not_edited(self):
        with self.assertRaises(boot_ssh.BootError):
            sc.values(LOCKED.replace('export SYS_LOCK_OPERATOR_SW="1"\n', ""))
        with self.assertRaises(boot_ssh.BootError):
            sc.values(LOCKED + 'export SYS_LOCK_OPERATOR_SW="1"\n')

    def test_unlock_saves_a_copy_writes_and_reads_back(self):
        disk = {"text": LOCKED}
        writes = []

        def fake(target, cmd, stdin=None, timeout=60, pw=""):
            if stdin is not None:
                writes.append(stdin.decode())
                disk["text"] = stdin.decode()
                return R()
            return R(b"/mnt/data/etc/tzcfg/system_config.use\n" + disk["text"].encode())
        boot_ssh_ssh, sc.ssh = sc.ssh, fake
        try:
            with tempfile.TemporaryDirectory() as d:
                sc.BACKUPS = Path(d)
                out = sc.unlock()
                self.assertTrue(out["unlocked"])
                self.assertEqual(len(writes), 1)
                self.assertEqual(next(Path(d).iterdir()).read_text(), LOCKED)  # the original is kept here first
                writes.clear()
                sc.unlock()  # already clear: nothing is written
                self.assertEqual(writes, [])
        finally:
            sc.ssh = boot_ssh_ssh

    def test_a_readback_that_differs_is_reported(self):
        state = {"n": 0}

        def fake(target, cmd, stdin=None, timeout=60, pw=""):
            if stdin is not None:
                return R()
            state["n"] += 1
            return R(b"/f\n" + (LOCKED if state["n"] <= 2 else LOCKED + "x").encode())
        keep, sc.ssh = sc.ssh, fake
        try:
            with tempfile.TemporaryDirectory() as d:
                sc.BACKUPS = Path(d)
                with self.assertRaisesRegex(boot_ssh.BootError, "read back"):
                    sc.unlock()
        finally:
            sc.ssh = keep


if __name__ == "__main__":
    unittest.main()
