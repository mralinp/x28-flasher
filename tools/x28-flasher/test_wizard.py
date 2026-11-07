"""Wizard helpers and the plain-prompt fallback (#272). Run: python3 tools/x28-flasher/test_wizard.py"""
import json
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "recovery"))  # the wizard imports common lazily, as x28_flasher arranges
import wizard  # noqa: E402


def receipt(root, name, status="VERIFIED", age=60):
    d = root / name
    d.mkdir(parents=True)
    (d / "receipt.json").write_text(json.dumps({"status": status, "created": time.time() - age}))
    return d


class HelperTests(unittest.TestCase):
    def test_only_fresh_verified_rehearsals_are_offered(self):
        root = Path(tempfile.mkdtemp())
        good = receipt(root, "slot-rootfs_a-identical-aaa")
        receipt(root, "slot-rootfs_a-identical-old", age=90000)
        receipt(root, "slot-rootfs_a-identical-bad", status="STOP_UNVERIFIED")
        self.assertEqual(wizard.verified_identicals(root), [good])

    def test_image_dirs_need_the_flashable_file(self):
        root = Path(tempfile.mkdtemp())
        (root / "native-ubi-1").mkdir()
        (root / "native-ubi-2").mkdir()
        (root / "native-ubi-2" / "rootfs-a-experimental.bin").write_bytes(b"x")
        self.assertEqual([d.name for d in wizard.image_dirs(root)], ["native-ubi-2"])

    def test_config_remembers_answers(self):
        path = Path(tempfile.mkdtemp()) / "sub" / "c.json"
        wizard.Config(path).set("loader", "/x")
        self.assertEqual(wizard.Config(path).get("loader"), "/x")
        self.assertEqual(wizard.Config(path).get("missing", "d"), "d")


class UartTests(unittest.TestCase):
    def test_console_text_scores_high_and_noise_low(self):
        self.assertGreater(wizard.printable_share(b"[  705.8] <3>.(3)[1440:ccci_sys] system message\r\n"), 0.95)
        self.assertLess(wizard.printable_share(bytes(range(128, 256)) * 2), 0.1)
        self.assertEqual(wizard.printable_share(b""), 0.0)


class BackupTests(unittest.TestCase):
    def test_backup_collects_answers_and_runs_the_tool(self):
        ran = []
        fl = types.SimpleNamespace(PRIVATE=Path(tempfile.mkdtemp()), default_backup_dir=lambda: Path("/x/b"), power_off_countdown=lambda: ran.append("countdown"),
                                   run_tool=lambda script, argv: ran.append((script, argv)) or 0)
        da = Path(tempfile.mkdtemp()) / "DA.bin"
        fl.default_backup_dir = lambda: fl.PRIVATE / "backups" / "x28-backup-new"
        da.write_bytes(b"x")
        cfg = wizard.Config(fl.PRIVATE / "c.json")
        cfg.set("loader", str(da))
        ui = types.SimpleNamespace(text=lambda msg, default="": default, confirm=lambda msg, default=True: False)
        self.assertEqual(wizard.backup(fl, ui, cfg), 0)
        self.assertEqual(ran, ["countdown", ("usb_backup.py", ["--out", str(fl.PRIVATE / "backups" / "x28-backup-new"), "--loader", str(da), "--no-verify"])])

    def test_an_unfinished_backup_is_offered_for_resume(self):
        ran = []
        fl = types.SimpleNamespace(PRIVATE=Path(tempfile.mkdtemp()), power_off_countdown=lambda: None, run_tool=lambda s, a: ran.append(a) or 0)
        old = fl.PRIVATE / "backups" / "x28-backup-old"
        old.mkdir(parents=True)
        (old / "SHA256SUMS.partial").write_text("aa  images/a\nbb  images/b\n")
        fl.default_backup_dir = lambda: fl.PRIVATE / "backups" / "x28-backup-new"
        da = fl.PRIVATE / "DA.bin"
        da.write_bytes(b"x")
        cfg = wizard.Config(fl.PRIVATE / "c.json")
        cfg.set("loader", str(da))
        ui = types.SimpleNamespace(text=lambda msg, default="": str(default), confirm=lambda msg, default=True: True)
        wizard.backup(fl, ui, cfg)
        self.assertEqual(ran[0][1], str(old))


class PlainPromptTests(unittest.TestCase):
    ui = wizard.Ui(fancy=False)

    def test_select_by_number_and_default(self):
        with mock.patch("builtins.input", side_effect=["", "9", "2"]):
            self.assertEqual(self.ui.select("pick", [("A", 1), ("B", 2)]), 1)
            self.assertEqual(self.ui.select("pick", [("A", 1), ("B", 2)]), 2)

    def test_text_and_confirm_defaults(self):
        with mock.patch("builtins.input", side_effect=["", "n", ""]):
            self.assertEqual(self.ui.text("path", "dflt"), "dflt")
            self.assertFalse(self.ui.confirm("go?", True))
            self.assertTrue(self.ui.confirm("go?", True))

    def test_menu_loop_runs_an_action_then_quits(self):
        calls = []
        started, stopped = [], []
        fl = types.SimpleNamespace(PRIVATE=Path(tempfile.mkdtemp()), start_capture=lambda ui: started.append(1), stop_capture=lambda: stopped.append(1))
        with mock.patch.dict(wizard.ACTIONS, {"test": lambda *a: calls.append("test")}), mock.patch("builtins.input", side_effect=["", "4", "8"]):
            self.assertEqual(wizard.run(fl, self.ui), 0)
        self.assertEqual(calls, ["test"])
        self.assertEqual((started, stopped), ([1], [1]))  # logger starts with the session and stops when it ends

    def test_autopilot_stops_at_the_first_failed_step_and_flashes_nothing(self):
        import io
        from contextlib import redirect_stdout
        ran = []
        ui = types.SimpleNamespace(confirm=lambda *a, **k: False)
        with redirect_stdout(io.StringIO()), mock.patch.object(wizard, "backup", lambda *a: ran.append("backup") or 3), \
                mock.patch.object(wizard, "build", lambda *a: ran.append("build") or 0), mock.patch.object(wizard, "flash", lambda *a, **k: ran.append("flash") or 0):
            code = wizard.autopilot(types.SimpleNamespace(FROZEN=False), ui, None)
        self.assertEqual((code, ran), (3, ["backup"]))

    def test_autopilot_does_not_flash_from_a_frozen_binary(self):
        import io
        from contextlib import redirect_stdout
        with redirect_stdout(io.StringIO()), mock.patch.object(wizard, "backup", side_effect=AssertionError):
            self.assertEqual(wizard.autopilot(types.SimpleNamespace(FROZEN=True), None, None), 0)

    def test_build_reports_a_missing_release_without_crashing(self):
        import io
        from contextlib import redirect_stdout
        ui = types.SimpleNamespace(select=lambda msg, choices: "download")
        out = io.StringIO()
        with redirect_stdout(out), mock.patch("images.get", return_value=b"[]"):
            self.assertEqual(wizard.build(types.SimpleNamespace(FROZEN=False), ui, None), 1)
        self.assertIn("#254", out.getvalue())


    def test_choose_key_lists_keys_remembers_and_never_guesses(self):
        home = Path(tempfile.mkdtemp())
        (home / ".ssh").mkdir()
        for n in ("a.pub", "router.pub"):
            (home / ".ssh" / n).write_text("ssh-rsa AAAA x")
        cfg = wizard.Config(home / "c.json")
        cfg.set("build_key", str(home / ".ssh/router.pub"))
        seen = []
        ui = types.SimpleNamespace(select=lambda msg, choices: seen.append([v for _, v in choices]) or choices[0][1])
        with mock.patch.object(wizard.Path, "home", return_value=home):
            key = wizard.choose_key(ui, cfg)
        self.assertEqual(key, str(home / ".ssh/router.pub"))  # remembered key is offered first, but it is still asked
        self.assertEqual(seen[0][-1], None)

    def test_choose_key_makes_an_rsa_pair_when_there_is_none(self):
        home = Path(tempfile.mkdtemp())
        (home / ".ssh").mkdir()
        (home / ".ssh" / "e.pub").write_text("ssh-ed25519 AAAA x")  # dropbear in the stock slot cannot use it
        cfg = wizard.Config(home / "c.json")
        ui = types.SimpleNamespace(select=lambda msg, choices: self.fail("nothing to choose from"))
        with mock.patch.object(wizard.Path, "home", return_value=home), __import__("contextlib").redirect_stdout(__import__("io").StringIO()):
            key = wizard.choose_key(ui, cfg)
        self.assertEqual(key, str(home / ".ssh/x28_rsa.pub"))
        self.assertTrue(Path(key).read_text().startswith("ssh-rsa "))
        self.assertEqual((home / ".ssh/x28_rsa").stat().st_mode & 0o077, 0)


class FancySelectTests(unittest.TestCase):
    """questionary returns a choice's label when its value is None (#325); select must hand back the real value."""
    def test_a_none_choice_comes_back_as_none(self):
        class Choice:
            def __init__(self, label, value=None):
                self.value = label if value is None else value  # what questionary does

        class Question:
            def __init__(self, choices, pick):
                self.choices, self.pick = choices, pick

            def ask(self):
                return self.choices[self.pick].value

        for pick, want in ((0, None), (1, "dir"), (2, "other")):
            fake = types.SimpleNamespace(Choice=Choice, select=lambda msg, choices, **kw: Question(choices, pick))
            with mock.patch.object(wizard, "questionary", fake):
                ui = wizard.Ui(fancy=True)
                self.assertEqual(ui.select("Image now on slot A", [("None / not known", None), ("native-ubi", "dir"), ("Another folder...", "other")]), want)


if __name__ == "__main__":
    unittest.main()
