"""The page's server: job output and prompts, and who may talk to it. Run: python3 tools/x28-flasher/test_gui.py"""
import http.client
import json
import sys
import tempfile
import threading
import time
import types
import unittest
import unittest.mock
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "recovery"))
import gui  # noqa: E402

PROMPT = "print('1) a'); print('2) b'); x = input('Pick [1]: '); print('got', x or '1')"


def wait(cond, secs=5):
    end = time.time() + secs
    while time.time() < end and not cond():
        time.sleep(0.02)
    return cond()


class JobTests(unittest.TestCase):
    def test_prompt_is_the_tail_and_the_answer_reaches_the_tool(self):
        job = gui.Job("t", [sys.executable, "-c", PROMPT])
        self.assertTrue(wait(lambda: job.tail == "Pick [1]: "))
        self.assertEqual(job.lines, ["1) a", "2) b"])
        job.send("2")
        self.assertTrue(wait(lambda: job.code == 0))
        self.assertEqual(job.lines[-2:], ["Pick [1]: 2", "got 2"])

    def test_the_tool_sees_a_terminal(self):  # the write tools refuse a stdin that is not one
        job = gui.Job("t", [sys.executable, "-c", "import sys; print('tty', sys.stdin.isatty(), sys.stdout.isatty())"])
        self.assertTrue(wait(lambda: job.code == 0))
        self.assertEqual(job.lines, ["tty True True"])

    def test_carriage_return_redraws_the_tail(self):
        job = gui.Job("t", [sys.executable, "-c", "print('10 s\\r9 s\\r8 s', end='')"])
        self.assertTrue(wait(lambda: job.code == 0))
        self.assertEqual((job.lines, job.tail), ([], "8 s"))

    def test_info_line_reaches_the_hook(self):
        seen = []
        job = gui.Job("t", [sys.executable, "-c", "print('X28INFO {\"hwcode\": 2450}')"], on_line=seen.append)
        self.assertTrue(wait(lambda: job.code == 0))
        self.assertEqual(seen, ['X28INFO {"hwcode": 2450}'])

    def test_stop_interrupts(self):
        job = gui.Job("t", [sys.executable, "-c", "import time; time.sleep(30)"])
        time.sleep(0.3)
        job.stop()
        self.assertTrue(wait(lambda: job.code is not None))


class FakeFl:
    FROZEN = False
    VENV_PY = Path(sys.executable)
    RECOVERY = Path("/r")
    __file__ = "/x/x28_flasher.py"


class CommandTests(unittest.TestCase):
    def test_build_needs_a_finished_backup_and_a_release(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "bk/images").mkdir(parents=True)
            (d / "key.pub").write_text("ssh-ed25519 AAAA")
            (d / "km").mkdir()
            params = {"backup": str(d / "bk"), "tag": "v1"}
            with self.assertRaisesRegex(ValueError, "ARCHIVE.sha256"):  # not finished
                gui.build_command(FakeFl, "build", params, "DA")
            (d / "bk/ARCHIVE.sha256").write_text("x  a.tar")
            with self.assertRaisesRegex(ValueError, "rootfs_b"):
                gui.build_command(FakeFl, "build", params, "DA")
            (d / "bk/images/mtd10-rootfs_b.bin").write_bytes(b"")
            with self.assertRaisesRegex(ValueError, "release"):
                gui.build_command(FakeFl, "build", {**params, "tag": ""}, "DA")
            self.assertIn("build", gui.build_command(FakeFl, "build", params, "DA"))

    def test_backup_needs_a_folder_and_maps_verify(self):
        with self.assertRaises(ValueError):
            gui.build_command(FakeFl, "backup", {}, "DA")
        cmd = gui.build_command(FakeFl, "backup", {"out": "O", "twice": False}, "DA")
        self.assertEqual(cmd[1:], ["/r/usb_backup.py", "--out", "O", "--loader", "DA", "--no-verify"])

    def test_only_known_actions_run(self):
        for bad in ("flash;rm", "restore", None):
            with self.assertRaises(ValueError):
                gui.build_command(FakeFl, bad, {"accept": True}, "DA")
        self.assertEqual(gui.build_command(FakeFl, "test", {}, "DA")[-2:], ["run", "test"])

    def test_writes_need_the_risk_accepted(self):
        for action in gui.WRITE_ACTIONS:
            for params in ({}, {"accept": False}, {"accept": "yes"}):
                with self.assertRaises(ValueError):
                    gui.build_command(FakeFl, action, params, "DA")
        for action in ("access", "rescue"):
            self.assertEqual(gui.build_command(FakeFl, action, {"accept": True}, "DA")[-2:], ["run", action])

    def test_flash_checks_slot_image_backup_copy_and_rehearsal(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            (d / "img").mkdir()
            (d / "img/rootfs-a-experimental.bin").write_bytes(b"")
            (d / "bk/images").mkdir(parents=True)
            (d / "bk/ARCHIVE.sha256").write_text("x  a.tar")
            (d / "bk/images/mtd10-rootfs_b.bin").write_bytes(b"")
            (d / "copy.tar").write_bytes(b"")
            ok = {"slot": "a", "mode": "identical", "candidate": str(d / "img"), "backup": str(d / "bk"), "accept": True}
            self.assertEqual(gui.build_command(FakeFl, "flash", ok, "DA")[-2:], ["run", "flash"])
            for bad, regex in (({"slot": "b"}, "locked"), ({"mode": "x"}, "rehearsal"), ({"candidate": str(d)}, "built image"),
                               ({"backup": str(d)}, "ARCHIVE"), ({"copy": str(d / "nope")}, "second copy"), ({"accept": False}, "accept"),
                               ({"mode": "write", "prior": ""}, "rehearsal")):
                with self.assertRaisesRegex(ValueError, regex):
                    gui.build_command(FakeFl, "flash", {**ok, **bad}, "DA")

    def test_frozen_runs_itself(self):
        fl = types.SimpleNamespace(FROZEN=True, RECOVERY=Path("/r"))
        self.assertEqual(gui.build_command(fl, "test", {}, "DA"), [sys.executable, "run", "test"])
        self.assertEqual(gui.build_command(fl, "identify", {}, "DA")[1], "--run-script")


class SetupTests(unittest.TestCase):
    def test_nothing_to_install_when_frozen(self):
        with self.assertRaises(ValueError):
            gui.build_command(types.SimpleNamespace(FROZEN=True, RECOVERY=Path("/r")), "setup", {}, "DA")

    def test_setup_runs_the_install_script_with_a_new_enough_python(self):
        with unittest.mock.patch.object(gui, "find_python", return_value="/p/python3.14"):
            self.assertEqual(gui.build_command(FakeFl, "setup", {}, "DA"), ["/p/python3.14", "/r/setup_mtkclient.py"])
        with unittest.mock.patch.object(gui, "find_python", return_value=None), self.assertRaises(ValueError):
            gui.build_command(FakeFl, "setup", {}, "DA")

    def test_libusb_needs_homebrew(self):
        with unittest.mock.patch.object(gui, "find_brew", return_value=None), self.assertRaises(ValueError):
            gui.build_command(FakeFl, "libusb", {}, "DA")
        with unittest.mock.patch.object(gui, "find_brew", return_value="/b/brew"):
            self.assertEqual(gui.build_command(FakeFl, "libusb", {}, "DA"), ["/b/brew", "install", "libusb"])

    def test_chooser_only_for_files_and_folders(self):
        with unittest.mock.patch.object(gui.sys, "platform", "darwin"), unittest.mock.patch.object(gui.subprocess, "run") as run:
            with self.assertRaises(RuntimeError):
                gui.pick_path("../../x", "p")
            run.return_value = types.SimpleNamespace(returncode=0, stdout="/a/b\n")
            self.assertEqual(gui.pick_path("file", 'say "hi"'), "/a/b")
            self.assertNotIn('"hi"', run.call_args[0][0][-1])


class RunningTests(unittest.TestCase):
    def test_a_second_launch_finds_the_server_only_while_it_is_alive(self):
        run = Path(tempfile.mkdtemp()) / "running.json"
        with unittest.mock.patch.object(gui, "RUN_FILE", run):
            self.assertIsNone(gui.running_server())  # no file
            run.write_text(json.dumps({"pid": 99999999, "port": 1, "token": "t"}))
            self.assertIsNone(gui.running_server())  # stale pid
            server = ThreadingHTTPServer(("127.0.0.1", 0), gui.make_handler(gui.App(FakeFl)))
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.shutdown)
            run.write_text(json.dumps({"pid": __import__("os").getpid(), "port": server.server_address[1], "token": "t"}))
            self.assertEqual(gui.running_server()["token"], "t")


class ServerTests(unittest.TestCase):
    def setUp(self):
        self.app = gui.App(FakeFl)
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), gui.make_handler(self.app))
        self.app.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.shutdown)

    def call(self, method, path, headers=None, body=None):
        c = http.client.HTTPConnection("127.0.0.1", self.app.port)
        c.request(method, path, body=body, headers=headers or {})
        r = c.getresponse()
        return r.status, r.read(), r

    def test_page_needs_the_token_then_the_cookie(self):
        self.assertEqual(self.call("GET", "/")[0], 403)
        self.assertEqual(self.call("GET", "/?t=wrong")[0], 403)
        status, _, r = self.call("GET", f"/?t={self.app.token}")
        self.assertEqual(status, 302)
        cookie = r.getheader("Set-Cookie").split(";")[0]
        self.assertEqual(self.call("GET", "/", {"Cookie": cookie})[0], 200)

    def test_other_hosts_and_origins_are_refused(self):
        cookie = {"Cookie": f"x28={self.app.token}"}
        self.assertEqual(self.call("GET", "/", {**cookie, "Host": "evil.example"})[0], 403)  # DNS rebinding
        post = {**cookie, "Content-Type": "application/json"}
        self.assertEqual(self.call("POST", "/api/job", post, b'{"action":"test"}')[0], 403)  # no Origin
        self.assertEqual(self.call("POST", "/api/job", {**post, "Origin": "http://evil.example"}, b'{"action":"test"}')[0], 403)

    def test_unknown_action_is_rejected_with_a_reason(self):
        origin = f"http://127.0.0.1:{self.app.port}"
        status, body, _ = self.call("POST", "/api/job", {"Cookie": f"x28={self.app.token}", "Origin": origin}, b'{"action":"nope"}')
        self.assertEqual(status, 409)
        self.assertIn("unknown action", json.loads(body)["error"])


if __name__ == "__main__":
    unittest.main()
