"""The page's server: job output and prompts, and who may talk to it. Run: python3 tools/x28-flasher/test_gui.py"""
import http.client
import json
import sys
import tempfile
import threading
import time
import types
import unittest
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
    def test_backup_needs_a_folder_and_maps_verify(self):
        with self.assertRaises(ValueError):
            gui.build_command(FakeFl, "backup", {}, "DA")
        cmd = gui.build_command(FakeFl, "backup", {"out": "O", "twice": False}, "DA")
        self.assertEqual(cmd[1:], ["/r/usb_backup.py", "--out", "O", "--loader", "DA", "--no-verify"])

    def test_only_known_actions_run(self):
        for bad in ("flash;rm", "restore", None):
            with self.assertRaises(ValueError):
                gui.build_command(FakeFl, bad, {}, "DA")
        self.assertEqual(gui.build_command(FakeFl, "flash", {}, "DA")[-2:], ["run", "flash"])

    def test_frozen_runs_itself(self):
        fl = types.SimpleNamespace(FROZEN=True, RECOVERY=Path("/r"))
        self.assertEqual(gui.build_command(fl, "test", {}, "DA"), [sys.executable, "run", "test"])
        self.assertEqual(gui.build_command(fl, "identify", {}, "DA")[1], "--run-script")


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
