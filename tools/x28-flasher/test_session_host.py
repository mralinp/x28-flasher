import os
import sys
import tempfile
import unittest
from pathlib import Path

import session_host


class RunCommandTests(unittest.TestCase):
    def run_script(self, body, **cmd):
        path = Path(tempfile.mkdtemp()) / "tool.py"
        path.write_text(body)
        return session_host.run_command(None, {"kind": "script", "script": str(path), **cmd})

    def test_exit_codes_and_messages(self):
        self.assertEqual(self.run_script("pass\n"), 0)
        self.assertEqual(self.run_script("import sys\nsys.exit(3)\n"), 3)
        self.assertEqual(self.run_script("raise SystemExit('stopped: reason')\n"), 1)
        self.assertEqual(self.run_script("raise RuntimeError('boom')\n"), 1)

    def test_environment_cwd_and_argv_are_restored_after_each_command(self):
        before = (dict(os.environ), os.getcwd(), sys.argv[:], sys.path[:])
        code = self.run_script("import os, sys\nos.chdir('/')\nsys.exit(0 if os.environ['X28_T'] == '1' and sys.argv[1] == 'a' else 9)\n",
                               env={"X28_T": "1"}, argv=["a"])
        self.assertEqual(code, 0)
        self.assertEqual((dict(os.environ), os.getcwd(), sys.argv[:], sys.path[:]), before)

    def test_a_stop_propagates(self):
        with self.assertRaises(KeyboardInterrupt):
            self.run_script("raise KeyboardInterrupt\n")


if __name__ == "__main__":
    unittest.main()


HOST = r'''
import sys, types
sys.path.insert(0, sys.argv[3]); sys.path.insert(0, sys.argv[4])
log = []
class Port:
    def close(self): log.append("real close")
class Mtk: port = Port()
stub = types.ModuleType("read_by_name")
stub.LIVE = None
def connect(out, loader):
    print("modem power must be OFF now", flush=True)
    return Mtk()
def hold(mtk):
    stub.LIVE = mtk
    mtk.port.close = lambda *a: log.append("close ignored")
def release():
    log.append("released")
stub.connect, stub.hold, stub.release = connect, hold, release
sys.modules["read_by_name"] = stub
import session_host
code = session_host.main(None, sys.argv[1], None)
print("EXIT", code, log, flush=True)
sys.exit(code)
'''


class HostProcessTests(unittest.TestCase):
    def test_connects_once_runs_commands_and_quits(self):
        import json, socket, subprocess, time
        d = Path(tempfile.mkdtemp())
        sock = str(d / "s.sock")
        tool = d / "tool.py"
        tool.write_text("import sys\nprint('tool ran', sys.argv[1:])\n")
        here = Path(__file__).resolve().parent
        proc = subprocess.Popen([sys.executable, "-c", HOST, sock, "", str(here), str(here.parent / "recovery")], stdout=subprocess.PIPE, text=True,
                                env={**os.environ, "X28_PRIVATE": str(d)})
        try:
            for _ in range(100):
                if Path(sock).exists():
                    break
                time.sleep(0.1)
            for cmd in ({"kind": "script", "script": str(tool), "argv": ["a"], "env": {}, "id": "c1"}, {"kind": "quit", "id": "q"}):
                with socket.socket(socket.AF_UNIX) as s:
                    s.connect(sock)
                    s.sendall((json.dumps(cmd) + "\n").encode())
            out, _ = proc.communicate(timeout=20)
        finally:
            proc.kill()
        self.assertIn("\x1eX28SESSION connected", out)
        self.assertIn("tool ran ['a']", out)
        self.assertIn("\x1eX28DONE c1 0", out)
        self.assertIn("EXIT 0 ['released']", out)  # closed for real only at the end, once
