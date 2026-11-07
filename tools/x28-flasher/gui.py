"""The browser front end of x28-flasher: a page on 127.0.0.1 that drives the same guarded tools as the wizard.

Nothing here writes flash. Every device action is one of the existing tools run as a child process; its questions (including
the typed confirmation phrase) reach the page as prompts and only the person at the page answers them. Frozen builds stay
read-only because the tools themselves refuse (#272).
"""
import ctypes.util
import glob
import json
import os
import pty
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import termios
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

FROZEN = getattr(sys, "frozen", False)
ASSETS = (Path(sys._MEIPASS) if FROZEN else Path(__file__).resolve().parent) / "gui"
WIZARD_ACTIONS = ("build", "test", "read")  # read-only wizard steps, run with plain prompts
WRITE_ACTIONS = ("flash", "access", "rescue")  # steps that write the board: refused unless the page sent the risk acceptance
INFO_PREFIX = "X28INFO "


class Job:
    """One child process. Output is kept as finished lines plus the unfinished tail (a prompt or a progress bar)."""

    def __init__(self, kind, argv, env=None, on_line=None):
        self.id, self.kind, self.lines, self.tail, self.code = secrets.token_hex(4), kind, [], "", None
        self.cond, self.on_line = threading.Condition(), on_line
        # A terminal, not pipes: the guarded write tools refuse a stdin that is not a tty. The person typing in the page is the
        # human at that terminal, and the terminal echoes what they type onto the prompt line.
        self.fd, slave = pty.openpty()
        attrs = termios.tcgetattr(slave)
        attrs[1] &= ~termios.OPOST  # no \n to \r\n: the page splits lines itself
        termios.tcsetattr(slave, termios.TCSANOW, attrs)
        try:
            self.proc = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave, close_fds=True,
                                         env={**os.environ, "PYTHONUNBUFFERED": "1", "NO_COLOR": "1", "TERM": "dumb", **(env or {})})
        finally:
            os.close(slave)
        threading.Thread(target=self._pump, daemon=True).start()

    def feed(self, text):
        """Terminal rules: \\n finishes the tail, \\r throws it away (a progress bar redraws itself)."""
        with self.cond:
            for ch in text:
                if ch == "\n":
                    line, self.tail = self.tail, ""
                    self.lines.append(line)
                    if self.on_line:
                        self.on_line(line)
                elif ch == "\r":
                    self.tail = ""
                else:
                    self.tail += ch
            self.cond.notify_all()

    def _pump(self):
        pending = b""
        while True:
            try:
                chunk = os.read(self.fd, 4096)
            except OSError:  # EIO: the child closed its end
                break
            if not chunk:
                break
            data, pending = pending + chunk, b""
            try:
                text = data.decode()
            except UnicodeDecodeError as err:  # a multi-byte character cut by the read
                if err.start < len(data) - 4:
                    text = data.decode(errors="replace")
                else:
                    text, pending = data[:err.start].decode(), data[err.start:]
            self.feed(text)
        code = self.proc.wait()
        os.close(self.fd)
        with self.cond:
            self.code = code
            self.cond.notify_all()

    def send(self, text):
        if self.code is not None:
            return False
        try:
            os.write(self.fd, (text + "\n").encode())  # the terminal echoes it onto the prompt line
        except OSError:
            return False
        return True

    def stop(self, force=False):
        if self.code is None:
            self.proc.send_signal(signal.SIGTERM if force else signal.SIGINT)


MARK = "\x1e"  # session_host's marker lines start with it
SESSION_ACTIONS = ("identify", "backup", "read", "test", "flash", "access", "rescue")  # the steps that talk to the modem


class RunJob(Job):
    """A command run inside the live session: it shows the session's output until the command's marker line arrives."""

    def __init__(self, kind, link, on_line=None):
        self.id, self.kind, self.lines, self.tail, self.code = secrets.token_hex(4), kind, [], "", None
        self.cond, self.on_line, self.link = threading.Condition(), on_line, link

    def send(self, text):
        return self.code is None and self.link.send(text)

    def stop(self, force=False):
        if self.code is None:
            self.link.interrupt()

    def finish(self, code):
        with self.cond:
            if self.code is None:
                self.code = code
            self.cond.notify_all()


class SessionLink(Job):
    """The process that holds the connection to the modem (session_host.py). Its terminal carries the output of whatever command it runs."""

    def __init__(self, argv, env, sock, app):
        self.sock, self.app, self.active, self.connected, self._marker = sock, app, None, False, None
        super().__init__("session", argv, env)
        threading.Thread(target=self._reap, daemon=True).start()

    def relay(self, out):
        text = "".join(out)
        out.clear()
        if text:
            if self.active:
                self.active.feed(text)
            super().feed(text)

    def feed(self, text):
        out = []
        for ch in text:
            if self._marker is not None:
                if ch == "\n":
                    self._handle(self._marker)
                    self._marker = None
                else:
                    self._marker += ch
            elif ch == MARK:
                self.relay(out)  # what came before the marker belongs to the command the marker ends
                self._marker = ""
            else:
                out.append(ch)
        self.relay(out)

    def _handle(self, text):
        if text == "X28SESSION connected":
            self.connected = True
        elif text.startswith("X28DONE "):
            _, ident, code = text.split()
            if self.active and self.active.id == ident:
                job, self.active = self.active, None
                job.finish(int(code))

    def _reap(self):
        code = self.proc.wait()
        self.connected = False
        if self.app.session is self:
            self.app.session = None
        if self.active:
            self.active.finish(code or 1)

    def submit(self, command):
        """Hand a command to the session over its socket (it may still be starting up)."""
        deadline = time.time() + 90
        while time.time() < deadline and self.code is None:
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
                    s.connect(self.sock)
                    s.sendall((json.dumps(command) + "\n").encode())
                return True
            except OSError:
                time.sleep(0.3)
        return False

    def interrupt(self):
        if self.code is None:
            self.proc.send_signal(signal.SIGINT)

    def disconnect(self, force=False):
        if self.code is None:
            if force:
                self.proc.terminate()
            else:
                self.submit({"kind": "quit", "id": "q"})
        for _ in range(60):
            if self.code is not None:
                return
            time.sleep(0.1)
        self.proc.terminate()


def session_command(argv, env, ident):
    """The command the session runs for a tool's argv: a script (run with the binary's --run-script or the venv python) or a wizard action."""
    if len(argv) >= 3 and argv[-2] == "run":
        return {"kind": "action", "action": argv[-1], "env": env, "id": ident}
    start = 2 if argv[1] == "--run-script" else 1
    return {"kind": "script", "script": argv[start], "argv": argv[start + 1:], "env": env, "id": ident}


def script_cmd(fl, script, argv):
    """A tool script under the mtkclient venv from a checkout, or this binary's --run-script when frozen."""
    return [sys.executable, "--run-script", str(script), *argv] if fl.FROZEN else [str(fl.VENV_PY), str(script), *argv]


def action_cmd(fl, action):
    return [sys.executable, "run", action] if fl.FROZEN else [str(fl.VENV_PY), str(Path(fl.__file__).resolve()), "run", action]


def find_python():
    """A Python >= 3.10 for the mtkclient install (setup_mtkclient.py needs it); the system one is often older."""
    for cand in (sys.executable, *(shutil.which(f"python3.{m}") or "" for m in range(15, 9, -1)),
                 *(f"/opt/homebrew/bin/python3.{m}" for m in range(15, 9, -1))):
        if cand and Path(cand).is_file():
            ok = subprocess.run([cand, "-c", "import sys; sys.exit(sys.version_info < (3, 10))"], capture_output=True).returncode == 0
            if ok:
                return cand
    return None


def find_brew():
    return shutil.which("brew") or next((p for p in ("/opt/homebrew/bin/brew", "/usr/local/bin/brew") if Path(p).is_file()), None)


def have_libusb():
    return bool(ctypes.util.find_library("usb-1.0") or glob.glob("/opt/homebrew/lib/libusb-1.0*.dylib") or glob.glob("/usr/local/lib/libusb-1.0*.dylib"))


def pick_path(kind, prompt):
    """A native chooser (macOS) so nobody types paths; the browser cannot give the page a real path."""
    if sys.platform != "darwin" or kind not in ("file", "folder"):
        raise RuntimeError("no file chooser on this system: type the path")
    what = "file" if kind == "file" else "folder"
    done = subprocess.run(["osascript", "-e", f'POSIX path of (choose {what} with prompt "{prompt.replace(chr(34), "")}")'], capture_output=True, text=True)
    return done.stdout.strip() if done.returncode == 0 else ""  # cancelled: empty


def build_command(fl, action, params, loader):
    """(kind, argv) for a request, or raises ValueError. Pure: nothing runs here."""
    if action == "setup":
        if fl.FROZEN:
            raise ValueError("nothing to install in this build")
        python = find_python()
        if not python:
            raise ValueError("Python 3.10 or newer is needed first: install it from python.org or with Homebrew")
        return [python, str(fl.RECOVERY / "setup_mtkclient.py")]
    if action == "libusb":
        brew = find_brew()
        if not brew:
            raise ValueError("Homebrew is not installed: see brew.sh, then try again")
        return [brew, "install", "libusb"]
    if action == "identify":
        return script_cmd(fl, ASSETS / "device_info.py", ["--loader", loader])
    if action == "backup":
        out = str(params.get("out") or "").strip()
        if not out:
            raise ValueError("choose a folder for the backup")
        return script_cmd(fl, fl.RECOVERY / "usb_backup.py", ["--out", out, "--loader", loader] + ([] if params.get("twice", True) else ["--no-verify"])
                          + (["--chunk-mib", str(int(params["chunk"]))] if params.get("chunk") else []))
    if action == "build":
        import wizard
        if problem := wizard.backup_problem(str(params.get("backup") or "")):
            raise ValueError(problem)
        if not str(params.get("tag") or "").strip():
            raise ValueError("choose the release to build from")
        return action_cmd(fl, action)
    if action == "flash":
        import wizard
        from common import PRIVATE, slot_tools_digest
        if str(params.get("slot") or "a") != "a":
            raise ValueError("slot B is locked: only slot A can be flashed with this build")
        if params.get("mode") not in ("identical", "write"):
            raise ValueError("choose a rehearsal or the write")
        if not (Path(str(params.get("candidate") or "")) / "rootfs-a-experimental.bin").is_file():
            raise ValueError("choose a built image to flash")
        if problem := wizard.backup_problem(str(params.get("backup") or "")):
            raise ValueError(problem)
        if params.get("copy") and not Path(str(params["copy"])).is_file():
            raise ValueError("the second copy of the backup archive was not found")
        if params["mode"] == "write" and params.get("prior") and str(params["prior"]) not in [str(r) for r in wizard.verified_identicals(PRIVATE / "usb-probe", tools=slot_tools_digest())]:
            raise ValueError("that rehearsal is older than 24 hours or was made with another version of the app: run it again, or write without one")
        if params.get("accept") is not True:
            raise ValueError("accept the risk first: this writes the board")
        return action_cmd(fl, action)
    if action == "read" and params.get("partition"):  # the page's Read form; without a partition the terminal wizard asks for one
        import re
        from common import PRIVATE
        name = str(params["partition"]).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,40}", name):
            raise ValueError("that is not a partition name")
        argv = [name, "--loader", loader, "--save-to", str(params.get("save") or PRIVATE / "reads")]
        if params.get("compare"):
            import wizard
            if problem := wizard.backup_problem(str(params.get("backup") or "")):
                raise ValueError(problem)
            argv += ["--backup", str(params["backup"])]
        else:
            argv.append("--no-compare")
        return script_cmd(fl, fl.RECOVERY / "read_by_name.py", argv)
    if action in WRITE_ACTIONS and params.get("accept") is not True:
        raise ValueError("accept the risk first: this writes the board")
    if action in WIZARD_ACTIONS + WRITE_ACTIONS:
        return action_cmd(fl, action)
    raise ValueError(f"unknown action {action!r}")


class App:
    def __init__(self, fl):
        self.fl, self.token, self.jobs, self.current, self.info, self.uart = fl, os.environ.pop("X28_TOKEN", None) or secrets.token_urlsafe(24), {}, None, None, None
        self.port = 0
        self.session = None
        self.lock = threading.Lock()

    def new_session(self, loader):
        fl = self.fl
        sock = str(RUN_FILE.parent / "session.sock")
        argv = [sys.executable, "session", "--sock", sock, "--loader", loader] if fl.FROZEN else \
            [str(fl.VENV_PY), str(Path(fl.__file__).resolve()), "session", "--sock", sock, "--loader", loader]
        RUN_FILE.parent.mkdir(mode=0o700, exist_ok=True)
        self.session = SessionLink(argv, {"X28_RECOVERY": str(fl.RECOVERY)}, sock, self)
        return self.session

    def disconnect(self, force=False):
        if self.session:
            self.session.disconnect(force)

    def config(self):
        import wizard
        from common import PRIVATE
        return wizard.Config(PRIVATE / "x28-flasher.json")

    def loader_path(self, params=None):
        from common import VENDOR_DA
        return str((params or {}).get("loader") or self.config().get("loader") or VENDOR_DA)

    def start_job(self, action, params):
        with self.lock:
            if self.current and self.current.code is None:
                raise RuntimeError("another job is still running")
            loader = self.loader_path(params)
            if action in ("identify", "backup"):
                if not Path(loader).is_file():
                    raise ValueError(f"download agent not found: {loader}")
                self.config().set("loader", loader)
            argv = build_command(self.fl, action, params, loader)
            if action == "backup":
                self.config().set("backup", str(params["out"]).strip())  # Build looks for finished backups here, and beside the usual places
            env = {"X28_RECOVERY": str(self.fl.RECOVERY)}
            if action == "flash":
                env["X28_FLASH"] = json.dumps({**{k: str(params.get(k) or "") or None for k in ("mode", "candidate", "backup", "copy", "prior")},
                                               "base": None, "no_ssh": True, "no_uart": True, "loader": loader})  # a flash needs neither SSH nor a UART log
            if action == "build":
                env["X28_BUILD"] = json.dumps({k: str(params[k]) for k in ("backup", "tag")})
            if self.uart and self.uart["cap"].is_alive():
                env["X28_UART_LOG"] = str(self.uart["path"])
            def on_line(line):
                if line.startswith(INFO_PREFIX):
                    try:
                        self.info = {**json.loads(line[len(INFO_PREFIX):]), "at": time.time()}
                    except ValueError:
                        pass
            if action in SESSION_ACTIONS:  # one process holds the modem connection: only the first action needs a power cycle
                link = self.session if self.session and self.session.code is None else self.new_session(loader)
                job = RunJob(action, link, on_line)
                link.active = job
                self.jobs[job.id] = self.current = job
                threading.Thread(target=link.submit, args=(session_command(argv, env, job.id),), daemon=True).start()
                return job
            job = Job(action, argv, env, on_line)
            self.jobs[job.id] = self.current = job
            return job

    def uart_status(self):
        u = self.uart
        if not u:
            return None
        return {"port": u["port"], "baud": u["baud"], "path": str(u["path"]), "bytes": u["cap"].bytes, "running": u["cap"].is_alive()}

    def uart_start(self, port, baud):
        fl = self.fl
        if self.uart and self.uart["cap"].is_alive():
            raise RuntimeError("the UART monitor is already running")
        baud = int(baud) or fl.auto_baud(port) or 921600  # 0 = listen and pick; the X28 console is 921600
        path = fl.log_dir() / f"x28-uart-{time.strftime('%Y%m%d-%H%M%S')}.log"
        path.parent.mkdir(parents=True, exist_ok=True)
        cap = fl.Capture(port, baud, path)
        cap.start()
        self.uart = {"cap": cap, "port": port, "baud": baud, "path": path}

    def uart_stop(self):
        if self.uart:
            self.uart["cap"].stop_event.set()

    def uart_tail(self, size=16384):
        if not self.uart:
            return ""
        with open(self.uart["path"], "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - size))
            return f.read().decode(errors="replace")

    def build_inputs(self):
        """What the Build form offers: finished backups near the usual places, the user's public keys, the kernel-modules folder."""
        import wizard
        from common import PRIVATE, slot_tools_digest
        desktop = Path.home() / "Desktop"
        roots = {Path(self.fl.default_backup_dir()), Path(self.config().get("backup") or "."), *desktop.glob("x28*")}
        found = []
        for root in list(roots):
            found += [root, *(d for d in root.glob("*") if d.is_dir())] if root.is_dir() else []
        backups = sorted({str(d) for d in found if wizard.backup_problem(d) is None})
        return {"backups": backups, "docker": bool(shutil.which("docker")),
                "reads_dir": str(PRIVATE / "reads"),
                "images": [str(d) for d in wizard.image_dirs(PRIVATE / "build")] if (PRIVATE / "build").is_dir() else [],
                "rehearsals": [str(r) for r in wizard.verified_identicals(PRIVATE / "usb-probe", tools=slot_tools_digest())] if (PRIVATE / "usb-probe").is_dir() else [],
                "stale_rehearsals": len(wizard.verified_identicals(PRIVATE / "usb-probe")) - len(wizard.verified_identicals(PRIVATE / "usb-probe", tools=slot_tools_digest())) if (PRIVATE / "usb-probe").is_dir() else 0}

    def state(self):
        from common import DEFAULT_BACKUP, PRIVATE
        import wizard
        fl = self.fl
        try:
            ports = [{"device": d, "desc": x} for d, x in fl.list_ports()]
        except Exception:
            ports = []
        loader = self.loader_path()
        images = [d.name for d in wizard.image_dirs(PRIVATE / "build")] if (PRIVATE / "build").is_dir() else []
        job = self.current
        from common import MTK_HOME
        in_venv = fl.FROZEN or os.path.realpath(sys.prefix) == os.path.realpath(MTK_HOME / "venv")
        setup = {"mtkclient": fl.FROZEN or fl.VENV_PY.exists(), "restart": not in_venv and fl.VENV_PY.exists(), "libusb": fl.FROZEN or have_libusb(),
                 "python": bool(fl.FROZEN or find_python()), "brew": bool(find_brew()), "mac": sys.platform == "darwin"}
        return {"frozen": fl.FROZEN, "setup": setup, "ports": ports, "loader": {"path": loader, "ok": Path(loader).is_file()},
                "backup_out": str(fl.default_backup_dir()), "backup_dir": self.config().get("backup") or str(DEFAULT_BACKUP),
                "images": images, "info": self.info, "build": self.build_inputs(), "uart": self.uart_status(),
                "session": {"state": "connected" if self.session.connected else "connecting"} if self.session and self.session.code is None else None,
                "job": {"id": job.id, "kind": job.kind, "running": job.code is None} if job else None}


def make_handler(app):
    class Handler(BaseHTTPRequestHandler):
        server_version = "x28-flasher"

        def log_message(self, *args):
            pass

        def reply(self, code, body=b"", ctype="application/json", headers=()):
            if not isinstance(body, bytes):
                body = json.dumps(body).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            for k, v in headers:
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def allowed(self, post):
            """Only this machine's page: right Host (DNS rebinding), right cookie, and for POST the page's own Origin."""
            if self.headers.get("Host") not in (f"127.0.0.1:{app.port}", f"localhost:{app.port}"):
                return False
            if f"x28={app.token}" not in (c.strip() for c in (self.headers.get("Cookie") or "").split(";")):
                return False
            return not post or self.headers.get("Origin") == f"http://{self.headers.get('Host')}"

        def body(self):
            n = int(self.headers.get("Content-Length") or 0)
            return json.loads(self.rfile.read(min(n, 65536)) or b"{}")

        def do_GET(self):
            url = urlparse(self.path)
            if url.path == "/" and parse_qs(url.query).get("t") == [app.token] and self.headers.get("Host") in (f"127.0.0.1:{app.port}", f"localhost:{app.port}"):
                return self.reply(302, headers=[("Location", "/"), ("Set-Cookie", f"x28={app.token}; HttpOnly; SameSite=Strict; Path=/")])
            if not self.allowed(False):
                return self.reply(403, b"Open the address that x28-flasher printed in the terminal.", "text/plain")
            if url.path == "/":
                return self.reply(200, (ASSETS / "index.html").read_bytes(), "text/html; charset=utf-8")
            if url.path == "/api/state":
                return self.reply(200, app.state())
            if url.path == "/api/boot":
                import boot_ssh
                try:
                    return self.reply(200, boot_ssh.state(self.headers.get("X-Addr", ""), self.headers.get("X-Pw", "")))
                except boot_ssh.BootError as err:
                    return self.reply(409, {"error": str(err)})
            if url.path == "/api/uart/tail":
                return self.reply(200, {"text": app.uart_tail(), "status": app.uart_status()})
            parts = url.path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "job"] and parts[3] == "stream" and parts[2] in app.jobs:
                return self.stream(app.jobs[parts[2]])
            self.reply(404, {"error": "not found"})

        def stream(self, job):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            sent, last = 0, None
            try:
                while True:
                    with job.cond:
                        job.cond.wait_for(lambda: len(job.lines) > sent or (job.tail, job.code) != last, timeout=15)
                        event = {"lines": job.lines[sent:], "tail": job.tail, "code": job.code}
                        sent, last = len(job.lines), (job.tail, job.code)
                    self.wfile.write(b"data: " + json.dumps(event).encode() + b"\n\n")
                    self.wfile.flush()
                    if event["code"] is not None:
                        return
            except (BrokenPipeError, ConnectionResetError):
                return

        def do_POST(self):
            if not self.allowed(True):
                return self.reply(403, {"error": "forbidden"})
            path = urlparse(self.path).path.strip("/").split("/")
            try:
                data = self.body()
                if path == ["api", "job"]:
                    job = app.start_job(data.get("action"), data)
                    return self.reply(200, {"id": job.id})
                if len(path) == 4 and path[:2] == ["api", "job"] and path[2] in app.jobs:
                    job = app.jobs[path[2]]
                    if path[3] == "input":
                        return self.reply(200, {"ok": job.send(str(data.get("text", "")))})
                    if path[3] == "stop":
                        job.stop(bool(data.get("force")))
                        return self.reply(200, {"ok": True})
                if path == ["api", "session"]:  # Disconnect: close the held connection to the modem
                    if app.current and app.current.code is None:
                        raise RuntimeError("a job is still running: stop it first")
                    app.disconnect()
                    return self.reply(200, {"ok": True})
                if path == ["api", "quit"]:  # the page's Quit button: stop the background server
                    if app.current and app.current.code is None:
                        raise RuntimeError("a job is still running: stop it first")
                    def bye():
                        time.sleep(0.3)
                        app.disconnect(force=True)
                        app.uart_stop()
                        RUN_FILE.unlink(missing_ok=True)
                        os._exit(0)
                    threading.Thread(target=bye, daemon=True).start()
                    return self.reply(200, {"ok": True})
                if path == ["api", "loader"]:
                    if not Path(str(data.get("path", ""))).is_file():
                        raise ValueError("that file does not exist")
                    app.config().set("loader", str(data["path"]))
                    return self.reply(200, {"ok": True})
                if path == ["api", "boot"]:  # over SSH on the running modem: no USB session needed
                    import boot_ssh
                    try:
                        return self.reply(200, boot_ssh.set_slot(str(data.get("slot")), str(data.get("addr") or ""), str(data.get("pw") or "")))
                    except boot_ssh.BootError as err:
                        raise RuntimeError(str(err))
                if path == ["api", "releases"]:
                    import images
                    return self.reply(200, {"releases": images.releases()})
                if path == ["api", "check_backup"]:
                    import wizard
                    return self.reply(200, {"problem": wizard.backup_problem(str(data.get("path") or ""))})
                if path == ["api", "pick"]:
                    return self.reply(200, {"path": pick_path(data.get("kind"), str(data.get("prompt") or "Choose"))})
                if path == ["api", "restart"]:  # after the install: run again inside the mtkclient venv, same port and token, so the page just reconnects
                    if app.current and app.current.code is None:
                        raise RuntimeError("a job is still running")
                    env = {**os.environ, "X28_PORT": str(app.port), "X28_TOKEN": app.token}
                    def again():
                        time.sleep(0.5)
                        app.uart_stop()
                        os.execve(str(app.fl.VENV_PY), [str(app.fl.VENV_PY), *sys.argv], env)
                    threading.Thread(target=again, daemon=True).start()
                    return self.reply(200, {"ok": True})
                if path == ["api", "uart"]:
                    app.uart_start(data["port"], data.get("baud", 0)) if data.get("on") else app.uart_stop()
                    return self.reply(200, app.uart_status() or {})
            except (ValueError, RuntimeError, KeyError) as err:
                return self.reply(409, {"error": str(err)})
            self.reply(404, {"error": "not found"})

    return Handler


RUN_FILE = Path.home() / ".x28-flasher" / "running.json"  # pid, port, token of the server that is up, so a second launch reuses it


def running_server():
    """The server another launch left running, or None."""
    try:
        info = json.loads(RUN_FILE.read_text())
        os.kill(info["pid"], 0)
        socket.create_connection(("127.0.0.1", info["port"]), timeout=1).close()
        return info
    except (OSError, ValueError, KeyError):
        return None


def serve(fl, open_browser=True, port=0):
    # An app opened from Finder has a bare PATH: Docker (Build) lives in one of these.
    os.environ["PATH"] = os.pathsep.join([os.environ.get("PATH", ""), "/usr/local/bin", "/opt/homebrew/bin", "/Applications/Docker.app/Contents/Resources/bin"])
    open_browser = open_browser and not os.environ.get("X28_NO_BROWSER")  # the native window shows the page itself
    restarted = "X28_PORT" in os.environ  # started again by /api/restart: same address, and the open page reconnects by itself
    if not restarted and (other := running_server()):  # opened the app twice: just show the page that is already up
        url = f"http://127.0.0.1:{other['port']}/?t={other['token']}"
        print(f"x28-flasher is already running at {url}", flush=True)
        if open_browser:
            webbrowser.open(url)
        return 0
    app = App(fl)
    port = int(os.environ.pop("X28_PORT", port))
    for attempt in range(20):  # the old process may still hold the port for a moment
        try:
            server = ThreadingHTTPServer(("127.0.0.1", port), make_handler(app))
            break
        except OSError:
            if attempt == 19:
                raise
            time.sleep(0.25)
    server.daemon_threads = True
    app.port = server.server_address[1]
    url = f"http://127.0.0.1:{app.port}/?t={app.token}"
    RUN_FILE.parent.mkdir(mode=0o700, exist_ok=True)
    RUN_FILE.write_text(json.dumps({"pid": os.getpid(), "port": app.port, "token": app.token}))
    RUN_FILE.chmod(0o600)
    print(f"x28-flasher is open at {url}\nPress Ctrl-C here to quit.", flush=True)
    if open_browser and not restarted:
        webbrowser.open(url)
    def terminated(*_):  # the native window closing: let go of the modem as well
        app.disconnect(force=True)
        RUN_FILE.unlink(missing_ok=True)
        os._exit(0)
    signal.signal(signal.SIGTERM, terminated)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        app.uart_stop()
        if app.current:
            app.current.stop()
        app.disconnect(force=True)
        RUN_FILE.unlink(missing_ok=True)
    return 0
