"""The live session: one process holds the download-agent connection and runs the tools inside it, so only the first action needs a power cycle.

`x28_flasher.py session --sock PATH --loader DA`: it opens the socket, waits for the modem (the same preloader handshake the tools do), holds the
connection (read_by_name.hold) and then runs the commands the page sends, one at a time, in this process: the guarded tools themselves, unchanged,
whose connect() now returns the held connection and whose close() leaves it open. Their output goes to this process's terminal (the page relays it)
and each command ends with a marker line. A stop (Ctrl-C) ends the session: a transfer cut in the middle leaves the agent in an unknown state.
"""
import json
import os
import queue
import runpy
import signal
import socket
import sys
import threading
import time
import traceback
from pathlib import Path

MARK = "\x1e"  # marker lines start with it; the page's relay strips them out of the output


def say(text):
    print(f"\n{MARK}{text}", flush=True)


def run_command(fl, cmd):
    """Run one command in this process; returns its exit code. KeyboardInterrupt (a stop) propagates."""
    env, cwd, argv, path = dict(os.environ), os.getcwd(), sys.argv[:], sys.path[:]
    os.environ.update({k: str(v) for k, v in (cmd.get("env") or {}).items()})
    try:
        if cmd["kind"] == "action":
            return __import__("wizard").run_action(fl, cmd["action"]) or 0
        script = str(Path(cmd["script"]).resolve())
        sys.argv = [script, *cmd.get("argv", [])]
        sys.path.insert(0, str(Path(script).parent))
        runpy.run_path(script, run_name="__main__")
        return 0
    except SystemExit as done:
        if isinstance(done.code, str):
            print(done.code, flush=True)
            return 1
        return done.code or 0
    except KeyboardInterrupt:
        raise
    except BaseException:
        traceback.print_exc()
        return 1
    finally:
        os.environ.clear()
        os.environ.update(env)
        os.chdir(cwd)
        sys.argv, sys.path[:] = argv, path


def listen(path, commands):
    """Commands arrive on a unix socket, one JSON line each; they queue up while the modem is still being waited for."""
    Path(path).unlink(missing_ok=True)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(str(path))
    os.chmod(path, 0o600)
    srv.listen(4)

    def accept():
        while True:
            conn, _ = srv.accept()
            with conn, conn.makefile("r") as stream:
                for line in stream:
                    if line.strip():
                        commands.put(json.loads(line))
    threading.Thread(target=accept, daemon=True).start()


def main(fl, sock, loader):
    import read_by_name  # the recovery tools are on sys.path (x28_flasher puts them there)
    from common import probe_dir
    commands = queue.Queue()
    listen(sock, commands)
    signal.signal(signal.SIGTERM, lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))
    parent = os.getppid()

    def orphaned():  # the app that started this session is gone: let go of the modem
        while True:
            time.sleep(2)
            if os.getppid() != parent:
                os._exit(1)
    threading.Thread(target=orphaned, daemon=True).start()
    out = probe_dir()
    os.chdir(out)  # mtkclient drops its hwparam/state files in the working directory
    code = 0
    try:  # a stop ends the session (KeyboardInterrupt); the page sees the process exit
        read_by_name.hold(read_by_name.connect(out, Path(loader) if loader else None))
        say("X28SESSION connected")
        while True:
            cmd = commands.get()
            if cmd["kind"] == "quit":
                break
            code = run_command(fl, cmd)
            say(f"X28DONE {cmd['id']} {code}")
    except KeyboardInterrupt:
        print("\nstopped: the connection to the modem is closed. Power-cycle the modem to connect again.", flush=True)
        code = 130
    finally:
        read_by_name.release()
        Path(sock).unlink(missing_ok=True)
    return code
