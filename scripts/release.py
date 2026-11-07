"""Release helper used by CI. Standard library only (same rules as the maintainer's MQute).

    python3 scripts/release.py check-title "feat(build): attach rootfs to releases"
    python3 scripts/release.py next-version
    python3 scripts/release.py selftest

Versions follow SemVer and are derived from Conventional Commits since the
latest ``vX.Y.Z`` tag:

* ``type!:`` or a ``BREAKING CHANGE:`` footer -> major (minor while < 1.0)
* ``feat:``                                    -> minor
* anything else                                -> patch

The first release is 0.1.0. Every 0.x release is published as a GitHub pre-release.
"""

from __future__ import annotations

import re
import subprocess
import sys

TYPES = ("feat", "fix", "perf", "refactor", "docs", "test", "build", "ci", "chore", "style", "revert")
TITLE = re.compile(rf"^(?P<type>{'|'.join(TYPES)})(\([\w./ -]+\))?(?P<breaking>!)?: \S.*$")
INITIAL_VERSION = "0.1.0"
PATCH, MINOR, MAJOR = 0, 1, 2


def is_conventional(title):
    return TITLE.match(title.strip()) is not None


def bump_for(message):
    subject, _, body = message.strip().partition("\n")
    match = TITLE.match(subject.strip())
    if (match and match["breaking"]) or re.search(r"^BREAKING[ -]CHANGE:", body, re.MULTILINE):
        return MAJOR
    if match and match["type"] == "feat":
        return MINOR
    return PATCH


def next_version(current, messages):
    if current is None:
        return INITIAL_VERSION
    major, minor, patch = (int(part) for part in current.split("."))
    bump = max((bump_for(m) for m in messages), default=PATCH)
    if bump == MAJOR and major == 0:
        bump = MINOR  # SemVer 0.x: breaking changes bump the minor version
    if bump == MAJOR:
        return f"{major + 1}.0.0"
    if bump == MINOR:
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def _git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout


def latest_tag():
    try:
        return _git("describe", "--tags", "--abbrev=0", "--match", "v[0-9]*.[0-9]*.[0-9]*").strip() or None
    except subprocess.CalledProcessError:
        return None


def commit_messages(since):
    revision = f"{since}..HEAD" if since else "HEAD"
    return [m for m in _git("log", "--format=%B%x00", revision).split("\x00") if m.strip()]


def selftest():
    assert is_conventional("feat(build): attach rootfs") and is_conventional("fix!: drop x")
    assert not is_conventional("Update README") and not is_conventional("feat:missing space")
    assert next_version(None, ["anything"]) == "0.1.0"
    assert next_version("0.1.0", ["fix(recovery): x", "docs: y"]) == "0.1.1"
    assert next_version("0.1.1", ["fix: a", "feat(build): b"]) == "0.2.0"
    assert next_version("0.2.0", ["feat!: break"]) == "0.3.0"  # minor while 0.x
    assert next_version("0.2.0", ["fix: a\n\nBREAKING CHANGE: b"]) == "0.3.0"
    assert next_version("1.4.2", ["refactor!: c"]) == "2.0.0"
    assert next_version("1.4.2", []) == "1.4.3"
    print("release.py self-check OK")


def main(argv):
    if len(argv) == 2 and argv[0] == "check-title":
        if is_conventional(argv[1]):
            return 0
        print(f"PR title {argv[1]!r} is not a Conventional Commit, e.g. 'feat(build): attach rootfs to releases'.")
        print(f"Allowed types: {', '.join(TYPES)}. Add '!' after the type for breaking changes.")
        return 1
    if argv == ["next-version"]:
        tag = latest_tag()
        current = tag[1:] if tag else None
        print(next_version(current, commit_messages(tag)))
        return 0
    if argv == ["selftest"]:
        selftest()
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
