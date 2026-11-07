"""Where a flashable image comes from (#285): a release download, or a local run of the build pipeline."""
import hashlib
import io
import json
import re
import tarfile
import time
import urllib.request
from pathlib import Path

REPO = "mralinp/zlt-x28-openwrt"
ARCHIVE = "x28-native-image.tar.gz"  # holds exactly manifest.json and rootfs-a-experimental.bin, the package_ubi output Flash reads
SUMS = "sha256sums"
FILES = ("manifest.json", "rootfs-a-experimental.bin")


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


def latest_release(fetch=get, repo=REPO):
    """The newest release that carries the image and its checksums, or None."""
    for rel in json.loads(fetch(f"https://api.github.com/repos/{repo}/releases")):
        urls = {a["name"]: a["browser_download_url"] for a in rel.get("assets", [])}
        if ARCHIVE in urls and SUMS in urls:
            return rel["tag_name"], urls
    return None


UNSUPPORTED_UP_TO = (0, 53, 3)  # releases up to and including v0.53.3 are not supported; the next version is the first one


def supported(tag):
    """vX.Y.Z newer than UNSUPPORTED_UP_TO; any other tag name (feed-2, kmods-...) is not an image release."""
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
    return bool(m) and tuple(map(int, m.groups())) > UNSUPPORTED_UP_TO


def releases(fetch=get, repo=REPO):
    """Releases that carry the userspace tarball, newest first: [{tag, date, beta}] (beta: GitHub marks it a pre-release)."""
    out = []
    for rel in json.loads(fetch(f"https://api.github.com/repos/{repo}/releases?per_page=30")):
        names = [a["name"] for a in rel.get("assets", [])]
        if supported(rel["tag_name"]) and any(n.startswith("x28-userspace-") and n.endswith("-rootfs.tar.gz") for n in names):
            out.append({"tag": rel["tag_name"], "date": (rel.get("published_at") or "")[:10], "beta": bool(rel.get("prerelease"))})
    return out


def download(dest_root, fetch=get, repo=REPO):
    """Fetch, verify and unpack the newest release image into dest_root/native-ubi-release-<tag>; returns that folder."""
    found = latest_release(fetch, repo)
    if not found:
        raise RuntimeError("no release carries a flashable image yet (#254)")
    tag, urls = found
    blob = fetch(urls[ARCHIVE])
    sums = {line.split()[-1]: line.split()[0] for line in fetch(urls[SUMS]).decode().splitlines() if line.strip()}
    if sums.get(ARCHIVE) != sha256(blob):
        raise ValueError(f"{ARCHIVE} does not match {SUMS} of release {tag}")
    out = dest_root / f"native-ubi-release-{tag}"
    if out.exists():
        raise FileExistsError(f"{out} already exists")
    with tarfile.open(fileobj=io.BytesIO(blob)) as tar:
        # by name only: nothing in the archive picks a path
        data = {n: tar.extractfile(n).read() for n in FILES}
    manifest = json.loads(data["manifest.json"])
    if manifest.get("padded_sha256") != sha256(data["rootfs-a-experimental.bin"]):
        raise ValueError("image does not match its manifest")
    out.mkdir(parents=True)
    for name, content in data.items():
        (out / name).write_bytes(content)
    return out


# Pinned: the same files the local builds have used. downloads.openwrt.org keeps a release's packages in place.
OPENWRT = "https://downloads.openwrt.org/releases/23.05.5/"
EXTRA_IPKS = {
    "alsa-lib_1.2.9-1_aarch64_cortex-a53.ipk": (OPENWRT + "packages/aarch64_cortex-a53/packages/", "4cca89805578f18778b5da41221256c2f87ea33cd1dfd083d151ed936cd9db37"),
    "libstdcpp6_12.3.0-4_aarch64_generic.ipk": (OPENWRT + "targets/armsr/armv8/packages/", "3f174e78dead3941736971da0bd99a2b4dd0b3411bbd6ea4870ae677c49dfef4"),
}
FEED_PREFIXES = ("ipset_", "libipset13_", "x28-ipset-kernel_")


def fetch_checked(url, want, dest, fetch=get):
    """dest if it already holds the right bytes, else the download after its SHA-256 matched; nothing is kept on a mismatch."""
    if dest.is_file() and sha256(dest.read_bytes()) == want:
        return dest
    data = fetch(url)
    if sha256(data) != want:
        raise ValueError(f"{dest.name} does not match its expected SHA-256")
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(data)
    return dest


def release_assets(tag, fetch=get, repo=REPO):
    """name -> (url, sha256) from GitHub's own digest for every asset of a release; 'latest' means the newest one with a userspace tarball."""
    api = f"https://api.github.com/repos/{repo}/releases"
    rels = json.loads(fetch(api if tag == "latest" else f"{api}/tags/{tag}"))
    for rel in (rels if tag == "latest" else [rels]):
        found = {a["name"]: (a["browser_download_url"], a.get("digest", "").removeprefix("sha256:")) for a in rel.get("assets", [])}
        if tag != "latest" or any(n.startswith("x28-userspace-") and n.endswith("-rootfs.tar.gz") for n in found):
            return found
    raise RuntimeError("no release carries the userspace tarball")


def extract_overlay(archive, dest):
    """The firmware's package files (first_boot reads them via X28_OVERLAY); only plain files and directories under package/ are accepted."""
    if dest.is_dir():
        return dest
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for m in members:
            parts = Path(m.name).parts
            if not (m.isfile() or m.isdir()) or Path(m.name).is_absolute() or ".." in parts or parts[0] != "package":
                raise ValueError(f"unexpected overlay entry: {m.name}")
        tmp = dest.with_name(dest.name + ".part")
        tar.extractall(tmp, members)
    tmp.rename(dest)
    return dest


def fetch_inputs(dest, tag="latest", fetch=get):
    """The public build inputs, cached in dest: userspace tarball, the firmware overlay (package files), the two OpenWrt ipks and the X28 feed's ipset packages."""
    out = {"extra_ipks": [], "feed": []}
    for name, (url, want) in release_assets(tag, fetch).items():
        if name.startswith("x28-userspace-") and name.endswith("-rootfs.tar.gz"):
            out["modern"] = str(fetch_checked(url, want, dest / name, fetch))
        if name.startswith("x28-overlay-") and name.endswith(".tar.gz"):
            out["overlay"] = str(extract_overlay(fetch_checked(url, want, dest / name, fetch), dest / name.removesuffix(".tar.gz")))
    for name, (url, want) in release_assets("feed-2", fetch).items():
        if name.startswith(FEED_PREFIXES):
            out["feed"].append(str(fetch_checked(url, want, dest / name, fetch)))
    for name, (base, want) in EXTRA_IPKS.items():
        out["extra_ipks"].append(str(fetch_checked(base + name, want, dest / name, fetch)))
    if "overlay" not in out or "modern" not in out or len(out["feed"]) != len(FEED_PREFIXES):
        raise RuntimeError("the release or feed-2 is missing an expected file")
    return out


def stock_command(rootfs_b, out_dir, repo):
    """Extract the stock rootfs from the backup's rootfs_b image in the tools container (read-only input, no network, Linux so case is kept)."""
    script = ("cd /w && ubireader_extract_images -o ub /in/rootfs_b.bin >/dev/null && f=$(find ub -name '*_vol-rootfs.ubifs' | head -n1) && test -n \"$f\" "
              "&& { unsquashfs -no-xattrs -d rootfs \"$f\" >/dev/null || true; } && rm -rf rootfs/dev && tar czf /out/rootfs-b-system.tar.gz rootfs")
    return ["docker", "run", "--rm", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/w:rw,exec,size=1g", "-v", f"{rootfs_b}:/in/rootfs_b.bin:ro", "-v", f"{out_dir}:/out", "x28-firmware-tools:ubi", "sh", "-c", script]


def stock_access_command(rootfs_b, key, out_dir, repo):
    """stock_access.py in the tools container: the backup's rootfs_b plus the public key in, rootfs_b-access.bin and report.json out.
    No network; the default capabilities stay because the extractor keeps file ownership (a root-owned overlay)."""
    return ["docker", "run", "--rm", "--network", "none", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,exec,size=1g",
            "-v", f"{rootfs_b}:/in/rootfs_b.bin:ro", "-v", f"{key}:/in/router.pub:ro",
            "-v", f"{Path(repo) / 'tools/build/stock_access.py'}:/opt/stock_access.py:ro", "-v", f"{out_dir}:/out",
            "x28-firmware-tools:ubi", "python3", "/opt/stock_access.py", "--image", "/in/rootfs_b.bin", "--public-key", "/in/router.pub", "--output", "/out"]


def local_commands(inputs, work, out, repo, python="python3"):  # python: a command, or a list when frozen (the binary's own --run-script)
    """The three build steps, in order. inputs: stock, modern (files), optional key, extra_ipks, feed (stage extras, feed ipks)."""
    stage, profile = work / "stage", work / "profile"
    python = python if isinstance(python, list) else [python]
    return [
        [*python, str(repo / "tools/build/stage_native.py"), "--stock", inputs["stock"], "--modern", inputs["modern"],
         "--ipk", *inputs["extra_ipks"], "--output", str(stage)],
        [*python, str(repo / "tools/build/first_boot.py"), "--stage", str(stage), "--stock", inputs["stock"], "--output", str(profile),
         *(["--public-key", inputs["key"]] if inputs.get("key") else []),
         "--ipk", *inputs["feed"]],
        ["docker", "build", "-t", "x28-firmware-tools:ubi", "-f", str(repo / "tools/firmware/Dockerfile"), str(repo / "tools/firmware")],
        ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--tmpfs", "/tmp:rw,exec,size=768m", "-v", f"{repo / 'tools'}:/tools:ro", "-v", f"{profile}:/profile:ro",
         "-v", f"{out.parent}:/out", "x28-firmware-tools:ubi", "python3", "/tools/build/package_ubi.py", "--profile", "/profile",
         "--output", f"/out/{out.name}"],
    ]


def stamp():
    return time.strftime("%Y%m%d-%H%M%S")
