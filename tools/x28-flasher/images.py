"""Where a flashable image comes from (#285): a release's signed image (downloaded and checked), or a local build from the release's assembly and your backup."""
import hashlib
import io
import json
import re
import shutil
import sys
import tarfile
import time
import urllib.request
from pathlib import Path

REPO = "mralinp/zlt-x28-openwrt"
SUMS = "SHA256SUMS"  # the release's one checksum file (asset names are case-insensitive, zlt-x28-openwrt#254)
FILES = ("manifest.json", "rootfs-a-experimental.bin")  # an image folder, as Flash reads it
PARTITION = 0x4000000  # rootfs_a/b: the image is padded to it with 0xff, like package_ubi's output


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def get(url):
    with urllib.request.urlopen(url, timeout=60) as r:
        return r.read()


UNSUPPORTED_UP_TO = (0, 53, 3)  # releases up to and including v0.53.3 are not supported; the next version is the first one


def supported(tag):
    """vX.Y.Z newer than UNSUPPORTED_UP_TO; any other tag name (feed-2, kmods-...) is not an image release."""
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
    return bool(m) and tuple(map(int, m.groups())) > UNSUPPORTED_UP_TO


def signed_name(tag):
    return f"x28-sysupgrade-{tag[1:]}.tar"


def releases(fetch=get, repo=REPO):
    """Releases that carry an assembly bundle, newest first: [{tag, date, beta, signed}] (beta: GitHub marks it a pre-release;
    signed: it also carries the signed image, so it can be downloaded instead of built)."""
    out = []
    for rel in json.loads(fetch(f"https://api.github.com/repos/{repo}/releases?per_page=30")):
        names = [a["name"] for a in rel.get("assets", [])]
        if supported(rel["tag_name"]) and any(n.startswith("x28-assembly-") and n.endswith(".tar.gz") for n in names):
            out.append({"tag": rel["tag_name"], "date": (rel.get("published_at") or "")[:10], "beta": bool(rel.get("prerelease")),
                        "signed": signed_name(rel["tag_name"]) in names})
    return out


def download(dest_root, tag, fetch=get, repo=REPO, now=None):
    """The signed image of one release as an image folder dest_root/native-ubi-release-<tag>; returns that folder. The download must match
    GitHub's digest, its signature must chain to the X28 feed key (signed_image), its metadata must name this board and release, and the
    UBI image inside must match its own hash and the X28 layout. Nothing is kept on any problem."""
    import signed_image
    name = signed_name(tag)
    assets = release_assets(tag, fetch, repo)
    if name not in assets:
        raise RuntimeError(f"release {tag} has no signed image")
    url, want = assets[name]
    blob = fetch(url)
    if not want or sha256(blob) != want:
        raise ValueError(f"{name} does not match its expected SHA-256")
    tarball, meta = signed_image.verify(blob, now=now)
    if meta.get("version", {}).get("release") != tag:
        raise ValueError(f"the signed image is for {meta.get('version', {}).get('release')}, not {tag}")
    with tarfile.open(fileobj=io.BytesIO(tarball)) as tar:  # by name only: nothing in the archive picks a path
        root = tar.extractfile("sysupgrade-x28/root").read()
        root_sha = tar.extractfile("sysupgrade-x28/root.sha256").read().decode().split()[0]
    if sha256(root) != root_sha or not 0 < len(root) <= PARTITION:
        raise ValueError("the image inside does not match its hash")
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build") if not getattr(sys, "frozen", False) else str(Path(sys._MEIPASS) / "tools/build"))
    from package_ubi import inspect  # the same layout check package_ubi runs on a local build
    padded = root + b"\xff" * (PARTITION - len(root))
    manifest = inspect(padded)
    manifest.update(flashable=False, ubi_sha256=sha256(root), padded_sha256=sha256(padded), padded_bytes=len(padded),
                    source={"release": tag, "signed_image": name, "signed_image_sha256": want, "metadata": meta})
    out = dest_root / f"native-ubi-release-{tag}"
    if out.exists():  # downloaded before: fine when it holds this very image
        if json.loads((out / "manifest.json").read_text()).get("padded_sha256") == manifest["padded_sha256"]:
            return out
        raise FileExistsError(f"{out} already exists with another image")
    out.mkdir(parents=True)
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    (out / "rootfs-a-experimental.bin").write_bytes(padded)
    return out


FEED_PREFIXES = ("ipset_", "libipset13_", "x28-ipset-kernel_")  # always installed by first_boot (--ipk)
# The packages an image carries (#420): ours, and the three module packages WireGuard and Passwall2 need. They are installed by
# first_boot as real packages. The bundle holds every module package of the feed; the others are left for the user to install.
PACKAGE_PREFIXES = ("x28-", "luci-proto-x28-mipc_", "kmod-wireguard_", "kmod-ipt-tproxy_", "kmod-ipt-socket_")
STAGE_PREFIXES = ("alsa-lib_", "libstdcpp6_", "ucert_")  # OpenWrt packages the staging step installs


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
    """name -> (url, sha256) from GitHub's own digest for every asset of a release."""
    rel = json.loads(fetch(f"https://api.github.com/repos/{repo}/releases/tags/{tag}"))
    return {a["name"]: (a["browser_download_url"], a.get("digest", "").removeprefix("sha256:")) for a in rel.get("assets", [])}


def extract_bundle(archive, dest):
    """Unpack an x28-assembly tarball (one top folder) to dest. Only plain files and directories inside that folder are accepted, and every
    file its own SHA256SUMS lists must match; on any problem nothing is kept."""
    if dest.is_dir():
        return dest
    tmp = dest.with_name(dest.name + ".part")
    shutil.rmtree(tmp, ignore_errors=True)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        tops = {Path(m.name).parts[0] for m in members if Path(m.name).parts}
        for m in members:
            parts = Path(m.name).parts
            if not (m.isfile() or m.isdir()) or Path(m.name).is_absolute() or ".." in parts:
                raise ValueError(f"unexpected bundle entry: {m.name}")
        if len(tops) != 1:
            raise ValueError("the bundle must have exactly one top folder")
        tar.extractall(tmp, members)
    root = tmp / tops.pop()
    try:
        sums = (root / "SHA256SUMS").read_text().splitlines()
        if not sums:
            raise ValueError("the bundle has no checksums")
        for line in sums:
            want, _, rel = line.partition("  ")
            target = (root / rel).resolve()
            if root.resolve() not in target.parents or not target.is_file() or sha256(target.read_bytes()) != want:
                raise ValueError(f"bundle file {rel} does not match its checksum")
    except (OSError, ValueError):
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    root.rename(dest)
    shutil.rmtree(tmp, ignore_errors=True)
    return dest


def fetch_inputs(dest, tag, fetch=get):
    """The build inputs from one release's assembly bundle, cached in dest: the userspace rootfs, the package files (overlay), the kernel modules
    and the extra packages, split into the X28 feed's (first_boot) and the rest (stage_native)."""
    found = [(n, v) for n, v in release_assets(tag, fetch).items() if n.startswith("x28-assembly-") and n.endswith(".tar.gz")]
    if not found:
        raise RuntimeError(f"release {tag} has no assembly bundle")
    name, (url, want) = found[0]
    root = extract_bundle(fetch_checked(url, want, dest / name, fetch), dest / name.removesuffix(".tar.gz"))
    rootfs = sorted(root.glob("openwrt-*-rootfs.tar.gz"))
    ipks = sorted(str(p) for p in root.glob("ipk/*.ipk"))
    out = {"modern": str(rootfs[0]) if rootfs else "", "overlay": str(root / "overlay"), "kmods": str(root / "kmods"),
           "feed": [p for p in ipks if Path(p).name.startswith(FEED_PREFIXES + PACKAGE_PREFIXES)],
           "extra_ipks": [p for p in ipks if Path(p).name.startswith(STAGE_PREFIXES)]}
    if not rootfs or not (root / "overlay").is_dir() or not any((root / "kmods").glob("*.ko")) or len(set(Path(p).name.split("_")[0] for p in out["feed"]) & {"ipset", "libipset13", "x28-ipset-kernel"}) != 3:
        raise RuntimeError(f"the bundle of {tag} is missing an expected file")
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
    """The three build steps, in order. inputs: stock, modern (files), optional key, extra_ipks, kmods (folder), feed (stage extras, kmods, feed ipks)."""
    stage, profile = work / "stage", work / "profile"
    python = python if isinstance(python, list) else [python]
    return [
        [*python, str(repo / "tools/build/stage_native.py"), "--stock", inputs["stock"], "--modern", inputs["modern"],
         "--ipk", *inputs["extra_ipks"], "--output", str(stage)],
        [*python, str(repo / "tools/build/first_boot.py"), "--stage", str(stage), "--stock", inputs["stock"], "--output", str(profile),
         *(["--public-key", inputs["key"]] if inputs.get("key") else []), "--kmods", inputs["kmods"],
         "--ipk", *inputs["feed"]],
        ["docker", "build", "-t", "x28-firmware-tools:ubi", "-f", str(repo / "tools/firmware/Dockerfile"), str(repo / "tools/firmware")],
        ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
         "--tmpfs", "/tmp:rw,exec,size=768m", "-v", f"{repo / 'tools'}:/tools:ro", "-v", f"{profile}:/profile:ro",
         "-v", f"{out.parent}:/out", "x28-firmware-tools:ubi", "python3", "/tools/build/package_ubi.py", "--profile", "/profile",
         "--output", f"/out/{out.name}"],
    ]


def stamp():
    return time.strftime("%Y%m%d-%H%M%S")
