"""Release download and local build commands (#285). Run: python3 tools/x28-flasher/test_images.py"""
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import images


def release(bin_=b"\xffimage", sums_ok=True, extra=()):
    manifest = json.dumps({"padded_sha256": images.sha256(bin_)}).encode()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (("manifest.json", manifest), ("rootfs-a-experimental.bin", bin_), *extra):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    blob = buf.getvalue()
    sums = f"{images.sha256(blob) if sums_ok else '0' * 64}  {images.ARCHIVE}\n".encode()
    listing = [{"tag_name": "v0.47.0", "assets": [{"name": images.ARCHIVE, "browser_download_url": "u/a"}, {"name": images.SUMS, "browser_download_url": "u/s"}]},
               {"tag_name": "v0.46.0", "assets": []}]
    files = {"u/a": blob, "u/s": sums}
    return lambda url: json.dumps(listing).encode() if "api.github" in url else files[url]


class DownloadTests(unittest.TestCase):
    def test_download_verifies_and_unpacks(self):
        root = Path(tempfile.mkdtemp())
        out = images.download(root, fetch=release())
        self.assertEqual(out.name, "native-ubi-release-v0.47.0")
        self.assertEqual((out / "rootfs-a-experimental.bin").read_bytes(), b"\xffimage")

    def test_checksum_mismatch_writes_nothing(self):
        root = Path(tempfile.mkdtemp())
        with self.assertRaises(ValueError):
            images.download(root, fetch=release(sums_ok=False))
        self.assertEqual(list(root.iterdir()), [])

    def test_manifest_must_match_image(self):
        fetch = release()
        listing = json.loads(fetch("https://api.github.com/x"))
        bad = release(bin_=b"a")
        blob = bad("u/a")
        with tarfile.open(fileobj=io.BytesIO(blob)) as src, tarfile.open(fileobj=(buf := io.BytesIO()), mode="w:gz") as dst:
            for name, data in (("manifest.json", b'{"padded_sha256": "x"}'), ("rootfs-a-experimental.bin", b"a")):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                dst.addfile(info, io.BytesIO(data))
        files = {"u/a": buf.getvalue(), "u/s": f"{images.sha256(buf.getvalue())}  {images.ARCHIVE}".encode()}
        with self.assertRaises(ValueError):
            images.download(Path(tempfile.mkdtemp()), fetch=lambda u: json.dumps(listing).encode() if "api.github" in u else files[u])

    def test_no_release_with_an_image(self):
        with self.assertRaises(RuntimeError):
            images.download(Path(tempfile.mkdtemp()), fetch=lambda u: b'[{"tag_name": "v1", "assets": []}]')


class StockAccessTests(unittest.TestCase):
    def test_container_is_offline_and_runs_the_repo_script_on_read_only_inputs(self):
        cmd = images.stock_access_command(Path("/b/rootfs_b.bin"), Path("/k/router.pub"), Path("/out"), Path("/repo"))
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertIn("/b/rootfs_b.bin:/in/rootfs_b.bin:ro", cmd)
        self.assertIn("/k/router.pub:/in/router.pub:ro", cmd)
        self.assertIn("/repo/tools/build/stock_access.py:/opt/stock_access.py:ro", cmd)
        self.assertEqual(cmd[-8:], ["python3", "/opt/stock_access.py", "--image", "/in/rootfs_b.bin", "--public-key", "/in/router.pub", "--output", "/out"])


class LocalTests(unittest.TestCase):
    def test_commands_run_in_pipeline_order_and_chain_outputs(self):
        inputs = {"stock": "s.tgz", "modern": "m.tgz", "key": "k.pub", "kmods": "km", "extra_ipks": ["a.ipk"], "feed": ["f.ipk"]}
        work, out = Path("/w"), Path("/b/native-ubi-local-1")
        cmds = images.local_commands(inputs, work, out, Path("/r"))
        self.assertEqual([c[1].split("/")[-1] if c[0] == "python3" else c[1] for c in cmds], ["stage_native.py", "first_boot.py", "build", "run"])
        self.assertEqual(cmds[0][-1], "/w/stage")
        self.assertIn("/w/stage", cmds[1])
        self.assertIn("/w/profile:/profile:ro", cmds[3])
        self.assertEqual(cmds[3][-1], "/out/native-ubi-local-1")


def overlay_tar(name="package/x28-leds/files/x"):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo(name)
        info.size = 1
        tar.addfile(info, io.BytesIO(b"x"))
    return buf.getvalue()


def public_inputs(tamper=False):
    blobs, assets = {}, {"latest": [], "feed-2": []}

    def add(tag, name, data):
        url = f"u/{tag}/{name}"
        blobs[url] = data
        assets[tag].append({"name": name, "browser_download_url": url, "digest": "sha256:" + images.sha256(b"x" if tamper else data)})

    add("latest", "x28-userspace-v1-openwrt-23.05.5-armsr-armv8-rootfs.tar.gz", b"userspace")
    add("latest", "x28-overlay-v1.tar.gz", overlay_tar())
    add("latest", "SHA256SUMS", b"ignored")
    for name in ("ipset_1.ipk", "libipset13_1.ipk", "x28-ipset-kernel_1.ipk", "kmod-other.ipk"):
        add("feed-2", name, name.encode())
    for name, (base, want) in images.EXTRA_IPKS.items():
        blobs[base + name] = name.encode()

    def fetch(url):
        if "api.github" in url:
            tag = "feed-2" if url.endswith("tags/feed-2") else "latest"
            rels = [{"tag_name": "v1", "assets": assets[tag]}]
            return json.dumps(rels if tag == "latest" else rels[0]).encode()
        return blobs[url]
    return fetch


class InputTests(unittest.TestCase):
    def test_extra_ipk_hashes_are_checked(self):
        with mock.patch.dict(images.EXTRA_IPKS, {n: (b, "0" * 64) for n, (b, _) in images.EXTRA_IPKS.items()}):
            with self.assertRaises(ValueError):
                images.fetch_inputs(Path(tempfile.mkdtemp()), fetch=public_inputs())

    def test_a_mismatch_keeps_nothing(self):
        dest = Path(tempfile.mkdtemp())
        with self.assertRaises(ValueError):
            images.fetch_inputs(dest, fetch=public_inputs(tamper=True))
        self.assertEqual(list(dest.iterdir()), [])

    def test_overlay_is_extracted_and_escapes_are_refused(self):
        dest = Path(tempfile.mkdtemp())
        with mock.patch.dict(images.EXTRA_IPKS, {n: (b, images.sha256(n.encode())) for n, (b, _) in images.EXTRA_IPKS.items()}):
            out = images.fetch_inputs(dest, fetch=public_inputs())
        self.assertTrue((Path(out["overlay"]) / "package/x28-leds/files/x").is_file())
        bad = dest / "bad.tar.gz"
        bad.write_bytes(overlay_tar("../evil"))
        with self.assertRaises(ValueError):
            images.extract_overlay(bad, dest / "bad")

    def test_stock_extraction_is_offline_and_read_only(self):
        cmd = images.stock_command(Path("/b/rootfs_b.bin"), Path("/o"), Path("/r"))
        self.assertIn("none", cmd)
        self.assertIn("*_vol-rootfs.ubifs", cmd[-1])  # not rootfs_data, which also matches *vol-rootfs*
        self.assertIn("/b/rootfs_b.bin:/in/rootfs_b.bin:ro", cmd)


if __name__ == "__main__":
    unittest.main()


class ReleaseListTests(unittest.TestCase):
    def test_lists_releases_with_the_userspace_tarball_and_flags_kernel_modules(self):
        rels = [{"tag_name": "v2", "published_at": "2026-11-06T01:00:00Z", "assets": [{"name": "x28-userspace-v2-x-rootfs.tar.gz"}, {"name": "x28-kmods-v2.tar.gz"}]},
                {"tag_name": "feed-2", "assets": [{"name": "ipset.ipk"}]},
                {"tag_name": "v1", "published_at": "2026-11-05T01:00:00Z", "assets": [{"name": "x28-userspace-v1-x-rootfs.tar.gz"}]}]
        got = images.releases(fetch=lambda url: json.dumps(rels).encode())
        self.assertEqual(got, [{"tag": "v2", "date": "2026-11-06", "kmods": True}, {"tag": "v1", "date": "2026-11-05", "kmods": False}])
