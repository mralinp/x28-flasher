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
        inputs = {"stock": "s.tgz", "modern": "m.tgz", "extra_ipks": ["a.ipk"], "kmods": "km", "feed": ["f.ipk"]}
        work, out = Path("/w"), Path("/b/native-ubi-local-1")
        cmds = images.local_commands(inputs, work, out, Path("/r"))
        self.assertEqual([c[1].split("/")[-1] if c[0] == "python3" else c[1] for c in cmds], ["stage_native.py", "first_boot.py", "build", "run"])
        self.assertEqual(cmds[0][-1], "/w/stage")
        self.assertIn("/w/stage", cmds[1])
        self.assertIn("/w/profile:/profile:ro", cmds[3])
        self.assertEqual(cmds[3][-1], "/out/native-ubi-local-1")


def bundle(tamper=False, extra=None, kmods=True):
    """An x28-assembly tarball: one top folder with the rootfs, overlay, kmods, ipk and its own SHA256SUMS."""
    files = {"openwrt-23.05.5-armsr-armv8-rootfs.tar.gz": b"userspace", "userspace.manifest": b"m", "overlay/package/x28-leds/files/x": b"x",
             "ipk/alsa-lib_1.ipk": b"a", "ipk/libstdcpp6_1.ipk": b"c", "ipk/ipset_1.ipk": b"i", "ipk/libipset13_1.ipk": b"l", "ipk/x28-ipset-kernel_1.ipk": b"k"}
    if kmods:
        files.update({"kmods/wireguard.ko": b"w", "kmods/xt_TPROXY.ko": b"t"})
    files.update(extra or {})
    top = "x28-assembly-v1"
    sums = "".join(f"{images.sha256(b'bad' if tamper and n.endswith('wireguard.ko') else d)}  ./{n}\n" for n, d in sorted(files.items()))
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in {**files, "SHA256SUMS": sums.encode()}.items():
            info = tarfile.TarInfo(f"{top}/{name}")
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def public_inputs(tamper=False, **kw):
    blob = bundle(**kw)
    url = "u/v1/x28-assembly-v1.tar.gz"

    def fetch(u):
        if "api.github" in u:
            return json.dumps({"tag_name": "v1", "assets": [{"name": "x28-assembly-v1.tar.gz", "browser_download_url": url,
                                                              "digest": "sha256:" + images.sha256(b"x" if tamper else blob)}]}).encode()
        return blob
    return fetch


class InputTests(unittest.TestCase):
    def test_a_download_that_does_not_match_its_digest_keeps_nothing(self):
        dest = Path(tempfile.mkdtemp())
        with self.assertRaises(ValueError):
            images.fetch_inputs(dest, "v1", fetch=public_inputs(tamper=True))
        self.assertEqual(list(dest.iterdir()), [])

    def test_the_bundle_is_unpacked_and_its_ipks_split_between_the_feed_and_the_rest(self):
        out = images.fetch_inputs(Path(tempfile.mkdtemp()), "v1", fetch=public_inputs())
        self.assertTrue(out["modern"].endswith("-rootfs.tar.gz") and Path(out["modern"]).is_file())
        self.assertTrue((Path(out["overlay"]) / "package/x28-leds/files/x").is_file())
        self.assertEqual(sorted(p.name for p in Path(out["kmods"]).glob("*.ko")), ["wireguard.ko", "xt_TPROXY.ko"])
        self.assertEqual(sorted(Path(p).name for p in out["feed"]), ["ipset_1.ipk", "libipset13_1.ipk", "x28-ipset-kernel_1.ipk"])
        self.assertEqual(sorted(Path(p).name for p in out["extra_ipks"]), ["alsa-lib_1.ipk", "libstdcpp6_1.ipk"])

    def test_a_file_that_differs_from_the_bundles_own_checksums_is_refused(self):
        dest = Path(tempfile.mkdtemp())
        with self.assertRaisesRegex(ValueError, "checksum"):
            images.fetch_inputs(dest, "v1", fetch=self._tampered())
        self.assertFalse(any(p.is_dir() for p in dest.iterdir()))

    def _tampered(self):
        blob = bundle(tamper=True)
        return lambda u: json.dumps({"tag_name": "v1", "assets": [{"name": "x28-assembly-v1.tar.gz", "browser_download_url": "u", "digest": "sha256:" + images.sha256(blob)}]}).encode() if "api.github" in u else blob

    def test_entries_that_escape_the_bundle_are_refused(self):
        dest = Path(tempfile.mkdtemp())
        bad = dest / "bad.tar.gz"
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            info = tarfile.TarInfo("top/../evil")
            info.size = 1
            tar.addfile(info, io.BytesIO(b"x"))
        bad.write_bytes(buf.getvalue())
        with self.assertRaises(ValueError):
            images.extract_bundle(bad, dest / "out")

    def test_a_bundle_without_kernel_modules_is_refused(self):
        with self.assertRaisesRegex(RuntimeError, "missing"):
            images.fetch_inputs(Path(tempfile.mkdtemp()), "v1", fetch=public_inputs(kmods=False))

    def test_stock_extraction_is_offline_and_read_only(self):
        cmd = images.stock_command(Path("/b/rootfs_b.bin"), Path("/o"), Path("/r"))
        self.assertIn("none", cmd)
        self.assertIn("*_vol-rootfs.ubifs", cmd[-1])  # not rootfs_data, which also matches *vol-rootfs*
        self.assertIn("/b/rootfs_b.bin:/in/rootfs_b.bin:ro", cmd)


if __name__ == "__main__":
    unittest.main()


class ReleaseListTests(unittest.TestCase):
    def test_lists_only_releases_with_the_userspace_tarball(self):
        rels = [{"tag_name": "v0.60.0", "published_at": "2026-11-06T01:00:00Z", "prerelease": True, "assets": [{"name": "x28-assembly-v0.60.0.tar.gz"}]},
                {"tag_name": "feed-2", "assets": [{"name": "ipset.ipk"}]},
                {"tag_name": "v0.59.0", "published_at": "2026-11-05T01:00:00Z", "assets": [{"name": "x28-assembly-v0.59.0.tar.gz"}]}]
        got = images.releases(fetch=lambda url: json.dumps(rels).encode())
        self.assertEqual(got, [{"tag": "v0.60.0", "date": "2026-11-06", "beta": True}, {"tag": "v0.59.0", "date": "2026-11-05", "beta": False}])


class FrozenBuildTests(unittest.TestCase):
    def test_frozen_build_runs_the_scripts_with_the_binarys_own_interpreter_and_passes_no_key_flag_without_a_key(self):
        inputs = {"stock": "s", "modern": "m", "extra_ipks": ["a"], "kmods": "km", "feed": ["f"]}
        cmds = images.local_commands(inputs, Path("/w"), Path("/o/img"), Path("/repo"), ["/app/x28-flasher", "--run-script"])
        self.assertEqual(cmds[0][:3], ["/app/x28-flasher", "--run-script", "/repo/tools/build/stage_native.py"])
        self.assertEqual(cmds[1][:3], ["/app/x28-flasher", "--run-script", "/repo/tools/build/first_boot.py"])
        self.assertNotIn("--public-key", cmds[1])
        self.assertEqual(cmds[1][cmds[1].index("--kmods") + 1], "km")


class SupportedReleaseTests(unittest.TestCase):
    def test_versions_up_to_0_53_3_are_dropped_and_the_next_one_is_the_first(self):
        for tag, ok in (("v0.53.3", False), ("v0.53.2", False), ("v0.52.0", False), ("v0.30.3", False), ("v0.53.4", True), ("v0.54.0", True), ("v1.0.0", True),
                        ("feed-2", False), ("kmods-4.19.205", False)):
            self.assertEqual(images.supported(tag), ok, tag)
        rels = [{"tag_name": t, "assets": [{"name": f"x28-assembly-{t}.tar.gz"}]} for t in ("v0.54.0", "v0.53.1")]
        self.assertEqual([r["tag"] for r in images.releases(fetch=lambda url: json.dumps(rels).encode())], ["v0.54.0"])
