"""Release download and local build commands (#285). Run: python3 tools/x28-flasher/test_images.py"""
import base64
import hashlib
import io
import json
import struct
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import images


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "build"))
from test_package_ubi import image as ubi_image  # a small valid X28 UBI image
import signed_image as si


def keypair(seed):  # Ed25519 signing, only for the tests (the flasher itself only verifies)
    h = hashlib.sha512(seed).digest()
    a = (int.from_bytes(h[:32], "little") & ((1 << 254) - 8)) | (1 << 254)
    return a, h[32:], point(si._mul(a, si._G))


def point(pt):
    zi = pow(pt[2], si._P - 2, si._P)
    x, y = pt[0] * zi % si._P, pt[1] * zi % si._P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def sign(key, msg):
    a, prefix, pub = key
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % si._L
    big_r = point(si._mul(r, si._G))
    h = int.from_bytes(hashlib.sha512(big_r + pub + msg).digest(), "little") % si._L
    return big_r + ((r + h * a) % si._L).to_bytes(32, "little")


def usign_text(kid, payload, comment="x"):
    return f"untrusted comment: {comment}\n".encode() + base64.b64encode(b"Ed" + kid + payload) + b"\n"


def blob(aid, data, ext=False):
    head = struct.pack(">I", (ext << 31) | (aid << 24) | (len(data) + 4))
    return head + data + b"\0" * (-len(data) % 4)


def msg(name, value, aid):  # a blobmsg entry: name length, name, NUL, padded to 4, then the value
    n = name.encode()
    return blob(aid, struct.pack(">H", len(n)) + n + b"\0" * (((2 + len(n) + 1 + 3) & ~3) - 2 - len(n)) + value, True)


def fw_block(kind, data):
    return data + struct.pack(">4sIB3xI", b"FWx0", 0, kind, len(data) + 16)


FEED, SIGNER = keypair(b"feed"), keypair(b"signer")
FEED_ID, SIGNER_ID = b"F" * 8, b"S" * 8
FEED_KEY = base64.b64encode(b"Ed" + FEED_ID + FEED[2]).decode()


def signed(root=None, devices=("Tozed,X28",), release="v1.0.0", signer=SIGNER, valid=(0, 2**40)):
    root = ubi_image() if root is None else root
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in (("sysupgrade-x28/root", root), ("sysupgrade-x28/root.sha256", f"{images.sha256(root)}\n".encode())):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    meta = json.dumps({"supported_devices": list(devices), "version": {"release": release, "kernel": "4.19.205"}}).encode()
    body = fw_block(1, b"\0" * 8 + meta)
    message = buf.getvalue() + body
    fields = (msg("certtype", struct.pack(">I", 1), 5) + msg("validfrom", struct.pack(">Q", valid[0]), 4)
              + msg("expiresat", struct.pack(">Q", valid[1]), 4) + msg("pubkey", usign_text(SIGNER_ID, SIGNER[2]) + b"\0", 3))
    payload = msg("ucert", fields, 2)
    cert = blob(0, usign_text(FEED_ID, sign(FEED, payload)) + b"\0") + blob(1, payload)
    sig = blob(0, blob(0, usign_text(SIGNER_ID, sign(signer, message)) + b"\0"))
    return message + fw_block(0, blob(0, cert) + sig)


def github(data, tag="v1.0.0", digest=None):
    name = images.signed_name(tag)
    rel = {"tag_name": tag, "assets": [{"name": name, "browser_download_url": "u/s", "digest": "sha256:" + (digest or images.sha256(data))}]}
    return lambda url: json.dumps(rel).encode() if "api.github" in url else data


class DownloadTests(unittest.TestCase):
    def setUp(self):
        patcher = mock.patch.object(si, "FEED_KEY", FEED_KEY)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.root = Path(tempfile.mkdtemp())

    def download(self, data, **kw):
        return images.download(self.root, "v1.0.0", fetch=github(data, **kw))

    def test_signed_image_becomes_an_image_folder(self):
        out = self.download(signed())
        self.assertEqual(out.name, "native-ubi-release-v1.0.0")
        bin_ = (out / "rootfs-a-experimental.bin").read_bytes()
        manifest = json.loads((out / "manifest.json").read_text())
        self.assertEqual(len(bin_), images.PARTITION)
        self.assertEqual(manifest["padded_sha256"], images.sha256(bin_))
        self.assertTrue(bin_.startswith(ubi_image()))
        self.assertEqual(manifest["source"]["metadata"]["version"]["release"], "v1.0.0")
        self.assertEqual(self.download(signed()), out)  # downloading it again keeps the same folder

    def test_refused_and_nothing_kept(self):
        good = signed()
        bad = bytearray(good)
        bad[600] ^= 1
        cases = {"digest": (good, {"digest": "0" * 64}), "tampered": (bytes(bad), {}), "uncertified signer": (signed(signer=keypair(b"other")), {}),
                 "other board": (signed(devices=("Tozed", "X28")), {}), "other release": (signed(release="v0.9.0"), {}),
                 "expired": (signed(valid=(0, 1)), {}), "not UBI": (signed(root=b"\xff" * 4096), {})}
        for why, (data, kw) in cases.items():
            with self.subTest(why), self.assertRaises(ValueError):
                self.download(data, **kw)
        self.assertEqual(list(self.root.iterdir()), [])

    def test_release_without_a_signed_image(self):
        with self.assertRaises(RuntimeError):
            images.download(self.root, "v1.0.0", fetch=lambda u: b'{"tag_name": "v1.0.0", "assets": []}')

    def test_release_list_marks_signed_releases(self):
        listing = [{"tag_name": "v1.0.0", "published_at": "2026-11-10T00:00:00Z", "assets": [{"name": "x28-assembly-v1.0.0.tar.gz"}, {"name": "x28-sysupgrade-1.0.0.tar"}]},
                   {"tag_name": "v0.99.0", "assets": [{"name": "x28-assembly-v0.99.0.tar.gz"}]}]
        self.assertEqual([(r["tag"], r["signed"]) for r in images.releases(fetch=lambda u: json.dumps(listing).encode())], [("v1.0.0", True), ("v0.99.0", False)])


class StockAccessTests(unittest.TestCase):
    def test_container_is_offline_and_runs_the_repo_script_on_read_only_inputs(self):
        cmd = images.stock_access_command(Path("/b/rootfs_b.bin"), Path("/k/router.pub"), Path("/out"), Path("/repo"))
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertIn(f"{Path('/b/rootfs_b.bin')}:/in/rootfs_b.bin:ro", cmd)  # host side in the platform's form, as Docker takes it
        self.assertIn(f"{Path('/k/router.pub')}:/in/router.pub:ro", cmd)  # host side in the platform's form, as Docker takes it
        self.assertIn(f"{Path('/repo/tools/build/stock_access.py')}:/opt/stock_access.py:ro", cmd)  # host side in the platform's form, as Docker takes it
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
             "ipk/alsa-lib_1.ipk": b"a", "ipk/libstdcpp6_1.ipk": b"c", "ipk/ucert_1.ipk": b"u", "ipk/ipset_1.ipk": b"i", "ipk/libipset13_1.ipk": b"l", "ipk/x28-ipset-kernel_1.ipk": b"k",
             "ipk/x28-base_1.ipk": b"b", "ipk/kmod-wireguard_1.ipk": b"w", "ipk/kmod-sched-cake_1.ipk": b"c"}
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
        # our packages and the three image modules are installed as packages; the bundle's other module packages are not
        self.assertEqual(sorted(Path(p).name for p in out["feed"]), ["ipset_1.ipk", "kmod-wireguard_1.ipk", "libipset13_1.ipk", "x28-base_1.ipk", "x28-ipset-kernel_1.ipk"])
        self.assertEqual(sorted(Path(p).name for p in out["extra_ipks"]), ["alsa-lib_1.ipk", "libstdcpp6_1.ipk", "ucert_1.ipk"])

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
        self.assertIn(f"{Path('/b/rootfs_b.bin')}:/in/rootfs_b.bin:ro", cmd)  # host side in the platform's form, as Docker takes it


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
