#!/usr/bin/env python3
import hashlib
import json
import tarfile
import tempfile
import unittest
from pathlib import Path
import package_ubi
import sysupgrade_tar as s
from test_package_ubi import image


def sha(b): return hashlib.sha256(b).hexdigest()


def image_dir(root, ubi):
    report = package_ubi.inspect(ubi); report['ubi_sha256'] = sha(ubi)
    (root / 'rootfs-experimental.ubi').write_bytes(ubi); (root / 'manifest.json').write_text(json.dumps(report))
    return root


class WrapTests(unittest.TestCase):
    def test_tarball_shape_and_hashes(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t); ubi = image(); out = t / 'x.tar'
            s.wrap(image_dir(t, ubi), out)
            with tarfile.open(out) as tar:
                self.assertEqual(tar.getnames(), s.NAMES)
                read = lambda n: tar.extractfile(f'sysupgrade-x28/{n}').read()
                self.assertEqual(read('root'), ubi)
                self.assertEqual(read('root.sha256'), f'{sha(ubi)}\n'.encode())
                self.assertEqual(read('root.rootfs'), f'{sha(ubi[2 * package_ubi.PEB + 8192:][:96])} 96\n'.encode())
                self.assertTrue(all(m.uid == 0 and m.mtime == 0 for m in tar.getmembers()))
            first = out.read_bytes(); out.unlink(); s.wrap(t, out)
            self.assertEqual(out.read_bytes(), first)  # reproducible

    def test_refused(self):
        with tempfile.TemporaryDirectory() as t:
            t = Path(t); ubi = image(); image_dir(t, ubi)
            with self.assertRaises(ValueError): s.wrap(t, t / 'manifest.json')  # output exists
            m = json.loads((t / 'manifest.json').read_text())
            (t / 'manifest.json').write_text(json.dumps({**m, 'ubi_sha256': '0' * 64}))
            with self.assertRaises(ValueError): s.wrap(t, t / 'a.tar')  # manifest mismatch
            bad = bytearray(ubi); bad[12] ^= 1; image_dir(t, bytes(ubi))
            (t / 'rootfs-experimental.ubi').write_bytes(bytes(bad))
            (t / 'manifest.json').write_text(json.dumps({**m, 'ubi_sha256': sha(bad)}))
            with self.assertRaises(ValueError): s.wrap(t, t / 'b.tar')  # bad UBI header
            (t / 'rootfs-experimental.ubi').write_bytes(ubi); (t / 'manifest.json').write_text(json.dumps({**m, 'rootfs_bytes_used': 95}))
            with self.assertRaises(ValueError): s.wrap(t, t / 'c.tar')  # volume does not match
            self.assertFalse(any((t / n).exists() for n in ('a.tar', 'b.tar', 'c.tar')))


if __name__ == '__main__':
    unittest.main()
