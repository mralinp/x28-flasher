#!/usr/bin/env python3
"""Wrap a package_ubi output into the unsigned X28 sysupgrade tarball (#80).

The tarball is what the router's /lib/upgrade/platform.sh reads (zlt-x28-openwrt package/x28-sysupgrade):
  sysupgrade-x28/root         the slot UBI image (unpadded; ubiformat writes it into rootfs_a or rootfs_b)
  sysupgrade-x28/root.sha256  SHA-256 of root
  sysupgrade-x28/root.rootfs  "sha256 bytes" of the SquashFS in volume 0, which the router reads back after writing
Host checks: the image matches its manifest, has the fixed X28 UBI geometry and fits the partition. Nothing else goes in: no kernel, no
boot or misc data (sysupgrade never writes boot_a/b). Signing is a separate step (zlt-x28-openwrt image_sign.sh / Sign image workflow).
Pure Python, no device.
"""
import argparse
import io
import json
import tarfile
from pathlib import Path
from package_ubi import PARTITION, inspect, require
from stage_native import digest

DIR = 'sysupgrade-x28'
NAMES = [DIR, f'{DIR}/root', f'{DIR}/root.sha256', f'{DIR}/root.rootfs']


def wrap(image_dir, output):
    require(not output.exists(), 'output exists')
    manifest = json.loads((image_dir / 'manifest.json').read_text())
    ubi = (image_dir / 'rootfs-experimental.ubi').read_bytes()
    require(0 < len(ubi) <= PARTITION, 'image does not fit a rootfs partition')
    require(digest(ubi) == manifest.get('ubi_sha256'), 'image does not match its manifest')
    report = inspect(ubi)
    require((report['rootfs_sha256'], report['rootfs_bytes_used']) == (manifest.get('rootfs_sha256'), manifest.get('rootfs_bytes_used')),
            'rootfs volume does not match the manifest')
    files = {'root': ubi, 'root.sha256': f'{digest(ubi)}\n'.encode(),
             'root.rootfs': f"{report['rootfs_sha256']} {report['rootfs_bytes_used']}\n".encode()}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode='w', format=tarfile.USTAR_FORMAT) as tar:  # busybox tar on the router; fixed metadata = reproducible
        d = tarfile.TarInfo(DIR); d.type = tarfile.DIRTYPE; d.mode = 0o755; tar.addfile(d)
        for name, data in files.items():
            info = tarfile.TarInfo(f'{DIR}/{name}'); info.size = len(data); info.mode = 0o644; tar.addfile(info, io.BytesIO(data))
    with tarfile.open(fileobj=io.BytesIO(buf.getvalue())) as tar:
        require(tar.getnames() == NAMES, 'unexpected tarball members')
    output.write_bytes(buf.getvalue())
    return {'output': str(output), 'sha256': digest(buf.getvalue()), 'root_sha256': digest(ubi), 'root_bytes': len(ubi),
            'rootfs_sha256': report['rootfs_sha256'], 'rootfs_bytes': report['rootfs_bytes_used']}


if __name__ == '__main__':
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--image', type=Path, required=True, help='package_ubi output directory')
    ap.add_argument('--output', type=Path, required=True, help='for example x28-sysupgrade-0.75.0-unsigned.tar')
    args = ap.parse_args(); print(json.dumps(wrap(args.image, args.output), indent=2))
