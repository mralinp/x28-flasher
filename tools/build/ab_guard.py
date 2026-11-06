#!/usr/bin/env python3
"""Offline check that nothing boot-reachable in a profile can touch flash or the other A/B slot (#87).

Follows the scripts that run at boot (inittab, enabled rc.d links, rc.local, preinit, hotplug, cron,
uci-defaults) through every /etc|/lib|/usr|/sbin|/bin path they mention. Text only: it does not prove
a binary never writes flash.
"""
import argparse
import io
import posixpath
import re
import sys

from stage_native import load_archive, resolve

FORBIDDEN = re.compile(rb'ab_image_sync|zmtk_boot_done|bootctrl|platform_do_upgrade|nandwrite|flash_erase|ubiupdatevol|'
                       rb'ubiformat|\bmtd\s[^\n]*\bwrite\b|(?:^|[\s;&|`(])(?:/sbin/)?sysupgrade\s|of=/dev/(?:mtd|ubi|block)|dd-nand|fw_setenv|ubi(?:rmvol|mkvol|rsvol|attach|detach)|flash_eraseall|flash_unlock|\bmtd\s[^\n]*\b(?:erase|unlock)\b')
# The one reviewed flash write the image may do (#145): x28-bootok clears slot A's boot "tries" byte in misc. The
# exemption covers only the dd-nand token, only in that script, and only while the script keeps the exact shape that
# was reviewed: one writer variable, one call, one of=.
BOOTOK = 'etc/init.d/x28-bootok'


def bootok_exempt(real, data):
    return (real == BOOTOK and data.count(b'dd-nand') == 1 and b'DDNAND=${X28_BOOTOK_DDNAND:-dd-nand}' in data
            and data.count(b'"$DDNAND" ') == 1 and data.count(b'of=') == 1)


# The other reviewed exception (#183): attaching user_data in preinit. It only names the volume for block extroot; the
# exemption holds only for this file, with one call, and any other UBI or flash writer in it is still reported.
USER_DATA = 'lib/preinit/79_x28_user_data'


def user_data_exempt(real, data):
    return (real == USER_DATA and data.count(b'ubiattach') == 1 and b'ubiattach /dev/ubi_ctrl -m "$mtd" -d 1 ' in data
            and b'"user_data"$/' in data)


PATHS = re.compile(rb'(?<![\w.-])/((?:etc|lib|usr|sbin|bin)/[A-Za-z0-9_./-]*[A-Za-z0-9_])')
ROOT_PREFIXES = ('etc/rc.d/','etc/hotplug.d/','etc/crontabs/','etc/uci-defaults/','lib/preinit/')
ROOT_FILES = ('etc/inittab','etc/rc.local','etc/preinit','etc/rc.common','etc/init.d/rcS')


def violations(tree):
    """[(reachable file, token)] for every boot-reachable file mentioning a flash/slot writer."""
    todo=[n for n in tree if n in ROOT_FILES or n.startswith(ROOT_PREFIXES)];seen=set();found=[]
    while todo:
        name=todo.pop()
        try:real,data=resolve(tree,name)
        except ValueError:continue
        if real in seen:continue
        seen.add(real)
        if data[:2]!=b'#!' and not name.endswith('.sh') and not name.startswith(ROOT_PREFIXES):continue  # data, ELF, JSON
        for hit in sorted({m.decode() for m in FORBIDDEN.findall(data)}):
            if hit=='dd-nand' and bootok_exempt(real,data):continue
            if hit=='ubiattach' and user_data_exempt(real,data):continue
            found.append((real,hit))
        for ref in PATHS.findall(data):
            ref=posixpath.normpath(ref.decode())
            todo.extend(n for n in tree if n==ref or n.startswith(ref+'/'))
    return sorted(set(found)),sorted(seen)


def check(tree):
    bad,seen=violations(tree)
    if bad:raise ValueError('boot-reachable flash/slot writer reference: '+'; '.join(f'{n}: {t}' for n,t in bad))
    extra=[n for n in tree if n.startswith('lib/upgrade/') or 'zmtk_boot_done' in n]
    if extra:raise ValueError('upgrade/A-B sync path present: '+', '.join(sorted(extra)))
    return seen


def main():
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('archive')
    seen=check(load_archive(ap.parse_args().archive));print(f'ok: {len(seen)} boot-reachable files scanned')


if __name__=='__main__':
    try:main()
    except ValueError as e:sys.exit(str(e))
