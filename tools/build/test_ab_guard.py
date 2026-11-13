#!/usr/bin/env python3
import io
import tarfile
import unittest
from pathlib import Path
import os
import ab_guard as g

ROOT=Path(os.environ.get('X28_OVERLAY') or Path(__file__).resolve().parents[2]/'overlay')


def tree(files,links=()):
    t={}
    for name,data in files.items():
        m=tarfile.TarInfo(name);m.size=len(data);m.mode=0o755;t[name]=(m,data)
    for name,target in links:
        m=tarfile.TarInfo(name);m.type=tarfile.SYMTYPE;m.linkname=target;t[name]=(m,b'')
    return t


BASE={'etc/init.d/network':b'#!/bin/sh /etc/rc.common\nstart(){ . /lib/functions.sh; }\n','lib/functions.sh':b'#!/bin/sh\nlog(){ :; }\n',
      'etc/inittab':b'::sysinit:/etc/init.d/rcS S boot\n','etc/init.d/rcS':b'#!/bin/sh\n'}
LINK=[('etc/rc.d/S20network','../init.d/network')]


class GuardTests(unittest.TestCase):
    def test_clean_boot_path_passes(self):
        self.assertIn('lib/functions.sh',g.check(tree(BASE,LINK)))

    def test_every_writer_form_is_caught_in_an_enabled_script(self):
        for bad in (b'ab_image_sync "_b"',b'mtd write - rootfs',b'mtd -p 262144 write - x',b'nandwrite /dev/mtd1 f',b'sysupgrade -n f',
                    b'/sbin/sysupgrade f',b'dd if=x of=/dev/mtd3',b'set_bootctrl 1 2',b'platform_do_upgrade f',b'ubiupdatevol /dev/ubi0_0 f',
                    b'dd-nand of=x',b'fw_setenv a b',b'ubirmvol /dev/ubi0 -n 1',b'ubiattach -m 3',b'flash_eraseall /dev/mtd3',b'mtd erase misc',b'mtd unlock misc'):
            t=tree({**BASE,'etc/init.d/network':b'#!/bin/sh /etc/rc.common\n'+bad+b'\n'},LINK)
            with self.assertRaises(ValueError,msg=bad):g.check(t)

    def test_writer_in_a_sourced_library_is_caught(self):
        t=tree({**BASE,'lib/functions.sh':b'#!/bin/sh\nab_image_sync _a\n'},LINK)
        with self.assertRaises(ValueError):g.check(t)

    def test_unreferenced_script_and_plain_reads_are_not_flagged(self):
        t=tree({**BASE,'usr/bin/tool':b'#!/bin/sh\nab_image_sync x\n','lib/functions.sh':b'#!/bin/sh\nP=/dev/mtdblock\n[ -f /sysupgrade.tgz ]\n'},LINK)
        g.check(t)

    def test_upgrade_helpers_and_boot_done_paths_refused_even_if_unreferenced(self):
        for extra in ('lib/upgrade/bootctrl.sh','etc/init.d/zmtk_boot_done'):
            with self.assertRaises(ValueError):g.check(tree({**BASE,extra:b'x'},LINK))

    def test_hotplug_cron_and_rclocal_are_roots(self):
        for root in ('etc/hotplug.d/iface/10-x','etc/crontabs/root','etc/rc.local','etc/uci-defaults/90-x','lib/preinit/80_x'):
            with self.assertRaises(ValueError,msg=root):g.check(tree({**BASE,root:b'#!/bin/sh\nmtd write a b\n'},LINK))


    def test_only_the_reviewed_preinit_hook_may_attach_ubi(self):
        hook=(ROOT/'package/x28-storage/files/x28-user-data.preinit').read_bytes()
        name='lib/preinit/79_x28_user_data'
        g.check(tree({**BASE,name:hook},LINK))  # as shipped
        for label,bad in (('second call',hook+b'\nubiattach /dev/ubi_ctrl -m 3 -d 2\n'),('other writer',hook+b'\nubiformat /dev/mtd50\n'),
                          ('new volume',hook+b'\nubimkvol /dev/ubi1 -N x -m\n')):
            with self.subTest(label),self.assertRaises(ValueError):g.check(tree({**BASE,name:bad},LINK))
        with self.assertRaises(ValueError):g.check(tree({**BASE,'lib/preinit/78_other':hook},LINK))  # same text, other file

    def test_only_the_reviewed_bootok_script_may_name_dd_nand(self):
        script=(ROOT/'package/x28-bootok/files/x28-bootok.init').read_bytes()
        link=[('etc/rc.d/S96x28-bootok','../init.d/x28-bootok')]
        g.check(tree({**BASE,'etc/init.d/x28-bootok':script},LINK+link))  # as shipped
        for name,bad in (('second call',script+b'\nprintf x | "$DDNAND" of=/dev/mtd1 seek=0 bs=1 count=1\n'),
                         ('other of=',script+b'\ndd if=x of=/dev/null\n'),('other writer',script+b'\nnandwrite /dev/mtd1 f\n'),
                         ('direct call',script+b'\ndd-nand of=/dev/mtd1\n'),('upgrade sync',script+b'\nab_image_sync _a\n')):
            with self.assertRaises(ValueError,msg=name):g.check(tree({**BASE,'etc/init.d/x28-bootok':bad},LINK+link))
        other=script.replace(b'x28-bootok',b'x28-other')  # same text, any other name: refused
        with self.assertRaises(ValueError):g.check(tree({**BASE,'etc/init.d/x28-other':other},LINK+[('etc/rc.d/S96x28-other','../init.d/x28-other')]))

    def test_x28_upgrade_may_name_sysupgrade_only_while_nothing_at_boot_starts_it(self):
        # The exemption does not depend on the script's text (unlike bootok's), and CI's overlay has no x28-update files: a stand-in.
        script=b'#!/bin/sh\n# x28-upgrade -y: download, sysupgrade -T, then sysupgrade -n\nSYSUPGRADE=sysupgrade\n$SYSUPGRADE -n "$f"\n'
        boot={**BASE,'etc/init.d/network':b'#!/bin/sh /etc/rc.common\nPATH=/usr/sbin:/bin\n'}  # a PATH makes all of /usr/sbin reachable
        name='usr/sbin/x28-upgrade'
        ok={name:script,'usr/share/rpcd/acl.d/x28-update.json':b'"/usr/sbin/x28-upgrade -y -b": [ "exec" ]',
            'usr/lib/opkg/info/x28-update.list':b'/usr/sbin/x28-upgrade\n','etc/x':b'/tmp/x28-upgrade-ok /tmp/x28-upgrade.log'}
        self.assertIn(name,g.check(tree({**boot,**ok},LINK)))  # as shipped, with the mentions that are allowed
        for label,files in (('other writer',{name:script+b'\nmtd write x rootfs\n'}),
                            ('same text, other name',{'usr/sbin/x28-other':script}),
                            ('started by an init script',{name:script,'etc/init.d/x28-auto':b'#!/bin/sh /etc/rc.common\nstart(){ x28-upgrade -y; }\n'}),
                            ('started by cron',{name:script,'etc/crontabs/root':b'0 4 * * * /usr/sbin/x28-upgrade -y\n'}),
                            ('started by hotplug',{name:script,'etc/hotplug.d/iface/99-x':b'#!/bin/sh\nx28-upgrade -y\n'}),
                            ('started by a helper',{name:script,'usr/libexec/h':b'#!/bin/sh\nx28-upgrade -y\n',
                                                    'etc/init.d/network':b'#!/bin/sh /etc/rc.common\nPATH=/usr/sbin:/bin\n/usr/libexec/h\n'}),
                            ('started by a button',{name:script,'etc/rc.button/reset':b'#!/bin/sh\n/usr/sbin/x28-upgrade -y\n'})):
            with self.subTest(label),self.assertRaises(ValueError):g.check(tree({**boot,**files},LINK))
        alias=tree({**boot,name:script,'etc/init.d/network':b'#!/bin/sh /etc/rc.common\nPATH=/usr/sbin:/bin\nupg -y\n'},LINK+[('usr/sbin/upg','x28-upgrade')])
        with self.subTest('symlink alias'),self.assertRaises(ValueError):g.check(alias)

    def test_only_the_reviewed_sysupgrade_files_may_be_present(self):
        pinned={n:b'#!/bin/sh\n# stand-in for '+n.encode()+b'\n' for n in g.UPGRADE_PINNED}
        import hashlib
        real=dict(g.UPGRADE_PINNED)
        try:
            g.UPGRADE_PINNED.update({n:hashlib.sha256(d).hexdigest() for n,d in pinned.items()})
            platform=b'#!/bin/sh\nRAMFS_COPY_BIN="/usr/sbin/ubiformat"\nplatform_do_upgrade(){ ubiformat x; dd-nand of=y; ubiattach; ubidetach; }\n'
            ok={**BASE,**pinned,'lib/upgrade/platform.sh':platform,'lib/upgrade/keep.d/base-files':b'/etc/config/\n'}
            g.check(tree(ok,LINK))  # as reviewed
            commented=platform+b"# `sysupgrade -F` is the override; (sysupgrade ...) and ;sysupgrade x\n"  # delimiters before the word
            g.check(tree({**ok,'lib/upgrade/platform.sh':commented},LINK))
            with self.subTest('changed stock file'),self.assertRaises(ValueError):
                g.check(tree({**ok,'lib/upgrade/common.sh':pinned['lib/upgrade/common.sh']+b'mtd write\n'},LINK))
            for label,bad in (('nandwrite',platform+b'nandwrite /dev/mtd1 f\n'),('flash_erase',platform+b'flash_erase /dev/mtd1 0 0\n'),
                              ('fw_setenv',platform+b'fw_setenv a b\n'),('mtd write',platform+b'mtd write a b\n'),('zmtk',platform+b'zmtk_boot_done\n'),
                              ('ab sync',platform+b'ab_image_sync _a\n'),('mkvol',platform+b'ubimkvol /dev/ubi0\n')):
                with self.subTest(label),self.assertRaises(ValueError):g.check(tree({**ok,'lib/upgrade/platform.sh':bad},LINK))
            for extra in ('lib/upgrade/nand.sh','lib/upgrade/bootctrl.sh'):
                with self.subTest(extra),self.assertRaises(ValueError):g.check(tree({**ok,extra:b'#!/bin/sh\n'},LINK))
            with self.subTest('platform without a pinned file'),self.assertRaises(ValueError):
                g.check(tree({k:v for k,v in ok.items() if k!='lib/upgrade/fwtool.sh'},LINK))
            boot={**ok,'etc/init.d/network':b'#!/bin/sh /etc/rc.common\nstart(){ . /lib/upgrade/platform.sh; }\n'}
            with self.subTest('reachable from boot'),self.assertRaises(ValueError):g.check(tree(boot,LINK))
        finally:
            g.UPGRADE_PINNED.clear();g.UPGRADE_PINNED.update(real)

    def test_keep_d_directory_entry_is_allowed_but_not_a_file_or_link(self):
        name='lib/upgrade/keep.d'
        for kind in (tarfile.DIRTYPE,tarfile.REGTYPE,tarfile.SYMTYPE,tarfile.LNKTYPE):
            with self.subTest(kind=kind):
                t=tree({**BASE,'lib/upgrade/keep.d/base-files':b'/etc/config/\n'},LINK)
                info=tarfile.TarInfo(name);info.type=kind;info.linkname='base-files'
                t[name]=(info,b'')
                if kind==tarfile.DIRTYPE:g.check(t)
                else:
                    with self.assertRaises(ValueError):g.check(t)

    def test_the_pins_are_the_openwrt_23_05_5_files(self):
        self.assertEqual(sorted(g.UPGRADE_PINNED),['lib/upgrade/common.sh','lib/upgrade/do_stage2','lib/upgrade/fwtool.sh','lib/upgrade/stage2'])
        self.assertTrue(all(len(v)==64 for v in g.UPGRADE_PINNED.values()))


if __name__=='__main__':unittest.main()
