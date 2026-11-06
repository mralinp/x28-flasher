#!/usr/bin/env python3
"""Synthetic archive tests; no vendor inputs, firmware execution or device access."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import stage_native as s


def archive(path, files):
    with tarfile.open(path, 'w:gz') as t:
        for name, value in files.items():
            m = tarfile.TarInfo(name)
            if isinstance(value, tuple):
                m.type = tarfile.SYMTYPE
                m.linkname = value[0]
                t.addfile(m)
            else:
                m.size = len(value)
                m.mode = 0o755
                t.addfile(m, io.BytesIO(value))


class StageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.modern = self.root/'new.tar.gz'
        self.stock = self.root/'old.tar.gz'
        self.output = self.root/'out'
        self.status = b'Package: kernel\nVersion: 4.19.205-test\n\nPackage: kmod-test\nVersion: stock\n\n'
        archive(self.stock, {'rootfs/usr/lib/opkg/status':self.status,
                'rootfs/lib/modules/4.19.205/xt_DSCP.ko':b'UPPER',
                'rootfs/lib/modules/4.19.205/xt_dscp.ko':b'lower',
                'rootfs/etc/modules.d/10-test':b'test',
                'rootfs/usr/lib/opkg/info/kmod-test.control':b'Package: kmod-test',
                'rootfs/etc/init.d/zmtk_boot_done':b'mtd write unsafe'})
        archive(self.modern, {'./usr/lib/opkg/status':b'Package: kernel\nVersion: 5.15\n\nPackage: kmod-new\n\nPackage: base-files\nVersion: new\n\n',
                './lib/modules/5.15/test.ko':b'wrong', './usr/lib/opkg/info/kmod-new.control':b'wrong',
                './etc/init.d/network':b'modern network', './bin/ash':('busybox',), './bin/busybox':b'modern'})

    def test_matching_modules_metadata_and_modern_core_without_stock_init(self):
        report = s.stage(self.stock, self.modern, [], self.output, roots=[])
        with tarfile.open(self.output/'rootfs-staging.tar.gz') as t:
            names=t.getnames()
            self.assertIn('lib/modules/4.19.205/xt_DSCP.ko', names)
            self.assertIn('lib/modules/4.19.205/xt_dscp.ko', names)
            self.assertNotIn('lib/modules/5.15/test.ko',names)
            self.assertNotIn('usr/lib/opkg/info/kmod-new.control',names)
            self.assertNotIn('etc/init.d/zmtk_boot_done',names)
            self.assertEqual(t.extractfile('etc/init.d/network').read(), b'modern network')
            status=t.extractfile('usr/lib/opkg/status').read()
            self.assertIn(b'4.19.205-test',status)
            self.assertNotIn(b'5.15',status)
        self.assertFalse(report['flashable'])
        self.assertTrue((self.output/'NOT-FLASHABLE').exists())

    def test_paths_duplicates_and_link_escapes_refused(self):
        for files in ({'../escape':b'X'}, {'/absolute':b'X'}, {'./link':('../../escape',)},
                      {'./a':b'1','a':b'2'}, {'./link':('bin',),'./link/file':b'X'}):
            with self.subTest(files=files):
                archive(self.modern,files)
                with self.assertRaises(ValueError):
                    s.load_archive(self.modern)

    def test_file_object_package_payload_and_conflicting_overlay(self):
        payload=io.BytesIO(self.modern.read_bytes())
        self.assertIn('bin/busybox',s.load_archive(payload))
        ipk=self.root/'extra.ipk'
        archive(ipk,{'data.tar.gz':self.modern.read_bytes()})
        # Identical duplicate entries are permitted, differing core files are not.
        s.stage(self.stock,self.modern,[ipk],self.output,roots=[])
        archive(self.modern,{'./usr/lib/opkg/status':b'Package: base-files\n', './bin/busybox':b'changed'})
        with self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[ipk],self.root/'conflict',roots=[])

    def test_symlink_resolution_and_merged_parent_validation(self):
        entries=s.load_archive(self.modern)
        self.assertEqual(s.resolve(entries,'bin/ash'),('bin/busybox',b'modern'))
        archive(self.modern,{'./a':('b',),'./b':('a',)})
        with self.assertRaises(ValueError):
            s.resolve(s.load_archive(self.modern),'a')
        archive(self.modern,{'./lib/modules':('elsewhere',)})
        entries=s.load_archive(self.modern)
        info=tarfile.TarInfo('lib/modules/4.19.205/test.ko')
        entries[info.name]=(info,b'')
        with self.assertRaises(ValueError):
            s.validate_parents(entries)

    def test_separate_safe_archives_cannot_create_symlink_parent_on_merge(self):
        with tarfile.open(self.modern) as t:
            status=t.extractfile('./usr/lib/opkg/status').read()
        archive(self.modern,{'./usr/lib/opkg/status':status, './lib':('other',)})
        with self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[],self.output,roots=[])
        payload=self.root/'payload.tar.gz'
        archive(payload,{'./lib':b''})
        # Directory/symlink conflicts cannot silently replace existing paths.
        entries=s.load_archive(self.modern)
        self.assertTrue(entries['lib'][0].issym())
        with tarfile.open(payload,'w:gz') as t:
            m=tarfile.TarInfo('./lib');m.type=tarfile.DIRTYPE;t.addfile(m)
        ipk=self.root/'dir.ipk';archive(ipk,{'data.tar.gz':payload.read_bytes()})
        with self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[ipk],self.output,roots=[])

    def test_vendor_multilink_closure_and_root_collision(self):
        with tarfile.open(self.stock) as t:
            files={m.name:t.extractfile(m).read() for m in t if m.isfile()}
        files.update({'rootfs/usr/bin/vendor':b'\x7fELFvendor','rootfs/lib/libv.so':('libv.so.1',),
                      'rootfs/lib/libv.so.1':('libv.so.1.2',),'rootfs/lib/libv.so.1.2':b'\x7fELFlib'})
        archive(self.stock,files)
        def deps(data):return (None,['libv.so'] if data.endswith(b'vendor') else [])
        with patch.object(s,'elf_dynamic',side_effect=deps):
            s.stage(self.stock,self.modern,[],self.output,roots=['usr/bin/vendor'])
        entries=s.load_archive(self.output/'rootfs-staging.tar.gz')
        self.assertEqual(s.resolve(entries,'lib/libv.so')[1],b'\x7fELFlib')
        with tarfile.open(self.modern) as t:
            modern={m.name:(m.linkname,) if m.issym() else t.extractfile(m).read() for m in t if not m.isdir()}
        modern['./usr/bin/vendor']=('other',);archive(self.modern,modern)
        with patch.object(s,'elf_dynamic',side_effect=deps), self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[],self.root/'collision',roots=['usr/bin/vendor'])

    def test_selected_root_symlink_cannot_reuse_changed_modern_terminal(self):
        with tarfile.open(self.stock) as t:
            files={m.name:t.extractfile(m).read() for m in t if m.isfile()}
        files.update({'rootfs/usr/bin/vendor':('vendor.real',), 'rootfs/usr/bin/vendor.real':b'\x7fELFstock'})
        archive(self.stock,files)
        with tarfile.open(self.modern) as t: status=t.extractfile('./usr/lib/opkg/status').read()
        archive(self.modern,{'./usr/lib/opkg/status':status, './usr/bin/vendor':('vendor.real',), './usr/bin/vendor.real':b'\x7fELFmodern'})
        with patch.object(s,'elf_dynamic',return_value=(None,[])), self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[],self.output,roots=['usr/bin/vendor'])

    def test_existing_output_not_overwritten(self):
        self.output.mkdir()
        with self.assertRaises(FileExistsError):
            s.stage(self.stock,self.modern,[],self.output,roots=[])

    def test_missing_vendor_root_and_unsafe_startup_fail_closed(self):
        with self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[],self.output,roots=['usr/bin/missing'])
        archive(self.modern,{'./etc/init.d/zmtk_boot_done':b'unsafe'})
        with self.assertRaises(ValueError):
            s.stage(self.stock,self.modern,[],self.output,roots=[])


if __name__=='__main__':
    unittest.main()
