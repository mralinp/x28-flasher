#!/usr/bin/env python3
import struct
import unittest
import tempfile
import json
from pathlib import Path
import package_ubi as p


def crc(data):return struct.pack('>I',p.crc(data))


def image():
    records=b''
    for reserve,name in [(124,b'rootfs'),(116,b'rootfs_data')]:
        record=bytearray(168);struct.pack_into('>III',record,0,reserve,1,0);record[12]=1
        struct.pack_into('>H',record,14,len(name));record[16:16+len(name)]=name
        records+=record+crc(record)
    records+=(b'\0'*168+crc(b'\0'*168))*126
    sq=bytearray(96);sq[:4]=b'hsqs';struct.pack_into('<I',sq,12,262144);struct.pack_into('<H',sq,20,4);struct.pack_into('<Q',sq,40,96)
    overlay=bytearray(4096);struct.pack_into('<I',overlay,0,0x06101831);struct.pack_into('<I',overlay,16,4096);overlay[20]=6;struct.pack_into('<IIII',overlay,32,4096,p.LEB,13,116)
    struct.pack_into('<I',overlay,4,p.crc(overlay[8:]))
    blocks=[]
    for vol,lnum,data in [(p.LAYOUT,0,records),(p.LAYOUT,1,records),(0,0,sq),*[(1,i,overlay if i==0 else b'') for i in range(13)]]:
        block=bytearray(b'\xff'*p.PEB);ec=bytearray(60);ec[:4]=b'UBI#';ec[4]=1;struct.pack_into('>II',ec,16,4096,8192)
        block[:64]=ec+crc(ec);vid=bytearray(60);vid[:4]=b'UBI!';vid[4]=vid[5]=1;vid[7]=5 if vol==p.LAYOUT else 0;struct.pack_into('>II',vid,8,vol,lnum)
        block[4096:4160]=vid+crc(vid);block[8192:8192+len(data)]=data;blocks.append(block)
    return b''.join(blocks)


class FormatTests(unittest.TestCase):
    def test_valid_fixed_geometry_and_payload(self):
        report=p.inspect(image())
        self.assertEqual(report['rootfs_bytes_used'],96)
        self.assertEqual(report['volumes'],['rootfs','rootfs_data'])

    def test_crc_wrong_geometry_duplicate_and_oversize_refused(self):
        original=image()
        for offset in (12,4096+10,8192+8,3*p.PEB+8192+100):
            b=bytearray(original);b[offset]^=1
            with self.assertRaises(ValueError):p.inspect(bytes(b))
        with self.assertRaises(ValueError):p.inspect(original+original[2*p.PEB:3*p.PEB])
        with self.assertRaises(ValueError):p.inspect(original+b'\xff'*(p.PARTITION+1))
        with self.assertRaises(ValueError):p.inspect(original[:-1])

    def test_semantic_mutations_with_recomputed_crcs_are_rejected(self):
        original=image()
        for kind in ('geometry','compat','extra-volume','overlay-geometry'):
            b=bytearray(original)
            if kind in ('geometry','compat'):
                start=0 if kind=='geometry' else 4096
                if kind=='geometry':struct.pack_into('>I',b,16,2048)
                else:b[start+7]=0
                b[start+60:start+64]=crc(b[start:start+60])
            elif kind=='extra-volume':
                for offset in (0,p.PEB):
                    start=offset+8192+2*172;b[start+12]=1
                    b[start+168:start+172]=crc(b[start:start+168])
            else:
                start=3*p.PEB+8192;struct.pack_into('<I',b,start+32,512)
                struct.pack_into('<I',b,start+4,p.crc(b[start+8:start+4096]))
            with self.subTest(kind=kind), self.assertRaises(ValueError):p.inspect(bytes(b))

    def test_whole_generated_payload_comparison_catches_other_overlay_blocks(self):
        raw=image()
        root=raw[2*p.PEB+8192:3*p.PEB]
        overlay=b''.join(raw[i*p.PEB+8192:(i+1)*p.PEB] for i in range(3,16))
        p.inspect(raw,[root,overlay])
        changed=bytearray(raw);changed[4*p.PEB+8192+100]^=1
        p.inspect(bytes(changed))  # Header inspection alone cannot validate all UBIFS contents.
        with self.assertRaises(ValueError):p.inspect(bytes(changed),[root,overlay])

    def test_packaging_identity_and_existing_output_fail_before_tools(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);profile=root/'profile';profile.mkdir();output=root/'output'
            (profile/'manifest.json').write_text(json.dumps({'flashable':False,'archive_sha256':'wrong'}))
            (profile/'NOT-FLASHABLE').touch();(profile/'rootfs-management.tar.gz').write_bytes(b'not an archive')
            with self.assertRaises(ValueError):p.package(profile,output)
            self.assertFalse(output.exists())
            output.mkdir();(output/'keep').write_text('keep')
            with self.assertRaises(ValueError):p.package(profile,output)
            self.assertEqual((output/'keep').read_text(),'keep')


if __name__=='__main__':unittest.main()
