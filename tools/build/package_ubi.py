#!/usr/bin/env python3
"""Offline experimental X28 UBI packaging. Output remains NOT-FLASHABLE.

Run inside the Linux analysis container; never connects to or writes a device.
"""
import argparse
import hashlib
import io
import json
import re
from pathlib import Path
import struct
import subprocess
import tarfile
import tempfile
import zlib
from ab_guard import check as ab_check
from stage_native import digest,load_archive

PEB,LEB,PARTITION,LAYOUT=0x40000,0x3e000,0x4000000,0x7fffefff


def crc(data):return (zlib.crc32(data)^0xffffffff)&0xffffffff


def require(condition,message):
    if not condition:raise ValueError(message)


def inspect(raw,expected_payloads=None):
    require(0<len(raw)<=PARTITION and len(raw)%PEB==0,'invalid partition size')
    volumes={0:{},1:{}};tables=[];sequence=set()
    for offset in range(0,len(raw),PEB):
        block=raw[offset:offset+PEB]
        if block==b'\xff'*PEB:continue
        ec=block[:64];require(ec[:4]==b'UBI#' and ec[4]==1 and crc(ec[:60])==struct.unpack_from('>I',ec,60)[0],'bad EC header/CRC')
        require(struct.unpack_from('>II',ec,16)==(4096,8192),'unexpected VID/data geometry')
        sequence.add(struct.unpack_from('>I',ec,24)[0])
        vid=block[4096:4160];require(vid[:4]==b'UBI!' and vid[4]==1 and vid[5]==1 and crc(vid[:60])==struct.unpack_from('>I',vid,60)[0],'bad dynamic VID header/CRC')
        volume,number=struct.unpack_from('>II',vid,8);data=block[8192:]
        require(vid[6]==0 and vid[7]==(5 if volume==LAYOUT else 0) and struct.unpack_from('>I',vid,28)[0]==0,'unexpected VID copy/compat/padding')
        if volume==LAYOUT:
            require(number in (0,1) and all(n!=number for n,_ in tables),'duplicate/invalid layout copy')
            records=[]
            for i in range(128):
                record=data[i*172:(i+1)*172];require(crc(record[:168])==struct.unpack_from('>I',record,168)[0],'bad volume table CRC')
                if i>=2:
                    require(record[:168]==b'\0'*168,'unexpected extra volume record')
                    records.append(record);continue
                reserve,align,pad=struct.unpack_from('>III',record);length=struct.unpack_from('>H',record,14)[0]
                require(length<=127,'volume name length');name=record[16:16+length].decode('ascii')
                require((reserve,align,pad,record[12],record[13],record[144])==((124 if i==0 else 116),1,0,1,0,0),'unexpected volume layout')
                require(name==('rootfs' if i==0 else 'rootfs_data'),'unexpected volume name')
                records.append(record)
            tables.append((number,records))
        else:
            require(volume in volumes,'unexpected volume ID')
            require(number not in volumes[volume] and number<(124 if volume==0 else 116),'duplicate/out-of-range LEB')
            volumes[volume][number]=data
    require(len(sequence)==1 and len(tables)==2 and tables[0][1]==tables[1][1],'layout copies/sequence disagree')
    payloads=[]
    for volume,blocks in volumes.items():
        require(blocks and sorted(blocks)==list(range(len(blocks))),'missing logical block')
        payloads.append(b''.join(blocks[i] for i in range(len(blocks))))
    if expected_payloads is not None:
        for volume,payload in enumerate(payloads):
            source=expected_payloads[volume]
            require(len(source)<=len(payload) and payload==source+b'\xff'*(len(payload)-len(source)),'reconstructed payload differs from generated filesystem')
    sq,overlay=payloads;require(sq[:4]==b'hsqs','rootfs is not SquashFS')
    used=struct.unpack_from('<Q',sq,40)[0]
    require(96<=used<=len(sq)<=124*LEB and struct.unpack_from('<I',sq,12)[0]==262144 and struct.unpack_from('<H',sq,20)[0]==4,'unexpected SquashFS size/format')
    require(overlay[:4]==b'1\x18\x10\x06' and overlay[20]==6,'overlay lacks UBIFS superblock')
    node_length=struct.unpack_from('<I',overlay,16)[0]
    require(4096==node_length<=len(overlay) and crc(overlay[8:node_length])==struct.unpack_from('<I',overlay,4)[0],'bad UBIFS superblock CRC')
    min_io,leb,current,maximum=struct.unpack_from('<IIII',overlay,32)
    require((min_io,leb,maximum)==(4096,LEB,116) and 13<=current<=maximum and current==len(volumes[1]),'unexpected UBIFS geometry')
    return {'volumes':['rootfs','rootfs_data'],'peb_bytes':PEB,'leb_bytes':LEB,'rootfs_capacity_bytes':124*LEB,
            'overlay_capacity_bytes':116*LEB,'rootfs_bytes_used':used,'rootfs_sha256':digest(sq[:used]),'overlay_image_sha256':digest(overlay),
            'populated_lebs':[len(volumes[0]),len(volumes[1])],'layout_copies':2}


def package(profile,output):
    require(not output.exists(),'output exists')
    manifest=json.loads((profile/'manifest.json').read_text());raw=(profile/'rootfs-management.tar.gz').read_bytes()
    require(manifest.get('flashable') is False and (profile/'NOT-FLASHABLE').is_file() and digest(raw)==manifest.get('archive_sha256'),'profile identity mismatch')
    ab_check(load_archive(io.BytesIO(raw)))  # Validate every member and link ancestor before host extraction; #87 guard.
    output.mkdir(parents=True,mode=0o700);(output/'INCOMPLETE').touch()
    (output/'NOT-FLASHABLE').write_text('Experimental UBI packaging only. Runtime management, hardware, signature and slot gates remain.\n')
    with tempfile.TemporaryDirectory(prefix='x28-package-') as work:
        work=Path(work);tree=work/'rootfs';tree.mkdir();overlay_tree=work/'overlay';overlay_tree.mkdir()
        (tree/'CaseProbe').touch()
        require(not (tree/'caseprobe').exists(),'case-sensitive Linux filesystem required')
        (tree/'CaseProbe').unlink()
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:tar.extractall(tree,filter='tar')
        sq=output/'rootfs.squashfs';ubifs=output/'rootfs_data.ubifs';ubi=output/'rootfs-experimental.ubi'
        commands=[['mksquashfs',str(tree),str(sq),'-noappend','-comp','xz','-b','262144','-all-root','-no-xattrs','-processors','1',
                   '-p','dev/console c 600 0 0 5 1'],  # kernel has no DEVTMPFS; stock also ships a static console node
                  ['mkfs.ubifs','-r',str(overlay_tree),'-m','4096','-e',str(LEB),'-c','116','-o',str(ubifs)]]
        with (output/'packaging.log').open('w') as log:
            for command in commands:subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True)
            listing=subprocess.run(['unsquashfs','-ll',str(sq)],capture_output=True,text=True,check=True).stdout
            require(re.search(r'^crw------- root/root\s+5,\s*1 \S+ \S+ squashfs-root/dev/console$',listing,re.M),'static /dev/console missing')
            require(sq.stat().st_size<=124*LEB and ubifs.stat().st_size<=116*LEB,'filesystem exceeds fixed volume reservation')
            config=work/'ubinize.ini';config.write_text(f'[rootfs]\nmode=ubi\nimage={sq}\nvol_id=0\nvol_type=dynamic\nvol_name=rootfs\nvol_size={124*LEB}\n\n[rootfs_data]\nmode=ubi\nimage={ubifs}\nvol_id=1\nvol_type=dynamic\nvol_name=rootfs_data\nvol_size={116*LEB}\n')
            command=['ubinize','-o',str(ubi),'-p',str(PEB),'-m','4096','-s','4096','-O','4096',str(config)]
            subprocess.run(command,stdout=log,stderr=subprocess.STDOUT,check=True);commands.append(command[:-1]+['<generated-config>'])
        packed=ubi.read_bytes();expected_payloads=[sq.read_bytes(),ubifs.read_bytes()];report=inspect(packed,expected_payloads)
        require(report['rootfs_sha256']==digest(sq.read_bytes()[:report['rootfs_bytes_used']]),'reconstructed SquashFS differs')
        require(len(packed)<=PARTITION,'UBI exceeds target partition')
        padded=packed+b'\xff'*(PARTITION-len(packed));(output/'rootfs-a-experimental.bin').write_bytes(padded)
        inspect(padded,expected_payloads)
        report.update(flashable=False,input_profile_sha256=digest(raw),ubi_sha256=digest(packed),padded_sha256=digest(padded),
                      padded_bytes=len(padded),overlay_policy='fresh empty UBIFS; no captured user data',commands=commands,
                      tool_versions={tool:subprocess.check_output([tool,'-V' if tool!='mksquashfs' else '-version'],text=True).splitlines()[0] for tool in ('mksquashfs','mkfs.ubifs','ubinize')})
        (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(output/'INCOMPLETE').unlink()
    return report


if __name__=='__main__':
    ap=argparse.ArgumentParser(description=__doc__);ap.add_argument('--profile',type=Path,required=True);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();print(json.dumps(package(args.profile.resolve(),args.output.resolve()),indent=2))
