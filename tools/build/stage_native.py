#!/usr/bin/env python3
"""Create a PRIVATE, NON-FLASHABLE native rootfs staging archive. Never runs firmware.

No init integration, network policy, UBI packaging, signing or device operations.
Archive-to-archive staging preserves case without extracting on the Mac filesystem.
"""
import argparse
import copy
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import posixpath
import sys
import tarfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'firmware'))
from inventory import elf_dynamic

ROOTS = ['usr/bin/'+n for n in ('nvram_daemon','ccci_fsd','ccci_mdinit','mtk_netagent',
         'mipc_wan_cli','ql_netd','ql_ril_service','mipc_submonitor','hwnat','switch')]


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_archive(path, prefix=''):
    entries={}
    with (tarfile.open(fileobj=path) if hasattr(path,'read') else tarfile.open(path)) as tar:
        for m in tar:
            raw=m.name
            if raw.startswith('/') or '..' in PurePosixPath(raw).parts:
                raise ValueError('unsafe member path: '+raw)
            name=posixpath.normpath(raw)
            if name=='.':
                continue
            if prefix:
                if name==prefix:
                    continue
                if not name.startswith(prefix+'/'):
                    raise ValueError('member outside expected prefix')
                name=name[len(prefix)+1:]
            if name in entries:
                raise ValueError('duplicate member: '+name)
            if not (m.isdir() or m.isfile() or m.issym()):
                raise ValueError('special/hard-link member refused: '+name)
            if m.issym():
                target=posixpath.normpath(posixpath.join(posixpath.dirname(name),m.linkname))
                if m.linkname.startswith('/'):
                    target=posixpath.normpath(m.linkname.lstrip('/'))
                if target=='..' or target.startswith('../'):
                    raise ValueError('escaping symlink: '+name)
            info=copy.copy(m);info.name=name
            entries[name]=(info,tar.extractfile(m).read() if m.isfile() else b'')
    validate_parents(entries)
    return entries


def validate_parents(entries):
    for name in entries:
        for parent in PurePosixPath(name).parents:
            if str(parent) in entries and not entries[str(parent)][0].isdir():
                raise ValueError('member below non-directory: '+name)


def resolve(entries,name,chain=None):
    seen=set()
    while name in entries and entries[name][0].issym():
        if name in seen:
            raise ValueError('symlink cycle: '+name)
        seen.add(name)
        if chain is not None:chain.append(name)
        link=entries[name][0].linkname
        name=posixpath.normpath(link.lstrip('/') if link.startswith('/') else posixpath.join(posixpath.dirname(name),link))
    if name not in entries or not entries[name][0].isfile():
        raise ValueError('missing regular file: '+name)
    if chain is not None:chain.append(name)
    return name,entries[name][1]


def kernel_record(block):
    package=next((line[9:] for line in block.splitlines() if line.startswith('Package: ')),'')
    return package=='kernel' or package.startswith('kmod-')


def stage(stock_path,modern_path,ipks,output,*,roots=ROOTS):
    if output.exists():
        raise FileExistsError(output)
    stock_bytes=Path(stock_path).read_bytes();modern_bytes=Path(modern_path).read_bytes()
    stock=load_archive(io.BytesIO(stock_bytes),'rootfs');tree=load_archive(io.BytesIO(modern_bytes))
    extra_hashes={}
    provenance={name:'modern' for name in tree}
    for ipk in ipks:
        package_bytes=Path(ipk).read_bytes();package_name=Path(ipk).name
        if package_name in extra_hashes:raise ValueError('duplicate extra-package basename')
        extra_hashes[package_name]=digest(package_bytes)
        with tarfile.open(fileobj=io.BytesIO(package_bytes)) as outer:
            members=[m for m in outer if m.name.lstrip('./')=='data.tar.gz']
            if len(members)!=1:
                raise ValueError('IPK must contain one data.tar.gz')
            payload=io.BytesIO(outer.extractfile(members[0]).read())
            for name,entry in load_archive(payload).items():
                if name in tree and entry[0].isdir() and not tree[name][0].isdir():
                    raise ValueError('extra package changes path type: '+name)
                if name in tree and not entry[0].isdir():
                    previous=tree[name]
                    if (previous[0].type,previous[0].linkname,previous[0].mode,previous[1]) != (entry[0].type,entry[0].linkname,entry[0].mode,entry[1]):
                        raise ValueError('extra package overwrites modern file: '+name)
                    continue
                tree[name]=entry;provenance[name]='extra-package:'+Path(ipk).name
    for name in list(tree):
        if name.startswith(('lib/modules/','etc/modules.d/','etc/modules-boot.d/','usr/lib/opkg/info/kmod-','usr/lib/opkg/info/kernel.')) or name in ('lib/modules','etc/modules.d','etc/modules-boot.d'):
            del tree[name];provenance.pop(name,None)
    for name,entry in stock.items():
        if name.startswith(('lib/modules/','etc/modules.d/','etc/modules-boot.d/','usr/lib/opkg/info/kmod-','usr/lib/opkg/info/kernel.')):
            tree[name]=entry;provenance[name]='stock-kernel'
    status='usr/lib/opkg/status'
    if status not in tree or not tree[status][0].isfile():
        raise ValueError('missing modern package status')
    modern_blocks=tree[status][1].decode().split('\n\n')
    stock_blocks=stock.get(status,(None,b''))[1].decode().split('\n\n')
    if not any(kernel_record(b) and 'Version: 4.19.205' in b for b in stock_blocks):
        raise ValueError('missing matching stock kernel metadata')
    merged='\n\n'.join([b for b in modern_blocks if b.strip() and not kernel_record(b)]+[b for b in stock_blocks if kernel_record(b)])+'\n\n'
    info=copy.copy(tree[status][0]);tree[status]=(info,merged.encode());provenance[status]='merged-kernel-records'
    todo=list(roots);visited=set()
    while todo:
        name=todo.pop()
        if name in visited:
            continue
        visited.add(name)
        chain=[]
        real,data=resolve(stock,name,chain)
        for candidate in chain:
            if candidate not in tree:
                tree[candidate]=stock[candidate];provenance[candidate]='stock-vendor-closure'
            elif name in roots:
                actual,expected=tree[candidate],stock[candidate]
                if (actual[0].type,actual[0].linkname,actual[0].mode,actual[1]) != (expected[0].type,expected[0].linkname,expected[0].mode,expected[1]):
                    raise ValueError('vendor root collides with modern file: '+name)
        if data[:4]!=b'\x7fELF':
            raise ValueError('vendor closure is not ELF: '+name)
        for needed in elf_dynamic(data)[1]:
            options=[d+'/'+needed for d in ('lib','usr/lib')]
            existing=next((p for p in options if p in tree),None)
            if existing:
                resolve(tree,existing)  # Broken links must never count as resolved libraries.
                continue
            old=next((p for p in options if p in stock),None)
            if old is None:
                raise ValueError('unresolved vendor library: '+needed)
            todo.append(old)
    pending=list(roots);checked=set()
    while pending:
        name=pending.pop()
        real,data=resolve(tree,name)
        if real in checked:continue
        checked.add(real)
        if data[:4]!=b'\x7fELF':raise ValueError('non-ELF in final dependency closure: '+name)
        for needed in elf_dynamic(data)[1]:
            target=next((d+'/'+needed for d in ('lib','usr/lib') if d+'/'+needed in tree),None)
            if target is None:raise ValueError('missing final dependency: '+needed)
            pending.append(target)
    forbidden=[name for name in tree if name.startswith('lib/upgrade/') or name=='etc/init.d/zmtk_boot_done' or 'zmtk_boot_done' in name]
    for name in forbidden:
        del tree[name];provenance.pop(name,None)
    # No stock init scripts or enable links are copied; integration needs separate review.
    if any(name.startswith(('etc/init.d/','etc/rc.d/')) and source.startswith('stock') for name,source in provenance.items()):
        raise ValueError('stock startup path unexpectedly selected')
    if any(name.startswith('lib/modules/') and not name.startswith('lib/modules/4.19.205/') for name,e in tree.items() if e[0].isfile()):
        raise ValueError('foreign module version remains')
    validate_parents(tree)
    output.mkdir(parents=True,mode=0o700)
    (output/'NOT-FLASHABLE').write_text('Staging only: init/network/overlay/device nodes/UBI/signature/slot review pending. Never flash this archive.\n')
    (output/'INCOMPLETE').touch()
    archive=output/'rootfs-staging.tar.gz'
    with tarfile.open(archive,'x:gz') as tar:
        for name,(meta,data) in sorted(tree.items()):
            meta=copy.copy(meta);meta.uid=meta.gid=0;meta.uname=meta.gname='root'
            if meta.isfile():meta.size=len(data)
            tar.addfile(meta,io.BytesIO(data) if meta.isfile() else None)
    report={'flashable':False,'stock_sha256':digest(stock_bytes),'modern_sha256':digest(modern_bytes),
            'extra_packages':extra_hashes,'archive_sha256':digest(archive.read_bytes()),
            'module_count':sum(n.endswith('.ko') for n in tree),'vendor_roots':roots,'removed_upgrade_paths':forbidden,
            'files':[{ 'path':n,'source':provenance[n],'sha256':digest(data) if m.isfile() else None,'symlink':m.linkname if m.issym() else None} for n,(m,data) in sorted(tree.items())]}
    (output/'manifest.json').write_text(json.dumps(report,indent=2)+'\n');(output/'INCOMPLETE').unlink()
    return report


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--stock',type=Path,required=True);ap.add_argument('--modern',type=Path,required=True)
    ap.add_argument('--ipk',type=Path,nargs='*',default=[]);ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args()
    report=stage(args.stock,args.modern,args.ipk,args.output)
    print(json.dumps({k:v for k,v in report.items() if k!='files'},indent=2))


if __name__=='__main__':main()
