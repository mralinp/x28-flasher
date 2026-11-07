#!/usr/bin/env python3
"""Guarded X28 restore entry. Dry-run is offline; --write requires separate approval.

Use the private mtkclient venv Python for --write. No automatic reboot or retry.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time

import changed_restore as engine
from common import DEFAULT_BACKUP, FROZEN, MTK_HOME, MTKCLIENT_COMMIT, PRIVATE, VENDOR_DA, backup_table, ensure_venv, loaded_code_matches, sha256_file
from setup_mtkclient import PATCHES
from write_verify import active_slot

DA_HASH = 'c3d9058aeb56373eaadc5868ce93198fb99a9cbf876a30f876714e9007d66d56'
LAYOUT_HASH = 'fdbadcb07558f89728fe98b4726ea84cc86fa0c0201ea614208db465bcf856a7'
XML = 'mtkclient/Library/DA/xmlflash/xml_lib.py'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def save(run, receipt):
    path = run / 'receipt.tmp'
    with path.open('w') as stream:
        json.dump(receipt, stream, indent=2)
        stream.flush()
        os.fsync(stream.fileno())
    path.replace(run / 'receipt.json')


def host_identity():
    """Pinned mtkclient source plus reviewed patches == the installed XML library; returns that text."""
    if FROZEN:  # no git or venv in the binary: the build embedded the patched XML library and its hash
        bundle = Path(sys._MEIPASS)
        meta = json.loads((bundle / 'identity.json').read_text())
        raw = (bundle / XML).read_bytes()  # bytes, as sha256_file hashes them later (no newline translation on Windows)
        if meta['commit'] != MTKCLIENT_COMMIT or digest(raw) != meta['xml_lib_sha256']:
            raise ValueError('bundled XML library does not match the pinned mtkclient build')
        return raw.decode()
    src = MTK_HOME / 'src'
    head = subprocess.check_output(['git', '-C', str(src), 'rev-parse', 'HEAD'], text=True).strip()
    if head != MTKCLIENT_COMMIT:
        raise ValueError('mtkclient checkout is not pinned')
    expected = subprocess.check_output(['git', '-C', str(src), 'show', f'{head}:{XML}'], text=True)
    for rel, old, new, required in PATCHES:
        if rel != XML.removeprefix('mtkclient/'):
            raise ValueError('unreviewed installer patch file')
        if expected.count(old) != 1:
            if required:
                raise ValueError('pinned source patch target changed')
            continue
        expected = expected.replace(old, new)
    installed = list((MTK_HOME / 'venv').glob('lib/python*/site-packages/' + XML))
    if len(installed) != 1 or installed[0].read_text() != expected:
        raise ValueError('installed XML library is not exactly pinned source plus reviewed patches; run setup_mtkclient.py')
    return expected


def local_inputs(backup, loader):
    table = backup_table(backup)
    layout = [{k: p[k] for k in ('index', 'name', 'size', 'erase_size', 'offset')} for p in table]
    if digest(json.dumps(layout, sort_keys=True).encode()) != LAYOUT_HASH:
        raise ValueError('backup layout is not this X28 layout')
    for p in table:
        image = Path(p['image'])
        if image.stat().st_size != p['size'] or sha256_file(image) != p['sha256']:
            raise ValueError('backup integrity failure: ' + p['name'])
    by_name = {p['name']: p for p in table}
    original = Path(by_name['rootfs_sig_a']['image']).read_bytes()
    if digest(original) != engine.ORIGINAL or sha256_file(loader) != DA_HASH:
        raise ValueError('source or DA identity mismatch')
    for name, addr, size, sha in engine.GUARDS:
        p = by_name[name]
        if (p['offset'], p['size'], p['sha256']) != (addr, size, sha):
            raise ValueError('guard identity mismatch: ' + name)
    expected = host_identity()
    tools = b''.join(Path(__file__).with_name(name).read_bytes() for name in
                     ('restore_entry.py', 'changed_restore.py', 'common.py', 'read_by_name.py', 'write_verify.py', 'setup_mtkclient.py'))
    identity = {'source': engine.ORIGINAL, 'da': DA_HASH, 'host': digest(expected.encode()),
                'tools': digest(tools), 'unit': by_name['proinfo']['sha256']}
    return by_name, table, original, identity


def load_receipt(run, identity, purpose):
    run = run.resolve(strict=True)
    if purpose == 'restore' and (run / 'restore-claim.json').exists():
        raise ValueError('restore attempt already claimed; separate review required')
    receipt = json.loads((run / 'receipt.json').read_text())
    mode, status = ('identical', 'VERIFIED') if purpose == 'identical' else ('test', 'STOP_UNVERIFIED')
    if (receipt.get('schema') != 1 or receipt.get('run') != str(run) or receipt.get('slot') != 'b'
            or receipt.get('identity') != identity or receipt.get('mode') != mode or receipt.get('status') != status):
        raise ValueError('receipt mode/status/unit/tool/run binding invalid')
    if purpose == 'identical' and not 0 <= time.time() - receipt.get('created', 0) <= 86400:
        raise ValueError('identical rehearsal evidence is stale')
    journal = run / receipt.get('journal', 'missing')
    if journal.resolve().parent.parent != run or journal.name != 'journal.jsonl':
        raise ValueError('journal outside bound run')
    raw = journal.read_bytes()
    if digest(raw) != receipt.get('journal_hash'):
        raise ValueError('journal changed or incomplete')
    events = [json.loads(line) for line in raw.splitlines()]
    attempts = [e['write_attempt'] for e in events if 'write_attempt' in e]
    if not events or attempts != (['original'] if purpose == 'identical' else ['staged']):
        raise ValueError('unexpected write history; no automatic retry')
    if events[0] != {'mode': mode, 'target_offset': engine.ADDRESS, 'target_length': engine.SIZE}:
        raise ValueError('journal target or mode mismatch')
    expected_attempt = {'write_attempt': 'original' if purpose == 'identical' else 'staged',
                        'sha256': engine.ORIGINAL if purpose == 'identical' else engine.STAGED}
    if [e for e in events if 'write_attempt' in e] != [expected_attempt]:
        raise ValueError('journal write identity mismatch')
    if purpose == 'identical':
        expected = [('rootfs_sig_a', engine.ADDRESS, engine.SIZE, engine.ORIGINAL), *engine.GUARDS]
        reads = [e for e in events if 'read' in e]
        results = [e for e in events if 'write_result' in e]
        if events[-1].get('status') != 'ORIGINAL_AND_GUARDS_VERIFIED' or results != [{'write_result': 'original', 'acknowledged': True}]:
            raise ValueError('identical write did not finish verified')
        if len(reads) != 12:
            raise ValueError('missing same-session readbacks')
        for index, (event, (name, _, size, sha)) in enumerate(zip(reads, expected * 2)):
            if event != {'read': 'before' if index < 6 else 'after-original', 'name': name,
                         'acknowledged': True, 'length': size, 'sha256': sha}:
                raise ValueError('invalid identical readback evidence')
    elif events[-1].get('status') != 'STOP_UNVERIFIED_NO_RETRY_OR_REBOOT':
        raise ValueError('restore requires a stopped test session')
    return receipt


def claim_restore(run, owner):
    # O_EXCL prevents two approved processes from consuming the same stopped run.
    with (run / 'restore-claim.json').open('x') as stream:
        json.dump({'owner': str(owner.resolve()), 'created': time.time()}, stream)
        stream.flush()
        os.fsync(stream.fileno())


def check_uart(path):
    stat = path.stat()
    if not path.is_file() or stat.st_size == 0 or not 0 <= time.time() - stat.st_mtime <= 60:
        raise ValueError('UART log must be nonempty and updated within 60 seconds')


def check_unit(da, part, run):
    path = run / 'unit-proinfo.bin'
    ack = da.readflash(addr=part['offset'], length=part['size'], filename=str(path), parttype=None, display=False)
    if ack is not True or not path.is_file() or path.stat().st_size != part['size'] or sha256_file(path) != part['sha256']:
        raise ValueError('DA unit identity read failed or belongs to another unit')


def open_da(run, loader):
    from read_by_name import connect
    return connect(run, loader)


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode', choices=('identical', 'test', 'restore'))
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--backup', type=Path, default=DEFAULT_BACKUP)
    ap.add_argument('--loader', type=Path, default=VENDOR_DA)
    ap.add_argument('--backup-copy', type=Path, help='optional second complete-captured-partitions.tar')
    ap.add_argument('--uart-log', type=Path)
    ap.add_argument('--prior-identical', type=Path)
    ap.add_argument('--resume', type=Path, help='stopped test entry run, restore mode only')
    args = ap.parse_args()
    backup, loader = args.backup.resolve(strict=True), args.loader.resolve(strict=True)
    parts, table, original, identity = local_inputs(backup, loader)
    if (args.mode == 'restore') != (args.resume is not None):
        raise ValueError('restore requires --resume; other modes forbid it')
    prior = None
    if args.mode == 'test':
        if not args.prior_identical:
            raise ValueError('test requires --prior-identical verified entry run')
        load_receipt(args.prior_identical, identity, 'identical')
    if args.mode == 'restore':
        prior = load_receipt(args.resume, identity, 'restore')
    print(f'{args.mode}: rootfs_sig_a only at {engine.ADDRESS:#x}, {engine.SIZE:#x} bytes; no reboot or retry')
    if not args.write:
        print('OFFLINE DRY RUN: no SSH, hardware import, USB command or write; execution gates not checked')
        return
    ensure_venv()
    if not args.uart_log:
        raise ValueError('--write requires --uart-log')
    copy, uart = args.backup_copy.resolve(strict=True) if args.backup_copy else None, args.uart_log.resolve(strict=True)
    archive = backup / 'complete-captured-partitions.tar'
    expected_archive = (backup / 'ARCHIVE.sha256').read_text().split()[0]
    if sha256_file(archive) != expected_archive:
        raise ValueError('the backup archive does not match its checksum; take the backup again')
    same_disk = False  # a second copy is optional: when given, it must be a different file with the same hash
    if copy is not None:
        if copy.samefile(archive) or sha256_file(copy) != expected_archive:
            raise ValueError('second archive copy is the same file or invalid')
        same_disk = copy.stat().st_dev == archive.stat().st_dev
    check_uart(uart)
    if args.mode != 'restore' and active_slot(table) != 'b':
        raise ValueError('live SSH must confirm B and exact full layout')
    # Runtime misc/boot_para guards must still match, including on no-SSH restore re-entry.
    base = PRIVATE / 'usb-probe'
    base.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(base).free < 768 * 1024 * 1024:
        raise ValueError('less than 768 MiB free for captures and sources')
    phrase = f'WRITE {args.mode} rootfs_sig_a' + (' SAME-DISK' if same_disk else '')
    print('Confirm UART RX capture continues, stable power, and no stock upgrade/FOTA is pending.')
    if same_disk:
        print('WARNING: backup copy is on the same filesystem; host disk loss would lose both copies.')
    print('This requires separate approval of this exact device operation. Merging a PR is not approval.')
    if input(f'Type exactly {phrase!r} to attest those checks and authorize this operation: ') != phrase:
        raise ValueError('operation not confirmed')
    run = Path(tempfile.mkdtemp(prefix='entry-' + args.mode + '-', dir=base)).resolve()
    receipt = {'schema': 1, 'run': str(run), 'mode': args.mode, 'status': 'STARTED', 'slot': 'b',
               'identity': identity, 'created': time.time(), 'uart': str(uart), 'same_disk_backup': same_disk,
               'prior_run': str(args.resume.resolve()) if prior else
               (str(args.prior_identical.resolve()) if args.mode == 'test' else None)}
    save(run, receipt)
    if prior:
        claim_restore(args.resume.resolve(), run)
        prior['status'] = 'RESTORE_ATTEMPTED'
        save(args.resume.resolve(), prior)  # Consume before connecting: never blindly retry a restore.
    mtk = None
    previous_cwd = Path.cwd()
    try:
        os.chdir(run)
        mtk = open_da(run, loader)
        check_uart(uart)
        check_unit(mtk.daloader, parts['proinfo'], run)
        xml_module = sys.modules.get('mtkclient.Library.DA.xmlflash.xml_lib')
        if xml_module is None or sha256_file(Path(xml_module.__file__)) != identity['host'] or not loaded_code_matches(xml_module):
            raise ValueError('loaded XML implementation differs from verified host')
        engine.run_session(mtk.daloader, original, run, mode=args.mode)
        receipt['status'] = 'VERIFIED'
        print('Original and guards verified. No reboot issued; review UART before approving normal B boot.')
    except BaseException:
        receipt['status'] = 'STOP_UNVERIFIED'
        print('STOP: no retry, slot switch or reboot. Preserve recovery state and private logs.')
        raise
    finally:
        journals = list(run.glob('bounded-restore-*/journal.jsonl'))
        if len(journals) == 1:
            receipt['journal'] = str(journals[0].relative_to(run))
            receipt['journal_hash'] = sha256_file(journals[0])
        try:
            save(run, receipt)
        finally:
            try:
                if mtk:
                    mtk.port.close()  # Host USB close only; no DA shutdown or device reboot.
            finally:
                os.chdir(previous_cwd)
                print(f'Private entry record: {run}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError) as error:
        sys.exit(str(error))
