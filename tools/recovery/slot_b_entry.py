#!/usr/bin/env python3
"""Guarded entry for the rootfs_b overlay tail, stock slot B (x28-flasher#5), around slot_session.py. Dry-run is offline.

The unit boots B and USB is the only way in, so there is no SSH check: the session's `before` read of misc must equal the
backup's B-selected misc, and the whole tail must equal the backup's. Take a FRESH backup right before (the overlay of a
booted stock B changes). Order: `identical` (rewrites the same bytes: proves the write and readback path), then `write`,
then `restore` if needed. Unlike rootfs_a, restore is NOT single-use here: B is the only slot that boots, so a failed restore
must be retryable (each try is a manual run with the typed phrase and the same before/after guards; nothing retries by itself). Use the private mtkclient venv Python for --write. No reboot or retry; merging this approves nothing.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

import slot_b
import slot_session as session
from common import DEFAULT_BACKUP, PRIVATE, VENDOR_DA, ensure_venv, loaded_code_matches, sha256_file
from restore_entry import DA_HASH, check_uart, check_unit, host_identity, open_da, save
from slot_entry import load_prior, verified_backup

PRIOR = {'identical': [], 'write': [('prior_identical', 'identical', True)], 'restore': [('resume', 'write', False)]}


def digest(data):
    return hashlib.sha256(data).hexdigest()


def load_inputs(backup, loader, mode, candidate_dir):
    table, by_name = verified_backup(backup, loader)
    images = {n: Path(by_name[n]['image']).read_bytes() for n in ('misc', 'rootfs_a', 'rootfs_b', 'boot_para')}
    if any(digest(images[n]) != by_name[n]['sha256'] for n in images):
        raise ValueError('backup image changed after verification')
    pins = session.unit_pins(images)
    original = images['rootfs_b'][session.ROOTFS_B_HEAD:]
    report = json.loads((candidate_dir / 'report.json').read_text())
    full = (candidate_dir / 'rootfs_b-access.bin').read_bytes()
    if digest(full) != report['output_sha256'] or report['source_sha256'] != digest(images['rootfs_b']):
        raise ValueError('candidate does not match its report or was not built from this backup\'s rootfs_b')
    if full[:session.ROOTFS_B_HEAD] != images['rootfs_b'][:session.ROOTFS_B_HEAD]:
        raise ValueError('candidate changes the static head of rootfs_b')
    candidate = full[session.ROOTFS_B_HEAD:]
    spec = slot_b.rootfs_b_tail_spec(digest(candidate), digest(original), digest(images['rootfs_a']), pins)
    if mode == 'write':
        spec.validate(original, candidate)
    for name, addr, size, sha in spec.guards:
        p = by_name[name]
        if name == 'rootfs_b':  # the static head only; the tail is the target
            if p['offset'] != addr or size > p['size'] or digest(Path(p['image']).read_bytes()[:size]) != sha:
                raise ValueError('prefix guard identity mismatch: ' + name)
        elif (p['offset'], p['size']) != (addr, size) or (isinstance(sha, str) and p['sha256'] != sha):
            raise ValueError('guard identity mismatch: ' + name)
    if (by_name['rootfs_b']['offset'] + session.ROOTFS_B_HEAD, by_name['rootfs_b']['size'] - session.ROOTFS_B_HEAD) != (spec.addr, spec.size):
        raise ValueError('target identity mismatch')
    here = Path(__file__).parent
    names = ('slot_b_entry.py', 'slot_b.py', 'slot_entry.py', 'slot_session.py', 'restore_entry.py', 'common.py', 'read_by_name.py',
             'write_verify.py', 'setup_mtkclient.py', 'changed_restore.py', 'read_verify.py')
    tools = b''.join((here / n).read_bytes() for n in names) + (here.parent / 'build' / 'stock_access.py').read_bytes()
    identity = {'target': spec.name, 'original': spec.original_sha, 'candidate': spec.candidate_sha, 'rootfs_a': digest(images['rootfs_a']),
                'base': '', 'base_head': 0, 'da': DA_HASH, 'host': digest(host_identity().encode()), 'tools': digest(tools),
                'unit': by_name['proinfo']['sha256']}
    return by_name, original, candidate, spec, identity


def check_chip(run, backup):
    """proinfo is identical on both owner units, so also require this connection's hwcode and meid to equal the backup's.
    mtkclient writes hwparam.json into the working directory (the run folder) when it connects; a missing file stops the session."""
    live, saved = run / 'hwparam.json', backup / 'hwparam.json'
    if not live.is_file() or not saved.is_file():
        raise ValueError('hwparam.json missing: cannot bind this connection to the backed-up unit')
    want, got = json.loads(saved.read_text()), json.loads(live.read_text())
    if not want.get('meid') or (str(want.get('hwcode')).lower(), str(want['meid']).lower()) != (str(got.get('hwcode')).lower(), str(got.get('meid')).lower()):
        raise ValueError('this connection is not the unit the backup was taken from (meid/hwcode differ)')


def phrase(spec, mode, same_disk, no_uart):
    image = spec.candidate_sha if mode == 'write' else spec.original_sha
    return f'WRITE {mode} {spec.name} {image[:12]} NO-SSH' + (' NO-UART' if no_uart else '') + (' SAME-DISK' if same_disk else '')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('mode', choices=tuple(PRIOR))
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--backup', type=Path, default=DEFAULT_BACKUP, help='a FRESH verified backup of this unit')
    ap.add_argument('--loader', type=Path, default=VENDOR_DA)
    ap.add_argument('--candidate-dir', type=Path, required=True, help='stock_access.py output (rootfs_b-access.bin + report.json)')
    ap.add_argument('--backup-copy', type=Path, help='verified second complete-captured-partitions.tar')
    ap.add_argument('--uart-log', type=Path)
    ap.add_argument('--no-uart', action='store_true', help='no UART log: no boot log if the image fails; the way back is a USB restore from the backup')
    ap.add_argument('--prior-identical', type=Path)
    ap.add_argument('--resume', type=Path, help='stopped or finished write run, restore mode only')
    args = ap.parse_args()
    wanted = PRIOR[args.mode]
    for flag in ('prior_identical', 'resume'):
        if (getattr(args, flag) is not None) != (flag in [w[0] for w in wanted]):
            raise ValueError(f'--{flag.replace("_", "-")} is {"required" if flag in [w[0] for w in wanted] else "not valid"} for {args.mode}')
    backup, loader = args.backup.resolve(strict=True), args.loader.resolve(strict=True)
    parts, original, candidate, spec, identity = load_inputs(backup, loader, args.mode, args.candidate_dir.resolve(strict=True))
    priors = {flag: load_prior(getattr(args, flag), {**identity}, spec, mode, verified) for flag, mode, verified in wanted}
    print(f'{args.mode}: rootfs_b overlay tail only at {spec.addr:#x}, {spec.size:#x} bytes; candidate {spec.candidate_sha[:12]}; no reboot or retry')
    print('the overlay is rebuilt from the unit\'s own files plus the SSH hook and your key; overlayfs whiteouts and xattrs are not carried over')
    if not args.write:
        print('OFFLINE DRY RUN: no hardware import, USB command or write; execution gates not checked')
        return
    ensure_venv()
    if not args.backup_copy or not (args.uart_log or args.no_uart):
        raise ValueError('--write requires --backup-copy and --uart-log (or --no-uart)')
    if args.no_uart and args.uart_log:
        raise ValueError('--no-uart excludes --uart-log')
    copy, uart = args.backup_copy.resolve(strict=True), args.uart_log.resolve(strict=True) if args.uart_log else None
    archive = backup / 'complete-captured-partitions.tar'
    expected_archive = (backup / 'ARCHIVE.sha256').read_text().split()[0]
    if copy.samefile(archive) or sha256_file(archive) != expected_archive or sha256_file(copy) != expected_archive:
        raise ValueError('second archive copy is missing, same file, or invalid')
    same_disk = copy.stat().st_dev == archive.stat().st_dev
    if uart:
        check_uart(uart)
    else:
        print('NO UART: no boot log will exist. If the unit does not boot, the way back is a USB restore from this backup.')
    print('NO SSH: the live slot rests on the USB read of misc matching the backup\'s B-selected misc.')
    probe_dir = PRIVATE / 'usb-probe'
    probe_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(probe_dir).free < 1024 * 1024 * 1024:
        raise ValueError('less than 1 GiB free for captures and sources')
    if not sys.stdin.isatty():
        raise ValueError('typed confirmation needs an interactive terminal')
    expected_phrase = phrase(spec, args.mode, same_disk, args.no_uart)
    print('This writes the slot the unit BOOTS FROM. Confirm stable power, the backup was taken just now with the unit idle,')
    print('slot A\'s boot counter is checked (stock B erases A when its tries are above 3), and that the NOT-FLASHABLE marker')
    print('on the candidate is deliberately overridden by the owner. Merging a PR is not approval.')
    if same_disk:
        print('WARNING: backup copy is on the same filesystem; host disk loss would lose both copies.')
    if input(f'Type exactly {expected_phrase!r} to attest those checks and authorize this operation: ') != expected_phrase:
        raise ValueError('operation not confirmed')
    run = Path(tempfile.mkdtemp(prefix=f'slot-{spec.name}-{args.mode}-', dir=probe_dir)).resolve()
    receipt = {'schema': 2, 'run': str(run), 'target': spec.name, 'mode': args.mode, 'status': 'STARTED', 'identity': identity,
               'created': time.time(), 'uart': str(uart) if uart else None, 'no_uart': args.no_uart, 'no_ssh': True, 'same_disk_backup': same_disk,
               'priors': {w[0]: str(getattr(args, w[0]).resolve()) for w in wanted}}
    save(run, receipt)
    mtk = None
    previous_cwd = Path.cwd()
    try:
        os.chdir(run)
        mtk = open_da(run, loader)
        xml_module = sys.modules.get('mtkclient.Library.DA.xmlflash.xml_lib')  # before the first flash command
        if xml_module is None or sha256_file(Path(xml_module.__file__)) != identity['host'] or not loaded_code_matches(xml_module):
            raise ValueError('loaded XML implementation differs from verified host')
        if uart:
            check_uart(uart)
        check_unit(mtk.daloader, parts['proinfo'], run)
        check_chip(run, backup)
        session.run_session(mtk.daloader, spec, original, candidate, run, mode=args.mode)
        receipt['status'] = 'VERIFIED'
        print('Target and guards verified. No reboot issued. Before any reboot check slot A\'s boot counter; do not reboot casually.')
    except BaseException:
        receipt['status'] = 'STOP_UNVERIFIED'
        print('STOP: no retry, slot switch or reboot. Preserve recovery state and private logs.')
        raise
    finally:
        journals = list(run.glob(f'{spec.name}-{args.mode}-*/journal.jsonl'))
        if len(journals) == 1:
            receipt['journal'] = str(journals[0].relative_to(run))
            receipt['journal_hash'] = sha256_file(journals[0])
        try:
            save(run, receipt)
        finally:
            try:
                if mtk:
                    mtk.port.close()
            finally:
                os.chdir(previous_cwd)
                print(f'Private entry record: {run}')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        sys.exit(str(error))
