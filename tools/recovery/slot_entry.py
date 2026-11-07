#!/usr/bin/env python3
"""Guarded rootfs_a / misc entry (#99, #100) around slot_session.py. Dry-run is offline; --write needs approval.

Use the private mtkclient venv Python for --write. No automatic reboot or retry. Merging this file approves
nothing: the typed phrase attests that the owner approved this exact target, mode and image, and that the
gates in docs/research/rootfs-a-write-plan.md hold (including a proven BROM route for any misc session).
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

import slot_session as session
from common import DEFAULT_BACKUP, PRIVATE, VENDOR_DA, backup_table, ensure_venv, loaded_code_matches, sha256_file, slot_tools_digest
from restore_entry import DA_HASH, LAYOUT_HASH, check_uart, check_unit, claim_restore, host_identity, open_da, save
from write_verify import active_slot

# (target, mode) -> prior runs it consumes: (flag, target, mode, must be verified)
PRIOR = {
    ('rootfs_a', 'identical'): [],
    ('rootfs_a', 'write'): [],  # a rehearsal is optional for the rootfs_a write (OPTIONAL_PRIOR); misc still requires its own
    ('rootfs_a', 'restore'): [('resume', 'rootfs_a', 'write', False)],
    ('misc', 'identical'): [('prior_rootfs_a', 'rootfs_a', 'write', True)],
    ('misc', 'write'): [('prior_identical', 'misc', 'identical', True), ('prior_rootfs_a', 'rootfs_a', 'write', True)],
    ('misc', 'restore'): [('resume', 'misc', 'write', False)],
}
# Priors a run may use but does not need: when given they are checked exactly like a required one.
OPTIONAL_PRIOR = {('rootfs_a', 'write'): [('prior_identical', 'rootfs_a', 'identical', True)]}
MAX_AGE = 86400


def digest(data):
    return hashlib.sha256(data).hexdigest()


def verified_backup(backup, loader):
    """The complete verified backup table and its by-name index; raises on any layout, integrity or DA mismatch."""
    table = backup_table(backup)
    layout = [{k: p[k] for k in ('index', 'name', 'size', 'erase_size', 'offset')} for p in table]
    if digest(json.dumps(layout, sort_keys=True).encode()) != LAYOUT_HASH:
        raise ValueError('backup layout is not this X28 layout')
    for p in table:
        image = Path(p['image'])
        if image.stat().st_size != p['size'] or sha256_file(image) != p['sha256']:
            raise ValueError('backup integrity failure: ' + p['name'])
    by_name = {p['name']: p for p in table}
    if sha256_file(loader) != DA_HASH:
        raise ValueError('DA identity mismatch')
    return table, by_name


def base_head(image, manifest):
    """Bytes of a booted base that must still match: its layout copies plus the rootfs LEBs, never the overlay (#139)."""
    peb, pebs = manifest['peb_bytes'], manifest['layout_copies'] + manifest['populated_lebs'][0]
    if manifest['volumes'][0] != 'rootfs' or peb != 0x40000 or not 0 < pebs * peb < len(image):
        raise ValueError('base manifest does not describe a rootfs-first UBI image')
    for n in range(pebs):  # every VID header in the head must be the layout volume or the rootfs volume (id 0)
        vid = image[n * peb + 4096:n * peb + 4108]
        if vid[:4] == b'UBI!' and int.from_bytes(vid[8:12], 'big') not in (0, 0x7fffefff):
            raise ValueError('base head contains an overlay block; layout differs from the manifest')
    return pebs * peb


def load_inputs(backup, loader, target, mode, candidate_dir, base_dir=None):
    """Verified originals, the pinned candidate and the spec; raises on any identity mismatch.

    base_dir (rootfs_a only, #137): package_ubi output of the image already on rootfs_a; identical/write start from it."""
    table, by_name = verified_backup(backup, loader)
    original = Path(by_name[target]['image']).read_bytes()
    manifest = json.loads((candidate_dir / 'manifest.json').read_text())
    rootfs_a_image = (candidate_dir / 'rootfs-a-experimental.bin').read_bytes()
    rootfs_a_sha = manifest.get('padded_sha256')
    if rootfs_a_sha != digest(rootfs_a_image):
        raise ValueError('candidate does not match its build manifest')
    base = None
    if base_dir is not None:
        if target != 'rootfs_a':
            raise ValueError('--base-dir is only valid for rootfs_a')
        base = (base_dir / 'rootfs-a-experimental.bin').read_bytes()
        if json.loads((base_dir / 'manifest.json').read_text()).get('padded_sha256') != digest(base):
            raise ValueError('base does not match its build manifest')
    if target == 'rootfs_a':
        head = base_head(base, json.loads((base_dir / 'manifest.json').read_text())) if base else 0
        images = {n: Path(by_name[n]['image']).read_bytes() for n in ('misc', 'rootfs_a', 'rootfs_b', 'boot_para')}
        if any(digest(images[n]) != by_name[n]['sha256'] for n in images):  # pin the bytes verified_backup hashed, not a second read
            raise ValueError('backup image changed after verification')
        pins = session.unit_pins(images, boot_order=False)  # the flash leaves misc alone (a guard re-reads it); the boot order is a separate step
        spec, candidate = session.rootfs_a_spec(rootfs_a_sha, digest(base) if base else '', head, pins), rootfs_a_image
    else:
        spec = session.misc_spec(rootfs_a_sha)
        candidate = bytearray(original)
        for off in session.MISC_COPIES:
            candidate[off:off + 16] = session.MISC_AFTER
        candidate = bytes(candidate)
        if digest(candidate) != session.MISC_A_SHA:
            raise ValueError('misc candidate differs from the pinned selection image')
    if mode == 'write':
        spec.validate(original, candidate)  # refuse a bad candidate before any connection or claim
    for name, addr, size, sha in spec.guards:
        p = by_name[name]
        if name == 'rootfs_b':  # static head only: stock B's overlay lives in the tail
            if p['offset'] != addr or size > p['size'] or digest(Path(p['image']).read_bytes()[:size]) != sha:
                raise ValueError('prefix guard identity mismatch: ' + name)
            continue
        if (p['offset'], p['size']) != (addr, size) or (isinstance(sha, str) and name != 'rootfs_a' and p['sha256'] != sha):
            raise ValueError('guard identity mismatch: ' + name)
    if (by_name[target]['offset'], by_name[target]['size']) != (spec.addr, spec.size):
        raise ValueError('target identity mismatch')
    host = digest(host_identity().encode())
    identity = {'target': target, 'original': spec.original_sha, 'candidate': spec.candidate_sha, 'rootfs_a': rootfs_a_sha,
                'base': spec.base_sha, 'base_head': spec.base_head, 'da': DA_HASH, 'host': host, 'tools': slot_tools_digest(), 'unit': by_name['proinfo']['sha256']}
    return by_name, table, original, candidate, spec, identity, base


def load_prior(run, expect, spec, mode, verified):
    """A previous run's receipt, bound to this unit, tools and image, and to a journal that was not edited."""
    run, target = Path(run).resolve(strict=True), spec.name
    if (run / 'restore-claim.json').exists():  # a run claimed for restore is spent, even as a verified prior
        raise ValueError('restore attempt already claimed; separate review required')
    receipt = json.loads((run / 'receipt.json').read_text())
    if (receipt.get('schema') != 2 or receipt.get('run') != str(run) or receipt.get('target') != target
            or receipt.get('mode') != mode
            or {k: receipt.get('identity', {}).get(k) for k in expect} != expect):
        raise ValueError(f'receipt for {target} {mode} does not match this unit, tools or image')
    if verified:
        if receipt.get('status') != 'VERIFIED' or not 0 <= time.time() - receipt.get('created', 0) <= MAX_AGE:
            raise ValueError(f'{target} {mode} evidence is not verified or is older than 24 h')
    elif receipt.get('status') not in ('VERIFIED', 'STOP_UNVERIFIED'):
        raise ValueError('resume needs a finished or stopped write run')
    journal = run / receipt.get('journal', 'missing')
    if journal.name != 'journal.jsonl' or journal.resolve().parent.parent != run:
        raise ValueError('journal outside bound run')
    raw = journal.read_bytes()
    if digest(raw) != receipt.get('journal_hash'):
        raise ValueError('journal changed or incomplete')
    events = [json.loads(line) for line in raw.splitlines()]
    header = {'mode': mode, 'target': target, 'target_offset': spec.addr, 'target_length': spec.size,
              'candidate_sha256': spec.candidate_sha if mode == 'write' else None}
    start = spec.original_sha if mode == 'restore' or not spec.base_sha else spec.base_sha
    attempt = {'write_attempt': mode, 'sha256': spec.candidate_sha if mode == 'write' else start}
    if not events or events[0] != header or [e for e in events if 'write_attempt' in e] != [attempt]:
        raise ValueError('journal target, image or write history mismatch; no automatic retry')
    if verified:
        if events[-1].get('status') != 'TARGET_AND_GUARDS_VERIFIED' or \
                [e for e in events if 'write_result' in e] != [{'write_result': mode, 'acknowledged': True}]:
            raise ValueError('prior run did not finish verified')
    return receipt


def phrase(spec, mode, rootfs_a_sha, same_disk, no_ssh=False, no_uart=False):
    # identical and restore write the original; the phrase names the bytes that will land on the target
    image = spec.candidate_sha if mode == 'write' else (spec.base_sha if spec.base_sha and mode == 'identical' else spec.original_sha)
    text = f'WRITE {mode} {spec.name} {image[:12]}'
    if spec.base_sha and mode != 'restore':
        text += f' BASE {spec.base_sha[:12]} MISC-SELECTS-A'
    if spec.name == 'misc':
        text += f' ROOTFS-A {rootfs_a_sha[:12]} BROM-ROUTE-PROVEN'
    return text + (' NO-SSH' if no_ssh else '') + (' NO-UART' if no_uart else '') + (' SAME-DISK' if same_disk else '')


def check_no_ssh(no_ssh, target, mode, spec):
    if no_ssh and (target != 'rootfs_a' or spec.base_sha or mode == 'restore'):
        raise ValueError('--no-ssh is only for rootfs_a identical/write from stock B (no --base-dir): the USB read of misc stands in for the live slot')


def check_no_uart(no_uart, target, uart_log):
    if no_uart and (target != 'rootfs_a' or uart_log):
        raise ValueError('--no-uart is only for rootfs_a and excludes --uart-log; misc keeps the UART requirement')


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('target', choices=('rootfs_a', 'misc'))
    ap.add_argument('mode', choices=('identical', 'write', 'restore'))
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--backup', type=Path, default=DEFAULT_BACKUP)
    ap.add_argument('--loader', type=Path, default=VENDOR_DA)
    ap.add_argument('--candidate-dir', type=Path, help='package_ubi output directory of the approved rootfs_a image (all sessions)')
    ap.add_argument('--base-dir', type=Path, help='rootfs_a only: package_ubi output of the image now on rootfs_a; identical/write start from it, misc may select A')
    ap.add_argument('--backup-copy', type=Path, help='optional second complete-captured-partitions.tar')
    ap.add_argument('--uart-log', type=Path)
    ap.add_argument('--no-uart', action='store_true', help='rootfs_a only: no UART log, so no boot log if the new image fails; the way back is a USB restore from the backup')
    ap.add_argument('--no-ssh', action='store_true', help='rootfs_a from stock B only: no live SSH check; the DA read of misc must equal the backup\'s B-selected misc instead')
    ap.add_argument('--prior-identical', type=Path)
    ap.add_argument('--prior-rootfs-a', type=Path, help='verified rootfs_a write run (misc sessions)')
    ap.add_argument('--resume', type=Path, help='stopped or finished write run, restore mode only')
    args = ap.parse_args()
    required = PRIOR[(args.target, args.mode)]
    for flag, *_ in required:
        if getattr(args, flag) is None:
            raise ValueError(f'{args.target} {args.mode} requires --{flag.replace("_", "-")}')
    wanted = required + [o for o in OPTIONAL_PRIOR.get((args.target, args.mode), []) if getattr(args, o[0]) is not None]
    for flag in ('prior_identical', 'prior_rootfs_a', 'resume'):
        if getattr(args, flag) is not None and flag not in [w[0] for w in OPTIONAL_PRIOR.get((args.target, args.mode), []) + required]:
            raise ValueError(f'--{flag.replace("_", "-")} is not valid for {args.target} {args.mode}')
    if args.candidate_dir is None:
        raise ValueError('--candidate-dir (the package_ubi output of the approved rootfs_a) is required for every session')
    backup, loader = args.backup.resolve(strict=True), args.loader.resolve(strict=True)
    parts, table, original, candidate, spec, identity, base = load_inputs(
        backup, loader, args.target, args.mode, args.candidate_dir.resolve(strict=True),
        args.base_dir.resolve(strict=True) if args.base_dir else None)
    rootfs_a_sha = identity['rootfs_a']
    # rootfs_a sessions use this unit's pins from its backup; misc sessions stay on the first unit's pins (not supported elsewhere)
    specs = {'rootfs_a': spec if args.target == 'rootfs_a' else session.rootfs_a_spec(rootfs_a_sha, identity['base'], identity['base_head']),
             'misc': session.misc_spec(rootfs_a_sha)}
    priors = {}
    for flag, target, mode, verified in wanted:
        # Every prior is bound to this unit, host, tools and the same approved rootfs_a image (from the manifest, not a receipt).
        expect = {**identity, 'target': target, 'original': specs[target].original_sha, 'candidate': specs[target].candidate_sha}
        priors[flag] = load_prior(getattr(args, flag), expect, specs[target], mode, verified)
    check_no_ssh(args.no_ssh, args.target, args.mode, spec)
    check_no_uart(args.no_uart, args.target, args.uart_log)
    print(f'{args.mode}: {args.target} only at {spec.addr:#x}, {spec.size:#x} bytes; candidate {spec.candidate_sha[:12]}; no reboot or retry')
    if spec.base_head:
        print(f'base mode: before the write only the first {spec.base_head:#x} bytes (layout + rootfs) must match base {spec.base_sha[:12]}; the whole partition, overlay included, is replaced')
    if not args.write:
        print('OFFLINE DRY RUN: no SSH, hardware import, USB command or write; execution gates not checked')
        return
    ensure_venv()
    if not (args.uart_log or args.no_uart):
        raise ValueError('--write requires --uart-log (or --no-uart for rootfs_a)')
    copy, uart = args.backup_copy.resolve(strict=True) if args.backup_copy else None, args.uart_log.resolve(strict=True) if args.uart_log else None
    archive = backup / 'complete-captured-partitions.tar'
    expected_archive = (backup / 'ARCHIVE.sha256').read_text().split()[0]
    if sha256_file(archive) != expected_archive:
        raise ValueError('the backup archive does not match its checksum; take the backup again')
    same_disk = False  # a second copy is optional: when given, it must be a different file with the same hash
    if copy is not None:
        if copy.samefile(archive) or sha256_file(copy) != expected_archive:
            raise ValueError('second archive copy is the same file or invalid')
        same_disk = copy.stat().st_dev == archive.stat().st_dev
    if uart:
        check_uart(uart)
    else:
        print('NO UART: no boot log will exist. If the new image does not boot nothing can be diagnosed; the way back is a USB restore from your backup.')
    live = 'a' if spec.base_sha and args.mode != 'restore' else 'b'  # base mode: misc selects A, the unit runs the base image
    if args.no_ssh:
        # No SSH: the session's `before` read of misc must equal the backup's misc, which load_inputs showed is the stock
        # B-selected record (priorities, zero tries), and the full layout is pinned by LAYOUT_HASH and the guard offsets.
        print('NO SSH: the live slot is not confirmed by the running system; it rests on the USB read of misc matching your backup.')
    elif args.mode != 'restore' and active_slot(table) != live:
        raise ValueError(f'live SSH must confirm {live.upper()} and exact full layout')
    probe_dir = PRIVATE / 'usb-probe'
    probe_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if shutil.disk_usage(probe_dir).free < 1024 * 1024 * 1024:
        raise ValueError('less than 1 GiB free for captures and sources')
    if not sys.stdin.isatty():
        raise ValueError('typed confirmation needs an interactive terminal')
    expected_phrase = phrase(spec, args.mode, rootfs_a_sha, same_disk, args.no_ssh, args.no_uart)
    print(('Confirm stable power' if args.no_uart else 'Confirm UART RX capture continues, stable power') + ', no stock upgrade/FOTA pending, and that the NOT-FLASHABLE marker')
    print('on the candidate is deliberately overridden by the owner. Merging a PR is not approval.')
    if args.target == 'misc':
        print('misc is the LIVE slot selector and is rewritten whole (1 MiB): a power or USB loss can leave no valid record.')
    if same_disk:
        print('WARNING: backup copy is on the same filesystem; host disk loss would lose both copies.')
    if input(f'Type exactly {expected_phrase!r} to attest those checks and authorize this operation: ') != expected_phrase:
        raise ValueError('operation not confirmed')
    run = Path(tempfile.mkdtemp(prefix=f'slot-{args.target}-{args.mode}-', dir=probe_dir)).resolve()
    receipt = {'schema': 2, 'run': str(run), 'target': args.target, 'mode': args.mode, 'status': 'STARTED', 'identity': identity,
               'created': time.time(), 'uart': str(uart) if uart else None, 'no_uart': args.no_uart, 'no_ssh': args.no_ssh, 'same_disk_backup': same_disk,
               'priors': {k: str(getattr(args, k).resolve()) for k in priors}}
    save(run, receipt)
    mtk = None
    previous_cwd = Path.cwd()
    try:
        os.chdir(run)
        mtk = open_da(run, loader)
        if uart:
            check_uart(uart)
        check_unit(mtk.daloader, parts['proinfo'], run)
        xml_module = sys.modules.get('mtkclient.Library.DA.xmlflash.xml_lib')
        if xml_module is None or sha256_file(Path(xml_module.__file__)) != identity['host'] or not loaded_code_matches(xml_module):
            raise ValueError('loaded XML implementation differs from verified host')
        if args.resume:  # claimed only once the DA, unit identity and host library are verified, and just before the session:
            claim_restore(args.resume.resolve(), run)  # a USB failure before this point does not spend the tooled restore
            prior = priors['resume']
            prior['status'] = 'RESTORE_ATTEMPTED'
            save(args.resume.resolve(), prior)
        session.run_session(mtk.daloader, spec, original, candidate, run, mode=args.mode, base=base)
        receipt['status'] = 'VERIFIED'
        print('Target and guards verified. No reboot issued; ' + ('after a no-UART flash do not reboot casually until x28-bootok has reset the boot counter.' if args.no_uart else 'review UART before approving the next step.'))
    except BaseException:
        receipt['status'] = 'STOP_UNVERIFIED'
        print('STOP: no retry, slot switch or reboot. Preserve recovery state and private logs.')
        raise
    finally:
        journals = list(run.glob(f'{args.target}-{args.mode}-*/journal.jsonl'))
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
    except (ValueError, OSError, KeyError, json.JSONDecodeError) as error:
        sys.exit(str(error))
