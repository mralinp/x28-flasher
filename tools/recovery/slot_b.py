"""Spec for the overlay tail of rootfs_b, stock slot B (x28-flasher#5). Host-tested only; entry command is slot_b_entry.py.

Only the last 32 MiB of rootfs_b (the rootfs_data overlay) is written. The first 32 MiB (UBI layout copies and the signed
SquashFS) is guarded by hash before and after, like every other neighbour. The engine is slot_session.run_session, unchanged.
"""
from pathlib import Path
import sys

import slot_session as session
from slot_session import ROOTFS_B_HEAD, Spec, common_guards

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'build'))
from stock_access import PEB, ROOTFS_DATA, parse

ROOTFS_B_ADDR, ROOTFS_B_SIZE = 0x1fc00000, 0x4000000
TAIL_ADDR, TAIL_SIZE = ROOTFS_B_ADDR + ROOTFS_B_HEAD, ROOTFS_B_SIZE - ROOTFS_B_HEAD
ROOTFS_A_ADDR, ROOTFS_A_SIZE = 0x13600000, 0x4000000
UBIFS_MAGIC = bytes.fromhex('31181006')


def validate_tail(original, candidate):
    if len(candidate) != TAIL_SIZE or candidate == original:
        raise ValueError('rootfs_b tail candidate must be a different 32 MiB image')
    mapped = {}
    for index, ec, vol, lnum, _ in parse(candidate):
        if vol not in (None, ROOTFS_DATA):
            raise ValueError('rootfs_b tail candidate contains a block that is not rootfs_data')
        if vol is not None:
            mapped[lnum] = candidate[index * PEB + ec[2]:index * PEB + ec[2] + 4]
    if mapped.get(0) != UBIFS_MAGIC or sorted(mapped) != list(range(len(mapped))):
        raise ValueError('rootfs_b tail candidate is not a UBIFS volume starting at LEB 0')


def rootfs_b_tail_spec(candidate_sha, original_tail_sha, rootfs_a_sha, pins):
    """Write the overlay tail. Every other partition the session reads, rootfs_a (the owner's image) and misc included, must be unchanged."""
    if len(candidate_sha) != 64 or candidate_sha == original_tail_sha:
        raise ValueError('rootfs_b tail candidate hash must be a new SHA-256')
    guards = (*common_guards(pins), ('rootfs_a', ROOTFS_A_ADDR, ROOTFS_A_SIZE, rootfs_a_sha), ('misc', 0x700000, 0x100000, pins['misc']))
    return Spec('rootfs_b_tail', TAIL_ADDR, TAIL_SIZE, original_tail_sha, guards, validate_tail, candidate_sha, guards)
