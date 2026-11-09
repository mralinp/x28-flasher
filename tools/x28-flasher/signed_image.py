"""Check a signed X28 sysupgrade image the way the router does (fwtool + ucert + usign), in plain Python.

The file is the sysupgrade tarball, then an fwtool info block (JSON: supported_devices, version), then an fwtool signature block
holding a ucert chain: the image signer's certificate (its public key, validity, signed by the feed key) and the signer's signature
over everything before the signature block. Trust starts at the X28 feed key (zlt-x28-openwrt package/x28-feed), built in below.
Ed25519 verification follows RFC 8032 (the reference algorithm, verify only).
"""
import base64
import hashlib
import json
import struct
import time

FEED_KEY = "RWR/7JlKsNFblyJiYxOYRrnx1SJIc3gS6O6VPbjJQdQqy2LlTPyY8v88"  # untrusted comment: public key 7fec994ab0d15b97
BOARD = "Tozed,X28"  # /tmp/sysinfo/board_name on the unit

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    e, h = (y1 + x1) * (y2 + x2) - (y1 - x1) * (y2 - x2), (y1 + x1) * (y2 + x2) + (y1 - x1) * (y2 - x2)
    c, d = 2 * t1 * t2 * _D, 2 * z1 * z2
    f, g = d - c, d + c
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, pt):
    q = (0, 1, 1, 0)
    while s:
        if s & 1:
            q = _add(q, pt)
        pt, s = _add(pt, pt), s >> 1
    return q


def _x(y, sign):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P) % _P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    return _P - x if (x & 1) != sign else x


def _point(b):
    y = int.from_bytes(b, "little")
    x = _x(y & ((1 << 255) - 1), y >> 255)
    return None if x is None else (x, y & ((1 << 255) - 1), 1, x * (y & ((1 << 255) - 1)) % _P)


_G = _point((4 * pow(5, _P - 2, _P) % _P).to_bytes(32, "little"))


def ed25519_verify(pub, msg, sig):
    a, r, s = _point(pub), _point(sig[:32]), int.from_bytes(sig[32:], "little")
    if a is None or r is None or s >= _L or len(sig) != 64:
        return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), "little") % _L
    left, right = _mul(s, _G), _add(r, _mul(h, a))
    return (left[0] * right[2] - right[0] * left[2]) % _P == 0 and (left[1] * right[2] - right[1] * left[2]) % _P == 0


def usign(text):
    """(key id, payload) of a usign key or signature: base64 of "Ed" + 8-byte id + payload, on its own line or after a comment line."""
    line = text.strip().split(b"\n")[-1] if isinstance(text, bytes) else text.strip().split("\n")[-1]
    raw = base64.b64decode(line)
    if raw[:2] != b"Ed":
        raise ValueError("not an Ed25519 usign key or signature")
    return raw[2:10], raw[10:]


def _blobs(b):
    """libubox blob attributes: [(id, data)], each header a big-endian u32 (extended bit, 7-bit id, 24-bit length with the header)."""
    out, i = [], 0
    while i + 4 <= len(b):
        h = struct.unpack(">I", b[i:i + 4])[0]
        n = h & 0xFFFFFF
        if n < 4 or i + n > len(b):
            raise ValueError("bad certificate encoding")
        out.append(((h >> 24) & 0x7F, b[i + 4:i + n]))
        i += (n + 3) & ~3
    return out


def _table(b):
    """A blobmsg table: name -> raw value."""
    out = {}
    for _, d in _blobs(b):
        n = struct.unpack(">H", d[:2])[0]
        out[d[2:2 + n].decode()] = d[(2 + n + 1 + 3) & ~3:]
    return out


def _block(data):
    """(type, data, the bytes before the block) of the last fwtool block; its trailer: magic FWx0, crc32, type, 3 pad, size (all of it)."""
    if len(data) < 16:
        raise ValueError("not a signed image")
    magic, _, kind, size = struct.unpack(">4sIB3xI", data[-16:])
    if magic != b"FWx0" or not 16 < size <= len(data):
        raise ValueError("not a signed image (no fwtool trailer)")
    return kind, data[-size:-16], data[:-size]


def certificate(cert, feed_key=None, now=None):
    """The signer's public key from one ucert certificate (signature + payload), after checking it against the feed key and its dates."""
    parts = dict(_blobs(cert))
    feed_key = feed_key or FEED_KEY
    if set(parts) != {0, 1}:
        raise ValueError("the image's signer certificate is incomplete")
    feed_id, feed_pub = usign(feed_key)
    sig_id, sig = usign(parts[0].rstrip(b"\0"))
    if sig_id != feed_id or not ed25519_verify(feed_pub, parts[1], sig):
        raise ValueError("the image's signer is not certified by the X28 feed key")
    (_, body), = _blobs(parts[1])
    fields = _table(body[(2 + struct.unpack(">H", body[:2])[0] + 1 + 3) & ~3:])
    start, end = (struct.unpack(">Q", fields[k][:8])[0] for k in ("validfrom", "expiresat"))
    if not start <= (now or time.time()) <= end:
        raise ValueError("the image's signer certificate is not valid now")
    return usign(fields["pubkey"].rstrip(b"\0"))


def verify(data, feed_key=None, board=None, now=None):
    """(tarball bytes, metadata) of a signed image, or ValueError: signed by a signer the feed key certified, for this board."""
    board = board or BOARD
    kind, sig_block, signed = _block(data)
    top = _blobs(sig_block)
    if kind != 0 or len(top) != 2:
        raise ValueError("the image has no signature block")
    signer_id, signer_pub = certificate(top[0][1], feed_key, now)
    (_, sig_text), = _blobs(top[1][1])
    sig_id, sig = usign(sig_text.rstrip(b"\0"))
    if sig_id != signer_id or not ed25519_verify(signer_pub, signed, sig):
        raise ValueError("the image signature is not valid")
    kind, info, tarball = _block(signed)
    if kind != 1:
        raise ValueError("the image has no metadata")
    meta = json.loads(info[8:])  # an 8-byte fwimage header, then the JSON
    if board not in meta.get("supported_devices", []):
        raise ValueError(f"the image is not for {board} (supported_devices: {meta.get('supported_devices')})")
    return tarball, meta
