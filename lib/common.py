"""
Shared utilities: config, paths, IO, hashing, hash chains and Merkle trees.
"""

import base64
import hashlib
import hmac
import json
import os
from typing import Optional

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_config():
    with open(os.path.join(ROOT_DIR, "config.json")) as f:
        return json.load(f)


_CFG = load_config()
DEBUG = _CFG.get("debug", False)


def debug(tag, msg):
    if DEBUG:
        print(f"  [DEBUG][{tag}] {msg}")


def keys_dir(*parts):
    p = os.path.join(ROOT_DIR, _CFG["paths"]["keys"], *parts)
    os.makedirs(p, exist_ok=True)
    return p


def certs_dir(*parts):
    p = os.path.join(ROOT_DIR, _CFG["paths"]["certs"], *parts)
    os.makedirs(p, exist_ok=True)
    return p


def registries_dir():
    p = os.path.join(ROOT_DIR, _CFG["paths"]["registries"])
    os.makedirs(p, exist_ok=True)
    return p


def safe_name(s):
    """Turn an identifier into something usable as a filename."""
    return s.replace("@", "_at_").replace(":", "_")


# Binary values such as signatures and public keys travel inside JSON and so
# have to be text. Hex costs 2 bytes per byte and base64 costs 1.33, and around
# 98% of a handshake payload is binary, so base64 saves roughly a third of the
# message. This is purely a wire-format choice: signatures are always computed
# over build_tuple_message(), never over the encoded form.

def b64e(data: bytes) -> str:
    """Encode bytes for transport inside JSON."""
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Decode a transport-encoded string back to bytes."""
    return base64.b64decode(text)


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def create_key(length=32):
    return os.urandom(length)


def prf(key, *params):
    """HMAC-SHA256(key, p1 || p2 || ...).

    Each param is encoded by type: str as UTF-8, int as 4-byte big-endian,
    bytes as-is.
    """
    message = b""
    for p in params:
        if isinstance(p, int):
            message += p.to_bytes(4, "big")
        elif isinstance(p, str):
            message += p.encode("utf-8")
        elif isinstance(p, bytes):
            message += p
        else:
            message += str(p).encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).digest()


def prf_verify(key: bytes, data: bytes, tag: bytes) -> bool:
    """Constant-time check that prf(key, data) equals tag."""
    return hmac.compare_digest(prf(key, data), tag)


def canonical_json(obj) -> bytes:
    """Canonical JSON encoding: sorted keys, compact separators, UTF-8."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def save_bytes(data, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as f:
        f.write(data)
    debug("IO", f"wrote {len(data)}B to {path}")


def save_json(obj, path):
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        json.dump(obj, f, indent=2)
    debug("IO", f"json to {path}")


_TAG_BYTES = 0x01
_TAG_STR = 0x02
_TAG_INT = 0x03


def build_tuple_message(*fields):
    """Injective encoding of a field tuple, used for signing only.

    Each field is emitted as tag(1) || len(4, big-endian) || value.

    Raw concatenation is not injective and is exploitable here. Signing
    (s_n, tau_start, Q=20, Delta=3600) as decimal ASCII produces the same
    preimage as (s_n, tau_start, Q=203, Delta=600), so a peer could present
    a 10x message budget under a genuine user signature. Length prefixes fix
    adjacent variable-length fields such as aid_I || aid_R, and fixed-width
    big-endian ints fix the decimal-split family.

    Unsupported types raise rather than falling back to str(), which would
    silently reintroduce decimal-ASCII ints.
    """
    out = bytearray()
    for f in fields:
        if isinstance(f, bool):
            # bool subclasses int, so reject it and make the caller explicit.
            raise TypeError("build_tuple_message: bool is ambiguous, pass int")
        elif isinstance(f, int):
            tag, value = _TAG_INT, f.to_bytes(8, "big", signed=True)
        elif isinstance(f, bytes):
            tag, value = _TAG_BYTES, f
        elif isinstance(f, bytearray):
            tag, value = _TAG_BYTES, bytes(f)
        elif isinstance(f, str):
            tag, value = _TAG_STR, f.encode()
        else:
            raise TypeError(
                f"build_tuple_message: unsupported field type "
                f"{type(f).__name__}, encode explicitly as bytes/str/int")
        out += bytes([tag])
        out += len(value).to_bytes(4, "big")
        out += value
    return bytes(out)


def personalized_hash_chain(seed, length, context):
    """Personalized hash chain rho_i = H(rho_{i-1} || i || context).

    chain[0] is the seed and chain[length] is the root that gets committed.

    Args:
        seed:    bytes, rho_0
        length:  int, chain length n'
        context: bytes, personalization (the peer aid)
    Returns:
        list of length + 1 byte strings
    """
    chain = [seed]
    value = seed
    for i in range(1, length + 1):
        value = hashlib.sha256(value + i.to_bytes(4, "big") + context).digest()
        chain.append(value)
    return chain


def verify_chain_element(element, position, chain_length, image, context):
    """Check that element sits at `position` of a chain ending in `image`."""
    if position < 0 or position > chain_length:
        return False
    value = element
    for i in range(position + 1, chain_length + 1):
        value = hashlib.sha256(value + i.to_bytes(4, "big") + context).digest()
    return value == image


def verify_chain_step(current: bytes, step_idx: int,
                      context: bytes, expected: bytes) -> bool:
    """Check a single chain step: H(current || step_idx || context) == expected."""
    return hashlib.sha256(
        current + step_idx.to_bytes(4, "big") + context
    ).digest() == expected


def _mt_leaf(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def _mt_node(a: bytes, b: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + a + b).digest()


def build_merkle_tree(leaves):
    """Build a SHA-256 Merkle tree with domain-separated leaves and nodes.

    Returns (root, levels) where levels[0] is the hashed-leaf level and
    levels[-1] is [root]. Odd-sized levels duplicate the last node.
    """
    if not leaves:
        raise ValueError("build_merkle_tree: empty leaves")
    level = [_mt_leaf(leaf) for leaf in leaves]
    levels = [level]
    while len(level) > 1:
        nxt = []
        for i in range(0, len(level), 2):
            left = level[i]
            right = level[i + 1] if i + 1 < len(level) else level[i]
            nxt.append(_mt_node(left, right))
        levels.append(nxt)
        level = nxt
    return level[0], levels


def get_merkle_proof(levels, leaf_idx):
    """Return the bottom-to-top sibling hashes for the leaf at leaf_idx."""
    proof = []
    idx = leaf_idx
    for lvl in levels[:-1]:
        sib = idx ^ 1
        if sib >= len(lvl):
            sib = idx
        proof.append(lvl[sib])
        idx >>= 1
    return proof


def merkle_depth(n_leaves: int) -> int:
    """Number of proof elements for a tree built by build_merkle_tree()."""
    if n_leaves < 1:
        raise ValueError("merkle_depth: n_leaves must be >= 1")
    d, n = 0, n_leaves
    while n > 1:
        n = (n + 1) // 2
        d += 1
    return d


def verify_merkle_proof(root: bytes, leaf: bytes, proof, leaf_idx: int,
                        n_leaves: Optional[int] = None) -> bool:
    """Verify that `leaf` sits at `leaf_idx` in a tree with the given `root`.

    Pass the signed leaf count as n_leaves to bound the opening. Odd levels are
    completed by duplicating the last node, so a tree over [a,b,c] has the same
    root as one over [a,b,c,c]. Without an explicit count a prover can open a
    phantom extra leaf, for example minting an unauthorised t+1'th A-session
    time budget. Checking the index range and the proof length closes that.
    """
    if n_leaves is not None:
        if not (0 <= leaf_idx < n_leaves):
            return False
        if len(proof) != merkle_depth(n_leaves):
            return False
    h = _mt_leaf(leaf)
    idx = leaf_idx
    for sib in proof:
        h = _mt_node(sib, h) if idx & 1 else _mt_node(h, sib)
        idx >>= 1
    return h == root


def icp_time_leaf(idx: int, peer_aid: str, delta: int) -> bytes:
    """Canonical leaf of the C-session time Merkle tree: (j, aid_j, Delta_j).

    The user builds the tree from these leaves and the receiving agent rebuilds
    its own leaf to check the proof, so both sides must derive byte-identical
    leaves. The index pins a leaf to its workflow position, which keeps things
    unambiguous when the same peer appears in more than one step.
    """
    return canonical_json([int(idx), str(peer_aid), int(delta)])
