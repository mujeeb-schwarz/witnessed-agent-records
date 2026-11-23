"""Shared pieces: canonical JSON, hashes, the witness's chain formula, and the
messages the witness signs (a stamp, a chain head and a decision head).

Adapted from `apart-sprint-custody`, `custody/witness.py` (the chain
formula) and `custody/core.py` (canonical JSON). Authentication uses Ed25519
signatures through PyNaCl in place of the source's HMAC test key. Each stamp
carries the chain head it creates, so every stamp is also a signed head.
"""
import hashlib
import json
from typing import Any, Dict, Optional

from nacl.exceptions import CryptoError
from nacl.signing import VerifyKey

FORMAT = "witnessed-gate/1"
ZERO_HASH = "0" * 64


def canon(obj: Any) -> str:
    """Canonical JSON: sorted keys, no spaces, UTF-8, no NaN."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False)


def canon_bytes(obj: Any) -> bytes:
    return canon(obj).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_hex64(value: Any) -> bool:
    return (isinstance(value, str) and len(value) == 64
            and all(c in "0123456789abcdef" for c in value))


def chain_head(prev_head: str, fp: str) -> str:
    """Hash chain adapted from `apart-sprint-custody`, `custody/witness.py`:
    head = sha256(prev_head + fp), starting from 64 zeros."""
    return hashlib.sha256((prev_head + fp).encode("utf-8")).hexdigest()


def stamp_body(witness: str, fp: str, index: int, head: str, t: int) -> Dict[str, Any]:
    """What a stamp says: this witness holds fp at this index, and the chain
    head after it is head. size = index + 1, so a stamp is also a signed head."""
    return {"kind": "stamp", "witness": witness, "fp": fp, "index": index,
            "size": index + 1, "head": head, "t": t}


def head_body(witness: str, size: int, head: str) -> Dict[str, Any]:
    """What a signed chain head says: after size entries the head is head."""
    return {"kind": "head", "witness": witness, "size": size, "head": head}


def decision_head_fp(journal: str, length: int, decision_hash: str) -> str:
    """Domain-separated chain leaf for a journal's final decision chain."""
    return sha256_hex(canon_bytes({"kind": "decision_head", "journal": journal,
                                  "length": length, "decision_hash": decision_hash}))


def decision_head_body(witness: str, journal: str, length: int, decision_hash: str,
                       index: int, head: str, t: int) -> Dict[str, Any]:
    """A signed decision anchor with its own domain-separated fingerprint."""
    return {"kind": "decision_head", "witness": witness, "journal": journal,
            "length": length, "decision_hash": decision_hash,
            "fp": decision_head_fp(journal, length, decision_hash), "index": index,
            "size": index + 1, "head": head, "t": t}


def signed_part(msg: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in msg.items() if k != "sig"}


def verify_signature(msg: Any, pubkey_hex: Optional[str]) -> bool:
    """True when msg["sig"] is an Ed25519 signature, under pubkey_hex, of the
    canonical bytes of msg without its sig. Never raises."""
    if not isinstance(msg, dict) or not isinstance(pubkey_hex, str):
        return False
    try:
        key = VerifyKey(bytes.fromhex(pubkey_hex))
        key.verify(canon_bytes(signed_part(msg)), bytes.fromhex(msg["sig"]))
        return True
    except (CryptoError, KeyError, TypeError, ValueError, AttributeError, UnicodeError,
            OverflowError, RecursionError):
        return False


def key_for(msg: Any, keys: Any) -> Optional[str]:
    """The pinned key for the witness a signed message names. `keys` is either
    {witness_id: pubkey hex} (one entry per witness) or one pubkey hex."""
    if isinstance(keys, dict):
        wid = msg.get("witness") if isinstance(msg, dict) else None
        return keys.get(wid) if isinstance(wid, str) else None
    return keys if isinstance(keys, str) else None


def is_uint(value: Any) -> bool:
    """An exact, nonnegative integer (booleans are not integers here)."""
    return type(value) is int and value >= 0


def signed_message_error(msg: Any) -> Optional[str]:
    """Validate the complete stamp/head domain before any signature check."""
    if not isinstance(msg, dict) or msg.get("kind") not in ("stamp", "head", "decision_head"):
        return "no signed head or stamp"
    fields = {"kind", "witness", "size", "head", "sig"}
    if msg["kind"] in ("stamp", "decision_head"):
        fields.update(("fp", "index", "t"))
    if msg["kind"] == "decision_head":
        fields.update(("journal", "length", "decision_hash"))
    if set(msg) != fields:
        return "the signed message schema is incomplete or unknown"
    if not isinstance(msg["witness"], str) or not msg["witness"]:
        return "the witness identity is malformed"
    if not is_uint(msg["size"]) or not is_hex64(msg["head"]):
        return "the signed head's size or hash is malformed"
    if msg["size"] == 0 and msg["head"] != ZERO_HASH:
        return "an empty signed head must be the zero hash"
    sig = msg["sig"]
    if not (isinstance(sig, str) and len(sig) == 128
            and all(c in "0123456789abcdef" for c in sig)):
        return "the signature is malformed"
    if msg["kind"] in ("stamp", "decision_head"):
        if not (is_uint(msg["index"]) and msg["size"] == msg["index"] + 1):
            return "the stamp's index and size disagree"
        if not is_hex64(msg["fp"]) or not is_uint(msg["t"]):
            return "the stamp's fingerprint or timestamp is malformed"
    if msg["kind"] == "decision_head":
        if not (is_hex64(msg["journal"]) and is_uint(msg["length"]) and msg["length"] > 0
                and is_hex64(msg["decision_hash"])):
            return "the decision head's journal, length or hash is malformed"
        if msg["fp"] != decision_head_fp(msg["journal"], msg["length"], msg["decision_hash"]):
            return "the decision head's fingerprint does not match its content"
    return None


def check_stamp(stamp: Any, fp: Optional[str], keys: Any) -> Optional[str]:
    """None when stamp is a good stamp for fp under the pinned key of the
    witness it names; otherwise the reason it is not. `keys` as in key_for.
    Schemas and domains are checked before the signature."""
    if not isinstance(stamp, dict) or stamp.get("kind") != "stamp":
        return "the reply holds no stamp"
    malformed = signed_message_error(stamp)
    if malformed:
        return malformed
    if not is_hex64(fp):
        return "the expected fingerprint is malformed"
    if not keys:
        return "the gate holds no witness key, so no stamp can be checked"
    pubkey_hex = key_for(stamp, keys)
    if pubkey_hex is None:
        return "the stamp names a witness the gate holds no key for"
    if not verify_signature(stamp, pubkey_hex):
        return "the stamp's signature does not verify under the witness's key"
    if stamp.get("fp") != fp:
        return "the stamp names another fingerprint"
    index, size = stamp.get("index"), stamp.get("size")
    if not (is_uint(index) and is_uint(size) and size == index + 1):
        return "the stamp's index and size disagree"
    if not is_hex64(stamp.get("head")):
        return "the stamp's chain head is malformed"
    return None
