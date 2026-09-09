"""Transaction envelope: state binding, replay protection, canonical txid.

This is the layer between "a proof about numbers" and "a transaction a
network can accept twice-proof". Protocol 1 + Protocol 5 prove that committed
amounts are bits and that they conserve. Neither says WHICH chain, WHICH
block, or WHICH spend those amounts belong to -- so a valid proof could be
replayed onto another chain, another height, or simply submitted twice.

The envelope binds a proof to:
  chain_id     -- domain separation between networks (testnet vs anything else)
  prev_state   -- the state root the tx is built against (ordering/fork binding)
  nonce        -- per-tx uniqueness (replay protection within one chain+state)
  expiry       -- bounded validity window, so a stuck tx cannot be revived
                  arbitrarily far in the future

...and makes ALL of it part of the Fiat-Shamir statement. That is the load-
bearing detail: binding fields that are merely *carried alongside* a proof are
not bound at all -- an attacker rewrites them and the proof still verifies.
Because `envelope_statement()` output IS the statement the proofs are
generated and verified against, mutating any field invalidates both proofs.

The txid is the hash of the canonical encoding, so it inherits the codec's
malleability rejection: there is exactly one byte string per transaction.

RESEARCH STATUS: this is replay/state plumbing for an EXPERIMENTAL network
with valueless tokens. It does not make the underlying proofs sound.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from .wire_codec import (
    MAGIC,
    CodecError,
    _Reader,
    _put_uint,
    decode_params,
    encode_params,
)

TXID_DOMAIN = b"CHITIN-TXID-V1"
STATEMENT_DOMAIN = b"CHITIN-STATEMENT-V1"


class EnvelopeError(ValueError):
    """Raised on malformed or unbound envelopes."""


@dataclass(frozen=True)
class TransactionEnvelope:
    """Binding context for one experimental PQ-CT transaction."""

    chain_id: bytes
    prev_state_root: bytes
    nonce: int
    expiry_height: int

    def __post_init__(self) -> None:
        if not self.chain_id:
            raise EnvelopeError("chain_id must not be empty (no domain separation)")
        if len(self.chain_id) > 64:
            raise EnvelopeError("chain_id too long")
        if len(self.prev_state_root) != 32:
            raise EnvelopeError("prev_state_root must be exactly 32 bytes")
        if not 0 <= self.nonce < 2 ** 64:
            raise EnvelopeError("nonce out of range")
        if not 0 <= self.expiry_height < 2 ** 64:
            raise EnvelopeError("expiry_height out of range")

    def encode(self) -> bytes:
        return (
            _put_uint(len(self.chain_id), 2)
            + self.chain_id
            + self.prev_state_root
            + _put_uint(self.nonce, 8)
            + _put_uint(self.expiry_height, 8)
        )

    @staticmethod
    def decode(reader: _Reader) -> "TransactionEnvelope":
        length = reader.uint(2)
        chain_id = reader.take(length)
        prev_state_root = reader.take(32)
        nonce = reader.uint(8)
        expiry_height = reader.uint(8)
        return TransactionEnvelope(
            chain_id=chain_id,
            prev_state_root=prev_state_root,
            nonce=nonce,
            expiry_height=expiry_height,
        )

    def statement(self, *, bit_width: int, account_count: int) -> bytes:
        """The Fiat-Shamir statement. MUST be what the prover/verifier use.

        Shape/relation parameters (bit_width, account_count) are included so a
        proof for one shape cannot be replayed as a proof for another.
        """
        hasher = hashlib.shake_256()
        hasher.update(STATEMENT_DOMAIN)
        hasher.update(_put_uint(len(self.chain_id), 2))
        hasher.update(self.chain_id)
        hasher.update(self.prev_state_root)
        hasher.update(_put_uint(self.nonce, 8))
        hasher.update(_put_uint(self.expiry_height, 8))
        hasher.update(_put_uint(bit_width, 4))
        hasher.update(_put_uint(account_count, 4))
        return hasher.digest(32)

    def is_expired(self, current_height: int) -> bool:
        return current_height > self.expiry_height


def envelope_statement(
    envelope: TransactionEnvelope, *, bit_width: int, account_count: int
) -> bytes:
    return envelope.statement(bit_width=bit_width, account_count=account_count)


def compute_txid(payload: bytes) -> bytes:
    """Canonical txid over the full encoded transaction."""
    hasher = hashlib.shake_256()
    hasher.update(TXID_DOMAIN)
    hasher.update(_put_uint(len(payload), 8))
    hasher.update(payload)
    return hasher.digest(32)


@dataclass
class ReplayGuard:
    """Rejects duplicate (chain_id, nonce) pairs and expired transactions.

    Deliberately keyed on (chain_id, nonce) rather than txid: an attacker who
    can perturb any non-bound byte would get a fresh txid, so txid-only
    tracking is not replay protection. Since chain_id and nonce are bound into
    the statement, a duplicate pair cannot carry a different valid proof.
    """

    seen: set = None
    chain_id: bytes = b""

    def __post_init__(self) -> None:
        if self.seen is None:
            self.seen = set()

    def check_and_record(
        self, envelope: TransactionEnvelope, current_height: int
    ) -> tuple[bool, str]:
        if self.chain_id and envelope.chain_id != self.chain_id:
            return False, (
                f"wrong chain: envelope {envelope.chain_id!r} != node "
                f"{self.chain_id!r}"
            )
        if envelope.is_expired(current_height):
            return False, (
                f"expired: height {current_height} > expiry "
                f"{envelope.expiry_height}"
            )
        key = (envelope.chain_id, envelope.nonce)
        if key in self.seen:
            return False, f"replay: nonce {envelope.nonce} already used"
        self.seen.add(key)
        return True, "accepted"


__all__ = [
    "EnvelopeError",
    "ReplayGuard",
    "STATEMENT_DOMAIN",
    "TXID_DOMAIN",
    "TransactionEnvelope",
    "compute_txid",
    "envelope_statement",
]
