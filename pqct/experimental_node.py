"""Single-process, in-memory, valueless PQ-CT transaction experiment.

Only complete canonical PUBLIC transactions enter admission. Policy is pinned
by the node, notes are tied to the proved commitments, and rejected/pending
transactions never mutate the committed note registry or replay markers.
This remains unproven research cryptography, without networking or consensus.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

from .authorization import Note, NoteRegistry, verify_signature
from .public_transaction import (PublicTransaction, VerifierConfig, decode_transaction,
                                 note_commitment, transaction_statement)
from .transaction_proof import verify_public_transaction
from .tx_envelope import ReplayGuard, TransactionEnvelope, compute_txid

GENESIS_DOMAIN = b"CHITIN-GENESIS-V2"
BLOCK_DOMAIN = b"CHITIN-BLOCK-V2"


class NodeError(ValueError):
    """Rejected experimental node transition."""


@dataclass(frozen=True)
class AcceptedTx:
    txid: bytes
    envelope: TransactionEnvelope
    account_count: int
    bit_width: int
    conservation_gates: tuple
    transaction: PublicTransaction
    payload: bytes


@dataclass(frozen=True)
class Block:
    height: int
    prev_state_root: bytes
    state_root: bytes
    txids: tuple


def genesis_state_root(chain_id: bytes) -> bytes:
    return hashlib.shake_256(GENESIS_DOMAIN + len(chain_id).to_bytes(2, "big") + chain_id).digest(32)


def next_state_root(prev: bytes, txids) -> bytes:
    hasher = hashlib.shake_256(BLOCK_DOMAIN + prev)
    items = tuple(txids)
    hasher.update(len(items).to_bytes(4, "big"))
    for txid in items:
        hasher.update(len(txid).to_bytes(2, "big"))
        hasher.update(txid)
    return hasher.digest(32)


def _copy_registry(registry):
    return NoteRegistry(dict(registry.unspent), set(registry.spent))


def _apply(registry, transaction):
    if not transaction.proof_only:
        registry.apply_spend(spent_note_ids=transaction.spent_note_ids,
                             created_notes=transaction.created_notes)


@dataclass
class ExperimentalNode:
    chain_id: bytes
    verifier: VerifierConfig
    genesis_notes: tuple[Note, ...] = ()
    height: int = field(default=0, init=False)
    state_root: bytes = field(default=b"", init=False)
    mempool: list = field(default_factory=list, init=False)
    blocks: list = field(default_factory=list, init=False)
    guard: ReplayGuard = field(init=False)
    registry: NoteRegistry = field(init=False)
    rejections: list = field(default_factory=list, init=False)
    _lock: object = field(default_factory=threading.RLock, init=False, repr=False)

    def __post_init__(self):
        if type(self.chain_id) is not bytes or not 1 <= len(self.chain_id) <= 64:
            raise NodeError("chain_id must contain 1..64 bytes")
        if type(self.verifier) is not VerifierConfig:
            raise NodeError("node requires a pinned verifier configuration")
        self.guard = ReplayGuard(chain_id=self.chain_id)
        self.registry = NoteRegistry()
        for note in self.genesis_notes:
            # Genesis allocations are trusted operator input, but their encoding
            # must be a valid commitment under this same profile.
            from .wire_codec import _Reader, decode_vector
            prefix = b"CHITIN-NOTE-COMMITMENT-V2" + self.verifier.profile_id
            if not note.commitment.startswith(prefix):
                raise NodeError("genesis note has another commitment profile")
            reader = _Reader(note.commitment[len(prefix):])
            row = decode_vector(reader, self.verifier.key.params)
            reader.finish()
            if note_commitment(self.verifier, row) != note.commitment:
                raise NodeError("noncanonical genesis commitment")
            self.registry.mint_genesis(note)
        genesis_ids = tuple(sorted(self.registry.unspent))
        self.state_root = next_state_root(
            genesis_state_root(self.chain_id), (self.verifier.profile_id,) + genesis_ids)

    def _verify(self, payload, registry, seen, height):
        transaction = decode_transaction(payload, self.verifier)
        envelope, proof = transaction.envelope, transaction.proof
        txid = compute_txid(payload)
        if envelope.chain_id != self.chain_id:
            raise NodeError("wrong chain")
        if envelope.is_expired(height):
            raise NodeError("expired transaction")
        if (self.chain_id, txid) in seen:
            raise NodeError("replay: transaction already accepted")
        if envelope.prev_state_root != self.state_root:
            raise NodeError("stale state root")
        if not transaction.proof_only:
            inputs, outputs = transaction.spent_note_ids, transaction.created_notes
            if len(set(inputs)) != len(inputs):
                raise NodeError("duplicate input note")
            output_ids = tuple(note.note_id for note in outputs)
            if len(set(output_ids)) != len(output_ids):
                raise NodeError("duplicate output note")
            message = transaction.authorization_payload(self.verifier)
            for note_id, position, signature in zip(
                    inputs, self.verifier.input_positions, transaction.signatures):
                note = registry.get_unspent(note_id)
                if note.commitment != note_commitment(self.verifier, proof.bit_commitments[position]):
                    raise NodeError("input note is not the commitment proved by this transaction")
                if not verify_signature(note.owner, message, signature):
                    raise NodeError("input not authorized by its owner")
            for note, position in zip(outputs, self.verifier.output_positions):
                if note.commitment != note_commitment(self.verifier, proof.bit_commitments[position]):
                    raise NodeError("output note is not the commitment proved by this transaction")
                if note.note_id in registry.unspent or note.note_id in registry.spent:
                    raise NodeError("output note already exists")
        verification = verify_public_transaction(
            statement=transaction_statement(self.verifier, envelope), key=self.verifier.key,
            proof=proof, p1_params=self.verifier.p1, p5=self.verifier.p5)
        if not verification.accepted:
            raise NodeError("proof rejected")
        return AcceptedTx(txid, envelope, len(proof.signs), proof.bit_width,
                          verification.conservation_gates, transaction, payload)

    def _pending_state(self):
        registry, seen = _copy_registry(self.registry), set(self.guard.seen)
        for pending in self.mempool:
            _apply(registry, pending.transaction)
            seen.add((self.chain_id, pending.txid))
        return registry, seen

    def validate(self, payload: bytes) -> tuple[bool, str]:
        """Read-only admission check, including current mempool reservations."""
        with self._lock:
            try:
                registry, seen = self._pending_state()
                self._verify(payload, registry, seen, self.height)
                return True, "valid"
            except (ValueError, TypeError, OverflowError, AttributeError) as error:
                return False, str(error)

    def submit(self, payload: bytes) -> tuple[bool, str]:
        """Decode/verify complete bytes and reserve a pending transition only."""
        with self._lock:
            try:
                registry, seen = self._pending_state()
                accepted = self._verify(payload, registry, seen, self.height)
            except (ValueError, TypeError, OverflowError, AttributeError) as error:
                self.rejections.append(str(error))
                return False, str(error)
            self.mempool.append(accepted)
            mode = "NO-VALUE (proof only)" if accepted.transaction.proof_only else "authorized"
            return True, f"accepted txid={accepted.txid.hex()[:16]} [{mode}]"

    def evict(self, txid: bytes) -> None:
        """Drop pending work; no committed replay or note state needs undoing."""
        with self._lock:
            # Later pending transfers may depend on an output being evicted.
            # Clear the suffix so reservations remain a valid transition chain.
            for index, pending in enumerate(self.mempool):
                if pending.txid == txid:
                    del self.mempool[index:]
                    return

    def seal_block(self) -> Block:
        """Revalidate and atomically publish notes, replay markers and block."""
        with self._lock:
            registry, seen = _copy_registry(self.registry), set(self.guard.seen)
            for pending in self.mempool:
                accepted = self._verify(pending.payload, registry, seen, self.height + 1)
                _apply(registry, accepted.transaction)
                seen.add((self.chain_id, accepted.txid))
            txids = tuple(tx.txid for tx in self.mempool)
            block = Block(self.height + 1, self.state_root,
                          next_state_root(self.state_root, txids), txids)
            self.registry = registry
            self.guard.seen = seen
            self.blocks.append(block)
            self.height, self.state_root = block.height, block.state_root
            self.mempool = []
            return block

    def summary(self) -> dict:
        with self._lock:
            return {"chain_id": self.chain_id.decode("ascii", "replace"),
                    "height": self.height, "state_root": self.state_root.hex(),
                    "blocks": len(self.blocks), "mempool": len(self.mempool),
                    "total_txs": sum(len(b.txids) for b in self.blocks),
                    "rejections": len(self.rejections),
                    "unspent_notes": len(self.registry.unspent),
                    "spent_notes": len(self.registry.spent),
                    "status": "EXPERIMENTAL -- valueless, unproven crypto, not consensus"}
