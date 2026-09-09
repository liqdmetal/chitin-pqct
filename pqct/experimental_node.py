"""Minimal experimental node: mempool, block assembly, chain state.

This is the thinnest thing that can honestly be called a network node for
Chitin transactions. It is a SINGLE-PROCESS, IN-MEMORY simulator: no p2p, no
mining, no persistence, no consensus rules beyond "the proof verifies and the
envelope is fresh". Its purpose is to exercise the crypto under
transaction-shaped pressure -- replay, expiry, fork/state binding, duplicate
nonces, malformed bytes -- which unit tests on proofs alone cannot reach.

WHAT IT IS NOT: it is not a blockchain, not consensus, not connected to DERO
or any real network, and it carries no value. Tokens here are integers in a
Python dict.

Acceptance pipeline for each transaction (all four must pass):
  1. envelope well-formed and on THIS chain
  2. not expired at the current height
  3. nonce unused (replay guard)
  4. witness-free proof verification against the ENVELOPE-DERIVED statement
     -- so a proof for another chain/state/nonce cannot be accepted

Deliberate design choice: the node derives the statement itself from the
envelope. It never accepts a caller-supplied statement. This is the same
lesson as the challenge-injection forgery -- anything the submitter chooses
that feeds verification is an attack surface.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .authorization import AuthorizationError, NoteRegistry
from .transaction_proof import verify_transaction
from .tx_envelope import ReplayGuard, TransactionEnvelope, compute_txid

GENESIS_DOMAIN = b"CHITIN-GENESIS-V1"
BLOCK_DOMAIN = b"CHITIN-BLOCK-V1"


class NodeError(ValueError):
    """Raised on node-level protocol violations."""


@dataclass(frozen=True)
class AcceptedTx:
    """A transaction that passed every gate, with its verification evidence."""

    txid: bytes
    envelope: TransactionEnvelope
    account_count: int
    bit_width: int
    conservation_gates: tuple


@dataclass(frozen=True)
class Block:
    height: int
    prev_state_root: bytes
    state_root: bytes
    txids: tuple


def genesis_state_root(chain_id: bytes) -> bytes:
    hasher = hashlib.shake_256()
    hasher.update(GENESIS_DOMAIN)
    hasher.update(len(chain_id).to_bytes(2, "big"))
    hasher.update(chain_id)
    return hasher.digest(32)


def next_state_root(prev: bytes, txids) -> bytes:
    """Fold txids into the next state root, length-bound to avoid ambiguity."""
    hasher = hashlib.shake_256()
    hasher.update(BLOCK_DOMAIN)
    hasher.update(prev)
    items = tuple(txids)
    hasher.update(len(items).to_bytes(4, "big"))
    for txid in items:
        hasher.update(len(txid).to_bytes(2, "big"))
        hasher.update(txid)
    return hasher.digest(32)


@dataclass
class ExperimentalNode:
    """In-memory node for an isolated, valueless experimental network."""

    chain_id: bytes
    height: int = 0
    state_root: bytes = b""
    mempool: list = field(default_factory=list)
    blocks: list = field(default_factory=list)
    guard: ReplayGuard = None
    registry: NoteRegistry = None
    rejections: list = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.chain_id:
            raise NodeError("chain_id required")
        if not self.state_root:
            self.state_root = genesis_state_root(self.chain_id)
        if self.guard is None:
            self.guard = ReplayGuard(chain_id=self.chain_id)
        if self.registry is None:
            self.registry = NoteRegistry()

    def submit(
        self, *, envelope, payload, key, bit_commitments, binary_proofs,
        conservation, signs, bit_width, p1_params, p5,
        spent_note_ids=None, created_notes=None, signatures=None,
    ) -> tuple[bool, str]:
        """Run the full acceptance pipeline. Returns (accepted, reason).

        Gates, in order: chain/expiry/replay -> state freshness -> proof
        verification -> AUTHORIZATION (provenance, ownership, double-spend).

        Authorization is last because it is the most expensive, but it is
        NOT optional: without it a transaction with fabricated inputs
        passes every other gate, since conserving 1,000,000 in and
        1,000,000 out is arithmetically valid. Passing `spent_note_ids=None`
        runs the node in NO-VALUE mode (proof plumbing only) and is
        reported as such, so it can never be mistaken for an authorized
        transfer.
        """
        # Gate 1-3: envelope, chain, expiry, replay.
        ok, reason = self.guard.check_and_record(envelope, self.height)
        if not ok:
            self.rejections.append(reason)
            return False, reason

        # Gate 3b: the tx must be built on THIS node's current state root.
        if envelope.prev_state_root != self.state_root:
            reason = (
                f"stale state: envelope built on {envelope.prev_state_root.hex()[:16]} "
                f"but node is at {self.state_root.hex()[:16]}"
            )
            self.rejections.append(reason)
            return False, reason

        # Gate 4: the node DERIVES the statement; it never trusts a caller's.
        statement = envelope.statement(
            bit_width=bit_width, account_count=len(tuple(signs))
        )
        verification = verify_transaction(
            statement=statement, key=key,
            bit_commitments=bit_commitments, binary_proofs=binary_proofs,
            conservation=conservation, signs=signs, bit_width=bit_width,
            p1_params=p1_params, p5=p5,
        )
        if not verification.accepted:
            reason = (
                f"proof rejected (dims={verification.dimensions_ok}, "
                f"signs={verification.signs_consistent}, "
                f"binary={verification.binary_ok}, "
                f"conservation={verification.conservation_ok})"
            )
            self.rejections.append(reason)
            return False, reason

        txid = compute_txid(payload)

        # Gate 5: AUTHORIZATION -- provenance, ownership, no double-spend.
        value_mode = spent_note_ids is not None
        if value_mode:
            authorized, auth_reason = self.registry.authorize_spend(
                statement=statement,
                spent_note_ids=spent_note_ids,
                created_notes=created_notes or (),
                signatures=signatures or (),
            )
            if not authorized:
                reason = f"unauthorized: {auth_reason}"
                self.rejections.append(reason)
                return False, reason
            try:
                self.registry.apply_spend(
                    spent_note_ids=spent_note_ids,
                    created_notes=created_notes or (),
                )
            except AuthorizationError as error:
                reason = f"spend application failed: {error}"
                self.rejections.append(reason)
                return False, reason

        self.mempool.append(AcceptedTx(
            txid=txid, envelope=envelope, account_count=len(tuple(signs)),
            bit_width=bit_width,
            conservation_gates=verification.conservation_gates,
        ))
        mode = "authorized" if value_mode else "NO-VALUE (proof only)"
        return True, f"accepted txid={txid.hex()[:16]} [{mode}]"

    def seal_block(self) -> Block:
        """Advance the chain by one block over the current mempool."""
        txids = tuple(tx.txid for tx in self.mempool)
        new_root = next_state_root(self.state_root, txids)
        block = Block(
            height=self.height + 1,
            prev_state_root=self.state_root,
            state_root=new_root,
            txids=txids,
        )
        self.blocks.append(block)
        self.height = block.height
        self.state_root = new_root
        self.mempool = []
        return block

    def summary(self) -> dict:
        return {
            "chain_id": self.chain_id.decode("ascii", "replace"),
            "height": self.height,
            "state_root": self.state_root.hex(),
            "blocks": len(self.blocks),
            "mempool": len(self.mempool),
            "total_txs": sum(len(b.txids) for b in self.blocks),
            "rejections": len(self.rejections),
            "unspent_notes": len(self.registry.unspent),
            "spent_notes": len(self.registry.spent),
            "status": "EXPERIMENTAL -- valueless, unproven crypto, not consensus",
        }


__all__ = [
    "AcceptedTx",
    "BLOCK_DOMAIN",
    "Block",
    "ExperimentalNode",
    "GENESIS_DOMAIN",
    "NodeError",
    "genesis_state_root",
    "next_state_root",
]
