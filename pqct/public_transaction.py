"""Public-only, canonical experimental transactions and pinned verifier policy.

There are deliberately no prover result, mask, witness or supplied-verdict
fields. The format is a breaking V2 research format, not production crypto.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, fields
from decimal import Decimal

from .authorization import Note, PUBLIC_KEY_SIZE, SIGNATURE_SIZE
from .binary_protocol1_ring import RingProtocol1Parameters, RingProtocol1Proof
from .hmc import HMCKey
from .protocol5 import Protocol5Parameters, Protocol5Proof
from .transaction_proof import PublicTransactionProof
from .tx_envelope import TransactionEnvelope
from .wire_codec import CodecError, _Reader, _put_uint, encode_vector, decode_element

MAGIC = b"CHITIN-PUBLIC-TX-EXPERIMENTAL-V2"
MAX_TRANSACTION_BYTES = 2 * 1024 * 1024
MAX_AMOUNTS = 32


def _policy_fields(value):
    return {field.name: (getattr(value, field.name).hex()
                        if isinstance(getattr(value, field.name), bytes)
                        else str(getattr(value, field.name)))
            for field in fields(value)}


@dataclass(frozen=True)
class VerifierConfig:
    """One operator-pinned research relation; transaction input cannot relax it.

    A configuration fixes the key, bounds, shape and input/output roles. A
    different shape requires an explicitly selected different profile.
    """

    key: HMCKey
    p1: RingProtocol1Parameters
    p5: Protocol5Parameters
    signs: tuple[int, ...]
    allow_proof_only: bool = False

    def __post_init__(self):
        if (type(self.signs) is not tuple or not 1 <= len(self.signs) <= MAX_AMOUNTS
                or any(type(s) is not int or s not in (-1, 1) for s in self.signs)
                or 1 not in self.signs or -1 not in self.signs):
            raise ValueError("profile needs bounded input/output roles")
        if (self.key.message_width != self.p5.k
                or self.key.randomness_width != self.p5.m
                or self.key.params.n != self.p5.d
                or len(self.signs) != self.p5.account_count
                or sum(abs(s) for s in self.signs) != self.p5.omega_l1
                or not 1 <= self.p5.k <= 64
                or not 1 <= self.key.randomness_width <= 64
                or not 1 <= self.key.ring_rows <= 64):
            raise ValueError("profile key, shape and conservation parameters disagree")
        bounds = (self.p1.g_bound, self.p1.zg_bound, self.p1.zb_bound,
                  self.p5.f_bound, self.p5.z_bound)
        if any(not Decimal(bound).is_finite() for bound in bounds):
            raise ValueError("profile bounds must be finite")
        self.key.encode()  # bounded, canonical parameter encoding

    @property
    def profile_id(self) -> bytes:
        body = json.dumps({"p1": _policy_fields(self.p1), "p5": _policy_fields(self.p5),
                           "signs": self.signs, "proof_only": self.allow_proof_only},
                          sort_keys=True, separators=(",", ":")).encode("ascii")
        return hashlib.sha3_256(b"CHITIN-VERIFIER-PROFILE-V2" + self.key.encode() + body).digest()

    @property
    def input_positions(self):
        return tuple(i for i, sign in enumerate(self.signs) if sign == 1)

    @property
    def output_positions(self):
        return tuple(i for i, sign in enumerate(self.signs) if sign == -1)


def transaction_statement(config: VerifierConfig, envelope: TransactionEnvelope) -> bytes:
    return hashlib.sha3_256(
        b"CHITIN-TRANSACTION-STATEMENT-V2" + config.profile_id
        + envelope.statement(bit_width=config.p5.k, account_count=len(config.signs))
    ).digest()


def note_commitment(config: VerifierConfig, row) -> bytes:
    if len(row) != config.key.ring_rows or any(e.params != config.key.params for e in row):
        raise CodecError("note commitment does not match profile")
    return b"CHITIN-NOTE-COMMITMENT-V2" + config.profile_id + encode_vector(row)


@dataclass(frozen=True)
class PublicTransaction:
    profile_id: bytes
    envelope: TransactionEnvelope
    proof: PublicTransactionProof
    spent_note_ids: tuple[bytes, ...] = ()
    created_notes: tuple[Note, ...] = ()
    signatures: tuple[bytes, ...] = ()
    proof_only: bool = False

    def encode(self, config: VerifierConfig) -> bytes:
        return encode_transaction(self, config)

    def authorization_payload(self, config: VerifierConfig) -> bytes:
        # This covers every public proof byte, every note and the chain context.
        return b"CHITIN-TRANSACTION-AUTH-V2" + encode_transaction(self, config, unsigned=True)


def _vector(elements, count, config):
    if (type(elements) is not tuple or len(elements) != count
            or any(e.params != config.key.params for e in elements)):
        raise CodecError("proof vector does not match pinned shape")
    return encode_vector(elements)


def _read_vector(reader, count, config):
    if reader.uint(4) != count:
        raise CodecError("proof vector does not match pinned shape")
    needed = count * config.key.params.n * ((config.key.params.q.bit_length() + 7) // 8)
    if needed > len(reader.data) - reader.pos:
        raise CodecError("truncated proof vector")
    return tuple(decode_element(reader, config.key.params) for _ in range(count))


def encode_transaction(tx: PublicTransaction, config: VerifierConfig, *, unsigned=False) -> bytes:
    if type(tx) is not PublicTransaction or type(tx.proof) is not PublicTransactionProof:
        raise CodecError("only public transaction/proof types may be encoded")
    proof = tx.proof
    count, rows, width = len(config.signs), config.key.ring_rows, config.key.randomness_width
    if (tx.profile_id != config.profile_id or proof.bit_width != config.p5.k
            or proof.signs != config.signs or len(proof.bit_commitments) != count
            or len(proof.binary_proofs) != count or type(tx.proof_only) is not bool):
        raise CodecError("transaction does not match pinned verifier profile")
    if tx.proof_only:
        if not config.allow_proof_only or tx.spent_note_ids or tx.created_notes or tx.signatures:
            raise CodecError("proof-only mode is disabled or contains note transfers")
    elif (len(tx.spent_note_ids) != len(config.input_positions)
          or len(tx.created_notes) != len(config.output_positions)
          or (not unsigned and len(tx.signatures) != len(tx.spent_note_ids))):
        raise CodecError("note roles/counts differ from proof roles")
    out = bytearray(MAGIC + tx.profile_id + tx.envelope.encode())
    out += bytes((int(tx.proof_only),)) + _put_uint(proof.bit_width, 2) + _put_uint(count, 2)
    out += bytes(1 if s == 1 else 0 for s in proof.signs)
    for row in proof.bit_commitments:
        out += _vector(row, rows, config)
    for binary in proof.binary_proofs:
        if type(binary) is not RingProtocol1Proof:
            raise CodecError("private prover result is not a public binary proof")
        for vector in (binary.commitment_e, binary.commitment_f, binary.commitment_g):
            out += _vector(vector, rows, config)
        if len(binary.responses_g) != 1:
            raise CodecError("one binary proof required per amount")
        out += _vector(binary.responses_g[0], proof.bit_width, config)
        out += _vector(binary.response_zg, width, config)
        out += _vector(binary.response_zb, width, config)
    if type(proof.conservation) is not Protocol5Proof:
        raise CodecError("private prover result is not a public conservation proof")
    out += _vector(proof.conservation.commitment_d, rows, config)
    out += _vector(proof.conservation.response_tail, proof.bit_width - 1, config)
    out += _vector(proof.conservation.response_z, width, config)
    out += _put_uint(len(tx.spent_note_ids), 2)
    for note_id in tx.spent_note_ids:
        if type(note_id) is not bytes or len(note_id) != 32:
            raise CodecError("input note ID must be 32 bytes")
        out += note_id
    out += _put_uint(len(tx.created_notes), 2)
    for index, note in enumerate(tx.created_notes):
        if (note.created_by != transaction_statement(config, tx.envelope)
                or note.index != index or len(note.owner) != PUBLIC_KEY_SIZE):
            raise CodecError("output note creation context/index is not canonical")
        out += _put_uint(len(note.commitment), 4) + note.commitment + note.owner
        out += note.created_by + _put_uint(note.index, 4)
    signatures = () if unsigned else tx.signatures
    out += _put_uint(len(signatures), 2)
    for signature in signatures:
        if type(signature) is not bytes or len(signature) != SIGNATURE_SIZE:
            raise CodecError("invalid signature encoding length")
        out += signature
    if len(out) > MAX_TRANSACTION_BYTES:
        raise CodecError("transaction exceeds byte limit")
    return bytes(out)


def decode_transaction(payload: bytes, config: VerifierConfig) -> PublicTransaction:
    if type(payload) is not bytes or len(payload) > MAX_TRANSACTION_BYTES:
        raise CodecError("transaction must be bounded bytes")
    reader = _Reader(payload)
    if reader.take(len(MAGIC)) != MAGIC:
        raise CodecError("unsupported transaction format")
    profile = reader.take(32)
    if profile != config.profile_id:
        raise CodecError("unknown verifier profile")
    envelope = TransactionEnvelope.decode(reader)
    mode, bit_width, count = reader.uint(1), reader.uint(2), reader.uint(2)
    if mode not in (0, 1) or bit_width != config.p5.k or count != len(config.signs):
        raise CodecError("transaction shape does not match profile")
    encoded_signs = reader.take(count)
    if any(s not in (0, 1) for s in encoded_signs):
        raise CodecError("noncanonical role")
    signs = tuple(1 if s else -1 for s in encoded_signs)
    if signs != config.signs:
        raise CodecError("transaction roles differ from profile")
    rows, width = config.key.ring_rows, config.key.randomness_width
    commitments = tuple(_read_vector(reader, rows, config) for _ in range(count))
    binaries = tuple(RingProtocol1Proof(
        _read_vector(reader, rows, config), _read_vector(reader, rows, config),
        _read_vector(reader, rows, config), (_read_vector(reader, bit_width, config),),
        _read_vector(reader, width, config), _read_vector(reader, width, config),
    ) for _ in range(count))
    conservation = Protocol5Proof(_read_vector(reader, rows, config),
        _read_vector(reader, bit_width - 1, config), _read_vector(reader, width, config))
    inputs = reader.uint(2)
    if inputs != (0 if mode else len(config.input_positions)):
        raise CodecError("input count differs from profile")
    spent = tuple(reader.take(32) for _ in range(inputs))
    outputs = reader.uint(2)
    if outputs != (0 if mode else len(config.output_positions)):
        raise CodecError("output count differs from profile")
    notes = []
    commitment_size = len(note_commitment(config, commitments[0]))
    for _ in range(outputs):
        if reader.uint(4) != commitment_size:
            raise CodecError("output commitment size differs from profile")
        notes.append(Note(reader.take(commitment_size), reader.take(PUBLIC_KEY_SIZE),
                          reader.take(32), reader.uint(4)))
    signature_count = reader.uint(2)
    if signature_count != inputs:
        raise CodecError("signature count differs from input count")
    signatures = tuple(reader.take(SIGNATURE_SIZE) for _ in range(signature_count))
    reader.finish()
    tx = PublicTransaction(profile, envelope, PublicTransactionProof(
        bit_width, commitments, binaries, conservation, signs), spent, tuple(notes), signatures, bool(mode))
    if encode_transaction(tx, config) != payload:
        raise CodecError("noncanonical transaction encoding")
    return tx
