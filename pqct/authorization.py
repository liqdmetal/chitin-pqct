"""Ownership and authorization: ML-DSA-65 keys, notes, and a spend registry.

WHY THIS MODULE IS THE REAL TESTNET BLOCKER
-------------------------------------------
Before this existed, the stack could prove:
  * committed amounts are bits           (Protocol 1)
  * amounts conserve over the integers   (Protocol 5)
and it bound proofs to a chain/state/nonce (tx_envelope). All true, and all
insufficient: NOTHING linked a transaction's inputs to previously created
outputs, and NOTHING checked that the spender owned them. A demonstration:

    inputs I never owned : 1,000,000
    output to me         : 1,000,000
    conserved?           : True

Conservation passes because 1,000,000 - 1,000,000 = 0. Perfect proofs of a
worthless statement. Value needs three more things, and this module supplies
them:

  1. OWNERSHIP     -- an output is bound to a public key; spending requires a
                      signature under the matching secret key.
  2. PROVENANCE    -- every input must name a note that a previous
                      transaction created (or genesis), so value cannot be
                      conjured.
  3. NO DOUBLE-SPEND -- each note may be consumed exactly once.

CRYPTO CHOICE
-------------
ML-DSA-65 (NIST FIPS 204, security category 3) via `pqcrypto`, i.e. a real
standardised implementation rather than something hand-rolled here. Keeping
the signature post-quantum matters: a classical Ed25519 authorization layer
on top of lattice commitments would leave the whole scheme breakable by a
quantum adversary through its weakest link.

API FOOTGUN, HANDLED: pqcrypto's `verify` returns None on success and RAISES
on failure. `if verify(...)` is therefore FALSY for a valid signature -- the
exact inversion that silently accepts forgeries. `verify_signature` below
normalises this to a real bool.

WHAT THIS DOES NOT DO
---------------------
It does not hide WHICH notes are spent (no ring signature / anonymity set),
so the transaction graph is public even though amounts are committed. It
does not encrypt amounts to the recipient (no note ciphertext), so an
out-of-band channel is still needed to tell a receiver what they got. Both
are named in docs/TESTNET_SCOPE.md. Authorization and provenance are
necessary for value; they are not sufficient for privacy.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from pqcrypto import ml_dsa_65

NOTE_DOMAIN = b"CHITIN-NOTE-V1"
AUTH_DOMAIN = b"CHITIN-AUTH-V1"

PUBLIC_KEY_SIZE = ml_dsa_65.PUBLIC_KEY_SIZE
SECRET_KEY_SIZE = ml_dsa_65.SECRET_KEY_SIZE
SIGNATURE_SIZE = ml_dsa_65.SIGNATURE_SIZE
ALGORITHM = "ML-DSA-65"


class AuthorizationError(ValueError):
    """Raised on ownership, provenance, or double-spend violations."""


@dataclass(frozen=True)
class Keypair:
    """An ML-DSA-65 keypair. `secret` never leaves the owner."""

    public: bytes
    secret: bytes = field(repr=False)

    def __post_init__(self) -> None:
        if len(self.public) != PUBLIC_KEY_SIZE:
            raise AuthorizationError(
                f"public key must be {PUBLIC_KEY_SIZE} bytes, got {len(self.public)}"
            )
        if len(self.secret) != SECRET_KEY_SIZE:
            raise AuthorizationError(
                f"secret key must be {SECRET_KEY_SIZE} bytes, got {len(self.secret)}"
            )

    @property
    def address(self) -> bytes:
        """Short, collision-resistant handle for the public key."""
        return address_for(self.public)


def generate_keypair() -> Keypair:
    public, secret = ml_dsa_65.keygen()
    return Keypair(public=bytes(public), secret=bytes(secret))


def address_for(public_key: bytes) -> bytes:
    hasher = hashlib.shake_256()
    hasher.update(b"CHITIN-ADDR-V1")
    hasher.update(public_key)
    return hasher.digest(20)


def sign_authorization(secret_key: bytes, message: bytes) -> bytes:
    if len(secret_key) != SECRET_KEY_SIZE:
        raise AuthorizationError("malformed secret key")
    return bytes(ml_dsa_65.sign(secret_key, AUTH_DOMAIN + message))


def verify_signature(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is valid. Normalises pqcrypto's raise-on-failure.

    pqcrypto.verify returns None (falsy!) on success and raises on failure.
    Never call it directly in a boolean context.
    """
    if len(public_key) != PUBLIC_KEY_SIZE or len(signature) != SIGNATURE_SIZE:
        return False
    try:
        ml_dsa_65.verify(public_key, AUTH_DOMAIN + message, signature)
        return True
    except Exception:  # noqa: BLE001 - any failure means invalid
        return False


@dataclass(frozen=True)
class Note:
    """An owned output: a committed amount bound to a public key.

    `commitment` is the HMC commitment bytes for the amount (opaque here;
    the lattice layer owns its meaning). `owner` is the ML-DSA public key
    entitled to spend it. The note id is a hash over ALL fields plus the
    creating transaction, so two notes can never collide and a note cannot
    be re-pointed at a different owner or amount without changing its id.
    """

    commitment: bytes
    owner: bytes
    created_by: bytes
    index: int

    def __post_init__(self) -> None:
        if not self.commitment:
            raise AuthorizationError("note commitment must not be empty")
        if len(self.owner) != PUBLIC_KEY_SIZE:
            raise AuthorizationError("note owner must be an ML-DSA-65 public key")
        if type(self.index) is not int or not 0 <= self.index < 2**32:
            raise AuthorizationError("note index must be uint32")

    @property
    def note_id(self) -> bytes:
        hasher = hashlib.shake_256()
        hasher.update(NOTE_DOMAIN)
        for part in (self.commitment, self.owner, self.created_by):
            hasher.update(len(part).to_bytes(4, "big"))
            hasher.update(part)
        hasher.update(self.index.to_bytes(4, "big"))
        return hasher.digest(32)


def authorization_message(
    *, statement: bytes, spent_note_ids, created_note_ids
) -> bytes:
    """The exact bytes each spender signs.

    Binds the Fiat-Shamir statement (which already carries chain/state/nonce)
    together with the FULL input and output note sets. Signing only the
    inputs would let an attacker re-target the outputs of an authorized
    spend; signing only the statement would let them swap which notes are
    consumed. Both sets are length-prefixed so no re-grouping is possible.
    """
    hasher = hashlib.shake_256()
    hasher.update(AUTH_DOMAIN)
    hasher.update(len(statement).to_bytes(4, "big"))
    hasher.update(statement)
    for label, ids in ((b"spend", spent_note_ids), (b"create", created_note_ids)):
        items = tuple(ids)
        hasher.update(label)
        hasher.update(len(items).to_bytes(4, "big"))
        for note_id in items:
            hasher.update(len(note_id).to_bytes(2, "big"))
            hasher.update(note_id)
    return hasher.digest(32)


@dataclass
class NoteRegistry:
    """Tracks which notes exist and which have been spent.

    This is the ledger's memory. Provenance (an input must be a known,
    unspent note) and double-spend prevention both live here, because both
    are statements about HISTORY that no single-transaction proof can make.
    """

    unspent: dict = field(default_factory=dict)
    spent: set = field(default_factory=set)

    def mint_genesis(self, note: Note) -> bytes:
        """Create a note with no predecessor. Genesis only -- this is the one
        place value may enter, and a real network must bound it explicitly."""
        note_id = note.note_id
        if note_id in self.unspent or note_id in self.spent:
            raise AuthorizationError("genesis note already exists")
        self.unspent[note_id] = note
        return note_id

    def create(self, note: Note) -> bytes:
        note_id = note.note_id
        if note_id in self.unspent or note_id in self.spent:
            raise AuthorizationError(f"note {note_id.hex()[:16]} already exists")
        self.unspent[note_id] = note
        return note_id

    def get_unspent(self, note_id: bytes) -> Note:
        note = self.unspent.get(note_id)
        if note is None:
            if note_id in self.spent:
                raise AuthorizationError(
                    f"note {note_id.hex()[:16]} already spent (double-spend)"
                )
            raise AuthorizationError(
                f"note {note_id.hex()[:16]} does not exist (no provenance)"
            )
        return note

    def mark_spent(self, note_id: bytes) -> None:
        note = self.unspent.pop(note_id, None)
        if note is None:
            raise AuthorizationError("cannot spend an unknown or spent note")
        self.spent.add(note_id)

    def authorize_spend(
        self, *, statement: bytes, spent_note_ids, created_notes, signatures
    ) -> tuple[bool, str]:
        """Verify provenance + ownership + freshness WITHOUT mutating state.

        Returns (ok, reason). One signature per spent note, in order, each
        under that note's owner key. Verification is deliberately separate
        from application (`apply_spend`) so a rejected transaction cannot
        leave the registry half-updated.
        """
        spent_ids = tuple(spent_note_ids)
        created = tuple(created_notes)
        sigs = tuple(signatures)

        if not spent_ids:
            return False, "no inputs: value cannot be created outside genesis"
        if len(sigs) != len(spent_ids):
            return False, (
                f"signature count {len(sigs)} != input count {len(spent_ids)}"
            )
        if len(set(spent_ids)) != len(spent_ids):
            return False, "duplicate input note in the same transaction"

        notes = []
        for note_id in spent_ids:
            try:
                notes.append(self.get_unspent(note_id))
            except AuthorizationError as error:
                return False, str(error)

        created_ids = tuple(note.note_id for note in created)
        if len(set(created_ids)) != len(created_ids):
            return False, "duplicate output note in the same transaction"
        for note_id in created_ids:
            if note_id in self.unspent or note_id in self.spent:
                return False, f"output note {note_id.hex()[:16]} already exists"

        message = authorization_message(
            statement=statement,
            spent_note_ids=spent_ids,
            created_note_ids=created_ids,
        )
        for position, (note, signature) in enumerate(zip(notes, sigs)):
            if not verify_signature(note.owner, message, signature):
                return False, (
                    f"input {position} not authorized by its owner "
                    f"({note.note_id.hex()[:16]})"
                )
        return True, "authorized"

    def apply_spend(self, *, spent_note_ids, created_notes) -> None:
        """Atomically consume/create notes; authorization must already pass."""
        spent_ids, created = tuple(spent_note_ids), tuple(created_notes)
        pending = NoteRegistry(dict(self.unspent), set(self.spent))
        for note_id in spent_ids:
            pending.mark_spent(note_id)
        for note in created:
            pending.create(note)
        self.unspent, self.spent = pending.unspent, pending.spent

    def summary(self) -> dict:
        return {
            "unspent_notes": len(self.unspent),
            "spent_notes": len(self.spent),
            "algorithm": ALGORITHM,
        }


__all__ = [
    "ALGORITHM",
    "AUTH_DOMAIN",
    "AuthorizationError",
    "Keypair",
    "NOTE_DOMAIN",
    "Note",
    "NoteRegistry",
    "PUBLIC_KEY_SIZE",
    "SECRET_KEY_SIZE",
    "SIGNATURE_SIZE",
    "address_for",
    "authorization_message",
    "generate_keypair",
    "sign_authorization",
    "verify_signature",
]
