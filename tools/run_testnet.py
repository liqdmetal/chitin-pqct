"""Run the valueless, in-memory Chitin transaction experiment.

No networking, mining or production cryptography. Complete V2 public proof
bytes now enter the node; private witnesses never cross that boundary.
"""

from __future__ import annotations

import secrets
import sys
import time
from dataclasses import replace
from decimal import Decimal
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pqct.authorization import Note, generate_keypair, sign_authorization
from pqct.balance_composition import SignedAmount
from pqct.binary_protocol1_ring import RingProtocol1Parameters
from pqct.experimental_node import ExperimentalNode
from pqct.matrix_generation import generate_hmc_key
from pqct.protocol1_sampling import (Protocol1DistributionParameters, XofByteSource,
                                     sample_box_ring_vector)
from pqct.protocol5 import protocol5_params_for_lambdas
from pqct.public_transaction import (PublicTransaction, VerifierConfig, note_commitment,
                                     transaction_statement)
from pqct.relations import decompose_unsigned
from pqct.ring_commitment import RingElement, ToyParameters
from pqct.transaction_proof import prove_transaction
from pqct.tx_envelope import TransactionEnvelope


def demo_config():
    params = ToyParameters(n=8, q=12289, k=1)
    key = generate_hmc_key(b"chitin-v2-demo-key", params, 1, 5)
    p1 = RingProtocol1Parameters.from_paper_bounds(
        challenge_weight=4, challenge_coefficient_bound=2,
        B=1, p=2, k=5, m=1, d=8, phi1=2, phi2=8)
    p5 = protocol5_params_for_lambdas((1, -1), p=2, w=4, k=5, B=1, m=1, d=8,
                                     phi2=Decimal(4), phi3=Decimal(4))
    return VerifierConfig(key, p1, p5, (1, -1))


def opening(config):
    return sample_box_ring_vector(XofByteSource(secrets.token_bytes(32)),
                                  config.key.params, config.p5.m, config.p5.B)


def commitment_for(config, amount, randomness):
    params = config.key.params
    bits = tuple(RingElement.from_coeffs((b,) + (0,) * (params.n - 1), params)
                 for b in decompose_unsigned(amount, config.p5.k))
    return config.key.commit(bits, randomness)


def sign(tx, signer, config):
    message = tx.authorization_payload(config)
    return replace(tx, signatures=tuple(sign_authorization(signer.secret, message)
                                        for _ in tx.spent_note_ids))


def transfer(node, source, source_opening, signer, recipient, nonce):
    config = node.verifier
    envelope = TransactionEnvelope(node.chain_id, node.state_root, nonce, node.height + 10)
    statement = transaction_statement(config, envelope)
    output_opening = opening(config)
    result = prove_transaction(
        seed=secrets.token_bytes(32), statement=statement, key=config.key,
        amounts=(SignedAmount(16, 1), SignedAmount(16, -1)), bit_width=5,
        distribution=Protocol1DistributionParameters(B=1, gaussian_tail=8, phi1=1, phi2=2),
        p1_params=config.p1, p5=config.p5, phi2=Decimal(4), phi3=Decimal(4),
        openings_override=(source_opening, output_opening))
    public = result.public_proof()
    output = Note(note_commitment(config, public.bit_commitments[1]),
                  recipient.public, statement, 0)
    tx = PublicTransaction(config.profile_id, envelope, public, (source.note_id,), (output,))
    return sign(tx, signer, config), output_opening


def main():
    print("CHITIN V2: in-memory, valueless, unproven research cryptography")
    config = demo_config()
    alice, bob = generate_keypair(), generate_keypair()
    initial_opening = opening(config)
    initial = Note(note_commitment(config, commitment_for(config, 16, initial_opening)),
                   alice.public, b"genesis", 0)
    node = ExperimentalNode(b"chitin-experiment-v2", config, (initial,))
    started = time.perf_counter()
    tx, bob_opening = transfer(node, initial, initial_opening, alice, bob, 1)
    payload = tx.encode(config)
    print(f"Complete public transaction: {len(payload)} bytes, prove/sign {time.perf_counter()-started:.3f}s")
    failures = 0

    def reject(label, hostile):
        nonlocal failures
        accepted, reason = node.submit(hostile)
        print(f"{label}: {'UNEXPECTED ACCEPTANCE' if accepted else 'rejected'} ({reason})")
        failures += int(accepted)

    reject("wrong owner", sign(tx, bob, config).encode(config))
    unknown = replace(tx, spent_note_ids=(b"x" * 32,))
    reject("fabricated input", sign(unknown, alice, config).encode(config))
    swapped = replace(tx, created_notes=(replace(tx.created_notes[0], commitment=initial.commitment),))
    reject("signed unrelated output commitment", sign(swapped, alice, config).encode(config))
    binary = tx.proof.binary_proofs[0]
    response = binary.responses_g[0]
    one = RingElement.from_coeffs((1,) + (0,) * 7, config.key.params)
    binary = replace(binary, responses_g=((response[0].add(one),) + response[1:],))
    changed = replace(tx, proof=replace(tx.proof, binary_proofs=(binary,) + tx.proof.binary_proofs[1:]))
    reject("signed corrupted proof", sign(changed, alice, config).encode(config))
    reject("truncated encoding", payload[:-1])

    before = dict(node.registry.unspent)
    valid, reason = node.validate(payload)
    assert valid, reason
    assert node.mempool == [] and node.registry.unspent == before
    accepted, reason = node.submit(payload)
    assert accepted, reason
    assert node.registry.unspent == before and not node.guard.seen
    node.seal_block()
    reject("verbatim replay", payload)
    double, _ = transfer(node, initial, initial_opening, alice, bob, 2)
    reject("double spend under fresh nonce", double.encode(config))

    # Recipient spends the actual output using its private opening. No shared
    # global nonce namespace: nonce 1 is valid again for a different spend.
    next_tx, _ = transfer(node, tx.created_notes[0], bob_opening, bob, alice, 1)
    accepted, reason = node.submit(next_tx.encode(config))
    assert accepted, reason
    node.seal_block()
    for name, value in node.summary().items():
        print(f"{name}: {value}")
    print(f"attacks that succeeded: {failures}; two authorized transitions committed.")
    print("Graph privacy, recipient encryption, security proofs and reviewed parameters remain open.")
    return int(failures != 0)


if __name__ == "__main__":
    raise SystemExit(main())
