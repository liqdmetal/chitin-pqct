# Protocol 1 prove/verify benchmark

`tools/bench_protocol1.py` measures wall-clock prove/verify throughput and proof
size for the synthetic sampled Protocol 1 path (`prove_protocol1_ring_sampled` +
`verify_protocol1_ring`), across the two toy candidates in `candidate_set()`.

No PoW, no consensus, no mining. This is a research-only performance
measurement of the equation/rejection/sampling harness, not a security or
production benchmark.

## Usage

```text
python tools/bench_protocol1.py --vectors 2 --bit-width 4 --max-attempts 256 --repeats 5
```

## Measured result (toy-ntt-32, toy-ntt-64; vectors=2, bit_width=4)

```text
toy-ntt-32: accepted attempt 1/256, proof 1102 bytes,
            prove ~2.6/s, verify ~12.9/s (median of 5 repeats)
toy-ntt-64: accepted attempt 1/256, proof 2638 bytes,
            prove ~0.53/s, verify ~1.76/s (median of 5 repeats)
```

## Boundary

These numbers describe the CURRENT unoptimized Python reference implementation
only (Decimal-precision inverse-CDF sampling, no NTT, no constant-time
arithmetic). They say nothing about:

- concrete Module-SIS/Module-LWE security level of the toy dimensions;
- an optimized/production implementation's throughput;
- whether the sampled distributions match Gao's exact D1/D2/D3 law
  (see `docs/SHVZK_COMPARISON.md`);
- soundness, SHVZK, or Fiat-Shamir security.

Still NOT approved: production use, real wallet keys, real balances, DERO
integration, consensus changes, or any "128-bit PQ" claim.
