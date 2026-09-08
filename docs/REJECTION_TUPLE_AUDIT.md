# Protocol 1 rejection-tuple audit

Gao Protocol 1 uses two different rejection tuples:

- Step 8: `(g_i)_i` shifted by `(x b_i)_i`;
- Step 10: `(z_g,(z_b,i)_i)` shifted by `x(r_e,(r_b,i)_i)`.

Step 10 occurs before the public aggregation `z_b = Σ ζ^i z_b,i`. A verifier that receives only aggregate `z_b` cannot reconstruct the exact rejection law. The research harness therefore keeps per-index simulator components or refuses the comparison.

`pqct.protocol1_rejection_audit` independently constructs these tuples, performs ring multiplication for the shift, checks dimensions, and exposes coefficient-level norms. It does not prove the paper's statistical-distance result.
