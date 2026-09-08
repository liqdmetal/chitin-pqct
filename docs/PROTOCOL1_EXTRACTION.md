# Protocol 1 extraction laboratory

## Implemented

The lab now has an executable, bounded extraction tree for the interactive
Protocol 1 equations in Gao et al. 2021/1674.

### Second layer

`pqct.protocol1_family.build_second_layer_family` builds three accepting
transcripts with fixed `zeta` and shared `E/F/G`, but distinct `x` challenges.
It then checks:

- common commitments;
- explicit verifier equations;
- response norm bounds;
- integer negacyclic identities before reduction modulo `q`;
- coefficient wraparound against the centered `q/2` boundary.

`extract_checked_second_layer` applies the three-transcript extraction and
verifies relaxed openings for:

- `y sum_i zeta^i B_i`;
- `y G`;
- `y E`;
- `y F`.

### First layer, S=2

`extract_first_layer_s2` implements Appendix B Equations (34)-(37). Given two
second-layer relaxed openings with distinct aggregation challenges `zeta0` and
`zeta1`, it computes `y_zeta = zeta0-zeta1` and returns relaxed openings for
`y_zeta*y*B0` and `y_zeta*y*B1` without inverting a ring element.

`build_two_layer_extraction_tree` connects both layers and verifies the final
relaxed openings for the first two public commitments.

## Important boundary

The family builder is an interactive rewindability experiment. It accepts
caller-supplied challenges and therefore does not claim that Fiat--Shamir
transcripts can be rewound. It also does not prove HMC binding, the complete
(S,3)-special-soundness reduction, SHVZK, exact statistical distance, or
Module-SIS/Module-LWE security. All dimensions and arithmetic are toy/reference
only.
