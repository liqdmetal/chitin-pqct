# Protocol 1 first-layer extraction laboratory

## Implemented

`pqct.protocol1_extraction.extract_first_layer_s2` implements the S=2 first-layer algebra from Gao et al. 2021/1674 Appendix B, Equations (34)-(37), after the second-layer extractor supplies two relaxed openings:

```text
zeta_0*y*(B_0 + zeta_0*B_1) = Com(M_0; R_0)
zeta_0*y*(B_0 + zeta_1*B_1) = Com(M_1; R_1)
```

The code computes, without inversion:

```text
y_zeta = zeta_0 - zeta_1
y_zeta*y*B_1 = Com(M_0 - M_1; R_0 - R_1)
y_zeta*y*B_0 = Com(zeta_0*M_1 - zeta_1*M_0;
                           zeta_0*R_1 - zeta_1*R_0)
```

`validate_first_layer_relation` checks both supplied branches against the extracted relaxed openings. It tests ring commitment algebra only; it does not establish HMC binding, accepting-transcript provenance, norm bounds, or the paper's soundness reduction.

## Family driver

`pqct.protocol1_family` builds two fixed-`zeta` families of three distinct `x` transcripts, audits response bounds, invokes the second-layer extractor, and invokes the S=2 first-layer extractor. It is an interactive rewind experiment. It does not rewind Fiat–Shamir and does not claim a knowledge extractor for the non-interactive protocol.

## Integer/modular boundary

The family driver reports response norm violations and performs small-modulus wraparound checks. A modular equation that loses the intended integer identity is rejected by the laboratory audit rather than treated as proof success.

## Boundary

The implementation remains a toy/reference experiment. It has no production sampler, no concrete Module-SIS/Module-LWE estimate, no complete HMC binding reduction, no Fiat–Shamir forking proof, and no production security claim.
