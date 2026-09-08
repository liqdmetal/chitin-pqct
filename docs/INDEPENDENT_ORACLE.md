# Independent Oracle Review

The lab now includes `pqct.independent_oracle`, which deliberately avoids the production-shaped ring and HMC helper methods. It independently implements:

- negacyclic polynomial multiplication;
- modular vector addition;
- matrix commitment arithmetic;
- bounded exhaustive exact-relation enumeration.

The test suite compares this oracle against the HMC/ring path on small parameters.

This is an implementation-consistency check only. Agreement between two implementations does not prove the protocol or its security reduction.
