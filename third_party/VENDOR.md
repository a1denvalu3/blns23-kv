# Vendored dependencies

## nfl-include/

NFLlib (https://github.com/quarkslab/NFLlib), MIT license (see MIT_LICENSE.txt
in that directory).

Vendor patches (marked `[blns23-kv vendor patch]` in the sources):
- Removed `nfl/gmp.hpp`, `nfl/prng/FastGaussianNoise.hpp` and all
  GMP/MPFR-dependent members of `nfl::poly` (unused by this project; avoids a
  GMP/MPFR dependency).
- Removed gaussian-distribution constructors/setters (unused).
- Added `<cmath>`/`<cstring>` includes to `core.hpp` (previously transitive).
- `nfl::fastrandombytes` is NOT taken from NFLlib's asm Salsa20; we implement
  it in `src/drbg.cpp` over SHAKE256 (seedable, test-friendly).

## fips202/

Public-domain Keccak/SHA3 (SHAKE) implementation; see fips202/VENDOR.md.

## labrador/

Git submodule: https://github.com/lazer-crypto/labrador (LaBRADOR proof
system, C, AVX-512 only). Only built when `BLNSKV_WITH_LABRADOR=ON`.
