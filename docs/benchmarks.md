# Benchmarks

All numbers from `blnskv-bench` (mock NIZK — proof cost NOT included in
commit/respond timings; those stages' timings reflect the arithmetic only).

**Reference machine:** 12-core x86-64 (AVX2, no AVX-512), gcc 13.3, -O3,
single-threaded. Parameters below are functional/research shapes, not
validated secure parameter sets.

## 2026-08-13 — initial numbers (mock proofs)

| stage          | toy (D=256, K=4, log2 Q≈62) | paper-shape (D=4096, K=2, log2 Q≈186) |
|----------------|-----------------------------|----------------------------------------|
| keygen         | 15.4 ms                     | 41.5 ms                                |
| commit         | 3.3 ms                      | 67.6 ms                                |
| respond        | 1.7 ms                      | 57.8 ms                                |
| finalize       | 0.33 ms                     | 9.7 ms                                 |
| **verify**     | **1.8 ms**                  | **17.6 ms**                            |

Primitive ops:

| op             | toy        | paper-shape |
|----------------|------------|-------------|
| poly_mul       | 0.006 ms   | 0.32 ms     |
| matvec         | 0.114 ms   | 1.04 ms     |
| inner          | 0.021 ms   | 0.52 ms     |
| round          | 0.016 ms   | 1.09 ms     |
| serialize      | 0.030 ms   | 5.17 ms     |

Signature size: 64 B (toy), 544 B (paper-shape with ROUND_P=2); paper target
48 B. Commitment c: 8 KB (toy) / 288 KB (paper-shape).

### Notes

- verify is dominated by CRT reconstruction in `round_poly` (boost
  cpp_int per coefficient); a dedicated fixed-width uint192 path should
  cut this substantially. TODO.
- respond/commit at paper-shape are dominated by matvec/inner NTT products.
- serialize at paper-shape is slow (cpp_int per coefficient); only used for
  hashing c into the e3 PRF — a per-slot serialization would suffice there.
  TODO.
