#pragma once
//
// Textbook SHA-256 (FIPS 180-4), vendored so the library gains no system
// crypto dependency: compression function plus one-shot hash over a byte
// buffer. Written directly from the spec; validated against the standard
// known-answer vectors in tests/test_sha256.cpp.
//
// Used by the SHA-256 counter-mode DRBG / XOF (drbg.hpp) that drives the
// cut-and-choose module's sampling hot path (cckvbs.hpp, CCKVBS-*-v1 labels).
// Plain portable C++ -- no SHA-NI intrinsics; the win over SHAKE256 here
// comes from the much cheaper per-block function, not from hardware
// acceleration.

#include <cstddef>
#include <cstdint>

namespace blnskv {

// out[32] = SHA-256(in[0..inlen)).
void sha256(const uint8_t *in, size_t inlen, uint8_t out[32]);

} // namespace blnskv
