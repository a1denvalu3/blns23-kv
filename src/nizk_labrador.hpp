#pragma once
//
// LaBRADOR-backed NIZK adapter (M1, docs/labrador-primer.md).
//
// pi2 (response proof) is proven for real with the vendored LaBRADOR proof
// system (third_party/labrador): the relation
//
//     h = s^T*c + e3,  t = s^T*B + e1^T        (mod p0)
//
// is lifted over the integers with quotient polynomials k_h, k_t (i.e.
// s^T*c + e3 - h = p0*k_h over Z[X]/(X^D+1)) and then proven mod LaBRADOR's
// proof modulus PS_Q ~ 2^38. SOUNDNESS OF THIS ENCODING IS NOT CLAIMED: it is
// the documented open M1 co-design item (see docs/roadmap.md). The adapter
// exists to exercise the real proof system on the real relation shape.
//
// pi1 (commit proof) stays MOCK until M3 (it needs the ZK-friendly hash);
// the commit-side methods simply delegate to an internal MockNizk.
//
// Restrictions: only ToyParams-shaped rings (P::D == 256 matches LaBRADOR's
// N; P::NMOD == 1 so Q is the single prime p0). NOT thread-safe: LaBRADOR
// keeps a global commitment key (comkey). Requires AVX-512 at runtime (run
// under Intel SDE on hosts without it).

#include "nizk.hpp"
#include "params.hpp"

namespace blnskv {

template <typename P> class LabradorNizk final : public Nizk<P> {
public:
  static_assert(P::D == 256 && P::NMOD == 1,
                "LabradorNizk requires D == 256 (LaBRADOR N) and NMOD == 1");

  // pi1: mock until M3 (see file comment).
  Proof prove_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                     const CommitWitness<P> &wit) override {
    return mock_.prove_commit(R, stmt, wit);
  }
  bool verify_commit(const Ring<P> &R, const CommitStatement<P> &stmt,
                     const Proof &proof) override {
    return mock_.verify_commit(R, stmt, proof);
  }

  // pi2: LaBRADOR. Defined in nizk_labrador.cpp.
  Proof prove_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                       const ResponseWitness<P> &wit) override;
  bool verify_response(const Ring<P> &R, const ResponseStatement<P> &stmt,
                       const Proof &proof) override;

private:
  MockNizk<P> mock_;
};

} // namespace blnskv
