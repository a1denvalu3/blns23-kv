// LaBRADOR round smoke test: one small single prove/reduce round with a
// fixed seed, exit nonzero on any failure. The vendored test_labrador.c
// runs 72 instances (up to len=100000), which is far too slow under the
// Intel SDE emulator used on non-AVX-512 hosts; this keeps the functional
// dev loop fast. Run the full vendored binary (labrador-test-round)
// manually on real AVX-512 hardware for the complete sweep.

#include <stdio.h>
#include <stdint.h>

#include "labrador.h"
#include "test_proofsystem_setup.h"

int main(void) {
  const size_t r = 5, len = 1000, ncnst = 5;
  const uint8_t seed[16] = {0x42};
  size_t nn, iwtbits, owtbits, pibits;
  size_t nonce = 0;
  int ret;
  polxvec sxl, *sxq;
  statement ist, ostp, ostv;
  witness iwt, owt;
  lab_params pp;
  lab_proof pi;

  witness_init(iwt, r, r);
  ps_witness_set(iwt, sxl, &sxq, &nn, &iwtbits, len, seed, &nonce);
  comkey_init(nn);
  statement_init(ist, iwt->r, iwt->r);
  ps_statement_set(ist, iwt, sxl, sxq, nn, ncnst, seed, &nonce);

  if (!verify(ist, iwt)) {
    fprintf(stderr, "smoke: INPUT statement does not verify\n");
    return 1;
  }
  if (lab_params_gen(pp, &pibits, &owtbits, ist, 0, 0, 0, 1, 1, JL_L2_SLACK)) {
    fprintf(stderr, "smoke: lab_params_gen failed\n");
    return 1;
  }

  ldr_prove(pi, ostp, owt, ist, iwt, pp);
  if (!verify(ostp, owt)) {
    fprintf(stderr, "smoke: prover's output statement does not verify\n");
    return 1;
  }

  ret = ldr_reduce(ostv, ist, pi, pp);
  if (ret != 0) {
    fprintf(stderr, "smoke: ldr_reduce failed (ret=%d)\n", ret);
    return 1;
  }
  if (!verify(ostv, owt)) {
    fprintf(stderr, "smoke: verifier's output statement does not verify\n");
    return 1;
  }

  printf("smoke: prove/reduce round OK (proof %zu bits, residual witness %zu bits)\n",
         pibits, owtbits);

  free(sxq);
  polxvec_free(sxl);
  statement_free(ist);
  statement_free(ostp);
  statement_free(ostv);
  witness_free(iwt);
  witness_free(owt);
  lab_params_free(pp);
  lab_proof_free(pi);
  comkey_free();
  return 0;
}
