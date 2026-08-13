// Micro-benchmarks for blns23-kv. The paper has essentially no public
// implementation, so even toy-parameter timings are useful reference data.
//
// Prints both human-readable text and JSON (to bench/results.jsonl when
// --json <path> is given).

#include "blnskv.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <pthread.h>
#include <string>

using namespace blnskv;
using Clock = std::chrono::steady_clock;

// Large parameter sets allocate big polynomial temporaries on the stack
// (a D=4096, 3-moduli poly is ~100 KB). Run them under a pthread with a
// large stack instead of relying on ulimit.
static void run_with_big_stack(void (*fn)(void *), void *arg) {
  pthread_attr_t attr;
  pthread_attr_init(&attr);
  pthread_attr_setstacksize(&attr, size_t{1} << 30); // 1 GiB
  pthread_t th;
  if (pthread_create(&th, &attr, reinterpret_cast<void *(*)(void *)>(fn), arg) != 0)
    throw std::runtime_error("pthread_create failed");
  pthread_join(th, nullptr);
  pthread_attr_destroy(&attr);
}

static double ms_since(Clock::time_point t0) {
  return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

template <typename F> static double bench(F &&f, int iters) {
  f(); // warmup
  auto t0 = Clock::now();
  for (int i = 0; i < iters; i++)
    f();
  return ms_since(t0) / iters;
}

template <typename P> static void run_params(const char *name, int iters) {
  using Sch = Scheme<P>;
  using R = Ring<P>;
  Sch scheme;
  MockNizk<P> nizk;
  R ring;

  std::printf("\n== %s (D=%zu K=%zu NMOD=%zu, log2 Q ~ %zu) ==\n", name, P::D,
              P::K, P::NMOD, static_cast<size_t>(msb(ring.Q()) + 1));

  // keygen / protocol stages
  typename Sch::SigningKey sk;
  double t_keygen = bench([&] { sk = scheme.keygen(); }, std::max(1, iters / 4));

  std::vector<uint8_t> msg = {'b', 'e', 'n', 'c', 'h'};
  typename Sch::UserState st;
  typename Sch::Commitment com;
  double t_commit = bench([&] { auto r = scheme.commit(sk.pk, msg, nizk); st = r.first; com = r.second; }, iters);
  typename Sch::Response resp;
  double t_respond = bench([&] { resp = scheme.respond(sk, com, nizk); }, iters);
  typename Sch::Signature sig = *scheme.finalize(sk.pk, st, resp, nizk);
  double t_finalize = bench([&] { scheme.finalize(sk.pk, st, resp, nizk); }, iters);
  double t_verify = bench([&] { scheme.verify(sk, msg, sig); }, iters);

  // primitive ops
  auto drbg1 = Drbg::from_u64(1);
  auto drbg2 = Drbg::from_u64(2);
  auto drbg3 = Drbg::from_u64(3);
  typename R::Vec va = sample_ternary_vec<P>(ring, drbg1);
  typename R::Poly pa = sample_uniform<P>(ring, drbg2);
  typename R::Poly pb = sample_uniform<P>(ring, drbg3);
  double t_mul = bench([&] { ring.mul(pa, pb); }, iters * 4);
  double t_matvec = bench([&] { ring.matvec(sk.pk.B, va); }, iters);
  double t_inner = bench([&] { ring.inner(sk.pk.t, va); }, iters * 4);
  double t_round = bench([&] { ring.round_poly(pa); }, iters * 4);
  double t_ser = bench([&] { ring.serialize(pa); }, iters * 4);

  auto row = [](const char *op, double ms) {
    std::printf("  %-12s %9.3f ms\n", op, ms);
  };
  row("keygen", t_keygen);
  row("commit", t_commit);
  row("respond", t_respond);
  row("finalize", t_finalize);
  row("verify", t_verify);
  row("poly_mul", t_mul);
  row("matvec", t_matvec);
  row("inner", t_inner);
  row("round", t_round);
  row("serialize", t_ser);
}

int main(int argc, char **argv) {
  int iters = 20;
  for (int i = 1; i < argc; i++)
    if (!std::strcmp(argv[i], "--iters") && i + 1 < argc)
      iters = std::stoi(argv[++i]);

  run_params<ToyParams>("toy", iters);

  struct Ctx {
    int iters;
  } ctx{std::max(1, iters / 4)};
  run_with_big_stack(
      [](void *p) {
        auto *c = static_cast<Ctx *>(p);
        run_params<PaperShapeParams>("paper-shape", c->iters);
      },
      &ctx);
  return 0;
}
