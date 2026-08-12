#pragma once
// Minimal test framework: register tests with TEST(name), run with
// RUN_ALL_TESTS(), check with CHECK(cond).

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace minitest {

struct Registry {
  std::vector<std::pair<std::string, std::function<void()>>> tests;
  static Registry &instance() {
    static Registry r;
    return r;
  }
};

struct Reg {
  Reg(std::string name, std::function<void()> fn) {
    Registry::instance().tests.push_back({std::move(name), std::move(fn)});
  }
};

inline int run_all() {
  int failed = 0;
  for (auto &[name, fn] : Registry::instance().tests) {
    try {
      fn();
      std::printf("PASS  %s\n", name.c_str());
    } catch (const std::exception &e) {
      std::printf("FAIL  %s  (%s)\n", name.c_str(), e.what());
      failed++;
    }
  }
  std::printf("%s: %d failed\n", failed ? "FAILURE" : "OK", failed);
  return failed ? 1 : 0;
}

} // namespace minitest

#define TEST(name)                                                             \
  static void test_##name();                                                   \
  static minitest::Reg reg_##name(#name, test_##name);                         \
  static void test_##name()

#define CHECK(cond)                                                            \
  do {                                                                         \
    if (!(cond))                                                               \
      throw std::runtime_error(std::string("CHECK failed: ") + #cond + " at " + \
                               __FILE__ + ":" + std::to_string(__LINE__));     \
  } while (0)

#define RUN_ALL_TESTS()                                                        \
  int main() { return minitest::run_all(); }
