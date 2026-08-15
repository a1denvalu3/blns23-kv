cmake_minimum_required(VERSION 3.22)
project(blns23kv LANGUAGES C CXX)

option(BLNSKV_WITH_LABRADOR "Build with the LaBRADOR NIZK backend (requires AVX-512)" OFF)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra)

# vendored, header-only
add_library(nfl INTERFACE)
target_include_directories(nfl INTERFACE third_party/nfl-include)

add_library(blnskv
  src/drbg.cpp
  third_party/fips202/fips202.c
)
target_include_directories(blnskv PUBLIC src third_party/fips202)
target_link_libraries(blnskv PUBLIC nfl)

if(BLNSKV_WITH_LABRADOR)
  # LaBRADOR's NTT/poly code uses AVX-512 intrinsics unconditionally; its
  # repo ships a plain Makefile with -march=native, so we pin an explicit
  # Ice Lake-class feature set instead. This compiles on any x86-64
  # toolchain; RUNNING the result still needs AVX-512 hardware or an
  # emulator (Intel SDE / qemu-x86_64) -- see docs/roadmap.md M1.
  set(LABRADOR_AVX512_FLAGS
      -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512cd
      -mavx512vbmi -mavx512vbmi2 -mavx512ifma -mavx512vpopcntdq -mavx512bitalg
      -mavx512vnni -mvaes -maes)
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-mavx512f" HAVE_AVX512)
  if(NOT HAVE_AVX512)
    message(FATAL_ERROR "BLNSKV_WITH_LABRADOR requires an x86-64 toolchain with AVX-512 codegen support")
  endif()
  file(GLOB LABRADOR_SOURCES third_party/labrador/*.c)
  list(FILTER LABRADOR_SOURCES EXCLUDE REGEX "(test_|bench_|timing|cpucycles|aggsig|falcon_poly|labrados_python)")
  add_library(labrador STATIC ${LABRADOR_SOURCES})
  target_compile_options(labrador PRIVATE ${LABRADOR_AVX512_FLAGS} -O3 -fwrapv -ffast-math)
  set_target_properties(labrador PROPERTIES C_STANDARD 23)
  target_link_libraries(blnskv PUBLIC labrador)
  target_compile_definitions(blnskv PUBLIC BLNSKV_WITH_LABRADOR=1)
  # TODO: labrador-backed NIZK adapter (src/nizk_labrador.cpp)

  # Vendored LaBRADOR self-tests. Running them needs an AVX-512 runtime; on
  # hosts without AVX-512, launch them under Intel SDE (expected unpacked in
  # tools/sde-external-*, see docs/roadmap.md M1). Without SDE the tests are
  # built but not registered with ctest.
  add_executable(labrador-test-jlproj
    third_party/labrador/test_jlproj.c
    third_party/labrador/cpucycles.c
    tests/labrador_warmup_stub.c)
  target_link_libraries(labrador-test-jlproj PRIVATE labrador m)

  # One small prove/reduce round with exit-code reporting: the main ctest
  # entry point. Fast enough to run under SDE.
  add_executable(labrador-test-smoke
    tests/labrador_round_smoke.c
    third_party/labrador/test_proofsystem_setup.c
    third_party/labrador/test_constraints_setup.c)
  target_link_libraries(labrador-test-smoke PRIVATE labrador m)

  # Full vendored sweep (72 instances) -- built for manual runs on AVX-512
  # hardware, too slow under emulation to register with ctest.
  add_executable(labrador-test-round
    third_party/labrador/test_labrador.c
    third_party/labrador/test_proofsystem_setup.c
    third_party/labrador/test_constraints_setup.c
    third_party/labrador/cpucycles.c
    tests/labrador_warmup_stub.c)
  target_link_libraries(labrador-test-round PRIVATE labrador m)

  foreach(t labrador-test-jlproj labrador-test-smoke labrador-test-round)
    target_compile_options(${t} PRIVATE ${LABRADOR_AVX512_FLAGS})
    target_include_directories(${t} PRIVATE third_party/labrador)
    set_target_properties(${t} PROPERTIES C_STANDARD 23)
  endforeach()

  file(GLOB SDE64 "${CMAKE_SOURCE_DIR}/tools/sde-external-*/sde64")
  if(SDE64)
    list(GET SDE64 0 SDE64)
    add_test(NAME labrador-jlproj
             COMMAND ${SDE64} -future -- $<TARGET_FILE:labrador-test-jlproj>)
    add_test(NAME labrador-smoke
             COMMAND ${SDE64} -future -- $<TARGET_FILE:labrador-test-smoke>)
    message(STATUS "LaBRADOR tests registered via Intel SDE: ${SDE64}")
  else()
    message(STATUS "Intel SDE not found in tools/ -- labrador-test-* binaries "
                   "are built but not registered with ctest (need AVX-512 or SDE)")
  endif()
endif()

add_executable(blnskv-demo examples/demo.cpp)
target_link_libraries(blnskv-demo PRIVATE blnskv)

find_package(Threads REQUIRED)
add_executable(blnskv-bench bench/bench_main.cpp)
target_link_libraries(blnskv-bench PRIVATE blnskv Threads::Threads)

enable_testing()
add_subdirectory(tests)
