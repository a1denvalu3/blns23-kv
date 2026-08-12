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
  # repo ships a plain Makefile, so we compile the library sources directly.
  include(CheckCXXCompilerFlag)
  check_cxx_compiler_flag("-mavx512f" HAVE_AVX512)
  if(NOT HAVE_AVX512)
    message(FATAL_ERROR "BLNSKV_WITH_LABRADOR requires an AVX-512-capable CPU/toolchain")
  endif()
  file(GLOB LABRADOR_SOURCES third_party/labrador/*.c)
  list(FILTER LABRADOR_SOURCES EXCLUDE REGEX "(test_|bench_|timing|cpucycles|aggsig|falcon_poly|labrados_python)")
  add_library(labrador STATIC ${LABRADOR_SOURCES})
  target_compile_options(labrador PRIVATE -mavx512f -O3 -fwrapv -ffast-math)
  set_target_properties(labrador PROPERTIES C_STANDARD 23)
  target_link_libraries(blnskv PUBLIC labrador)
  target_compile_definitions(blnskv PUBLIC BLNSKV_WITH_LABRADOR=1)
  # TODO: labrador-backed NIZK adapter (src/nizk_labrador.cpp)
endif()

add_executable(blnskv-demo examples/demo.cpp)
target_link_libraries(blnskv-demo PRIVATE blnskv)

enable_testing()
add_subdirectory(tests)
