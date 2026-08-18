add_executable(test_ring test_ring.cpp)
target_link_libraries(test_ring PRIVATE blnskv)
add_test(NAME ring COMMAND test_ring)

add_executable(test_poseidon2 test_poseidon2.cpp)
target_link_libraries(test_poseidon2 PRIVATE blnskv)
add_test(NAME poseidon2 COMMAND test_poseidon2)

add_executable(test_protocol test_protocol.cpp)
target_link_libraries(test_protocol PRIVATE blnskv)
add_test(NAME protocol COMMAND test_protocol)

# LaBRADOR-backed pi2 adapter. One real prove (minutes under SDE) plus verify
# replays; registered through the SDE launcher like labrador-smoke (SDE64 is
# detected in the top-level CMakeLists). Skipped entirely when
# BLNSKV_WITH_LABRADOR=OFF.
if(BLNSKV_WITH_LABRADOR)
  add_executable(test_nizk_labrador test_nizk_labrador.cpp)
  target_link_libraries(test_nizk_labrador PRIVATE blnskv)
  if(SDE64)
    add_test(NAME nizk-labrador
             COMMAND ${SDE64} -future -- $<TARGET_FILE:test_nizk_labrador>)
    set_tests_properties(nizk-labrador PROPERTIES TIMEOUT 1800)
  else()
    message(STATUS "Intel SDE not found -- test_nizk_labrador is built but "
                   "not registered with ctest (needs AVX-512 or SDE)")
  endif()
endif()
