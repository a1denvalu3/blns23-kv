add_executable(test_ring test_ring.cpp)
target_link_libraries(test_ring PRIVATE blnskv)
add_test(NAME ring COMMAND test_ring)

add_executable(test_protocol test_protocol.cpp)
target_link_libraries(test_protocol PRIVATE blnskv)
add_test(NAME protocol COMMAND test_protocol)
