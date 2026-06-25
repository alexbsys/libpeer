set(TEST_COMMON test_env.cpp test_env.h)
set(LIBPEER_SRC "${CMAKE_SOURCE_DIR}/../../src")

function(add_ice_test name)
  add_executable(${name} ${ARGN} ${TEST_COMMON})
  target_compile_definitions(${name} PRIVATE LOG_LEVEL=LEVEL_DEBUG)
  target_include_directories(${name} PRIVATE ${LIBPEER_SRC})
  target_link_directories(${name} PRIVATE ${LIBPEER_DIST_LIB})
  target_link_libraries(${name} PRIVATE peer GTest::gtest_main pthread)
  set_target_properties(${name} PROPERTIES
    BUILD_RPATH "${LIBPEER_DIST_LIB}"
    INSTALL_RPATH "${LIBPEER_DIST_LIB}")
  add_dependencies(${name} peer cjson mbedtls usrsctp srtp2)
  gtest_discover_tests(${name} PROPERTIES TIMEOUT 300)
endfunction()

add_ice_test(test_turn_tcp_allocate turn_tcp_allocate.cpp)
add_ice_test(test_ice_relay_pair ice_relay_pair.cpp)
