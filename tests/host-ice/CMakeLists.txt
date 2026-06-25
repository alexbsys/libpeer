cmake_minimum_required(VERSION 3.16)
project(libpeer_ice LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 17)

option(LIBPEER_ICE_RELAY_ONLY "Default ICE relay-only for libpeer" OFF)

# This test lives inside libpeer at tests/host-ice, so the library root is two
# levels up. Override -DLIBPEER_DIR=... to point at a libpeer checkout elsewhere.
set(LIBPEER_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.."
    CACHE PATH "Path to libpeer")

if(NOT EXISTS "${LIBPEER_DIR}/CMakeLists.txt")
  message(FATAL_ERROR "libpeer not found at ${LIBPEER_DIR}")
endif()

if(LIBPEER_ICE_RELAY_ONLY)
  add_compile_definitions(CONFIG_ICE_RELAY_ONLY=1)
endif()

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()
include(GoogleTest)

add_subdirectory("${LIBPEER_DIR}" libpeer_build EXCLUDE_FROM_ALL)

# libpeer ExternalProject installs static deps here during the build.
set(LIBPEER_DIST_LIB "${CMAKE_BINARY_DIR}/dist/lib" CACHE PATH "libpeer vendored deps")
link_directories(${LIBPEER_DIST_LIB})

add_subdirectory(tests)
