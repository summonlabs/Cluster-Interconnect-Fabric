# Cluster Interconnect Fabric (CIF)
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
cmake_minimum_required(VERSION 3.25)

project(ClusterInterconnectFabric
  VERSION 1.0.0
  DESCRIPTION "Cluster-wide communication-authority runtime for accelerator clusters"
  HOMEPAGE_URL "https://github.com/summonlabs/Cluster-Interconnect-Fabric"
  LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

option(CIF_BUILD_TESTS "Build the CIF test suite" ON)
option(CIF_BUILD_EXAMPLES "Build the CIF examples" ON)
option(CIF_BUILD_BENCHMARKS "Build the CIF benchmarks" ON)
option(CIF_ENABLE_TEST_HOOKS "Compile test-only crash hooks into cifd" OFF)
option(CIF_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)
option(CIF_ENABLE_SANITIZERS "Enable AddressSanitizer/UBSan where supported" OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE "Release" CACHE STRING "Build type" FORCE)
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

foreach(_cfg IN ITEMS DEBUG RELEASE RELWITHDEBINFO MINSIZEREL)
  set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${_cfg} "${CMAKE_BINARY_DIR}/lib")
  set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${_cfg} "${CMAKE_BINARY_DIR}/lib")
  set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${_cfg} "${CMAKE_BINARY_DIR}/bin")
endforeach()

include(GNUInstallDirs)
include(CTest)
include(CMakePackageConfigHelpers)

find_package(Threads REQUIRED)

# ---------------------------------------------------------------------------
# Warning configuration
# ---------------------------------------------------------------------------
add_library(cif_warnings INTERFACE)
if(MSVC)
  target_compile_options(cif_warnings INTERFACE /W4 /permissive- /utf-8 /Zc:__cplusplus /Zc:preprocessor)
  if(CIF_WARNINGS_AS_ERRORS)
    target_compile_options(cif_warnings INTERFACE /WX)
  endif()
  target_compile_definitions(cif_warnings INTERFACE
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
    WIN32_LEAN_AND_MEAN
    _WIN32_WINNT=0x0A00)
else()
  target_compile_options(cif_warnings INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion
    -Wnon-virtual-dtor -Wold-style-cast -Wcast-align -Wunused
    -Woverloaded-virtual -Wnull-dereference -Wdouble-promotion
    -Wformat=2 -Wimplicit-fallthrough)
  if(CIF_WARNINGS_AS_ERRORS)
    target_compile_options(cif_warnings INTERFACE -Werror)
  endif()
endif()

add_library(cif_sanitizers INTERFACE)
if(CIF_ENABLE_SANITIZERS)
  if(MSVC)
    target_compile_options(cif_sanitizers INTERFACE /fsanitize=address)
  else()
    target_compile_options(cif_sanitizers INTERFACE
      -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
    target_link_options(cif_sanitizers INTERFACE -fsanitize=address,undefined)
  endif()
endif()

# ---------------------------------------------------------------------------
# Core library: pure model + authority engine, no sockets
# ---------------------------------------------------------------------------
set(CIF_CORE_SOURCES
  src/version.cpp
  src/status.cpp
  src/hash.cpp
  src/bytes.cpp
  src/text.cpp
  src/identity.cpp
  src/model.cpp
  src/contract.cpp
  src/request.cpp
  src/grant.cpp
  src/rng.cpp
  src/journal.cpp
  src/authority.cpp
  src/render.cpp
  src/platform.cpp)

add_library(cif_core ${CIF_CORE_SOURCES})
add_library(cif::core ALIAS cif_core)
set_target_properties(cif_core PROPERTIES EXPORT_NAME core)
target_include_directories(cif_core
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
# Build-only dependencies are wrapped in $<BUILD_INTERFACE:...> so that an
# installed package never references targets the consumer does not have.
target_link_libraries(cif_core PRIVATE $<BUILD_INTERFACE:cif_warnings> $<BUILD_INTERFACE:cif_sanitizers>)
target_compile_definitions(cif_core PRIVATE CIF_BUILDING_LIBRARY)
target_compile_features(cif_core PUBLIC cxx_std_20)

# An instrumented static library must be linked into an instrumented program.
# Carrying the sanitizer flags as INTERFACE requirements keeps the installed
# package self-describing: a consumer of an ASan build gets ASan automatically
# instead of failing to link.
if(CIF_ENABLE_SANITIZERS)
  if(MSVC)
    target_compile_options(cif_core INTERFACE /fsanitize=address)
  else()
    target_compile_options(cif_core INTERFACE -fsanitize=address,undefined -fno-omit-frame-pointer)
    target_link_options(cif_core INTERFACE -fsanitize=address,undefined)
  endif()
endif()

# ---------------------------------------------------------------------------
# Net library: framed transport, daemon runtime, client, process control
# ---------------------------------------------------------------------------
set(CIF_NET_SOURCES
  src/wire.cpp
  src/runtime.cpp
  src/server.cpp
  src/client.cpp
  src/process.cpp
  src/platform_sockets.cpp)

add_library(cif_net ${CIF_NET_SOURCES})
add_library(cif::net ALIAS cif_net)
set_target_properties(cif_net PROPERTIES EXPORT_NAME net)
target_include_directories(cif_net
  PUBLIC
    "$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>"
    "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
  PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/src")
target_link_libraries(cif_net PUBLIC cif_core PRIVATE $<BUILD_INTERFACE:cif_warnings> $<BUILD_INTERFACE:cif_sanitizers>)
target_compile_features(cif_net PUBLIC cxx_std_20)
if(WIN32)
  target_link_libraries(cif_net PRIVATE ws2_32)
endif()

add_library(cif_cif INTERFACE)
add_library(cif::cif ALIAS cif_cif)
set_target_properties(cif_cif PROPERTIES EXPORT_NAME cif)
target_link_libraries(cif_cif INTERFACE cif_core cif_net)

# ---------------------------------------------------------------------------
# Applications
# ---------------------------------------------------------------------------
add_executable(cifd apps/cifd_main.cpp)
target_link_libraries(cifd PRIVATE cif_net $<BUILD_INTERFACE:cif_warnings> $<BUILD_INTERFACE:cif_sanitizers>)
if(CIF_ENABLE_TEST_HOOKS)
  target_compile_definitions(cifd PRIVATE CIF_ENABLE_TEST_HOOKS=1)
endif()

add_executable(cif apps/cif_main.cpp)
target_link_libraries(cif PRIVATE cif_net $<BUILD_INTERFACE:cif_warnings> $<BUILD_INTERFACE:cif_sanitizers>)

# ---------------------------------------------------------------------------
# Tests / examples / benchmarks
# ---------------------------------------------------------------------------
if(CIF_BUILD_TESTS)
  add_subdirectory(tests)
endif()
if(CIF_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()
if(CIF_BUILD_BENCHMARKS)
  add_subdirectory(benchmarks)
endif()

# ---------------------------------------------------------------------------
# Install / export
# ---------------------------------------------------------------------------
install(TARGETS cif_core cif_net cif_cif
  EXPORT CIFTargets
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
  LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
  INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

install(TARGETS cifd cif
  RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")

install(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/include/"
  DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
  FILES_MATCHING PATTERN "*.hpp")

install(EXPORT CIFTargets
  FILE CIFTargets.cmake
  NAMESPACE cif::
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CIF")

configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/CIFConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/CIFConfig.cmake"
  INSTALL_DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CIF")

write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/CIFConfigVersion.cmake"
  VERSION "${PROJECT_VERSION}"
  COMPATIBILITY SameMajorVersion)

install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/CIFConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/CIFConfigVersion.cmake"
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/cmake/CIF")

install(FILES
  "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
  "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
  DESTINATION "${CMAKE_INSTALL_DATADIR}/CIF")
