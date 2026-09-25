# Installs the CIF build into a scratch prefix, then configures, builds and runs
# an independent consumer that uses nothing but find_package(CIF).
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0

foreach(required BUILD_DIR SRC_DIR INSTALL_ROOT)
  if(NOT DEFINED ${required})
    message(FATAL_ERROR "run_consumer.cmake requires -D${required}=...")
  endif()
endforeach()

if(NOT DEFINED CONFIG OR CONFIG STREQUAL "")
  set(CONFIG Release)
endif()

set(prefix "${INSTALL_ROOT}")
file(REMOVE_RECURSE "${prefix}")
file(MAKE_DIRECTORY "${prefix}")

set(install_command "${CMAKE_COMMAND}" --install "${BUILD_DIR}" --prefix "${prefix}")
if(NOT CONFIG STREQUAL "" AND NOT CONFIG STREQUAL "NOCONFIG")
  list(APPEND install_command --config "${CONFIG}")
endif()
execute_process(COMMAND ${install_command} RESULT_VARIABLE install_result
                OUTPUT_VARIABLE install_output ERROR_VARIABLE install_error)
if(NOT install_result EQUAL 0)
  message(FATAL_ERROR "cmake --install failed (${install_result})\n${install_output}\n${install_error}")
endif()
message(STATUS "installed CIF into ${prefix}")

set(consumer_build "${BUILD_DIR}/downstream-consumer")
file(REMOVE_RECURSE "${consumer_build}")

set(configure_command "${CMAKE_COMMAND}" -S "${SRC_DIR}" -B "${consumer_build}"
    "-DCMAKE_PREFIX_PATH=${prefix}" "-DCMAKE_BUILD_TYPE=${CONFIG}")
if(DEFINED GENERATOR AND NOT GENERATOR STREQUAL "")
  list(APPEND configure_command -G "${GENERATOR}")
  if(DEFINED PLATFORM AND NOT PLATFORM STREQUAL "")
    list(APPEND configure_command -A "${PLATFORM}")
  endif()
  if(DEFINED TOOLSET AND NOT TOOLSET STREQUAL "")
    list(APPEND configure_command -T "${TOOLSET}")
  endif()
endif()
# The consumer is configured from a test runner, which is not guaranteed to
# have a compiler on PATH. Reuse exactly the toolchain this build was
# configured with, so "it built downstream" means the same compiler built it.
if(DEFINED CXX_COMPILER AND NOT CXX_COMPILER STREQUAL "")
  list(APPEND configure_command "-DCMAKE_CXX_COMPILER=${CXX_COMPILER}")
endif()
if(DEFINED MAKE_PROGRAM AND NOT MAKE_PROGRAM STREQUAL "")
  list(APPEND configure_command "-DCMAKE_MAKE_PROGRAM=${MAKE_PROGRAM}")
endif()
execute_process(COMMAND ${configure_command} RESULT_VARIABLE configure_result
                OUTPUT_VARIABLE configure_output ERROR_VARIABLE configure_error)
if(NOT configure_result EQUAL 0)
  # A compiler that CMake can find but cannot *use* means this test runner was
  # started without a developer environment (on Windows, without vcvars). That
  # is an environment problem, not a defect in the package, so it is reported
  # as a skip with the exact reason rather than as a pass or a silent failure.
  string(FIND "${configure_error}" "is not able to compile a simple test program" no_env)
  string(FIND "${configure_error}" "No CMAKE_CXX_COMPILER could be found" no_compiler)
  if(NOT no_env EQUAL -1 OR NOT no_compiler EQUAL -1)
    message(STATUS "SKIPPED: the downstream consumer needs a working compiler environment.")
    message(STATUS "On Windows, run the tests from a shell initialised by vcvars64.bat.")
    message(STATUS "configure output was:")
    message(STATUS "${configure_error}")
    message(STATUS "installed prefix: ${prefix}")
    # Exit with the code the test declares as a skip, so CTest reports SKIPPED.
    # Returning 0 here would be a false pass.
    cmake_language(EXIT 77)
  endif()
  message(FATAL_ERROR "downstream configure failed${eol}${configure_output}${eol}${configure_error}")
endif()

set(build_command "${CMAKE_COMMAND}" --build "${consumer_build}")
if(NOT CONFIG STREQUAL "" AND NOT CONFIG STREQUAL "NOCONFIG")
  list(APPEND build_command --config "${CONFIG}")
endif()
execute_process(COMMAND ${build_command} RESULT_VARIABLE build_result
                OUTPUT_VARIABLE build_output ERROR_VARIABLE build_error)
if(NOT build_result EQUAL 0)
  message(FATAL_ERROR "downstream build failed\n${build_output}\n${build_error}")
endif()

find_program(CIF_DOWNSTREAM_EXE
  NAMES cif_downstream cif_downstream.exe
  PATHS "${consumer_build}/bin" "${consumer_build}/Release" "${consumer_build}/Debug"
        "${consumer_build}"
  NO_DEFAULT_PATH)
if(NOT CIF_DOWNSTREAM_EXE)
  message(FATAL_ERROR "downstream consumer binary not found under ${consumer_build}")
endif()

execute_process(COMMAND "${CIF_DOWNSTREAM_EXE}" RESULT_VARIABLE run_result
                OUTPUT_VARIABLE run_output ERROR_VARIABLE run_error)
message(STATUS "downstream output:\n${run_output}")
if(NOT run_result EQUAL 0)
  message(FATAL_ERROR "downstream consumer failed (${run_result})\n${run_error}")
endif()
message(STATUS "downstream consumer OK")
