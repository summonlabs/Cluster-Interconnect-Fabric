# Cluster Interconnect Fabric (CIF) -- tests
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
#
# NOTE: no test in this tree sets a timeout, a watchdog, or a "treat forced
# termination as success" rule. A hang is a defect and must be diagnosed.

add_library(cif_test_support STATIC harness.cpp)
target_include_directories(cif_test_support PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}")
target_link_libraries(cif_test_support PUBLIC cif_net)
target_link_libraries(cif_test_support PRIVATE cif_warnings cif_sanitizers)
set_target_properties(cif_test_support PROPERTIES FOLDER "tests")

function(cif_test_binary target)
  add_executable(${target} ${ARGN})
  target_link_libraries(${target} PRIVATE cif_test_support cif_warnings cif_sanitizers)
  set_target_properties(${target} PROPERTIES FOLDER "tests")
endfunction()

cif_test_binary(cif_test_core test_core.cpp)
cif_test_binary(cif_test_authority test_authority.cpp)
cif_test_binary(cif_test_property test_property.cpp)
cif_test_binary(cif_test_adversarial test_adversarial.cpp)
cif_test_binary(cif_test_net test_net.cpp)
cif_test_binary(cif_test_process test_process.cpp)
target_compile_definitions(cif_test_process PRIVATE CIF_ENABLE_TEST_HOOKS=1)

set(CIF_TEST_BINARIES
  cif_test_core
  cif_test_authority
  cif_test_property
  cif_test_adversarial
  cif_test_net
  cif_test_process)

foreach(binary IN LISTS CIF_TEST_BINARIES)
  add_test(NAME "${binary}" COMMAND "${binary}" --verbose)
endforeach()

# Granular entries for the highest-value individual tests. If a name here drifts
# out of the binary the binary exits 2 ("no tests matched"), so CTest reports a
# failure rather than silently passing.
set(CIF_NAMED_TESTS
  "cif_test_core:hash.sha256_known_vectors"
  "cif_test_core:hash.crc32c_known_vector"
  "cif_test_core:bytes.canonical_roundtrip"
  "cif_test_core:text.rejects_malformed_utf8"
  "cif_test_core:journal.reopen_preserves_state"
  "cif_test_core:journal.detects_torn_tail"
  "cif_test_core:journal.detects_corruption"
  "cif_test_core:journal.detects_replay_and_reorder"
  "cif_test_authority:authority.grant_happy_path"
  "cif_test_authority:authority.every_outcome_is_reachable"
  "cif_test_authority:fencing.stale_member_generation"
  "cif_test_authority:fencing.member_replacement_invalidates_grant"
  "cif_test_authority:capacity.closure_is_exact"
  "cif_test_authority:commit.prepare_without_commit_is_not_authority"
  "cif_test_property:property.capacity_never_overcommits"
  "cif_test_property:differential.matches_reference_model"
  "cif_test_adversarial:hostile.message_payloads_are_bounds_checked"
  "cif_test_adversarial:hostile.journal_rejects_spliced_records"
  "cif_test_adversarial:hostile.frame_bomb_is_rejected"
  "cif_test_net:server.repeated_start_stop"
  "cif_test_net:concurrency.competing_grants_are_serialised"
  "cif_test_process:multiprocess.daemon_hard_kill_and_restart_fences_the_old_incarnation"
  "cif_test_process:multiprocess.commit_before_acknowledge_is_exactly_the_boundary"
  "cif_test_process:multiprocess.repeated_hard_kill_and_restart_is_stable")


foreach(entry IN LISTS CIF_NAMED_TESTS)
  string(REPLACE ":" ";" parts "${entry}")
  list(GET parts 0 binary)
  list(GET parts 1 testname)
  add_test(NAME "${testname}" COMMAND "${binary}" --filter "${testname}")
endforeach()

add_test(NAME cif.downstream.consumer
  COMMAND "${CMAKE_COMMAND}"
    "-DBUILD_DIR=${CMAKE_BINARY_DIR}"
    "-DSRC_DIR=${CMAKE_CURRENT_SOURCE_DIR}/downstream"
    "-DINSTALL_ROOT=${CMAKE_BINARY_DIR}/downstream-root"
    "-DCONFIG=$<CONFIG>"
    "-DGENERATOR=${CMAKE_GENERATOR}"
    "-DPLATFORM=${CMAKE_GENERATOR_PLATFORM}"
    "-DTOOLSET=${CMAKE_GENERATOR_TOOLSET}"
    "-DCXX_COMPILER=${CMAKE_CXX_COMPILER}"
    "-DMAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
    -P "${CMAKE_CURRENT_SOURCE_DIR}/downstream/run_consumer.cmake")

# The consumer test needs a usable compiler environment. When the runner has
# none, the script prints exactly why and exits 77 instead of failing the suite.
set_tests_properties(cif.downstream.consumer PROPERTIES SKIP_RETURN_CODE 77)
