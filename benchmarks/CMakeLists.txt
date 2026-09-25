# Cluster Interconnect Fabric (CIF) -- benchmarks
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
add_executable(cif_bench_authority bench_authority.cpp)
target_link_libraries(cif_bench_authority PRIVATE cif_net cif_warnings cif_sanitizers)
set_target_properties(cif_bench_authority PROPERTIES FOLDER "benchmarks")

add_executable(cif_bench_transport bench_transport.cpp)
target_link_libraries(cif_bench_transport PRIVATE cif_net cif_warnings cif_sanitizers)
set_target_properties(cif_bench_transport PROPERTIES FOLDER "benchmarks")
