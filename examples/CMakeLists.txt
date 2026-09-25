# Cluster Interconnect Fabric (CIF) -- examples
# Copyright 2026 Summon Software Labs.
# SPDX-License-Identifier: Apache-2.0
add_executable(cif_example_authority authority_walkthrough.cpp)
target_link_libraries(cif_example_authority PRIVATE cif_net cif_warnings cif_sanitizers)
set_target_properties(cif_example_authority PROPERTIES FOLDER "examples")

add_executable(cif_example_durability durability_restart.cpp)
target_link_libraries(cif_example_durability PRIVATE cif_net cif_warnings cif_sanitizers)
set_target_properties(cif_example_durability PROPERTIES FOLDER "examples")

add_executable(cif_example_parallel_clients parallel_clients.cpp)
target_link_libraries(cif_example_parallel_clients PRIVATE cif_net cif_warnings cif_sanitizers)
set_target_properties(cif_example_parallel_clients PROPERTIES FOLDER "examples")
