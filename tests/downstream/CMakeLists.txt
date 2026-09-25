# Independent downstream consumer of the installed CIF package.
# This project deliberately knows nothing about the CIF source tree: it uses
# only find_package(CIF) against an install prefix.
cmake_minimum_required(VERSION 3.25)
project(CifDownstreamConsumer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(CIF 1.0 REQUIRED)

add_executable(cif_downstream main.cpp)
target_link_libraries(cif_downstream PRIVATE cif::core cif::net)

set_target_properties(cif_downstream PROPERTIES
  CXX_STANDARD 20
  CXX_STANDARD_REQUIRED ON)

install(TARGETS cif_downstream RUNTIME DESTINATION bin)
