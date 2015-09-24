cmake_minimum_required(VERSION 3.2)
project(elfparse)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14")


set(CMAKE_VERBOSE_MAKEFILE ON)


include_directories(binutils)

add_subdirectory(binutils)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(SOURCE_FILES main.cpp)

add_executable(dithumb ${SOURCE_FILES} main.cpp)

add_dependencies(dithumb elf++ dwarf++)


target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libelf++.a)
target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libdwarf++.a)

