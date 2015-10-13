cmake_minimum_required(VERSION 3.2)
project(elfparse)

set(CMAKE_BUILD_TYPE Debug)

#SET (CMAKE_CXX_COMPILER    "/usr/bin/clang++-3.5")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++14 -fno-omit-frame-pointer")

#SET(DEBUG_LINK_FLAGS "-fsanitize=address")

#add_definitions(${DEBUG_LINK_FLAGS})

#SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${DEBUG_LINK_FLAGS}" )

set(CMAKE_SOURCE_DIR "/home/ammar/ClionProjects/dithumb")

set(CMAKE_VERBOSE_MAKEFILE ON)


include_directories(binutils)

add_subdirectory(binutils)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_SOURCE_DIR}/bin)

set(SOURCE_FILES main.cpp)

add_executable(dithumb ${SOURCE_FILES} main.cpp)
add_library(capstone STATIC IMPORTED)
add_dependencies(dithumb elf++ dwarf++ capstone)


target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libelf++.a)
target_link_libraries(dithumb ${CMAKE_SOURCE_DIR}/lib/libdwarf++.a)
target_link_libraries(dithumb /usr/lib/libcapstone.a)

