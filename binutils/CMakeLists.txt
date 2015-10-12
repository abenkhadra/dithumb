set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR}/lib)

add_library(
        elf++ STATIC
        elf/mmap_loader.cc
        elf/to_string.cc
        elf/elf.cc
        disassembly/ElfDisassembler.cpp
)

add_library(
        dwarf++ STATIC
        dwarf/abbrev.cc
        dwarf/attrs.cc
        dwarf/cursor.cc
        dwarf/die.cc
        dwarf/die_str_map.cc
        dwarf/dwarf.cc
        dwarf/elf.cc
        dwarf/expr.cc
        dwarf/line.cc
        dwarf/rangelist.cc
        dwarf/value.cc
        dwarf/to_string.cc
)
