//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include "binutils/elf/elf++.hh"
#include <capstone/capstone.h>

namespace disasm {

enum class ARMCodeSymbol: std::uint8_t {
    kThumb = 1,
    kARM = 2,
    kData = 4
};

/**
 * ElfDisassembler
 */
class ElfDisassembler {
public:
    /**
     * Construct a Elf Disassembler that is initially not valid.  Calling
     * methods other than valid on this results in undefined behavior.
     */
    ElfDisassembler();

    /**
     * Prepares input file for disassembly.
     * Precondition: file is a valid ELF file.
     */
    ElfDisassembler(const elf::elf& elf_file);
    virtual ~ElfDisassembler() = default;
    ElfDisassembler(const ElfDisassembler &src) = delete;
    ElfDisassembler &operator=(const ElfDisassembler &src) = delete;
    ElfDisassembler(ElfDisassembler &&src) = default;

    bool valid() const { return m_valid; }
    void disassembleCodeUsingSymbols() const;

    void disassembleSectionbyName(std::string& sec_name) const;
    void print_string_hex(unsigned char *str, size_t len) const;
    bool isSymbolTableAvailable();

private:
    void disassembleSectionUsingSymbols(const elf::section &sec) const;
    void initializeCapstone(csh *handle) const;
    void prettyPrintInst(const csh& handle, cs_insn* inst) const;
    std::vector<std::pair<size_t, ARMCodeSymbol>>
        getCodeSymbolsForSection(const elf::section &sec) const;

private:
    bool m_valid;
    const elf::elf* m_elf_file;

    struct CapstoneConfig final{
        public:
        CapstoneConfig():
        arch_type{CS_ARCH_ARM},
            mode{CS_MODE_THUMB},
            details{true}{
        }
        CapstoneConfig(const CapstoneConfig& src) = default;
        CapstoneConfig &operator=(const CapstoneConfig& src) = default;

        cs_arch arch_type;
        cs_mode mode;
        bool details;
    };
    CapstoneConfig m_config;
};
}



