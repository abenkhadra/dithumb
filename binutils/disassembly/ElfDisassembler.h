//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once
#include "elf/elf++.hh"
#include <capstone/capstone.h>

namespace disasm {

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
/**
 * ElfDisassembler
 * This class is internally reference counted and efficiently
 * copyable.
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
     * Pre-condition: file is a valid ELF file.
     */
    ElfDisassembler(const elf::elf &elf_obj);
    ElfDisassembler(const elf::elf &elf_obj, const CapstoneConfig &config);
    virtual ~ElfDisassembler() = default;
    ElfDisassembler(const ElfDisassembler &src) = default;
    ElfDisassembler &operator=(const ElfDisassembler &src) = default;
    ElfDisassembler(ElfDisassembler &&src) = default;

    bool valid() const { return m_valid; }
    void disassembleCode() const;
    void disassembleSectionbyName(std::string& sec_name) const;
    void print_string_hex(unsigned char *str, size_t len) const;

private:
    void disassembleSection(const elf::section &sec) const;
    void initializeCapstone(csh *handle) const;

private:
    bool m_valid;
    const elf::elf* m_elf_obj;
    CapstoneConfig ls;
};
}



