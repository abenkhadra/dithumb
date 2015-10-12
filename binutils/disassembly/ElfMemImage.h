//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#pragma once

#include <memory>
#include <elf/elf++.hh>

namespace disasm {
/**
 * ElfMemImage
 * This class is internally reference counted and efficiently
 * copyable.
 */
class ElfMemImage {
public:
    /**
     * Construct a ElfMemImage that is initially not valid.  Calling
     * methods other than operator= and valid on this results in
     * undefined behavior.
     */
    ElfMemImage() = default;

    /**
     * Construct a ElfMemImage based on a given ELF file.
     * We assume that the ELF files out-lives the current image.
     */
    ElfMemImage(const elf::elf &elf_file);

    virtual ~ElfMemImage() = default;

    ElfMemImage(const ElfMemImage &src) = delete;
    ElfMemImage &operator=(const ElfMemImage &src) = delete;

    ElfMemImage(ElfMemImage &&src) = default;

    size_t getEntryAddress() const;
    const std::vector<elf::section*> getReadOnlySections() const;
    const std::vector<elf::section*> getWriteSections() const;
    const std::vector<elf::section*> getExecSections() const;

    bool Valid(){ return m_valid;}

    const void *Load(off_t vaddr, size_t size);
private:
    const elf::elf &m_elf_file;
    std::vector<elf::section*> m_read_only_sec;
    std::vector<elf::section*> m_write_sec;
    std::vector<elf::section*> m_exec_sec;

    bool m_valid;
};
}




