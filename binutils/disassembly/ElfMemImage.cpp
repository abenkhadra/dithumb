//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

#include "ElfMemImage.h"
#include <algorithm>
#include <assert.h>

namespace disasm {

using namespace std;


ElfMemImage::ElfMemImage(const elf::elf &elf_file) :
    m_elf_file(elf_file),
    m_valid{true}
{
    for (const auto &sec : elf_file.sections()) {
        if (sec.is_alloc()) {
            if (sec.is_writable()) {
                m_write_sec.push_back(&sec);
            } else if (sec.is_exec()) {
                m_exec_sec.push_back(&sec);
            } else {
                m_read_only_sec.push_back(&sec);
            }
        }
    }
}


const void *
ElfMemImage::Load(off_t vaddr, size_t size)
{
//    if (vaddr < pimpl->m_base_vaddr || size > pimpl->m_size )
//        throw range_error("virtual address out of range");
//    return (const char*) pimpl->getPAddr(vaddr) ;
    return nullptr;
}


const vector<elf::section *>
ElfMemImage::getReadOnlySections() const
{
//    std::vector<elf::section> result;
//
//    assert(m_elf_file.sections().size() != 0);
//
//    std::copy_if(m_elf_file.sections().begin(),
//                 m_elf_file.sections().end(),
//                 std::back_inserter(result),
//                 [](const elf::section &sec) { return sec.is_alloc()
//                     &&(!(sec.is_writable()||sec.is_exec())); });

    return m_read_only_sec;
}

const vector<elf::section *>
ElfMemImage::getWriteSections() const
{
    return m_write_sec;
}

const vector<elf::section *>
ElfMemImage::getExecSections() const
{
    return m_exec_sec;
}

}