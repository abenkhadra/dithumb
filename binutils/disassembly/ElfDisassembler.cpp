//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.
// Created by M. Ammar Ben Khadra.

//

#include "ElfDisassembler.h"
#include "BCInst.h"
#include <inttypes.h>

namespace disasm {

struct platform {
    cs_arch arch;
    cs_mode mode;
    unsigned char *code;
    size_t size;
    char *comment;
    cs_opt_type opt_type;
    cs_opt_value opt_value;
};


ElfDisassembler::ElfDisassembler() : m_valid{false}
{ }

ElfDisassembler::ElfDisassembler(const elf::elf &elf_obj) :
    m_valid{true},
    m_elf_obj{&elf_obj},
    m_config{}
{
}

ElfDisassembler::ElfDisassembler(const elf::elf &elf_obj,
                                 const CapstoneConfig &config) :
    m_valid{true},
    m_elf_obj{&elf_obj},
    m_config{config}
{
}


void
ElfDisassembler::print_string_hex(unsigned char *str, size_t len) const
{
    unsigned char *c;

    printf("Code: ");
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }
    printf("\n");
}


void inline
ElfDisassembler::initializeCapstone(csh *handle) const
{
    cs_err err_no;
    err_no = cs_open(m_config.arch_type, m_config.mode, handle);
    if (err_no) {
        throw std::runtime_error("Failed on cs_open() "
                                     "with error returned:" + err_no);
    }

    if (m_config.details)
        cs_option(*handle, CS_OPT_DETAIL, CS_OPT_ON);
    else
        cs_option(*handle, CS_OPT_DETAIL, CS_OPT_OFF);

}

void
ElfDisassembler::disassembleSection(
    const elf::section &sec) const
{
    csh handle;
    initializeCapstone(&handle);

    uint64_t address = sec.get_hdr().addr;
    size_t size = sec.get_hdr().size;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();
    cs_insn *inst;
    cs_detail *detail;

    inst = cs_malloc(handle);
    BCInst instr(inst);
    printf("Section Name: %s\n", sec.get_name().c_str());
    while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
        int n;

        printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
               inst->address, inst->mnemonic, inst->op_str,
               inst->id, cs_insn_name(handle, inst->id));

        // print implicit registers used by this instruction
        detail = inst->detail;

        if (detail->regs_read_count > 0) {
            printf("\tImplicit registers read: ");
            for (n = 0; n < detail->regs_read_count; n++) {
                printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
            }
            printf("\n");
        }

        // print implicit registers modified by this instruction
        if (detail->regs_write_count > 0) {
            printf("\tImplicit registers modified: ");
            for (n = 0; n < detail->regs_write_count; n++) {
                printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
            }
            printf("\n");
        }

        // print the groups this instruction belong to
        if (detail->groups_count > 0) {
            printf("\tThis instruction belongs to groups: ");
            for (n = 0; n < detail->groups_count; n++) {
                printf("%s ", cs_group_name(handle, detail->groups[n]));
            }
            printf("\n");
        }
    }

    printf("\n");

    // free memory allocated by cs_malloc()
//    cs_free(inst, 1);
    cs_close(&handle);

}


void
ElfDisassembler::disassembleSectionbyName(std::string &sec_name) const
{

    for (auto &sec : m_elf_obj->sections()) {
        if (sec.get_name() == sec_name) {
            disassembleSection(sec);
        }
    }

}

void
ElfDisassembler::disassembleCode() const
{

    for (auto &sec : m_elf_obj->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleSection(sec);
        }
    }
}
}

