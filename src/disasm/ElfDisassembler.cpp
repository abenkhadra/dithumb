//===------------------------------------------------------------*- C++ -*-===//
//
// This file is distributed under the MIT License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
// 
// Copyright (c) 2015 Technical University of Kaiserslautern.

#include "ElfDisassembler.h"
#include "BCInst.h"
#include <inttypes.h>
#include <algorithm>

namespace disasm {


class ARMCodeSymbolStrings {
public:
    static std::string
    kThumb() { return "$t"; }

    static std::string
    kARM() { return "$a"; }

    static std::string
    kData() { return "$d"; }
};

ElfDisassembler::ElfDisassembler() : m_valid{false} { }

ElfDisassembler::ElfDisassembler(const elf::elf &elf_file) :
    m_valid{true},
    m_elf_file{&elf_file},
    m_config{} { }

void
ElfDisassembler::print_string_hex(unsigned char *str, size_t len) const {
    unsigned char *c;

    printf("Code: ");
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }
    printf("\n");
}

void inline
ElfDisassembler::initializeCapstone(csh *handle) const {
    cs_err err_no;
    err_no = cs_open(CS_ARCH_ARM, CS_MODE_THUMB, handle);
    if (err_no) {
        throw std::runtime_error("Failed on cs_open() "
                                     "with error returned:" + err_no);
    }

    cs_option(*handle, CS_OPT_DETAIL, CS_OPT_ON);
}

void
ElfDisassembler::disassembleSectionUsingLinearSweep
    (const elf::section &sec) const {
    csh handle;

    initializeCapstone(&handle);
    if (m_elf_file->get_hdr().entry % 2) {
        cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);
    } else {
        cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
    }
    cs_option(handle, CS_OPT_SKIPDATA, CS_OPT_ON);
    size_t address = sec.get_hdr().addr;
    size_t size = sec.get_hdr().size;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();
    cs_insn *inst;

    inst = cs_malloc(handle);
    BCInst instr(inst);

    printf("Section Name: %s\n", sec.get_name().c_str());

    while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
        prettyPrintInst(handle, inst);
    }

    cs_close(&handle);
}

void
ElfDisassembler::disassembleSectionUsingSymbols(const elf::section &sec) const {
    auto symbols = getCodeSymbolsForSection(sec);
//    printf("Symbols size is %lu \n", symbols.size());
//
//    for (auto& symbol : symbols) {
//        printf("Type %d, Addrd, 0x%#x \n", symbol.second, symbol.first);
//    }
    csh handle;

    initializeCapstone(&handle);
    size_t start_addr = sec.get_hdr().addr;
    size_t last_addr = start_addr + sec.get_hdr().size;
    const uint8_t *code_ptr = (const uint8_t *) sec.data();
    cs_insn *inst;

    inst = cs_malloc(handle);
    BCInst instr(inst);
    printf("***********************************\n");
    printf("Section name: %s\n", sec.get_name().c_str());

    // We assume that symbols are ordered by their address.
    size_t index = 0;
    size_t address = 0;
    size_t size = 0;
    size_t instruction_count = 0;
    size_t basic_block_count = 0;
    for (auto &symbol : symbols) {
        index++;
        if (symbol.second == ARMCodeSymbol::kData) {
            if (index < symbols.size())
                // adjust code_ptr to start of next symbol.
                code_ptr += (symbols[index].first - symbol.first);
            continue;
        }
        address = symbol.first;
        if (index < symbols.size())
            size = symbols[index].first - symbol.first;
        else
            size = last_addr - symbol.first;

        if (symbol.second == ARMCodeSymbol::kARM)
            cs_option(handle, CS_OPT_MODE, CS_MODE_ARM);
        else
            // We assume that the value of code symbol type is strictly
            // either Data, ARM, or Thumb.
            cs_option(handle, CS_OPT_MODE, CS_MODE_THUMB);

        while (cs_disasm_iter(handle, &code_ptr, &size, &address, inst)) {
            prettyPrintInst(handle, inst);
            instruction_count++;
            if (isBranch(inst)) {
                printf("Basic block end.\n");
                printf("***********************************\n");
                basic_block_count++;
            }
        }
    }
    printf("Instruction count: %lu, Basic Block count: %lu\n",
           instruction_count,
           basic_block_count);
    cs_close(&handle);
}

const elf::section &
ElfDisassembler::findSectionbyName(std::string sec_name) const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.get_name() == sec_name) {
            return sec;
        }
    }
}

void
ElfDisassembler::disassembleCodeUsingSymbols() const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleSectionUsingSymbols(sec);
        }
    }
}

void
ElfDisassembler::disassembleCodeUsingLinearSweep() const {
    for (auto &sec : m_elf_file->sections()) {
        if (sec.is_alloc() && sec.is_exec()) {
            disassembleSectionUsingLinearSweep(sec);
        }
    }
}

bool ElfDisassembler::isBranch(const cs_insn *inst) const {
    if (inst->detail == NULL) return false;

    cs_detail *detail = inst->detail;
    // assuming that each instruction should belong to at least one group
    if (detail->groups[detail->groups_count - 1] == ARM_GRP_JUMP)
        return true;
    if (inst->id == ARM_INS_POP) {
        // pop accepts a register list. If pc was among them then this a branch
        for (int i = 0; i < detail->arm.op_count; ++i) {
            if (detail->arm.operands[i].reg == ARM_REG_PC) return true;
        }
    }

    if ((detail->arm.operands[0].type == ARM_OP_REG)
        && (detail->arm.operands[0].reg == ARM_REG_PC)) {
        if (inst->id == ARM_INS_STR) {
            return false;
        }
        return true;
    }
    return false;
}

void ElfDisassembler::prettyPrintInst(const csh &handle, cs_insn *inst) const {

    cs_detail *detail;
    int n;

    printf("0x%" PRIx64 ":\t%s\t\t%s // insn-ID: %u, insn-mnem: %s\n",
           inst->address, inst->mnemonic, inst->op_str,
           inst->id, cs_insn_name(handle, inst->id));

    // print implicit registers used by this instruction
//    detail = inst->detail;
//
//    if (detail == NULL) return;
//
//    if (detail->regs_read_count > 0) {
//        printf("\tImplicit registers read: ");
//        for (n = 0; n < detail->regs_read_count; n++) {
//            printf("%s ", cs_reg_name(handle, detail->regs_read[n]));
//        }
//        printf("\n");
//    }
//
//    // print implicit registers modified by this instruction
//    if (detail->regs_write_count > 0) {
//        printf("\tImplicit registers modified: ");
//        for (n = 0; n < detail->regs_write_count; n++) {
//            printf("%s ", cs_reg_name(handle, detail->regs_write[n]));
//        }
//        printf("\n");
//    }
//
//    // print the groups this instruction belong to
//    if (detail->groups_count > 0) {
//        printf("\tThis instruction belongs to groups: ");
//        for (n = 0; n < detail->groups_count; n++) {
//            printf("%s ", cs_group_name(handle, detail->groups[n]));
//        }
//        printf("\n");
//    }
}

std::vector<std::pair<size_t, ARMCodeSymbol>>
ElfDisassembler::getCodeSymbolsForSection(const elf::section &sec) const {
    std::vector<std::pair<size_t, ARMCodeSymbol>> result;

    // Check for symbol table, if none was found then
    // the instance is invalid.
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a valid section means that there was no symbol table
    //  provided in ELF file.
    if (!sym_sec.valid())
        return result;

    size_t start_addr = sec.get_hdr().addr;
    size_t end_addr = start_addr + sec.get_hdr().size;

    // The following can throw a type_mismatch exception in case
    // of corrupted symbol table in ELF.

    for (auto symbol: sym_sec.as_symtab()) {
        size_t value = symbol.get_data().value;
        // we assume that the start addr of each section is available in
        // code symbols.
        if ((start_addr <= value) && (value < end_addr)) {
            if (symbol.get_name() == ARMCodeSymbolStrings::kThumb()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbol::kThumb));

            } else if (symbol.get_name() == ARMCodeSymbolStrings::kARM()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbol::kARM));

            } else if (symbol.get_name() == ARMCodeSymbolStrings::kData()) {
                result.emplace_back(std::make_pair(value,
                                                   ARMCodeSymbol::kData));

            }
        }
    }
    // Symbols are not necessary sorted, this step is required to
    // avoid potential SEGEV.
    std::sort(result.begin(), result.end());
    return result;
}

bool
ElfDisassembler::isSymbolTableAvailable() {
    elf::section sym_sec = m_elf_file->get_section(".symtab");
    // Returning a invalid section means that there was no symbol table
    //  provided in ELF file.

    return sym_sec.valid();
}
}

