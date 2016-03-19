#include "binutils/elf/elf++.hh"
#include "disasm/ElfDisassembler.h"
#include "disasm/ElfData.h"
#include <fcntl.h>
#include <util/cmdline.h>

using namespace std;

struct ConfigConsts {
    const std::string kFile;
    const std::string kLinearSweep;
    const std::string kTextSectionOnly;

    ConfigConsts() : kFile{"file"},
                     kLinearSweep{"linear-sweep"},
                     kTextSectionOnly{"text-section"} { }
};

int main(int argc, char **argv) {
    ConfigConsts config;

    cmdline::parser cmd_parser;
    cmd_parser.add<string>(config.kFile,
                           'f',
                           "Path to an ARM ELF file to be disassembled",
                           true,
                           "");
    cmd_parser.add(config.kLinearSweep, 'l', "Disassembly using linear sweep");
    cmd_parser.add(config.kTextSectionOnly,
                   't',
                   "Disassembly text section only");

    cmd_parser.parse_check(argc, argv);

    auto file_path = cmd_parser.get<string>(config.kFile);

    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    elf::elf elf_file(elf::create_mmap_loader(fd));

    // We only disassmble ARM/Thumb executables.
    if (static_cast<elf::ElfISA>(elf_file.get_hdr().machine)
        != elf::ElfISA::kARM) {
        fprintf(stderr, "%s : Elf file architecture is not ARM!\n", argv[1]);
        return 3;
    }

    disasm::ElfDisassembler disassembler{elf_file};
    if (!disassembler.isSymbolTableAvailable()
        || cmd_parser.exist(config.kLinearSweep)) {
        if (cmd_parser.exist(config.kTextSectionOnly)) {
            disassembler.disassembleSectionUsingLinearSweep
                (disassembler.findSectionbyName(".text"));
        } else {
            disassembler.disassembleCodeUsingLinearSweep();
        }
    } else {
        if (cmd_parser.exist(config.kTextSectionOnly)) {
            disassembler.disassembleSectionUsingSymbols
                (disassembler.findSectionbyName(".text"));
        } else {
            disassembler.disassembleCodeUsingSymbols();
        }
    }


    return 0;
}
