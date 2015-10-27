#include "binutils/elf/elf++.hh"
#include "disasm/ElfDisassembler.h"
#include "disasm/ElfData.h"
#include <fcntl.h>
#include <util/cmdline.h>

using namespace std;

struct ConfigConsts {
    const std::string kFile;
    const std::string kNoSymbols;
    const std::string kSpeculative;

    ConfigConsts(): kFile{"file"},
                  kNoSymbols{"no-symbols"},
                  kSpeculative{"speculative"}{}
};

int main(int argc, char **argv) {
    ConfigConsts config;

    cmdline::parser cmd_parser;
    cmd_parser.add<string>(config.kFile, 'f', "Path to an ARM ELF file to be disassembled", true, "");
//    a.add<int>("port", 'p', "port number", false, 80, cmdline::range(1, 65535));
//    a.add<string>("type", 't', "protocol type", false, "http", cmdline::oneof<string>("http", "https", "ssh", "ftp"));
    cmd_parser.add(config.kNoSymbols, '\0', "Do not use symbol table even if exists");
    cmd_parser.add(config.kSpeculative, '\0', "Show all 'valid' dissambly");

    cmd_parser.parse_check(argc, argv);

    auto file_path = cmd_parser.get<string>(config.kFile);

    cout << file_path << "://" << endl;

    if (cmd_parser.exist(config.kNoSymbols))
        cout << config.kNoSymbols << endl;

    if (cmd_parser.exist(config.kSpeculative))
        cout << config.kSpeculative << endl;

//    if (argc != 2) {
//        fprintf(stderr, "usage: %s elf-file\n", argv[0]);
//        return 2;
//    }

    int fd = open(file_path.c_str(), O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    elf::elf elf_file(elf::create_mmap_loader(fd));

    // We only disassmble ARM/Thumb executables.
    if (static_cast<elf::ElfISA>(elf_file.get_hdr().machine) !=  elf::ElfISA::kARM){
        fprintf(stderr, "%s : Elf file architechture is not ARM.\n", argv[1]);
        return 3;
    }

    disasm::ElfDisassembler disassembler{elf_file};
    if (cmd_parser.exist("speculative")) {
        cout << "Speculative disassmbly of file: "
            << file_path << "\n";

        disassembler.disassembleCodeSpeculative();
    }else if (cmd_parser.exist("no-symbols")
        || !disassembler.isSymbolTableAvailable()) {
        cout << "Standard disassmbly of file: "
            << file_path << "\n";

        disassembler.disassembleCode();

    } else {
        cout << "Disassembly using symbol table of file: "
            << file_path << "\n";

        disassembler.disassembleCodeUsingSymbols();
    }

    return 0;
}
