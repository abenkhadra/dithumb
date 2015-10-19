#include "binutils/elf/elf++.hh"
#include "disasm/ElfDisassembler.h"
#include "disasm/ElfData.h"
#include <fcntl.h>

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "usage: %s elf-file\n", argv[0]);
        return 2;
    }

    int fd = open(argv[1], O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
        return 1;
    }

    elf::elf elf_obj(elf::create_mmap_loader(fd));

    if (static_cast<elf::ElfISA>(elf_obj.get_hdr().machine) !=  elf::ElfISA::kARM){
        fprintf(stderr, "%s : Elf file architechture is not ARM.\n", argv[1]);
        return 3;
    }

    disasm::ElfDisassembler disassembler{elf_obj};
    disassembler.disassembleCode();

    return 0;
}
