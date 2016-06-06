# dithumb
A demo ARM/Thumb disassembler. Given an ARM ELF file as input, we look 
into the symbol table for ARM code mapping symbols, namely, `$a`, `$t`, 
and `$d`. Available instructions are disassembled based on code symbols 
and printed to stdout. When symbol table is not found, disassmebly is done 
using linear sweep similar to **objdump**.

Additionally, the tool displays some useful statistics such as the 
number of basic blocks, direct jumps and indirect jumps found in the binary.

# Trying it
Build the project and try it on one of the binaries available [here], for example:

> ./dithumb -t -f coreutils/echo

It's possible to use linear sweep directly using **-l** option.

# Dependencies 

The project depends on [Capstone] disassembly library.              

  [Capstone]: <https://github.com/aquynh/capstone>
  [here]: <https://github.com/abenkhadra/cases16-benchmarks>

