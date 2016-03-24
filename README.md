# dithumb
A demo ARM/Thumb disassembler based on Capstone disassembly library. Given
an ARM ELF file as input, we look into the symbol table for ARM code symbols. 
Available instructions are read based on code symbols and printed to stdout.

When symbol table is not found, disassmebly is done using a linear sweep 
similar to **objdump**. It's possible to use linear sweep directly using **-l** option. 

For a quick test, compile the program and run it on the demo ELF :
> ./dithumb -t -f tests/echo

# Dependencies 

The project is self-contained except for Capstone disassembly library. 
