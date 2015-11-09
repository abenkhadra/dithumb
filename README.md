# dithumb
A demo ARM/Thumb disassembler based on Capstone disassembly library. Given
an ARM ELF as input, we look in the symbol table for ARM code symbols. 
Available instructions are read based on code symbols and printed to stdout.
