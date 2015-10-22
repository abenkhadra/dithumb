# dithumb
A simple disassembler for ELF files based on Capstone disassembly library. Given
an ARM ELF as input, we look in the symbol table for ARM code symbols. 
Available instructions are read based on the symbols and printed to the screen.   
