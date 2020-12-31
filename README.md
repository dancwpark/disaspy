# disaspy
Learning how the capstone project can be used to write a disassembler!

## Current status
This is a purely academic/learning "project" for understanding how a 
disassembler works.

The code is in no way my own creation. It is entirely a rewriting and
and re-implementation of the works listed below. However, it is reorganized 
and typed in a way that helps me better understand how a disassembler works. 

### Resources
I am heavily using the following resources:
* https://github.com/terminaldweller/delf
* Practical Binary Analysis: by Dennis Andriesse
* elf - Linux man page
* glibc project - elf
  * unofficial mirror : https://github.com/bminor/glibc/blob/master/elf/elf.h

## To-do list
* [ ] Split .text disassembly into functions using symbol table entries for .text section
