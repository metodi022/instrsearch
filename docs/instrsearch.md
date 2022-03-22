# Description

---
The instruction search project is a Python project which aims to find complex instruction patterns in a binary file. The
project uses the [angr](https://github.com/angr/angr) library to facilitate binary analysis.

# Requirements & Installation

---

The project requires the angr library. It is recommended to create a virtual environment and install angr there. Then
run the _instrsearch.py_ file with the required parameters.

# Usage

---
Following is a short description how to use the program:

1. Specify the path to the binary with the _-p_ argument
2. Specify the search pettern with the _-s_ argument

Run the program with the _-h_ argument to list additional optional arguments.

# Search Pattern

Every search pattern has to begin with the _\ADDR:\s_ string

The search pattern is any valid Python regular expression. The program expects _Intel instruction syntax_. For example
"_\ADDR: test rax, rax_" will search for all instructions that have the mnemonic _test_ and the two operands _rax_.

**Each pattern matches one instruction exactly**. Multiple patterns can be chained with the *;* separator to match
multiple instructions. For example, "_\ADDR: sub eax, ecx; \ADDR: add eax, eax_" search pattern will search for the
instruction "_sub eax, ecx_" followed immediately by the instruction "_add eax, eax_".

The program extends the RegEx by the following commands:

- _\GP_ matches any general purpose register
- _\IMM_ matches any immediate value
- _\ADDR_ matches any address
- _\DEREF_ matches any dereference
- _\AVX_ matches any AVX register
- _\ANY_ matches any mnemonic or operand
- _\ANYINS_ matches any instruction

Example queries:

- "_\ADDR: cmp \GP, \ANY; \ADDR: \ANYINS_" - this pattern searches for an instruction with the _cmp_ mnemonic which has
  first operand a general purpose register and a second operand a register, immediate or memory dereference. Then the
  instruction has to be followed by any other instruction.
- "_\ADDR: add eax, eax; (\ADDR: \ANYINS){2,4}; \ADDR: sub eax, ecx_" - this pattern searches for the instruction "_add
  eax, eax_" followed by 2 to 4 other instructions and finally ending with a "_sub eax, ecx_" instruction.