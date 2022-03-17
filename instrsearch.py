import argparse
import pathlib
import re
from datetime import datetime
from typing import List, Dict, TextIO

import angr
import cle

pattern_dict: Dict[str, str] = {
    "\\ANYINS": "([^\\n\\r]+)",
    "\\ANY": "([^\\s\\r\\n,]+)",
    "\\ADDR": "(0x[a-fA-F0-9]+)",
    "\\IMM": "([0-9]+)",
    "\\GP": "(([re]?[abcd][xhl])|(r[01234589]{1,2}[dwb]?)|([re]?(si|di|bp|sp)l?))",
    "\\DEREF": "(((word|dword|qword) ptr )?\\[[[^\\]]+]\\])",
    "\\AVX": "([xyzXYZ]?(MM|mm)[0-9][0-5]?)"
}


def parse_pattern(pattern: str) -> str:
    result = []

    for entry in pattern.split(';'):
        for key in pattern_dict:
            entry = (entry.strip()).replace(key, pattern_dict[key])

        result.append(entry)

    return '\n'.join(result)


def search(cfg: angr.analyses.CFGFast, pattern: str, file: TextIO):
    visited = set()

    # Iterate over each function
    for func in cfg.kb.functions:
        # Iterate over basic blocks of each function
        for block in cfg.kb.functions[func].blocks:
            if block.addr not in visited and block.size > 0:
                search_block_full(block.capstone, pattern, file)
                visited.add(block.addr)


def search_block_full(block: angr.block.CapstoneBlock, pattern: str, file: TextIO):
    block = (str(block)).replace('\t', ' ')

    match = re.search(pattern, block)
    if match is not None:
        result = match.group(0)

        if file is not None:
            result = result.replace('\n', ';')
            file.write(f"{result}\n")
        else:
            print('\t' + result.replace('\n', "\n\t"))
            print()


def search_block_custom(block: angr.block.CapstoneBlock, pattern: List[str]):
    matched = 0  # Keep track of each matched pattern
    index = 0  # Index of current instruction
    back = False  # Go back to first matched instruction when needed

    # List of capstone instructions
    instructions: List[angr.block.CapstoneInsn] = block.insns

    # Iterate over each instruction until the last instruction is reached
    while index < len(instructions):
        instruction = instructions[index]  # Current instruction

        # If instruction matches -> increase matched instruction number
        # Otherwise go back to first matched instruction + 1
        if match_instruction_custom(instruction, pattern[matched]):
            matched += 1
        elif matched > 0:
            back = True

        index += 1

        # Go back to first matched instruction + 1
        if matched == len(pattern) or back:
            if matched == len(pattern):
                print(instruction)

            index -= (matched - 1)
            matched = 0
            back = False


def match_instruction_custom(instruction: angr.block.CapstoneInsn, pattern: str) -> bool:
    if pattern == pattern_dict["\\ANY"]:
        return True

    temp = instruction.mnemonic + ' ' + instruction.op_str
    return re.search(pattern, temp) is not None


def main():
    # Preparing command line argument parser
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-p", "--path", help="path to binary file", type=pathlib.Path, required=True)
    args_parser.add_argument("-s", "--search", help="instruction search pattern", type=str, required=True)
    args_parser.add_argument("-b", "--base", help="base address of binary", type=(lambda x: int(x, 16)), required=False)
    args_parser.add_argument("-a", "--arch", help="architecture of binary", type=str, required=False)
    args_parser.add_argument("-o", "--output", help="output query result to file", type=pathlib.Path, required=False)
    args_parser.add_argument("-v", "--verbose", help="verbose mode", action="store_true")

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    path: pathlib.Path = args.get("path")
    pattern: str = args.get("search")
    base: str = args.get("base") if ("base" in args) else None
    arch: str = args.get("arch") if ("arch" in args) else None
    output: pathlib.Path = args.get("output") if ("arch" in args) else None
    verbose: bool = args.get("verbose")

    # Open output file if needed
    file = None
    if output is not None:
        file = open(output, 'w')

    # DEBUG TIME
    if verbose:
        print("[*] Pattern parsing starts " + str(datetime.now()))

    # Validate instruction search pattern
    pattern = parse_pattern(pattern)
    if verbose:
        print("[*] Parsing with:\n\t[+] " + pattern.replace('\n', "\n\t[+] "))

    # DEBUG TIME
    if verbose:
        print("[*] Pattern parsing ends and angr project load starts " + str(datetime.now()))

    # Create an angr instance
    angr_proj = angr.Project(path, load_options={"auto_load_libs": False}, main_opts={"base_addr": base, "arch": arch})

    # Get entry object of binary
    angr_main: cle.Backend = angr_proj.loader.main_object
    if angr_main is None:
        if verbose:
            print("Binary entry not detected ... exiting")
        return

    if verbose:
        print(f"[*] Loaded {angr_proj.filename}, {angr_proj.arch.name} {angr_proj.arch.memory_endness}")
        print(f"[*] Entry object {angr_main}; entry address {hex(angr_main.entry)}")

    # DEBUG TIME
    if verbose:
        print("[*] Angr project load ends and CFGFast analysis starts " + str(datetime.now()))

    # Create control flow graph for binary
    cfg: angr.analyses.CFGFast = angr_proj.analyses.CFGFast()

    # DEBUG TIME
    if verbose:
        print("[*] CFGFast analysis ends and search starts " + str(datetime.now()))
        if not file:
            print()

    # Execute instruction pattern search
    search(cfg, pattern, file)

    # DEBUG TIME
    if verbose:
        print("[*] Search ends " + str(datetime.now()))

    # Close output file if needed
    if output is not None:
        file.close()


if __name__ == "__main__":
    main()
