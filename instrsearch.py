import argparse
import pathlib
import re
import time
from typing import List, Dict

import angr
import cle

pattern_dict: Dict[str, str] = {
    "\\ANY": "[^\\s,]+",
    "\\ADDR": "0x[a-fA-F0-9]+",
    "\\IMM": "[0-9]+",
    "\\GP": "(rax|eax|ax|ah|al|rbx|ebx|bx|bh|bl|rcx|ecx|cx|ch|cl|rdx|edx|dx|dh|dl|rsi|esi|rdi|edi|rbp|ebp|rsp|esp)",
    "\\DEFER": "((word|dword|qword) ptr )?\\[0x[a-fA-F0-9]+\\]"
}


def parse_pattern(pattern: str) -> str:
    result = []

    for entry in pattern.split(';'):
        if entry.strip() == "\\ANY":
            result.append("[^\\n\\r]+")

        for key in pattern_dict:
            entry = (entry.strip()).replace(key, pattern_dict[key])
        result.append(pattern_dict["\\ADDR"] + ": " + entry)

    return '\n'.join(result)


def search(cfg: angr.analyses.CFGFast, pattern: str):
    visited = set()

    # Iterate over each function
    for func in cfg.kb.functions:
        # Iterate over basic blocks of each function
        for block in cfg.kb.functions[func].blocks:
            if block.addr not in visited and block.size > 0:
                search_block_full(block.capstone, pattern)
                visited.add(block.addr)


def search_block_full(block: angr.block.CapstoneBlock, pattern: str):
    block = (str(block)).replace('\t', ' ')

    match = re.search(pattern, block)
    if match is not None:
        print(match.group(0))


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
    args_parser.add_argument("-v", "--verbose", help="verbose mode", action="store_true")

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    path: pathlib.Path = args.get("path")
    pattern: str = args.get("search")
    base: str = args.get("base") if ("base" in args) else None
    arch: str = args.get("arch") if ("arch" in args) else None
    verbose: bool = args.get("verbose")

    # Validate instruction search pattern
    pattern = parse_pattern(pattern)
    time.sleep(1)

    # Create an angr instance
    angr_proj = angr.Project(path, load_options={"auto_load_libs": False}, main_opts={"base_addr": base, "arch": arch})
    time.sleep(1)

    # Get entry object of binary
    angr_main: cle.Backend = angr_proj.loader.main_object
    if angr_main is None:
        if verbose:
            print("Binary entry not detected ... exiting")
        return

    if verbose:
        print(f"[*] Loaded {angr_proj.filename}, {angr_proj.arch.name} {angr_proj.arch.memory_endness}")
        print(f"[*] Entry object {angr_main}; entry address {hex(angr_main.entry)}")

    # Create control flow graph for binary
    cfg: angr.analyses.CFGFast = angr_proj.analyses.CFGFast()
    time.sleep(1)

    # Execute instruction pattern search
    search(cfg, pattern)


if __name__ == "__main__":
    main()
