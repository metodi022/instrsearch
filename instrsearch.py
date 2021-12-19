import argparse
import pathlib
import re
import time
from collections import deque
from typing import List, Dict

import angr
import cle

pattern_dict: Dict[str, str] = {
    '\\ANY': '[^\\s,]+',
    '\\IMMH': '0x[a-fA-F0-9]+',
    '\\IMMI': '[0-9]+',
    '\\GP': '[^\\s,]+',
}


def parse_pattern(pattern: str) -> List[str]:
    result = []

    for entry in pattern.split(';'):
        for key in pattern_dict:
            entry = entry.replace(key, pattern_dict[key])
        result.append(entry)

    return result


def search(cfg: angr.analyses.CFGFast, node: angr.knowledge_plugins.cfg.CFGNode, pattern: List[str]):
    queue = deque()
    visited_blocks = set()
    visited = set()

    # Initialization of BFS
    queue.append(node.addr)
    visited.add(node.addr)

    # BFS in control flow graph
    while len(queue) > 0:
        func = cfg.kb.functions[queue.popleft()]  # Function

        # Iterate over basic blocks in function and search it
        for block in func.blocks:
            if block.addr not in visited_blocks and block.size > 0:
                block.pp()
                search_block(block.capstone, pattern)
                visited_blocks.add(block.addr)

        # Iterate over successors
        for endpoint in func.get_call_sites():
            endpoint = func.get_call_target(endpoint)
            if endpoint not in visited:
                queue.append(endpoint)
                visited.add(endpoint)


def search_block(block: angr.block.CapstoneBlock, pattern: List[str]):
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
        if match_instruction(instruction, pattern[matched]):
            matched += 1
        elif matched > 0:
            back = True

        index += 1

        # Go back to first matched instruction + 1
        if matched == len(pattern) or back:
            index -= (matched - 1)
            matched = 0
            back = False


def match_instruction(instruction: angr.block.CapstoneInsn, pattern: str) -> bool:
    temp = instruction.mnemonic + ' ' + instruction.op_str

    return re.search(pattern, temp) is not None


def main():
    # Preparing command line argument parser
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument('-p', '--path', help='path to binary file', type=pathlib.Path, required=True)
    args_parser.add_argument('-s', '--search', help='instruction search pattern', type=str, required=True)
    args_parser.add_argument('-b', '--base', help='base address of binary', type=(lambda x: int(x, 16)), required=False)
    args_parser.add_argument('-a', '--arch', help='architecture of binary', type=str, required=False)
    args_parser.add_argument('-v', '--verbose', help='verbose mode', action='store_true')

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    path: pathlib.Path = args.get('path')
    pattern = args.get('search')
    base: str = args.get('base') if ('base' in args) else None
    arch: str = args.get('arch') if ('arch' in args) else None
    verbose: bool = args.get('verbose')

    # Validate instruction search pattern
    pattern = parse_pattern(pattern)
    time.sleep(1)

    # Create an angr instance
    angr_proj = angr.Project(path, load_options={'auto_load_libs': False}, main_opts={'base_addr': base, 'arch': arch})
    time.sleep(1)

    # Get entry object of binary
    angr_main: cle.Backend = angr_proj.loader.main_object
    if angr_main is None:
        if verbose:
            print('Binary entry not detected ... exiting')
        return

    if verbose:
        print(f'[*] Loaded {angr_proj.filename}, {angr_proj.arch.name} {angr_proj.arch.memory_endness}')
        print(f'[*] Entry object {angr_main}; entry address {hex(angr_main.entry)}')

    # Create control flow graph for binary
    cfg: angr.analyses.CFGFast = angr_proj.analyses.CFGFast()
    time.sleep(1)

    # Try to get main function
    symbol_main: cle.Symbol = angr_proj.loader.find_symbol('main')
    if symbol_main is None:
        entry_node: angr.knowledge_plugins.cfg.CFGNode = cfg.model.get_any_node(angr_main.entry)

        if verbose:
            print('[*] Main function not detected; starting from entry address')
    else:
        entry_node: angr.knowledge_plugins.cfg.CFGNode = cfg.model.get_any_node(symbol_main.rebased_addr)

        if verbose:
            print(f'[*] Main function detected at {hex(entry_node.addr)}; starting from main function')

    # Execute instruction pattern search
    search(cfg, entry_node, pattern)


if __name__ == '__main__':
    main()
