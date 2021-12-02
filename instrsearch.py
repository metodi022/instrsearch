import argparse
import pathlib
import time
from collections import deque
from typing import List

import angr
import cle


def validate_parse_pattern(pattern: str) -> List[List[str]]:
    return [[]]


def search(cfg: angr.analyses.CFGFast, node: angr.knowledge_plugins.cfg.CFGNode, pattern: List[List[str]]):
    queue = deque()
    visited = set()
    visited_blocks = set()
    queue.append(node.addr)
    visited.add(node.addr)

    # BFS in control flow graph
    while len(queue) > 0:
        func = cfg.kb.functions[queue.popleft()]  # Function
        node = cfg.model.get_any_node(func.addr)  # Function Node

        # Iterate over basic blocks in function
        for block in func.blocks:
            # Do something with block ...
            if block.addr not in visited_blocks:
                search_block(block.capstone, pattern)
                visited_blocks.add(block.addr)

        # Iterate over successor nodes of function node
        for successor in node.successors:
            if successor.addr not in visited:
                queue.append(successor.addr)
                visited.add(node.addr)


def search_block(block: angr.block.CapstoneBlock, pattern: List[List[str]]):
    matched = 0
    index = 0
    instructions: List[angr.block.CapstoneInsn] = block.insns

    while index < len(instructions):
        instruction = instructions[index]

        # Do something with instruction ...
        # ...

        index += 1
        break


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
    pattern = validate_parse_pattern(pattern)

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
        entry_node: angr.knowledge_plugins.cfg.CFGNode = cfg.model.get_any_node(angr_proj.entry or 0)

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
