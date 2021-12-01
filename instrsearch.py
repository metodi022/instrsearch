import argparse
import pathlib
import time
from collections import deque

import angr


def validate_pattern(pattern):
    print(pattern)


def search(cfg, node, pattern):
    queue = deque()
    seen = set()
    queue.append(node.addr)

    while len(queue) > 0:
        func = cfg.kb.functions[queue.popleft()]
        node = cfg.model.get_any_node(func.addr)
        seen.add(node.addr)

        for block in func.blocks:
            block.pp()

        for successor in node.successors:
            if successor.addr not in seen:
                queue.append(successor.addr)


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
    path = args.get('path')
    pattern = args.get('search')
    base = args.get('base') if ('base' in args) else None
    arch = args.get('arch') if ('arch' in args) else None
    verbose = args.get('verbose')

    # Validate instruction search pattern
    validate_pattern(pattern)

    # Create an angr instance
    angr_proj = angr.Project(path, load_options={'auto_load_libs': False}, main_opts={'base_addr': base, 'arch': arch})
    time.sleep(1)

    # Get entry object of binary
    angr_main = angr_proj.loader.main_object

    if verbose:
        print(f'[*] Loaded {angr_proj.filename}, {angr_proj.arch.name} {angr_proj.arch.memory_endness}')
        print(f'[*] Entry object {angr_main}; entry address {hex(angr_main.entry)}')

    # Create control flow graph for binary
    cfg = angr_proj.analyses.CFGFast()
    time.sleep(1)

    # Try to get main function
    symbol_main = angr_proj.loader.find_symbol('main')
    if symbol_main is None:
        entry_node = cfg.model.get_any_node(angr_proj.entry)

        if verbose:
            print('[*] Main function not detected; starting from entry address')
    else:
        entry_node = cfg.model.get_any_node(symbol_main.rebased_addr)

        if verbose:
            print(f'[*] Main function detected at {hex(entry_node.addr)}; starting from main function')

    # Execute instruction pattern search
    search(cfg, entry_node, pattern)


if __name__ == '__main__':
    main()
