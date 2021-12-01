import argparse
import pathlib
import time

import angr


def validate_pattern(pattern):
    print(pattern)


def search(cfg, entry_node, pattern):
    print(pattern)


def main():
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument('-p', '--path', help='path to binary file', type=pathlib.Path, required=True)
    args_parser.add_argument('-s', '--search', help='instruction search pattern', type=str, required=True)
    args_parser.add_argument('-b', '--base', help='base address of binary', type=(lambda x: int(x, 16)), required=False)
    args_parser.add_argument('-a', '--arch', help='architecture of binary', type=str, required=False)

    args = vars(args_parser.parse_args())
    path = args.get('path')
    pattern = args.get('search')
    base = args.get('base') if ('base' in args) else None
    arch = args.get('arch') if ('arch' in args) else None

    validate_pattern(pattern)

    angr_proj = angr.Project(path, load_options={'auto_load_libs': False}, main_opts={'base_addr': base, 'arch': arch})
    time.sleep(1)

    angr_main = angr_proj.loader.main_object

    print(f'[*] Loaded {angr_proj.filename}, {angr_proj.arch.name} {angr_proj.arch.memory_endness}')
    print(f'[*] Entry object {angr_main}; entry address {hex(angr_main.entry)}')

    cfg = angr_proj.analyses.CFGFast()
    time.sleep(1)

    # Try to get main function immediately
    symbol_main = angr_proj.loader.find_symbol('main')
    if symbol_main is None:
        entry_node = cfg.model.get_any_node(angr_proj.entry)
        print('[*] Main function not detected; starting from entry address')
    else:
        entry_node = cfg.model.get_any_node(symbol_main.rebased_addr)
        print(f'[*] Main function detected at {hex(entry_node.addr)}; starting from main function')

    search(cfg, entry_node, pattern)


if __name__ == '__main__':
    main()
