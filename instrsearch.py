import argparse
import hashlib
import pathlib
import re
import time
from datetime import datetime
from typing import Dict, TextIO, List

import angr
import cle
import networkx

pattern_dict: Dict[str, str] = {
    "\\ANYINS": "([^\\n\\r]+)",
    "\\ANY": "([^\\s\\r\\n,]+)",
    "\\ADDR": "(0x[a-fA-F0-9]+)",
    "\\IMM": "([0-9]+)",
    "\\GP": "(([re]?[abcd][xhl])|(r[01234589]{1,2}[dwb]?)|([re]?(si|di|bp|sp)l?))",
    "\\DEREF": "(((word|dword|qword) ptr )?\\[[^\\]]+\\])",
    "\\AVX": "([xyzXYZ]?(MM|mm)[0-9][0-5]?)"
}


def parse_pattern(pattern: str) -> str:
    result = []

    for entry in pattern.split(';'):
        for key in pattern_dict:
            entry = (entry.strip()).replace(key, pattern_dict[key])

        result.append(entry)

    return '\n'.join(result)


def unwind(angr_proj: angr.Project, g: dict, entry: dict) -> dict:
    if not entry:
        return entry

    new_entry: dict = dict()

    for key in entry:
        new_key = angr_proj.kb.functions.get_by_addr(key).name + " " + hex(key)
        new_entry[new_key] = unwind(angr_proj, g, g[key])

    return new_entry


def unwind_cached(names: dict, g: dict, entry: dict) -> dict:
    if not entry:
        return entry

    new_entry: dict = dict()

    for key in entry:
        new_key = names[key] + " " + hex(key)
        new_entry[new_key] = unwind_cached(names, g, g[key])

    return new_entry


def search(angr_proj: angr.Project, cfg: angr.analyses.CFGFast, pattern: str, file: TextIO, cache: TextIO,
           depth: int, verbose: bool):
    visited = set()

    # Iterate over each function
    for func_addr in cfg.kb.functions:
        func: angr.knowledge_plugins.Function = cfg.kb.functions[func_addr]

        # Get callers
        callers: dict = networkx.to_dict_of_dicts(
            networkx.bfs_tree(angr_proj.kb.callgraph, func.addr, reverse=True, depth_limit=depth))
        serialized_callers: dict = unwind(angr_proj, callers, callers[func.addr])

        # Serialize function and cache it for future re-use
        cache.write(func.serialize().hex() + '\n')

        # Iterate over basic blocks of each function
        for block in func.blocks:
            if block.addr not in visited and block.size > 0:
                search_block_full(block.capstone, pattern, file, func.name, hex(func.addr), serialized_callers, verbose)
                visited.add(block.addr)


def search_cached(angr_proj: angr.Project, pattern: str, file: TextIO, cache: TextIO, graph: networkx.DiGraph,
                  names: Dict[int, str], depth: int, verbose: bool):
    visited = set()

    # Iterate over each cached line
    for line in cache:
        # Deserialize function
        func: angr.knowledge_plugins.Function = angr.knowledge_plugins.Function.parse(bytes.fromhex(line),
                                                                                      project=angr_proj,
                                                                                      function_manager=angr_proj.kb.functions)

        callers: dict = networkx.to_dict_of_dicts(networkx.bfs_tree(graph, func.addr, reverse=True,
                                                                    depth_limit=depth)) if func.addr in graph.nodes else dict()
        serialized_callers: dict = unwind_cached(names, callers, callers[func.addr]) if callers else dict()

        # Iterate over basic blocks of each function
        for block in func.blocks:
            if block.addr not in visited and block.size > 0:
                search_block_full(block.capstone, pattern, file, func.name, hex(func.addr), serialized_callers, verbose)
                visited.add(block.addr)


def search_block_full(block: angr.block.CapstoneBlock, pattern: str, file: TextIO, func_name: str, func_addr: str,
                      callers, verbose: bool):
    block = (str(block)).replace('\t', ' ')
    match = re.search(pattern, block)

    if match is not None:
        result = match.group(0)

        if verbose:
            print(func_addr + ' ' + func_name + " <- " + str([caller for caller in callers]))
            print(result + '\n')

        if file is not None:
            result = result.replace('\n', ';')
            file.write(f"{func_name}|{func_addr}|{callers}|{result}\n")


# Old code
"""
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
"""


def main():
    # Preparing command line argument parser
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-p", "--path", help="path to binary file", type=pathlib.Path, required=True)
    args_parser.add_argument("-s", "--search", help="instruction search pattern", type=str, required=True)
    args_parser.add_argument("-t", "--depth", help="caller depth output", type=int, required=False)
    args_parser.add_argument("-b", "--base", help="base address of binary in hex", type=(lambda x: int(x, 16)),
                             required=False)
    args_parser.add_argument("-a", "--arch", help="architecture of binary", type=str, required=False)
    args_parser.add_argument("-o", "--output", help="output query result in CSV format to file", type=pathlib.Path,
                             required=False)
    args_parser.add_argument("-d", "--debug", help="debug mode", action="store_true")
    args_parser.add_argument("-v", "--verbose", help="verbose print mode", action="store_true")

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    path: pathlib.Path = args.get("path")
    pattern: str = args.get("search")
    depth: int = args.get("depth")
    base: str = args.get("base")
    arch: str = args.get("arch")
    output: pathlib.Path = args.get("output")
    debug: bool = args.get("debug")
    verbose: bool = args.get("verbose")

    # DEBUG
    if debug:
        print("[*] Preparing cache")

    # Create cache
    pathlib.Path("./cache").mkdir(parents=True, exist_ok=True)

    # Check for cache
    cache_path = pathlib.Path("./cache/" + path.name + ".cache")
    cache: TextIO = open(cache_path, 'r') if cache_path.exists() else open(cache_path, 'w')

    # Check hash
    with open(path, "rb") as f:
        md5 = hashlib.md5()
        md5.update(f.read())

        if (not cache.writable()) and (cache.readline().strip() != md5.hexdigest()):
            cache.close()
            cache = open(cache_path, 'w')

        if cache.writable():
            cache.write(md5.hexdigest() + '\n')

    # Validate instruction search pattern
    pattern = parse_pattern(pattern)

    # DEBUG
    if debug:
        print("[*] Parsing with:\n\t[+] " + pattern.replace('\n', "\n\t[+] "))
        print("[*] Loading angr project " + str(datetime.now()))

    # Create an angr instance
    angr_proj = angr.Project(path, load_options={"auto_load_libs": False}, main_opts={"base_addr": base, "arch": arch})
    time.sleep(5.0)

    # Get entry object of binary
    angr_main: cle.Backend = angr_proj.loader.main_object
    if angr_main is None:
        # DEBUG
        if debug:
            print("[!] Binary entry not detected ... exiting")

        # Close opened file and exit immediately
        cache.close()
        return

    # DEBUG
    if debug:
        print(f"[*] Loaded {angr_proj.filename}, {angr_proj.arch.name} {angr_proj.arch.memory_endness}")
        print(f"[*] Entry object {angr_main}; entry address {hex(angr_main.entry)}")

    # Open output file if needed
    file: TextIO = open(output, 'w') if (output is not None) else None

    if cache.writable():
        # DEBUG
        if debug:
            print("[*] CFGFast analysis initiated " + str(datetime.now()))

        # Create control flow graph for binary
        cfg: angr.analyses.CFGFast = angr_proj.analyses.CFGFast()

        # Serialize control flow graph
        graph_path = pathlib.Path("./cache/" + path.name + ".graph")
        with open(graph_path, "w") as graph_cache:
            for edge in angr_proj.kb.callgraph.edges:
                func1 = angr_proj.kb.functions.get_by_addr(edge[0])
                func2 = angr_proj.kb.functions.get_by_addr(edge[1])
                graph_cache.write(func1.name + ' ' + hex(edge[0]) + ';' + func2.name + ' ' + hex(edge[1]) + '\n')

        if debug:
            print("[*] Search initiated " + str(datetime.now()))
            if verbose:
                print()

        # Execute instruction pattern search
        search(angr_proj, cfg, pattern, file, cache, 1 if (depth is None or depth <= 0) else depth, verbose)
    else:
        # DEBUG
        if debug:
            print("[*] Search initiated " + str(datetime.now()))
            if verbose:
                print()

        # Import callgraph
        graph_path: pathlib.Path = pathlib.Path("./cache/" + path.name + ".graph")
        graph: networkx.DiGraph = networkx.DiGraph()
        names = dict()
        with open(graph_path, "r") as graph_cache:
            for line in graph_cache:
                line = line.strip().split(';')
                line1: List[str] = line[0].split(' ')
                line2: List[str] = line[1].split(' ')

                graph.add_edge(int(line1[1], 16), int(line2[1], 16))
                names[int(line1[1], 16)] = line1[0]
                names[int(line2[1], 16)] = line2[0]

        search_cached(angr_proj, pattern, file, cache, graph, names, 1 if (depth is None or depth <= 0) else depth,
                      verbose)

    # DEBUG
    if debug:
        print("[*] Closing files " + str(datetime.now()))

    # Close cache file
    cache.close()

    # Close output file if needed
    if output is not None:
        file.close()


if __name__ == "__main__":
    main()
