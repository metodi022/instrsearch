import argparse
import hashlib
import pathlib
import time
from datetime import datetime
from typing import TextIO, List

import angr
import cle
import matplotlib
import networkx


def main():
    # Preparing command line argument parser
    args_parser = argparse.ArgumentParser()
    args_parser.add_argument("-p", "--path", help="path to binary file", type=pathlib.Path, required=True)
    args_parser.add_argument("-s", "--search", help="search function address in hex", type=(lambda x: int(x, 16)),
                             required=True)
    args_parser.add_argument("-b", "--base", help="base address of binary in hex", type=(lambda x: int(x, 16)),
                             required=False)
    args_parser.add_argument("-a", "--arch", help="architecture of binary", type=str, required=False)
    args_parser.add_argument("-o", "--output", help="output of directed graph to file", type=pathlib.Path,
                             required=False)
    args_parser.add_argument("-i", "--image", help="output of directed graph to image", type=pathlib.Path,
                             required=False)
    args_parser.add_argument("-d", "--debug", help="debug mode", action="store_true")
    args_parser.add_argument("-v", "--verbose", help="verbose print mode, output directed graph to console",
                             action="store_true")

    # Parse command line arguments
    args = vars(args_parser.parse_args())
    path: pathlib.Path = args.get("path")
    address: int = args.get("search")
    base: str = args.get("base")
    arch: str = args.get("arch")
    output: pathlib.Path = args.get("output")
    image: pathlib.Path = args.get("image")
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

    # DEBUG
    if debug:
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

    graph_path = pathlib.Path("./cache/" + path.name + ".graph")

    # Run analysis if needed
    if cache.writable():
        # DEBUG
        if debug:
            print("[*] CFGFast analysis initiated " + str(datetime.now()))

        cfg: angr.analyses.CFGFast = angr_proj.analyses.CFGFast()

        # Serialize control flow graph
        with open(graph_path, "w") as graph_cache:
            for edge in angr_proj.kb.callgraph.edges:
                func1 = angr_proj.kb.functions.get_by_addr(edge[0])
                func2 = angr_proj.kb.functions.get_by_addr(edge[1])
                graph_cache.write(func1.name + ',' + hex(edge[0]) + ';' + func2.name + ',' + hex(edge[1]) + '\n')

        # Serialize functions
        for func_addr in cfg.kb.functions:
            func: angr.knowledge_plugins.Function = cfg.kb.functions[func_addr]
            cache.write(func.serialize().hex() + '\n')

    # Close files
    cache.close()

    # DEBUG
    if debug:
        print("[*] Loading cache " + str(datetime.now()))

    # Deserialize graph
    graph: networkx.DiGraph = networkx.DiGraph()
    names = dict()
    with open(graph_path, "r") as graph_cache:
        for line in graph_cache:
            line = line.strip().split(';')
            line1: List[str] = line[0].split(',')
            line2: List[str] = line[1].split(',')

            graph.add_edge(int(line1[1], 16), int(line2[1], 16))
            names[int(line1[1], 16)] = line1[0]
            names[int(line2[1], 16)] = line2[0]

    # Initialize new sub-graph
    subgraph: networkx.DiGraph = networkx.DiGraph()

    # In case address is missing
    if address not in names:
        if debug:
            print("[*] No function found with this address")

        return

    if debug:
        print("[*] Searching callgraph " + str(datetime.now()))

    # DFS in reverse
    for entry in networkx.edge_dfs(graph, address, orientation="reverse"):
        addr1 = hex(entry[0])
        addr2 = hex(entry[1])
        subgraph.add_edge((names[entry[0]], addr1), (names[entry[1]], addr2))

        # Verbose mode
        if verbose:
            print(f"{names[entry[0]]} {addr1} -> {names[entry[1]]} {addr2}")

    # Output mode
    if output:
        with open(output, "w") as f:
            f.write(str(subgraph.edges))

    if image:
        networkx.draw(subgraph,
                      node_color=["tomato" if int(node[1], 16) == address else "cornflowerblue" for node in
                                  subgraph.nodes],
                      with_labels=True)
        matplotlib.pyplot.margins(0.35)
        matplotlib.pyplot.savefig(image)


if __name__ == "__main__":
    main()
