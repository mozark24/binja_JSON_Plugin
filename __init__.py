#!/usr/bin/env python
# Author:  Chris Henry
# Dated: 5 May 2018

# Runs via plugin in Binary Ninja.  Recommend executing after performing Linear Sweep.
# Dumps all functions, basic blocks, and instruction properties into a JSON file.
# Instruction level = Medium-Level Intermediate Language (MLIL) resolves
#   flags, removes nops, resolves stack to variables and eliminates dead stores.
#   https://docs.binary.ninja/dev/bnil-llil/index.html#low-level-il-instructions

import sys
import json
import os
import tempfile
import binaryninja as binja
from binaryninja.binaryview import BinaryViewType
import binaryninja.interaction as interaction
from binaryninja.plugin import PluginCommand
import binaryninja.log as log


def invert_dol_nonunique(d):
    newdict = {}
    for k in d:
        for v in d[k]:
            newdict.setdefault(v, []).append(k)
    return newdict

def instr_iterator(bv):

    filename = "" 
    if bv is None:
        if len(sys.argv) > 1:
            filename = sys.argv[1]
        else:
            filename = interaction.get_open_filename_input("Filename:")
            print filename
            if filename is None:
                log.log_warn("No file specified")
                sys.exit(1)

        bv = BinaryViewType.get_view_of_file(filename)
        log.log_to_stdout(True)

    #bv = binja.BinaryViewType.get_view_of_file(filename)  # No headless =/
    
    # Not sent to JSON log output
    binja.log_to_stdout(True)
    binja.log_info("-------- %s --------" % filename)
    binja.log_info("START: 0x%x" % bv.start)
    binja.log_info("ENTRY: 0x%x" % bv.entry_point)
    binja.log_info("ARCH: %s" % bv.arch.name)

    flowgraph = {}
    
    # TODO:  Insert xrefs of IAT symbols into instructions calling them
    # for function in bv.functions:
    #     flowgraph[function.symbol.name] = []
    #     for xref in bv.get_code_refs(function.symbol.address):
    #         if xref.function.symbol.name not in flowgraph[function.symbol.name]:
    #             flowgraph[function.symbol.name].append(xref.function.symbol.name)
    
    # Above loop loads backwards, so fix the key/value pairs.
    # inv_list = invert_dol_nonunique(flowgraph)   
    # flowgraph = inv_list

    flowgraph = {}
    list_result = []
    for func in bv.functions:
        func_result = []
        for block in func.medium_level_il:
            block_result = []
            for instr in block:
                block_result.append({
                    'index' : str(instr.instr_index),
                    'instr' : str(instr),
                    'asm_addr' : str(hex(instr.address)).strip('L')
                })
            func_result.append({
                'name': str(block).strip('<block: >'),
                'instructions': block_result,
            })
        list_result.append({
            'name': str(func).strip('<func: >'),
            'blocks': func_result
        })
    flowgraph = {
        'functions': list_result
    }
    
    target_json = json.dumps(flowgraph, default=lambda o: o.__dict__, indent=4, sort_keys=True)
    
    try:
        jf = None
        fullpath = os.path.join(tempfile.gettempdir(), 'data.json')
        jf = open(fullpath, "w")
        jf.write(target_json)
        jf.close()
    except IOError:
        print "ERROR: Unable to open/write to /tmp/data.json" #.format(basename(filename))
        return #target_json


PluginCommand.register("Create JSON", "Port all functions, bb, and il", instr_iterator)