#!/usr/bin/env python

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

def json_iterator(bv):

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
                    'index' : instr.instr_index,
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
    
    json_dump = json.dumps(flowgraph, default=lambda o: o.__dict__, indent=4, sort_keys=True)
    
    try:
        jf = None
        fullpath = os.path.join(tempfile.gettempdir(), 'data.json')
        jf = open(fullpath, "w")
        jf.write(json_dump)
        jf.close()
    except IOError:
        print "ERROR: Unable to open/write to {}".format(fullpath)
        return 


PluginCommand.register("Export to JSON", "Port all functions, bb, and il", json_iterator)