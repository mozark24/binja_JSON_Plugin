#!/usr/bin/env python
# Dated: 5 May 2018

# Runs via plugin in Binary Ninja (non-headless).  Recommend executing after performing Linear Sweep.
# Dumps all functions, basic blocks, and instruction properties into a JSON file.
# Instruction level = Medium-Level Intermediate Language (MLIL) resolves
#   flags, removes nops, resolves stack to variables and eliminates dead stores.
#   https://docs.binary.ninja/dev/bnil-llil/index.html#medium-level-il-instructions

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

def merge_two_dicts(x, y):
    z = x.copy()   # start with x's keys and values
    z.update(y)    # modifies z with y's keys and values & returns None
    return z


def json_extractor(bv):

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


    flowgraph = {}
    list_result = []
    for ind_func, func in enumerate(bv.functions):
        func_result = []
        for ind_block, block in enumerate(func.medium_level_il):
            block_result = []
            for ind_instr, instr in enumerate(block):                
                branch_list = str(instr.branch_dependence).strip('{}L>').split(': ')
                # getting vars_read results in exception if undefined
                try:
                    vars_read_list = []
                    vars_read_type = []
                    for i in range(len(instr.vars_read)):
                        vars_read_list.append(str(instr.vars_read[i]))
                        vars_read_type.append(str(instr.vars_read[i].type))
                    
                    # build_json(
                    #     block_result,
                    #     instr,
                    #     branch_list,
                    #     vars_written,
                    #     vars_written_type,
                    #     vars_read,
                    #     vars_read_type,
                    #     src,
                    #     dest = str(instr.dest),
                    #     test_str = 'full branch')
                    # There is a branch dependence property in these instrcts
                    if len(branch_list) is not 1:
                        branch_list[0] = branch_list[0].strip('L')
                        branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                        
                        block_result.append({
                            'index' : instr.instr_index,
                            'instr' : str(instr),
                            'asm_addr' : hex(instr.address).strip('L'),
                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                            'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                            'vars_read' : vars_read_list,
                            'vars_read_type' : vars_read_type,
                            'branch_dep_from' : branch_list[0],
                            'branch_dep_cond' : branch_list[1],
                            'dest' : str(instr.dest),
                            'poss_values' : str(instr.possible_values).strip('<>'),
                            'test': 'full branch',
                            'src' : str(instr.src)
                        })

                    else:
                        block_result.append({
                            'index' : instr.instr_index,
                            'instr' : str(instr),
                            'asm_addr' : hex(instr.address).strip('L'),
                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                            'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                            'vars_read' : vars_read_list,
                            'vars_read_type' : vars_read_type,
                            'dest' : str(instr.dest),
                            'poss_values' : str(instr.possible_values).strip('<>'),
                            'branch_dep_from' : "",
                            'branch_dep_cond' : "",
                            'test': 'full no branch',
                            'src' : str(instr.src)
                        })

                # vars_read results in exception if undefined
                # dest results if exception if undefined
                # vars_written.type 'list' object has no attribute 'type'
                # dest no attribute
                # src no attribute
                
                # No read
                except AttributeError:
                    try:
                        if len(branch_list) is not 1:
                            branch_list[0] = branch_list[0].strip('L')
                            branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                            
                            block_result.append({
                                'index' : instr.instr_index,
                                'instr' : str(instr),
                                'asm_addr' : hex(instr.address).strip('L'),
                                'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                'branch_dep_from' : branch_list[0],
                                'branch_dep_cond' : branch_list[1],
                                'poss_values' : str(instr.possible_values).strip('<>'),
                                'vars_read' : "",
                                'vars_read_type' : "",
                                'dest': str(instr.dest),
                                'src': str(instr.src).strip('[<il: >]'),
                                'test': 'AttrError branch'
                            })

                        else:
                            block_result.append({
                                'index' : instr.instr_index,
                                'instr' : str(instr),
                                'asm_addr' : hex(instr.address).strip('L'),
                                'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                'poss_values' : str(instr.possible_values).strip('<>'),
                                'vars_read' : "",
                                'vars_read_type' : "",
                                'dest': str(instr.dest),
                                'branch_dep_from' : "",
                                'branch_dep_cond' : "",
                                'src' : str(instr.src).strip('[<il: >]'),
                                'test': 'AttrError no branch'
                            })
                    # No dest
                    # With Read
                    except AttributeError:
                        try:
                            if len(branch_list) is not 1:
                                branch_list[0] = branch_list[0].strip('L')
                                branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : vars_read_type,
                                    'branch_dep_from' : branch_list[0],
                                    'branch_dep_cond' : branch_list[1],
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': "",
                                    'test': "AttrError AttrError branch",
                                    'src' : str(instr.src).strip('[<il: >]')
                                })

                            else:
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : "",
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': "",
                                    'src' : str(instr.src).strip('[<il: >]'),
                                    'branch_dep_from' : "",
                                    'branch_dep_cond' : "",
                                    'test': "AttrError AttrError no branch"
                                })
                        
                        # No src
                        except AttributeError:
                            if len(branch_list) is not 1:
                                branch_list[0] = branch_list[0].strip('L')
                                branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : vars_read_type,
                                    'branch_dep_from' : branch_list[0],
                                    'branch_dep_cond' : branch_list[1],
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': str(instr.dest),
                                    'test': "AttrError AttrError AttrError branch",
                                    'src' : ""
                                })

                            else:
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : vars_read_type,
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': str(instr.dest),
                                    'src' : "",
                                    'branch_dep_from' : "",
                                    'branch_dep_cond' : "",
                                    'test': "AttrError AttrError AttrError no branch"
                                })


                    # Write type fails after a read type fails  
                    except IndexError:
                        try:
                            if len(branch_list) is not 1:
                                branch_list[0] = branch_list[0].strip('L')
                                branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : "",
                                    'branch_dep_from' : branch_list[0],
                                    'branch_dep_cond' : branch_list[1],
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'vars_read' : "",
                                    'vars_read_type' : "",
                                    'dest': str(instr.dest),
                                    'test': 'AttrError IndError branch',
                                    'src' : str(instr.src).strip('[<il: >]')
                                })

                            else:
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : "",
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'vars_read' : "",
                                    'vars_read_type' : "",
                                    'dest': str(instr.dest),
                                    'branch_dep_from' : "",
                                    'branch_dep_cond' : "",
                                    'test': 'AttrError IndError no branch',
                                    'src' : str(instr.src).strip('[<il: >]')
                                })
                        # dest no attribute
                        # src no attribute
                        except AttributeError:
                            try:
                                if len(branch_list) is not 1:
                                    branch_list[0] = branch_list[0].strip('L')
                                    branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                    
                                    block_result.append({
                                        'index' : instr.instr_index,
                                        'instr' : str(instr),
                                        'asm_addr' : hex(instr.address).strip('L'),
                                        'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                        'vars_written_type' : "",
                                        'vars_read' : vars_read_list,
                                        'vars_read_type' : "",
                                        'branch_dep_from' : branch_list[0],
                                        'branch_dep_cond' : branch_list[1],
                                        'poss_values' : str(instr.possible_values).strip('<>'),
                                        'dest': "",
                                        'test': "AttrError IndError AttrError branch",
                                        'src' : str(instr.src).strip('[<il: >]')
                                    })

                                else:
                                    block_result.append({
                                        'index' : instr.instr_index,
                                        'instr' : str(instr),
                                        'asm_addr' : hex(instr.address).strip('L'),
                                        'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                        'vars_written_type' : "",
                                        'vars_read' : vars_read_list,
                                        'vars_read_type' : "",
                                        'poss_values' : str(instr.possible_values).strip('<>'),
                                        'dest': "",
                                        'src' : str(instr.src).strip('[<il: >]'),
                                        'branch_dep_from' : "",
                                        'branch_dep_cond' : "",
                                        'test': "AttrError IndError AttrError no branch"
                                    })
                            except AttributeError:
                                if len(branch_list) is not 1:
                                    branch_list[0] = branch_list[0].strip('L')
                                    branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                    
                                    block_result.append({
                                        'index' : instr.instr_index,
                                        'instr' : str(instr),
                                        'asm_addr' : hex(instr.address).strip('L'),
                                        'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                        'vars_written_type' : "",
                                        'vars_read' : vars_read_list,
                                        'vars_read_type' : "",
                                        'branch_dep_from' : branch_list[0],
                                        'branch_dep_cond' : branch_list[1],
                                        'poss_values' : str(instr.possible_values).strip('<>'),
                                        'dest': str(instr.dest),
                                        'test': "AttrError IndError AttrError AttrError AttrError branch",
                                        'src' : ""
                                    })
                                else:
                                        block_result.append({
                                            'index' : instr.instr_index,
                                            'instr' : str(instr),
                                            'asm_addr' : hex(instr.address).strip('L'),
                                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[1],
                                            'vars_written_type' : "",
                                            'vars_read' : vars_read_list,
                                            'vars_read_type' : "",
                                            'poss_values' : str(instr.possible_values).strip('<>'),
                                            'dest': str(instr.dest),
                                            'src' : "",
                                            'branch_dep_from' : "",
                                            'branch_dep_cond' : "",
                                            'test': "AttrError IndError AttrError AttrError AttrError no branch"
                                        })

                # vars_read_type is out of range
                # vars_written_type is out of range
                except IndexError:
                    try:
                        if len(branch_list) is not 1:
                            branch_list[0] = branch_list[0].strip('L')
                            branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                            
                            block_result.append({
                                'index' : instr.instr_index,
                                'instr' : str(instr),
                                'asm_addr' : hex(instr.address).strip('L'),
                                'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                'vars_written_type' : "",
                                'vars_read' : vars_read_list,
                                'vars_read_type' : vars_read_type,
                                'branch_dep_from' : branch_list[0],
                                'branch_dep_cond' : branch_list[1],
                                'poss_values' : str(instr.possible_values).strip('<>'),
                                'dest': str(instr.dest),
                                'test': 'IndError branch',
                                'src' : str(instr.src).strip('[<il: >]')
                            })

                        else:
                            block_result.append({
                                'index' : instr.instr_index,
                                'instr' : str(instr),
                                'asm_addr' : hex(instr.address).strip('L'),
                                'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                'vars_written_type' : "",
                                'vars_read' : vars_read_list,
                                'vars_read_type' : vars_read_type,
                                'poss_values' : str(instr.possible_values).strip('<>'),
                                'dest': str(instr.dest),
                                'branch_dep_from' : "",
                                'branch_dep_cond' : "",
                                'test': 'IndError no branch',
                                'src' : str(instr.src).strip('[<il: >]')
                            })
                        # No read_type, Yes write_type
                    except IndexError:
                        try:
                            if len(branch_list) is not 1:
                                branch_list[0] = branch_list[0].strip('L')
                                branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : "",
                                    'branch_dep_from' : branch_list[0],
                                    'branch_dep_cond' : branch_list[1],
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': str(instr.dest),
                                    'test': 'IndError IndError branch',
                                    'src' : str(instr.src).strip('[<il: >]')
                                })

                            else:
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : str(instr.vars_written[0].type).strip('[<>]').split(' ')[0],
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : "",
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': str(instr.dest),
                                    'branch_dep_from' : "",
                                    'branch_dep_cond' : "",
                                    'test': 'IndError IndError no branch',
                                    'src' : str(instr.src).strip('[<il: >]')
                                })
                            # No read_type, Yes write_type
                        except IndexError:
                            
                            if len(branch_list) is not 1:
                                branch_list[0] = branch_list[0].strip('L')
                                branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : "",
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : "",
                                    'branch_dep_from' : branch_list[0],
                                    'branch_dep_cond' : branch_list[1],
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': str(instr.dest),
                                    'test': 'IndError IndError IndError branch',
                                    'src' : str(instr.src).strip('[<il: >]')
                                })

                            else:
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : "",
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : "",
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': str(instr.dest),
                                    'branch_dep_from' : "",
                                    'branch_dep_cond' : "",
                                    'test': 'IndError IndError IndError no branch',
                                    'src' : str(instr.src).strip('[<il: >]')
                                })
                                
                    # dest case
                    except AttributeError:
                        try:
                            if len(branch_list) is not 1:
                                branch_list[0] = branch_list[0].strip('L')
                                branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : "",
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : vars_read_type,
                                    'branch_dep_from' : branch_list[0],
                                    'branch_dep_cond' : branch_list[1],
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': "",
                                    'test': "IndError AttrError branch",
                                    'src' : str(instr.src).strip('[<il: >]')
                                })

                            else:
                                block_result.append({
                                    'index' : instr.instr_index,
                                    'instr' : str(instr),
                                    'asm_addr' : hex(instr.address).strip('L'),
                                    'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                    'vars_written_type' : "",
                                    'vars_read' : vars_read_list,
                                    'vars_read_type' : vars_read_type,
                                    'poss_values' : str(instr.possible_values).strip('<>'),
                                    'dest': "",
                                    'src' : str(instr.src).strip('[<il: >]'),
                                    'branch_dep_from' : "",
                                    'branch_dep_cond' : "",
                                    'test': "IndError AttrError no branch"
                                })
                        except AttributeError:
                            try:

                                if len(branch_list) is not 1:
                                    branch_list[0] = branch_list[0].strip('L')
                                    branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                    
                                    block_result.append({
                                        'index' : instr.instr_index,
                                        'instr' : str(instr),
                                        'asm_addr' : hex(instr.address).strip('L'),
                                        'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                        'vars_written_type' : "",
                                        'vars_read' : vars_read_list,
                                        'vars_read_type' : vars_read_type,
                                        'branch_dep_from' : branch_list[0],
                                        'branch_dep_cond' : branch_list[1],
                                        'poss_values' : str(instr.possible_values).strip('<>'),
                                        'dest': str(instr.dest),
                                        'test': "IndError AttrError AttrError branch",
                                        'src' : ""
                                    })

                                else:
                                    block_result.append({
                                        'index' : instr.instr_index,
                                        'instr' : str(instr),
                                        'asm_addr' : hex(instr.address).strip('L'),
                                        'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                        'vars_written_type' : "",
                                        'vars_read' : vars_read_list,
                                        'vars_read_type' : vars_read_type,
                                        'poss_values' : str(instr.possible_values).strip('<>'),
                                        'dest': str(instr.dest),
                                        'src' : "",
                                        'branch_dep_from' : "",
                                        'branch_dep_cond' : "",
                                        'test': "IndError AttrError AttrError no branch"
                                    })
                            except AttributeError:
                                try:
                                    if len(branch_list) is not 1:
                                        branch_list[0] = branch_list[0].strip('L')
                                        branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                        
                                        block_result.append({
                                            'index' : instr.instr_index,
                                            'instr' : str(instr),
                                            'asm_addr' : hex(instr.address).strip('L'),
                                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                            'vars_written_type' : "",
                                            'vars_read' : vars_read_list,
                                            'vars_read_type' : vars_read_type,
                                            'branch_dep_from' : branch_list[0],
                                            'branch_dep_cond' : branch_list[1],
                                            'poss_values' : str(instr.possible_values).strip('<>'),
                                            'dest': "",
                                            'test': "IndError AttrError AttrError AttrError branch",
                                            'src' : ""
                                        })
                                    else:
                                        block_result.append({
                                            'index' : instr.instr_index,
                                            'instr' : str(instr),
                                            'asm_addr' : hex(instr.address).strip('L'),
                                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                            'vars_written_type' : "",
                                            'vars_read' : vars_read_list,
                                            'vars_read_type' : vars_read_type,
                                            'poss_values' : str(instr.possible_values).strip('<>'),
                                            'dest': "",
                                            'src' : "",
                                            'branch_dep_from' : "",
                                            'branch_dep_cond' : "",
                                            'test': "IndError AttrError AttrError AttrError no branch"
                                        })
                                except AttributeError:
                                    if len(branch_list) is not 1:
                                        branch_list[0] = branch_list[0].strip('L')
                                        branch_list[1] = branch_list[1].strip('<ILBranchDependence.')
                                                        
                                        block_result.append({
                                            'index' : instr.instr_index,
                                            'instr' : str(instr),
                                            'asm_addr' : hex(instr.address).strip('L'),
                                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                            'vars_written_type' : "",
                                            'vars_read' : vars_read_list,
                                            'vars_read_type' : "",
                                            'branch_dep_from' : branch_list[0],
                                            'branch_dep_cond' : branch_list[1],
                                            'poss_values' : str(instr.possible_values).strip('<>'),
                                            'dest': "",
                                            'test': "IndError AttrError AttrError AttrError AttrError branch",
                                            'src' : ""
                                        })
                                    else:
                                        block_result.append({
                                            'index' : instr.instr_index,
                                            'instr' : str(instr),
                                            'asm_addr' : hex(instr.address).strip('L'),
                                            'vars_written' : str(instr.vars_written).strip('[<>]').split(' ')[-1],
                                            'vars_written_type' : "",
                                            'vars_read' : vars_read_list,
                                            'vars_read_type' : "",
                                            'poss_values' : str(instr.possible_values).strip('<>'),
                                            'dest': "",
                                            'src' : "",
                                            'branch_dep_from' : "",
                                            'branch_dep_cond' : "",
                                            'test': "IndError AttrError AttrError AttrError AttrError no branch"
                                        })
            if bv.arch.name == 'x86':
                
                #str(func.basic_blocks)[13:-2].split('-')
                func_result.append({
                    'name': str(block)[12:-1], #.lstrip('<block: x86@').rstrip('>')),
                    'start': str(block)[12:-1].split('-')[0],
                    'end': str(block)[12:-1].split('-')[1],
                    'instructions': block_result
                })
            elif bv.arch.name == 'x86_64':
                
                func_result.append({
                    'name': str(block)[15:-1], #.lstrip('<block: x86_64@').rstrip('>'),
                    'instructions': block_result
                })
        if bv.arch.name == 'x86':
            list_result.append({
                'name': str(func)[11:-1], #.lstrip('<func: x86@').rstrip('>'),
                'basic_blocks': str(func.medium_level_il.basic_blocks).strip('[]'),
                'blocks': func_result
            })
        elif bv.arch.name == 'x86_64':
            list_result.append({
                'name': str(func)[14:-1], #.lstrip('<func: x86_64@').rstrip('>'),
                'basic_blocks': str(func.medium_level_il.basic_blocks).strip('[]'),
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


PluginCommand.register("Export to JSON", "Port all functions, bb, and il", json_extractor)
