import threading
import sys
# import signal
# # this is the heavy monkey-patching that actually works
# # i.e. you can start the kernel fine and connect to it e.g. via
# # ipython console --existing
# signal.signal = lambda *args, **kw: None

import gc
import os, sys
import binaryninja as bn
import ctypes
import json
from binaryninja import scriptingprovider
import tempfile

id = 0
current_addr = 0
current_view = ""

def serialize(obj):
    """JSON serializer for objects not serializable by default json code"""

    return obj.__dict__

def printJSONFile(data):

    fullpath = "C:\\Users\\Chris\\Documents\\Work\\PhD\\JavaScript\\Binja-NodeJS\\jsondata.json"

    json_dump = json.dumps(data, default=serialize)

    try:
        # fullpath = os.path.join(tempfile.gettempdir(), 'jsondata.json')
        
        jf = open(fullpath, "a+")
        # jf.seek(0)
        # jf.truncate()
        jf.write(json_dump + "\n")
        jf.close()
    except IOError:
        print "ERROR: Unable to open/write to {}".format(fullpath)
        return 


def setValue(bip, bv):
    global current_addr, selChanged, current_view
    valueChanged = current_addr != bip.current_addr
    viewChanged = current_view != bv.file.view
    if (valueChanged or viewChanged):
        update_ns(bip, bv, current_addr, current_view)
    current_addr = bip.current_addr
    current_view = bv.file.view


def update_ns(bip, bv, oldaddr, oldview):
    """Updates the namespace of the running kernel with the binja magic variables"""

    global id

    print("[+] Printing view updates!")
    # print("{}".format(bip.write_at_cursor))
    # print("{}".format(bip.get_selected_data))
    # print("{}".format(bip.current_view))
    print("File View: {}".format(bv.file.view))
    print("Current Func: {}".format(str(bip.current_func)[11:-1]))
    print("Current Block: {}".format(str(bip.current_block)[12:-1]))
    print("Current Addr: 0x{:x}".format(int(bip.current_addr)))
    print("Current Selection: 0x{:x}".format(int(bip.current_selection_begin)))
    # print("0x{0:x}, 0x{1:x}".format(int(bip.current_selection_begin), int(bip.current_selection_end)))
    # print(bip.current_func.low_level_il)
    # print(bip.current_func.medium_level_il)
    
    data = {
        'type': 'view',
        'bv.file.view': bv.file.view,
        # 'bip.current_func': str(bip.current_func)[11:-1],
        # 'bip.current_block': str(bip.current_block)[12:-1],
        'address': "0x{:x}".format(int(bip.current_addr)),
        'oldaddress': "0x{:x}".format(int(oldaddr)),
        'oldview': oldview
    }

    id += 1

    printJSONFile(data)

    

def start_watch(bv):

    obj = [o for o in gc.get_objects() if isinstance(o, scriptingprovider.PythonScriptingInstance.InterpreterThread)]
    if len(obj) == 1:
        bip = obj[0]
    else:
        raise Exception("Couldn't find scriptingprovider. Sure you are in the right kernel?")

    setValue(bip, bv)
    # update_ns(bip, bv)
    threading.Timer(1.0, start_watch, [bv]).start()


def func_name(bv, function):
    global id
    print('[*] Changing function <{name}>'.format(name=function.symbol.name))
    print('funcion: {}'.format(function))

    function_name = bn.get_text_line_input(
		"Change Function Name", "Enter function name:")

    data = {
        'type': 'func',
        'function': function.symbol.name,
        'func_addr': str(function)[11:-1],
        'new_function': function_name
    }

    id += 1
    function.name = function_name
    printJSONFile(data)

def make_comm(bv, address):
    global id
    print('[*] Changing comment <0x{name:x}>'.format(name=address))

    comment = bn.get_text_line_input(
		"Insert Comment", "Enter comment:")

    # text_f = bn.MultilineTextField("Insert Comment")
    # comment = bn.get_form_input(text_f, "the options")

    start_addr = bv.get_previous_function_start_before(int(address))
    print("start_addr: {}".format(start_addr))
    
    func = bv.get_function_at(int(start_addr))
    print("func: {}".format(func))

    oldcomm = func.get_comment_at(address)
    func.set_comment_at(address, comment)
    

    data = {
        'type': 'comment',
        'address': "0x{:x}".format(int(address)),
        'comment': comment,
        'oldcomment': oldcomm
    }

    id += 1
    printJSONFile(data)


bn.PluginCommand.register("Binja Print Interactions_2", "Binja Print Interactions_2", start_watch)
bn.PluginCommand.register_for_function("Binja Change function name", "Binja Change function name", func_name)
bn.PluginCommand.register_for_address("Binja Make comment", "Binja Make comment", make_comm)


