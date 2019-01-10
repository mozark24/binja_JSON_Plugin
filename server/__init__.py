'''
1. Load Binary Ninja
2. Verify no errors in start-up
3. Open executable for analysis
4. Tools > Start server
5. View > Script console  (Ctrl + `)
6. Enter:
import xmlrpclib
s = xmlrpclib.ServerProxy('http://localhost:1337')
7. Access commands:
s.SetColor('0x40101b','0xfff000')
s.Jump('0x40101b', 'Graph:PE')
s.SetFunc('0x401477', 'NewFunc')
s.MakeComm('0x40101b','Test Comment')
s.Undo()
s.version()
s.shutdown()
s.system.listMethods()
['Jump', 'MakeComm', 'SetColor', 'Sync', 'shutdown', 'system.listMethods', 'system.methodHelp', 'system.methodSignature', 'version']

8. Get view of main screen:
print bv.file.view
9.  Change view of main screen:
>>> bv.file.view = 'Linear:PE'
>>> bv.file.view = 'Strings:PE'
>>> bv.file.view = 'Strings:PE'
>>> bv.file.view = 'Hex:PE'

'''
from collections import OrderedDict
from SimpleXMLRPCServer import SimpleXMLRPCRequestHandler, SimpleXMLRPCServer, list_public_methods

import threading, string, inspect, xmlrpclib, copy, socket
import binaryninja as bn

HOST, PORT = "0.0.0.0", 1337
DEBUG = True
HL_NO_COLOR = bn.HighlightStandardColor.NoHighlightColor
HL_BP_COLOR = bn.HighlightStandardColor.RedHighlightColor
HL_CUR_INSN_COLOR = bn.HighlightStandardColor.GreenHighlightColor

started = False
t = None
#_breakpoints = set()
_current_instruction = 0

PAGE_SZ = 0x1000

def expose(f):
	"Decorator to set exposed flag on a function."
	f.exposed = True
	return f

def is_exposed(f):
	"Test whether another function should be publicly exposed."
	return getattr(f, 'exposed', False)

def ishex(s):
	return s.startswith("0x") or s.startswith("0X")

	
def start_service(host, port, bv):
	print("[+] Starting service on {}:{}".format(host, port))
	server = SimpleXMLRPCServer((host, port),
								requestHandler=RequestHandler,
								logRequests=False,
								allow_none=True)
	server.register_introspection_functions()
	server.register_instance(Bookmark(server, bv))
	print("[+] Registered {} functions.".format( len(server.system_listMethods()) ))
	while True:
		if hasattr(server, "shutdown") and server.shutdown==True: break
		server.handle_request()
	return

def start_server(bv):
	global t, started
	t = threading.Thread(target=start_service, args=(HOST, PORT, bv))
	t.daemon = True
	print("[+] Creating new thread {}".format(t.name))
	t.start()

	if not started:
		create_binja_menu()
		started = True
	return

def stop_server(bv):
	global t
	t.join()
	t = None
	print("[+] Server stopped")
	return

def server_start_stop(bv):
	if t is None:
		start_server(bv)
		bn.show_message_box("Serv","Service successfully started, you can now connect to it",
						 bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.InformationIcon)
						 
	else:
		try:
			cli = xmlrpclib.ServerProxy("http://{:s}:{:d}".format(HOST, PORT))
			cli.shutdown()
		except socket.error:
			pass
		stop_server(bv)
		bn.show_message_box("Serv", "Service successfully stopped",
						 bn.MessageBoxButtonSet.OKButtonSet, bn.MessageBoxIcon.InformationIcon)
	return

class Bookmark:
	"""
	Top level class where exposed methods are declared.
	"""
	
	def __init__(self, server, bv, *args, **kwargs):
		self.server = server
		self.view = bv
		self.base = bv.entry_point & ~(PAGE_SZ-1)
		self._version = ("Binary Ninja", bn.core_version)
		self.old_bps = set()
		return


	def _dispatch(self, method, params):
		"""
		Plugin dispatcher
		"""
		func = getattr(self, method)
		if not is_exposed(func):
			raise NotImplementedError('Method "%s" is not exposed' % method)

		if DEBUG:
			print("[+] Executing %s(%s)" % (method, params))
		return func(*params)


	def _listMethods(self):
		"""
		Class method listing (required for introspection API).
		"""
		m = []
		for x in list_public_methods(self):
			if x.startswith("_"): continue
			if not is_exposed( getattr(self, x) ): continue
			m.append(x)
		return m


	def _methodHelp(self, method):
		"""
		Method help (required for introspection API).
		"""
		f = getattr(self, method)
		return inspect.getdoc(f)


	@expose
	def shutdown(self):
		""" shutdown() => None
		Cleanly shutdown the XML-RPC service.
		Example: binaryninja shutdown
		"""
		self.server.server_close()
		print("[+] XMLRPC server stopped")
		setattr(self.server, "shutdown", True)
		return 0

	@expose
	def version(self):
		""" version() => None
		Return a tuple containing the tool used and its version
		Example: binaryninja version
		"""
		return self._version

	@expose
	def Undo(self):
		""" Undo() => None
		Undo most recent action
		Example: binaryninja Undo 
		"""
		return self.view.undo()

	@expose
	def SetFunc(self, address, funcName):
		""" SetFunc(int address, string funcName) => None
		Set Function name address to string
		Example: binaryninja SetFunc '0x401477' new
		"""
		self.view.get_function_at(int(address,16)).name = funcName
		return self.view.get_function_at(int(address,16)).name
		
	@expose
	def Jump(self, address, view):
		""" Jump(int addr) => None
		Move the EA pointer to the address pointed by `addr`.
		Example: binaryninja Jump '0x4049de' PE:Graph
		"""
		addr = long(address, 16) if ishex(address) else long(address)
		return self.view.file.navigate(view, addr)

	@expose
	def MakeComm(self, address, comment):
		""" MakeComm(int addr, string comment) => None
		Add a comment at the location `address`.
		Example: binaryninja MakeComm 0x40000 "Important call here!"
		"""
		addr = long(address, 16) if ishex(address) else long(address)
		start_addr = self.view.get_previous_function_start_before(addr)
		func = self.view.get_function_at(start_addr)
		return func.set_comment(addr, comment)

	@expose
	def SetColor(self, address, color):
		""" SetColor(int addr [, int color]) => None
		Set the location pointed by `address` with `color`.
		Example: binaryninja SetColor 0x40000 0xff0000
		"""
		addr = long(address, 16) if ishex(address) else long(address)
		color = long(color, 16) if ishex(color) else long(color)
		R,G,B = (color >> 16)&0xff, (color >> 8)&0xff, (color&0xff)
		color = bn.highlight.HighlightColor(red=R, green=G, blue=B)
		return hl(self.view, addr, color)

		
	@expose
	def Sync(self, off, added, removed):
		""" Sync(off, added, removed) => None
		Synchronize debug info with gef. This is an internal function. It is
		not recommended using it from the command line.
		"""
		global _current_instruction # ,_breakpoints

		# we use long() for pc because if using 64bits binaries might create
		# OverflowError for XML-RPC service
		off = long(off, 16) if ishex(off) else long(off)
		pc = self.base + off
		if DEBUG: print("[*] current_pc=%#x , old_pc=%#x" % (pc, _current_instruction))

		# unhighlight the _current_instruction
		if _current_instruction > 0:
			hl(self.view, _current_instruction, HL_NO_COLOR)
		hl(self.view, pc, HL_CUR_INSN_COLOR)

		# update the _current_instruction
		_current_instruction = pc

		if DEBUG:
			print("[*] pre-gdb-add-breakpoints: %s" % (added,))
			print("[*] pre-gdb-del-breakpoints: %s" % (removed,))
			#print("[*] pre-binja-breakpoints: %s" % (_breakpoints))

		#bn_added = [ x-self.base for x in _breakpoints if x not in self.old_bps ]
		#bn_removed = [ x-self.base for x in self.old_bps if x not in _breakpoints ]

		for bp in added:
			gef_add_breakpoint_to_list(self.view, self.base + bp)

		for bp in removed:
			gef_del_breakpoint_from_list(self.view, self.base + bp)

		#self.old_bps = copy.deepcopy(_breakpoints)

		if DEBUG:
			print("[*] post-gdb-add-breakpoints: %s" % (bn_added,))
			print("[*] post-gdb-del-breakpoints: %s" % (bn_removed,))
			#print("[*] post-binja-breakpoints: %s" % (_breakpoints,))
		return [bn_added, bn_removed]

		
class RequestHandler(SimpleXMLRPCRequestHandler):
	rpc_paths = ("/RPC2",)
	
	def do_OPTIONS(self):
		self.send_response(200)
		self.end_headers()

	# Add these headers to all responses
	def end_headers(self):
		self.send_header("Access-Control-Allow-Headers", 
						 "Origin, X-Requested-With, Content-Type, Accept")
		self.send_header("Access-Control-Allow-Origin", "*")
		SimpleXMLRPCRequestHandler.end_headers(self)
	

			
def hl(bv, addr, color):
	if DEBUG: print("[*] hl(%#x, %s)" % (addr, color))
	start_addr = bv.get_previous_function_start_before(addr)
	func = bv.get_function_at(start_addr)
	if func is None: return
	func.set_user_instr_highlight(addr, color)
	return

def create_bookmark(view, address):
	try:
		bookmarks = view.query_metadata('bookmarks')
	except KeyError:
		bookmarks = OrderedDict()
		view.store_metadata('bookmarks', bookmarks)

	bookmark_name = bn.get_text_line_input(
		"Create new bookmark", "Enter bookmark name:"
	)
	if bookmark_name:
		bookmarks[address] = bookmark_name
		view.store_metadata("bookmarks", bookmarks)
		view.modified = True
		
def goto_bookmark(view):
	try:
		bookmarks = view.query_metadata('bookmarks')
	except KeyError:
		bookmarks = OrderedDict()
		view.store_metadata('bookmarks', bookmarks)

	if not bookmarks:
		bn.show_message_box(
			'Bookmark error', 'There are no bookmarks yet.',
			icon=bn.enums.MessageBoxIcon.ErrorIcon
		)
		return

	# Metadata can only store string keys in dictionaries currently.
	# Therefore, we have to convert keys to integers.
	chosen_bookmark = bn.get_choice_input(
		'Go to bookmark', 'Bookmarks:',
		['0x{:x} {}'.format(int(addr), bookmark)
		 for addr, bookmark in bookmarks.iteritems()]
	)

	# Again, we hae to convert string keys to integers.
	if chosen_bookmark is not None:
		navigate_to = int(bookmarks.keys()[chosen_bookmark])

		view.file.navigate(view.file.view, navigate_to)

def create_binja_menu():
	# Binja does not really support menu in its GUI just yet
	bn.PluginCommand.register_for_address("Serv : add bookmark",
									   "Add a serv bookmark at the specified location.",
									   create_bookmark)
	bn.PluginCommand.register("Serv : goto bookmark",
									   "Remove a serv bookmark at the specified location.",
									   goto_bookmark)
	return

	
bn.PluginCommand.register("Start/Stop XML Server", "Start/Stop XML Server.", server_start_stop)
#bn.PluginCommand.register('Go to server Bookmark', 'Go to a server bookmark.', goto_bookmark)