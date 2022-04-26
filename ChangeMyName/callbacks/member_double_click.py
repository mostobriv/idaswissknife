import idaapi
import ida_hexrays
import ida_lines

from . import callbacks

def try_extract_address(node):
	pass

def cref_exists(addr_from, addr_to):
	cref_to = idaapi.get_first_cref_from(addr_from)
	while cref_to != idaapi.BADADDR:
		if cref_to == addr_to:
			return True		
		cref_to = idaapi.get_next_cref_from(addr_from, cref_to)

	return False


class MemberDoubleClick(callbacks.HexRaysEventHook):
	'''
	HexRays hook to track member double clicks and jump to according address of virtual functions.
	Also if ctrl key is pressed then cref will be added.
	'''
	def __init__(self):
		super().__init__()

	def double_click(self, vu, shift_state):
		if vu.item.citype == idaapi.VDI_EXPR:
			item = vu.item.it.to_specific_type

			if not isinstance(item, idaapi.cexpr_t):
				return 0

			expr = item
			if not expr.type.is_funcptr():
				# [!] Clicked item isn't a function pointer
				return 0

			struct_name = ""
			
			if expr.op == idaapi.cot_memptr: # x->e
				vtable_tinfo = expr.x.type
				if vtable_tinfo.is_ptr():
					vtable_tinfo = vtable_tinfo.get_pointed_object()
				struct_name = vtable_tinfo.get_type_name()

			elif expr.op == idaapi.cot_memref: # x.e
				vtable_tinfo = expr.x.type
				struct_name = vtable_tinfo.get_type_name()
			
			else:
				# [!] Not memref or memptr choosen
				return 0
				
			if len(struct_name) == 0:
				print("[!] Unable to locate structure name for some reason")
				return 0
					
			sid = idaapi.get_struc_id(struct_name)
			if sid == idaapi.BADADDR:
				return 0
				
			sptr = idaapi.get_struc(sid)
			mid = idaapi.get_member_id(sptr, expr.m)
			comment = idaapi.get_member_cmt(mid, False)
			func_ea = idaapi.BADADDR
			if comment:
				try:
					commented_address = int(comment, 16)
					func_ea = commented_address
				except ValueError:
					return 0

			if func_ea == idaapi.BADADDR:
				return 0
			
			if shift_state & idaapi.VES_CTRL:
				parent = vu.cfunc.body.find_parent_of(expr).it.to_specific_type
				while parent.op == idaapi.cot_cast:
					parent = vu.cfunc.body.find_parent_of(parent).it.to_specific_type
				
				if parent.op == idaapi.cot_call and parent.ea != idaapi.BADADDR and \
				   not cref_exists(parent.ea, func_ea) and idaapi.add_cref(parent.ea, func_ea, idaapi.fl_CN):
					
					print("[*] Added cref from %#x to %#x" % (parent.ea, func_ea))
			
			idaapi.jumpto(func_ea)
			return 1

		return 0

	def populating_popup(self, widget, popup_handle, vu):
		# TODO
		return 0


callbacks.hx_callback_manager.register(MemberDoubleClick())