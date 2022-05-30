import idaapi
import idautils

from . import callbacks
from ChangeMyName.forms import MyChoose


class MsgSendDoubleClick(callbacks.HexRaysEventHook):
	def __init__(self):
		super().__init__()
		self.__functions_cache = list()

	def double_click(self, vu, shift_state):
		if vu.item.citype == idaapi.VDI_EXPR:
			item = vu.item.it.to_specific_type

			if not isinstance(item, idaapi.cexpr_t):
				return 0
			
			# check if clicked foo() expr
			parent_item = vu.cfunc.body.find_parent_of(item).to_specific_type
			if not isinstance(parent_item, idaapi.cexpr_t):
				return 0

			if item.op != idaapi.cot_obj or parent_item.op != idaapi.cot_call:
				return 0

			if idaapi.get_name(item.obj_ea) != '_objc_msgSend':
				return 0

			self.__update_functions_cache()

			args = parent_item.a
			if len(args) < 2 and args[1].op != idaapi.cot_obj:
				return 0
			
			method_name = idaapi.get_strlit_contents(args[1].obj_ea, -1, idaapi.STRTYPE_C)
			if len(method_name) == 0:
				return 0

			
			candidates = self.find_method_candidates(method_name)
			if len(candidates) == 0:
				return 0
				
			preview_candidates = [('%#x' % address, name) for address, name in candidates]
			candidate_chooser = MyChoose(preview_candidates,
						"Possible candidates",
						[["Address", 10 | MyChoose.CHCOL_HEX], ["Function name", 64]]
				)
			idx = candidate_chooser.Show(True)
			if idx == -1:
				return 0

			idaapi.jumpto(candidates[idx][0])
			return 1

		return 0

	def find_method_candidates(self, candidate_name):
		candidates = list()
		for address, name in self.__functions_cache:
			if name.endswith(candidate_name.decode()+']'):
				candidates.append((address, name))
		
		return candidates

	def __update_functions_cache(self):
		if len(self.__functions_cache) != idaapi.get_func_qty():
			self.__functions_cache.clear()
			for address in idautils.Functions():
				name = idaapi.get_name(address)
				if name[0] in ['+', '-'] and name[1] == '[' and name[-1] == ']':
					self.__functions_cache.append((address, name))


callbacks.hx_callback_manager.register(MsgSendDoubleClick())
