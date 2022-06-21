import idaapi
import idautils

from . import callbacks
from ChangeMyName.forms import MyChoose

from collections import defaultdict
import re


OBJC_FUNCNAME_PATTERN = re.compile(r"(?<=[-+]\[)[\w_:]+ ([\w_:]+)(?=\])")

class MsgSendDoubleClick(callbacks.HexRaysEventHook):
	def __init__(self):
		super().__init__()
		self.__functions_cache = defaultdict(list)
		self.__previously_revised = 0

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
			
			method_name = idaapi.get_strlit_contents(args[1].obj_ea, -1, idaapi.STRTYPE_C).decode()
			if len(method_name) == 0:
				return 0

			
			candidates = self.find_method_candidates(method_name)
			if len(candidates) == 0:
				return 0
				

			if len(candidates) == 1:
				idaapi.jumpto(candidates[0][0])
				return 1

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
		return self.__functions_cache[candidate_name]

	def __update_functions_cache(self):
		if self.__previously_revised != idaapi.get_func_qty():
			self.__previously_revised = idaapi.get_func_qty()
			self.__functions_cache.clear()
			for address in idautils.Functions():
				name = idaapi.get_name(address)
				match_result = OBJC_FUNCNAME_PATTERN.search(name)
				if match_result:
					self.__functions_cache[match_result.group(1)].append((address, name))


callbacks.hx_callback_manager.register(MsgSendDoubleClick())
