import idaapi
import ida_hexrays
import ida_lines

from ChangeMyName.forms import MyChoose
from . import actions
 

def get_line_items(vdui, lnnum):
	items = []
	pc = vdui.cfunc.get_pseudocode()
	if lnnum >= len(pc):
		return items
	line = pc[lnnum].line
	tag = ida_lines.COLOR_ON + chr(ida_lines.COLOR_ADDR)
	pos = line.find(tag)
	while pos != -1 and len(line[pos+len(tag):]) >= ida_lines.COLOR_ADDR_SIZE:
		addr = line[pos+len(tag):pos+len(tag)+ida_lines.COLOR_ADDR_SIZE]
		idx = int(addr, 16)
		a = ida_hexrays.ctree_anchor_t()
		a.value = idx
		if a.is_valid_anchor() and a.is_citem_anchor():
			item = vdui.cfunc.treeitems.at(a.get_index())
			if item:
				items.append(item)
		pos = line.find(tag, pos+len(tag)+ida_lines.COLOR_ADDR_SIZE)
	return items


class GetCasesOfSwitch(actions.HexRaysPopupAction):
	description = "Get cases of switch"

	def __init__(self):
		super().__init__()
 
	def activate(self, ctx):
		vdui = idaapi.get_widget_vdui(ctx.widget)

		if vdui.item.citype == idaapi.VDI_EXPR:
			if vdui.item.it.op == idaapi.cit_switch:
				switch_insn = vdui.item.it.cinsn
			else:
				switch_insn = self.find_parent_switch_of(vdui.item.it, vdui.cfunc)
		else:
			items = get_line_items(vdui, vdui.cpos.lnnum)
			if items[-1].op == idaapi.cit_switch:
				switch_insn = items[-1].cinsn
			else:
				switch_insn = self.find_parent_switch_of(items[-1], vdui.cfunc)
		
		if switch_insn is None:
			return
			
		switch = switch_insn.cswitch
			 
		concrete_cases, default_case = self.fetch_cases(switch)
 
		chooser_cases = [['%#x' % address, 'case %d: // %#x' % (value, value)] for address, value in concrete_cases]
		if default_case is not None:
			chooser_cases.append(['%#x' % default_case[0], "default:"])
 
		case_chooser = MyChoose(chooser_cases,
								"Cases of switch at %#x" % switch_insn.ea,
								[["Address", 10 | MyChoose.CHCOL_HEX], ["Case value", 20]]
						)
		idx = case_chooser.Show(True)
		if idx != -1:
			idaapi.jumpto((concrete_cases + [default_case])[idx][0])
 
	def fetch_cases(self, cswitch) -> list:
		concrete_cases = list()
		default_case = None
		for case in cswitch.cases:
			# concrete-value case
			if len(case.values) > 0:
				for value in case.values:
					concrete_cases.append((case.ea, value))
 
			# default case
			else:
				default_case = (case.ea, None)
 
		return concrete_cases, default_case
 
	def check(self, vdui) -> bool:
		if vdui.item.citype == idaapi.VDI_EXPR and vdui.item.i.op == idaapi.cit_switch:
			return True
 
		items = get_line_items(vdui, vdui.cpos.lnnum)
		if len(items) == 0:
			return False

		return self.find_parent_switch_of(items[-1], vdui.cfunc) is not None or items[-1].op == idaapi.cit_switch
 
	def find_parent_switch_of(self, item, cfunc):
		while item != cfunc.body:
			item = cfunc.body.find_parent_of(item)
			if item is None:
				return None
			item = item.to_specific_type
			if item.op == idaapi.cit_switch:
				return item
 
		return None

actions.action_manager.register(GetCasesOfSwitch())