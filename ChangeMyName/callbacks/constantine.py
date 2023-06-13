import idaapi
import ida_hexrays
import ida_lines
import idc

from . import actions



class Constantine(actions.Action):
	hotkey = "Shift-C"
	description = "Toogle const specificator"

	def __init__(self):
		super().__init__()

	def activate(self, ctx):
		vdui = idaapi.get_widget_vdui(ctx.widget)
		if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
			if vdui.item.citype != idaapi.VDI_EXPR:
				return
			
			expr = vdui.item.e
			if expr.op == idaapi.cot_obj:
				tinfo = expr.type
				if tinfo.is_const():
					return
				
				const_tinfo = idaapi.tinfo_t(tinfo)
				const_tinfo.clr_volatile()
				const_tinfo.set_const()

				idc.SetType(expr.obj_ea, const_tinfo.dstr())
				# vdui.refresh_view(True)
				

		elif ctx.widget_type == idaapi.BWN_DISASM:

			raise NotImplementedError("Handling of Constantine not yet enabled for BWN_DISASM")
		else:
			# Guess we can't fall to this branch, because of update result
			return

	def update(self, ctx):
		if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
			return idaapi.AST_ENABLE_FOR_WIDGET
		return idaapi.AST_DISABLE_FOR_WIDGET

actions.action_manager.register(Constantine())