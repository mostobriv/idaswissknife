from dataclasses import dataclass
import typing
import re

import idaapi

from ChangeMyName.forms import MyChoose
from . import actions


@dataclass
class CollectedEntry:
    address: int
    expression: str

    def __init__(self, address, expression):
        self.address = address
        self.expression = expression


class CallVisitor(idaapi.ctree_visitor_t):
    def __init__(self):
        super().__init__(idaapi.CV_FAST)
        self.collected = list()

    def visit_expr(self, expr: idaapi.cexpr_t):
        if expr.op != idaapi.cot_call:
            return 0

        if self.should_be_included(expr):
            self.collected.append(CollectedEntry(expr.ea, idaapi.tag_remove(expr.print1(None))))

        return 0
    
    def should_be_included(self, expr: idaapi.cexpr_t) -> bool:
        # TODO: complete list of ida's inline helpers, which is makes no sense for us to keep track of.
        pattern = re.compile(r"[A-Z]*WORD\d?|[A-Z]*BYTE\d?|COERCE_.+|__ROL\d*__|__ROR\d*__|__S?PAIR\d*__")

        if expr.x.op != idaapi.cot_helper:
            return True
        
        helper_name = expr.x.helper
        return not bool(pattern.match(helper_name))
        
def collect_calls(root_expr: idaapi.citem_t) -> list[CollectedEntry]: 
    visitor = CallVisitor()
    visitor.apply_to(root_expr, None)
    return visitor.collected


class ShowOutgoingCalls(actions.HexRaysPopupAction):
    description = "Show outgoing calls"

    def __init__(self):
        super().__init__()

    def activate(self, ctx) -> None:
        vdui = idaapi.get_widget_vdui(ctx.widget)
        root_expr = vdui.cfunc.body
        calls = sorted(collect_calls(root_expr), key=lambda x: x.address)
        max_expr_len = max(calls, key=lambda x: len(x.expression)).address
        prepared_calls = [('%#x' % c.address, c.expression) for c in calls]

        
        call_chooser = MyChoose(prepared_calls,
							"Outgoing calls of %s" % idaapi.get_ea_name(ctx.cur_func.start_ea),
							[["Address", 10 | MyChoose.CHCOL_HEX], ["Call expression", min(max_expr_len, 32)]]
						)
        idx = call_chooser.Show(True)
        if idx != -1:
            idaapi.jumpto(calls[idx].address)

    def check(self, vdui) -> bool:
        return True

actions.action_manager.register(ShowOutgoingCalls())
