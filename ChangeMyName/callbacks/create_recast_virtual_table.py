import idaapi
import idc

from ChangeMyName.core.ida_strugle.virtual_table import VirtualTable
from ChangeMyName.core.ida_strugle import const, util

from . import actions


def define_all_vtables():
    segments = util.enum_all_segments()
    vtables_total = 0

    for segm in segments:
        addr = segm.start_ea
        while addr < segm.end_ea:
            funcs_counted = VirtualTable.check(addr)
            if funcs_counted:
                try:
                    print(
                        'Found possible vtable: %#x (%s) with %d functions' 
                        % (addr, 
                            repr(idaapi.get_ea_name(addr)),
                            funcs_counted
                            )
                        )

                    v = VirtualTable(addr)
                    v.import_to_idb()
                except Exception as e:
                    print('[!] An error occured due parsing vtable at %#x' % addr)
                    raise e
                
                addr+= funcs_counted * const.PTR_SIZE
                vtables_total+= 1
            addr+= const.PTR_SIZE

    print('[!] Imported %d virtual tables in total!' % vtables_total)


def create_vtable(address):
    try:
        v = VirtualTable(address)
        v.import_to_idb()
        print("Imported: %s" % v.type_name)
        return v.type_name
    except:
        print("Got an exception!")


class MakeVirtualTable(actions.Action):
    description    = "Create virtual table according to ida_strugle logic, at given address"
    hotkey         = "Shift-V"
    
    def __init__(self):
        super().__init__()


    def activate(self, ctx):
        # Called from disassembly view
        if ctx.widget_type == idaapi.BWN_DISASM:
            create_vtable(idc.here())
            
        # Called from pseudocode view
        else:
            vdui = idaapi.get_widget_vdui(ctx.widget)
            expr = vdui.item.e
            assert expr.op == idaapi.cot_obj, "Selected item isn't a cot_obj expression"
            create_vtable(expr.obj_ea)
            

    def update(self, ctx):
        if ctx.widget_type in (idaapi.BWN_DISASM, idaapi.BWN_PSEUDOCODE):
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET


class RecastFieldToVirtualTable(actions.Action):
    description = "Recast field to vtab* type"
    hotkey = "Ctrl-Alt-R"
    def __init__(self):
        super().__init__()

    def activate(self, ctx):
        vdui = idaapi.get_widget_vdui(ctx.widget)
        current_func = vdui.cfunc
        mptr = vdui.item.get_memptr()
        
        asg_expr = current_func.body.find_parent_of(vdui.item.e).cexpr
        if asg_expr.op != idaapi.cot_asg:
            print("[!] Parent expression isn't cot_asg")
            return

        parent_type = self._skip_casts(vdui.item.e.x).type
        sid = idaapi.get_struc_id(parent_type.dstr())
        sptr = idaapi.get_struc(sid)
        mptr = idaapi.get_member(sptr, vdui.item.e.m)
        
        vtable_obj = self._skip_nodes(asg_expr.y, [idaapi.cot_cast, idaapi.cot_ref])
        if vtable_obj.op != idaapi.cot_obj:
            print("[!] Rh-expression isn't cot_obj")
            return

        type_name = create_vtable(vtable_obj.obj_ea)
        if type_name is None:
            print("[!] Name of type returned from creation routine None or empty-string")
            return

        type_tinfo = idaapi.tinfo_t()
        type_tinfo.get_named_type(idaapi.cvar.idati, type_name)
        vtable_tinfo = idaapi.tinfo_t()
        vtable_tinfo.create_ptr(type_tinfo)
    

        # TODO: fix it, `idaapi.set_member_tinfo` returns -6 as error code.
        result = idaapi.set_member_tinfo(sptr, mptr, 0, vtable_tinfo, 0)
        if result == idaapi.SMT_OK:
            print("[*] Recasted successful to %s*" % type_name)
        else:
            print(result)

    def _skip_nodes(self, item, rejected):
        while item.op in rejected:
            item = item.x
        return item

    def _skip_casts(self, item):
        return self._skip_nodes(item, [idaapi.cot_cast])

    def update(self, ctx):
        if ctx.widget_type == idaapi.BWN_PSEUDOCODE:
            return idaapi.AST_ENABLE_FOR_WIDGET
        return idaapi.AST_DISABLE_FOR_WIDGET

actions.action_manager.register(MakeVirtualTable())
actions.action_manager.register(RecastFieldToVirtualTable())