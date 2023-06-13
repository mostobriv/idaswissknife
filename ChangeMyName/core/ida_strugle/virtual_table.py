import idaapi


from .structure import Structure, FunctionPointer
from . import util, const

class VirtualTable(Structure):

    def __init__(self, addr, offset=0):
        Structure.__init__(self, 'Vtable_%X' % addr, field_name='vtable_%X' % offset, offset=offset,)

        self.addr = addr

        self.populate()

    def populate(self):
        cur_addr = self.addr

        while True:
            if not FunctionPointer.check(util.get_ptr(cur_addr)):
                break

            self.add(FunctionPointer(util.get_ptr(cur_addr), offset=cur_addr - self.addr, comment=('%#x' % util.get_ptr(cur_addr))))
            cur_addr+= const.PTR_SIZE

            if len(idaapi.get_name(cur_addr)) != 0:
                break


    @staticmethod
    def check(addr, MIN_FUNCTIONS_REQUIRED=3):
        # 1 - name is defined here == has xref(s)
        # 2 - at least MIN_FUNCTIONS_REQUIRED valid function pointers
        # TODO: 3 - xref's going from instructions like `mov [reg_X], vtable_offset` / `lea reg_X, vtable_offset`

        # 1
        if len(idaapi.get_name(addr)) == 0:
            return False

        # 3
        # TODO

        # 2
        functions_counted = 0
        while True:
            if not FunctionPointer.check(util.get_ptr(addr + functions_counted * const.PTR_SIZE)):
                break

            functions_counted+= 1

            if len(idaapi.get_name(addr + functions_counted * const.PTR_SIZE)) != 0:
                break

        if functions_counted < MIN_FUNCTIONS_REQUIRED:
            return False

        return functions_counted