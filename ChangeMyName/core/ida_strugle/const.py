import idaapi

# from ida_strugle import util

from . import util



PTR_SIZE        = util.get_ptr_size()
BITS            = util.get_bitness()

VOID_TINFO      = None
PVOID_TINFO     = idaapi.tinfo_t()
CHAR_TINFO      = None
PCHAR_TINFO     = idaapi.tinfo_t()
BYTE_TINFO      = None
PBYTE_TINFO     = idaapi.tinfo_t()
WORD_TINFO      = None
PWORD_TINFO     = idaapi.tinfo_t()
DWORD_TINFO     = None
PDWORD_TINFO    = idaapi.tinfo_t()
QWORD_TINFO     = None
PQWORD_TINFO    = idaapi.tinfo_t()
XWORD_TINFO     = None
PXWORD_TINFO    = idaapi.tinfo_t()
DUMMY_FUNC      = idaapi.tinfo_t()

def init():
    VOID_TINFO  = idaapi.tinfo_t(idaapi.BTF_VOID) # make no sense lol `BT_VOID | 0`
    PVOID_TINFO.create_ptr(VOID_TINFO)

    CHAR_TINFO  = idaapi.tinfo_t(idaapi.BTF_CHAR)
    PCHAR_TINFO.create_ptr(idaapi.tinfo_t(CHAR_TINFO))

    BYTE_TINFO = idaapi.tinfo_t(idaapi.BTF_BYTE)
    PBYTE_TINFO.create_ptr(BYTE_TINFO)

    WORD_TINFO  = idaapi.get_unk_type(2)
    PWORD_TINFO.create_ptr(WORD_TINFO)

    DWORD_TINFO = idaapi.get_unk_type(4)
    PDWORD_TINFO.create_ptr(DWORD_TINFO)

    QWORD_TINFO = idaapi.get_unk_type(8)
    PQWORD_TINFO.create_ptr(QWORD_TINFO)

    XWORD_TINFO = idaapi.get_unk_type(util.get_bitness() >> 3)
    PXWORD_TINFO.create_ptr(XWORD_TINFO)

    func_data = idaapi.func_type_data_t()
    func_data.rettype = PVOID_TINFO
    func_data.cc = idaapi.CM_CC_UNKNOWN
    DUMMY_FUNC.create_func(func_data, idaapi.BT_FUNC)


    assert PVOID_TINFO.get_pointed_object() == VOID_TINFO
    assert PCHAR_TINFO.get_pointed_object() == CHAR_TINFO
    assert PBYTE_TINFO.get_pointed_object() == BYTE_TINFO
    assert PWORD_TINFO.get_pointed_object() == WORD_TINFO
    assert PDWORD_TINFO.get_pointed_object() == DWORD_TINFO
    assert PQWORD_TINFO.get_pointed_object() == QWORD_TINFO
    assert PXWORD_TINFO.get_pointed_object() == XWORD_TINFO

init()