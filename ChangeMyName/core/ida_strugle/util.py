import idaapi
import idc


def is_code_ea(ea):
    if idaapi.cvar.inf.procname == "ARM":
        flags = idc.get_full_flags(ea & -2)  # flags_t
    else:
        flags = idc.get_full_flags(ea)
    return idc.is_code(flags)


def is_func_start(ea):
    if idaapi.cvar.inf.procname == "ARM":
        flags = idc.get_full_flags(ea & -2)  # flags_t
    else:
        flags = idc.get_full_flags(ea)

    return (flags & idc.MS_CODE) & idc.FF_FUNC
    
def is_valid_ea(ea):
    return idc.get_full_flags(ea) != 0

def get_bitness():
    info = idaapi.get_inf_structure()
    if info.is_64bit():
        bitness = 64
    elif info.is_32bit():
        bitness = 32
    else:
        raise NotImplementedError

    return bitness


def get_ptr_size():
    return get_bitness() >> 3


def get_ptr(ea):
    """ Reads ptr at specified address. """
    if get_bitness() == 64:
        return idaapi.get_64bit(ea)

    ptr = idaapi.get_32bit(ea)
    if idaapi.cvar.inf.procname == "ARM":
        ptr &= -2    # Clear thumb bit
    return ptr


def enum_all_segments():
    segm = idaapi.get_first_seg()
    segments = list()
    while segm is not None:
        segments.append(segm)
        segm = idaapi.get_next_seg(segm.start_ea)

    return segments