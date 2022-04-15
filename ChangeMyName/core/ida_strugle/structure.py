# -*- coding: utf-8 -*-

import idaapi
import idautils
import idc

from ida_strugle import const
from ida_strugle import util


import re
from collections import defaultdict


BAD_C_NAME_PATTERN = re.compile('[^a-zA-Z_0-9:]')


def demangled_name_to_c_str(name):
    """
    Removes or replaces characters from demangled symbol so that it was possible to create legal C structure from it
    """
    if not BAD_C_NAME_PATTERN.findall(name):
        return name

    # FIXME: This is very ugly way to find and replace illegal characters
    idx = name.find("::operator")
    if idx >= 0:
        idx += len("::operator")
        if idx == len(name) or name[idx].isalpha():
            # `operator` is part of name of some name and not a keyword
            pass
        elif name[idx:idx + 2] == "==":
            name = name.replace("operator==", "operator_EQ_")
        elif name[idx:idx + 2] == "!=":
            name = name.replace("operator!=", "operator_NEQ_")
        elif name[idx] == "=":
            name = name.replace("operator=", "operator_ASSIGN_")
        elif name[idx:idx + 2] == "+=":
            name = name.replace("operator+=", "operator_PLUS_ASSIGN_")
        elif name[idx:idx + 2] == "-=":
            name = name.replace("operator-=", "operator_MINUS_ASSIGN_")
        elif name[idx:idx + 2] == "*=":
            name = name.replace("operator*=", "operator_MUL_ASSIGN_")
        elif name[idx:idx + 2] == "/=":
            name = name.replace("operator/=", "operator_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "%=":
            name = name.replace("operator%=", "operator_MODULO_DIV_ASSIGN_")
        elif name[idx:idx + 2] == "|=":
            name = name.replace("operator|=", "operator_OR_ASSIGN_")
        elif name[idx:idx + 2] == "&=":
            name = name.replace("operator&=", "operator_AND_ASSIGN_")
        elif name[idx:idx + 2] == "^=":
            name = name.replace("operator^=", "operator_XOR_ASSIGN_")
        elif name[idx:idx + 3] == "<<=":
            name = name.replace("operator<<=", "operator_LEFT_SHIFT_ASSIGN_")
        elif name[idx:idx + 3] == ">>=":
            name = name.replace("operator>>=", "operator_RIGHT_SHIFT_ASSIGN_")
        elif name[idx:idx + 2] == "++":
            name = name.replace("operator++", "operator_INC_")
        elif name[idx:idx + 2] == "--":
            name = name.replace("operator--", "operator_PTR_")
        elif name[idx:idx + 2] == "->":
            name = name.replace("operator->", "operator_REF_")
        elif name[idx:idx + 2] == "[]":
            name = name.replace("operator[]", "operator_IDX_")
        elif name[idx] == "*":
            name = name.replace("operator*", "operator_STAR_")
        elif name[idx:idx + 2] == "&&":
            name = name.replace("operator&&", "operator_LAND_")
        elif name[idx:idx + 2] == "||":
            name = name.replace("operator||", "operator_LOR_")
        elif name[idx] == "!":
            name = name.replace("operator!", "operator_LNOT_")
        elif name[idx] == "&":
            name = name.replace("operator&", "operator_AND_")
        elif name[idx] == "|":
            name = name.replace("operator|", "operator_OR_")
        elif name[idx] == "^":
            name = name.replace("operator^", "operator_XOR_")
        elif name[idx:idx + 2] == "<<":
            name = name.replace("operator<<", "operator_LEFT_SHIFT_")
        elif name[idx:idx + 2] == ">>":
            name = name.replace("operator>", "operator_GREATER_")
        elif name[idx:idx + 2] == "<=":
            name = name.replace("operator<=", "operator_LESS_EQUAL_")
        elif name[idx:idx + 2] == ">=":
            name = name.replace("operator>>", "operator_RIGHT_SHIFT_")
        elif name[idx] == "<":
            name = name.replace("operator<", "operator_LESS_")
        elif name[idx] == ">":
            name = name.replace("operator>=", "operator_GREATER_EQUAL_")
        elif name[idx] == "+":
            name = name.replace("operator+", "operator_ADD_")
        elif name[idx] == "-":
            name = name.replace("operator-", "operator_SUB_")
        elif name[idx] == "/":
            name = name.replace("operator/", "operator_DIV_")
        elif name[idx] == "%":
            name = name.replace("operator%", "operator_MODULO_DIV_")
        elif name[idx:idx + 2] == "()":
            name = name.replace("operator()", "operator_CALL_")
        elif name[idx: idx + 6] == " new[]":
            name = name.replace("operator new[]", "operator_NEW_ARRAY_")
        elif name[idx: idx + 9] == " delete[]":
            name = name.replace("operator delete[]", "operator_DELETE_ARRAY_")
        elif name[idx: idx + 4] == " new":
            name = name.replace("operator new", "operator_NEW_")
        elif name[idx: idx + 7] == " delete":
            name = name.replace("operator delete", "operator_DELETE_")
        elif name[idx:idx + 2] == "\"\" ":
            name = name.replace("operator\"\" ", "operator_LITERAL_")
        elif name[idx] == "~":
            name = name.replace("operator~", "operator_NOT_")
        elif name[idx] == ' ':
            pass
        else:
            raise AssertionError("Replacement of demangled string by c-string for keyword `operatorXXX` is not yet"
                                 "implemented ({}). You can do it by yourself or create an issue".format(name))

    name = name.replace("public:", "")
    name = name.replace("protected:", "")
    name = name.replace("private:", "")
    name = name.replace("~", "DESTRUCTOR_")
    name = name.replace("*", "_PTR")
    name = name.replace("<", "_t_")
    name = name.replace(">", "_t_")
    name = "_".join(filter(len, BAD_C_NAME_PATTERN.split(name)))
    return name

def parse_vtable_name(address):
    name = idaapi.get_name(address)
    if idaapi.is_valid_typename(name):
        if name[0:3] == 'off':
            return "Vtable" + name[3:], False
        elif "table" in name:
            return name, True
        print("[Warning] Weird virtual table name -", name)
        return "Vtable_" + name, False
    name = idc.demangle_name(idaapi.get_name(address), idc.get_inf_attr(idc.INF_SHORT_DN))
    assert name, "Virtual table must have either legal c-type name or mangled name"
    return demangled_name_to_c_str(name).replace("const_", "").replace("::_vftable", "_vtbl"), True



class AbstractStructMember:
    def __init__(self, offset=0, comment=''):
        self.offset = offset
        self.comment = comment

    @property
    def size(self):
        size = self.tinfo.get_size()
        return size if size != idaapi.BADSIZE else 1



class StructMember(AbstractStructMember):
    def __init__(self, tinfo, field_name='', **kwargs):
        AbstractStructMember.__init__(self, **kwargs)
        self.tinfo = tinfo
        self.field_name = field_name or ('field_%X' % offset)
        self.type_name = self.tinfo.dstr() # actually useless

    def __str__(self):
        return '%#x: %s: %s' % (self.offset, self.field_name, self.tinfo.dstr())


class Structure(AbstractStructMember):
    def __init__(self, type_name, field_name='', is_union=False, **kwargs):
        AbstractStructMember.__init__(self, **kwargs)
        self.members = list()
        self.type_name = type_name
        self.field_name = field_name or ('field_%X' % offset)
        self.imported = False
        self.is_union = is_union

    def __str__(self):
        cdecl_typedef = idaapi.print_tinfo(None, 4, 5, idaapi.PRTYPE_MULTI | idaapi.PRTYPE_TYPE | idaapi.PRTYPE_SEMI,
                                           self.tinfo, self.type_name, None)
        return cdecl_typedef

    def add(self, member):
        self.members.append(member)

    def import_to_idb(self):
        old_sid = idaapi.get_struc_id(self.type_name)
        if old_sid != idaapi.BADADDR:
            idaapi.del_struc(idaapi.get_struc(old_sid))

        sid = idaapi.add_struc(old_sid, self.type_name, self.is_union)
        sptr = idaapi.get_struc(sid)
        min_next_possible_offset = 0
        duplicates = defaultdict(int)
        for m in sorted(self.members, key=lambda x: x.offset):
            assert m.offset >= min_next_possible_offset, \
                "Got collision of fields, desired offset=%#x, min_next_possible_offset=%#x" % (m.offset, min_next_possible_offset)

            field_name = m.field_name
            if duplicates[m.field_name]:
                field_name = 'duplicate_%s_%X' % (m.field_name, duplicates[m.field_name])
            duplicates[m.field_name]+= 1

            assert idaapi.add_struc_member(sptr, field_name, m.offset, idaapi.FF_DATA, None, 0) == 0, \
                "An error occured due adding of new member %s to struct %s" % (repr(m.field_name), repr(self.type_name))

            mptr = idaapi.get_member(sptr, m.offset)
            assert idaapi.set_member_tinfo(sptr, mptr, 0, m.tinfo, 0) == idaapi.SMT_OK
            if m.comment:
                idaapi.set_member_cmt(mptr, m.comment, False)
            
            min_next_possible_offset = m.offset + m.size

        self.imported = True

    @property
    def tinfo(self):
        if not self.imported:
            self.import_to_idb()

        tinfo = idaapi.tinfo_t()
        tinfo.get_named_type(idaapi.cvar.idati, self.type_name)
        return tinfo


    @property
    def size(self):
        return sum([m.size for m in self.members])



class FunctionPointer(AbstractStructMember):
    def __init__(self, address, **kwargs):
        AbstractStructMember.__init__(self, **kwargs)
        self.address = address
        self.type_name = 'func_%X' % (self.address) # actually useless

    @property
    def tinfo(self):
        func_ptr_tinfo = idaapi.tinfo_t()
        try:
            decompiled_func =  idaapi.decompile(self.address) 
        except:
            decompiled_func = None

        if not decompiled_func or not decompiled_func.type:
            func_tinfo = idaapi.tinfo_t()
            if not idaapi.get_type(self.address, func_tinfo, idaapi.GUESSED_FUNC):
                func_ptr_tinfo.create_ptr(const.DUMMY_FUNC)
            else:
                func_ptr_tinfo.create_ptr(func_tinfo)
        else:
            func_ptr_tinfo.create_ptr(decompiled_func.type)

        return func_ptr_tinfo

    @property
    def field_name(self):
        name = idaapi.get_name(self.address)
        demangled_name = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
        if demangled_name:
            name = demangled_name_to_c_str(demangled_name)


        if len(name) == 0:
            name = 'sub_%X' % (self.address)

        return name

    @staticmethod
    def check(address):
        # 1 - check if it's even code
        # 2 - check that address is pointing to the start of function or imported

        # 1
        if not util.is_code_ea(address):
            return False

        # 2
        if not util.is_func_start(address):
            return False

        return True