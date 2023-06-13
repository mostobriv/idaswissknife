import idaapi
import ida_bytes

from . import util

class Stream:

    def __init__(self, addr, bitness=util.get_bitness()):
        self.addr = addr
        self.bitness = bitness
        self.history = list()

    def read_word(self):
        res = ida_bytes.get_word(self.addr)
        self.inc(2)
        return res

    def read_dword(self):
        res = ida_bytes.get_dword(self.addr)
        self.inc(4)
        return res

    def read_qword(self):
        res = ida_bytes.get_qword(self.addr)
        self.inc(8)
        return res

    def read_xword(self):
        if self.bitness == 32:
            res = ida_bytes.get_dword(self.addr)
        elif self.bitness == 64:
            res = ida_bytes.get_qword(self.addr)
        else: # bitness == 16
            res = ida_bytes.get_word(self.addr)
        self.inc(self.bitness >> 3)

        return res

    def get_addr(self):
        return addr

    def inc(self, step):
        self.addr+= step
        self.history.append(step)

    def undo(self):
        self.addr-= self.history.pop()

