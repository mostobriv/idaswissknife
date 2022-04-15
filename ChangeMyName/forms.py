from PyQt5 import QtCore, QtWidgets

import idaapi

class MyChoose(idaapi.Choose):
    def __init__(self, items, title, cols, icon=-1):
        idaapi.Choose.__init__(self, title, cols, flags=idaapi.Choose.CH_MODAL, icon=icon)
        self.items = items

    def OnClose(self):
        pass

    def OnGetLine(self, n):
        return self.items[n]

    def OnGetSize(self):
        return len(self.items)