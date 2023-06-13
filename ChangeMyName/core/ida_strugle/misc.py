import idaapi

def add_call_ref(addr_from, addr_to, additional_flags=idaapi.XREF_USER):
	# idaapi.XREF_USER - User specified xref. This xref will not be deleted by IDA.
	# This bit should be combined with the existing xref types (cref_t & dref_t).
	# Cannot be used for fl_F xrefs
	return idaapi.add_cref(addr_from, addr_to, idaapi.fl_CN | additional_flags)

def offset(addr=None):
	if addr is None:
		addr = idaapi.here()
	return addr - idaapi.get_imagebase()

def jumpto_rva(rva):
	return idaapi.jumpto(idaapi.get_imagebase()+rva)