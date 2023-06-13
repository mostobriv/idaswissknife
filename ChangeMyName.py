import idaapi


class ChangeMyPlugin(idaapi.plugin_t):
	flags = idaapi.PLUGIN_HIDE
	comment = "Set of random features and enhancements"
	help = ""
	wanted_name = "ChangeMyName"
	wanted_hotkey = ""

	@staticmethod
	def init():
		if not idaapi.init_hexrays_plugin():
			print("Failed to initialize Hex-Rays SDK")
			return idaapi.PLUGIN_SKIP
		
		from ChangeMyName.callbacks import hx_callback_manager, action_manager
		hx_callback_manager.initialize()
		action_manager.initialize()
		
		print("ChangeMyName plugin initialized!")
		return idaapi.PLUGIN_KEEP


	@staticmethod
	def run(*args):
		pass

	
	@staticmethod
	def term():
		from ChangeMyName.callbacks import hx_callback_manager, action_manager
		hx_callback_manager.finalize()
		action_manager.finalize()

		idaapi.term_hexrays_plugin()


# def initialize_callbacks():
# 	if not hx_callback_manager.is_initialized:
# 		hx_callback_manager.initialize()

def PLUGIN_ENTRY():
	# idaapi.notify_when(idaapi.NW_OPENIDB, initialize_callbacks)
	return ChangeMyPlugin()