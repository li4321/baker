#include "../binary.h"


IMPORT_MODULE* BINARY::import_module(std::string module_name) {
	IMPORT_MODULE* mod = NULL;
	for (int i = 0; i < import_modules.size(); i++) {
		mod = import_modules[i];

		if (mod->name == module_name) {
			return mod;
		}
	}

	mod = new IMPORT_MODULE{};
	mod->name = module_name;
	
	import_modules.push_back(mod);
	return mod;
}


IMPORT_ROUTINE* BINARY::import_routine(IMPORT_MODULE* mod, std::string routine_name) {
	for (IMPORT_ROUTINE* routine : mod->routines) {
		if (routine->name == routine_name) {
			return routine;
		}
	}

	SYMBOL* sym = new SYMBOL{};
	sym->id		= symbols.size();
	symbols.push_back(sym);

	IMPORT_ROUTINE* routine = new IMPORT_ROUTINE{};
	routine->id			= sym->id;
	routine->name		= routine_name;
	sym->type			= SYMBOL_TYPE_IMPORT;
	sym->import_routine = routine;
	sym->name			= "__imp_" + routine_name;
	mod->routines.push_back(routine);

	logger_log(
		BRIGHT_MAGENTA, "+import", 
		WHITE, fmtf("{ id: %d, %s --> %s }\n", sym->id, mod->name.c_str(), routine_name.c_str()));

	return routine;
}