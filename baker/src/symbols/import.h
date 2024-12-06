#pragma once
#include <vector>
#include <string>

typedef uint32_t sym_id_t;

struct IMPORT_ROUTINE {
	sym_id_t id;
	std::string name;
};

struct IMPORT_MODULE {
	std::string name;
	std::vector<IMPORT_ROUTINE*> routines;
};