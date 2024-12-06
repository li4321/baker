#include "file.h"

std::vector<uint8_t> read_file_to_buffer(std::string path) {
	std::ifstream file(path, std::ios::binary);
	if (!file)
		return {};

	file.seekg(0, file.end);
	std::vector<std::uint8_t> buf(file.tellg());
	file.seekg(0, file.beg);

	file.read(reinterpret_cast<char*>(buf.data()), buf.size());
	
	return buf;
}

void output_file(uint8_t* buffer, size_t size, std::string path) {
	FILE* file = NULL;
	fopen_s(&file, path.c_str(), "wb");
	fwrite(buffer, size, 1, file);
	fclose(file);
}