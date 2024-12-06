#pragma once

#include <iostream>
#include <Windows.h>
#include <vector>
#include <fstream>

std::vector<uint8_t> read_file_to_buffer(std::string path);
void output_file(uint8_t* buffer, size_t size, std::string path);