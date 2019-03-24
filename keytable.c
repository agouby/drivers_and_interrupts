#include "stroke.h"

struct keycode_s keytable[] = {
	{0x0, "Empty", -1},
	{0x1, "ESC", 1},
	{'1', "1", 0},
	{'2', "2", 0},
	{'3', "3", 0},
	{'4', "4", 0},
	{'5', "5", 0},
	{'6', "6", 0},
	{'7', "7", 0},
	{'8', "8", 0},
	{'9', "9", 0},
	{'0', "0", 0},
	{'-', "MINUS", 0},
	{'+', "PLUS", 0},
	{0xE, "BACKSPACE", 1},
	{'\t', "TAB", 1},
	{'q', "q", 0},
	{'w', "w", 0},
	{'e', "e", 0},
	{'r', "r", 0},
	{'t', "t", 0},
	{'y', "y", 0},
	{'u', "u", 0},
	{'i', "i", 0},
	{'o', "o", 0},
	{'p', "p", 0},
	{'[', "[", 0},
	{']', "]", 0},
	{'\n', "ENTER", 1},
	{0x1D, "CONTROL", 1},
	{'a', "a", 0},
	{'s', "s", 0},
	{'d', "d", 0},
	{'f', "f", 0},
	{'g', "g", 0},
	{'h', "h", 0},
	{'j', "j", 0},
	{'k', "k", 0},
	{'l', "l", 0},
	{';', ";", 0},
	{'\'', "\'", 0},
	{'`', "`", 0},
	{0x2A, "LEFT SHIFT", 1},
	{'\\', "\\", 0},
	{'z', "z", 0},
	{'x', "x", 0},
	{'c', "c", 0},
	{'v', "v", 0},
	{'b', "b", 0},
	{'n', "n", 0},
	{'m', "m", 0},
	{',', ",", 0},
	{'.', ".", 0},
	{'/', "/", 0},
	{0x36, "RIGHT SHIFT", 1},
	{0x37, "PRINT", 1},
	{0x38, "ALT", 1},
	{' ', "SPACE", 1},
	{0x3A, "CAPS LOCK", 1},
	{0x3B, "F1", 1},
	{0x3C, "F2", 1},
	{0x3D, "F3", 1},
	{0x3E, "F4", 1},
	{0x3F, "F5", 1},
	{0x40, "F6", 1},
	{0x41, "F7", 1},
	{0x42, "F8", 1},
	{0x43, "F9", 1},
	{0x44, "F10", 1},
	{0x45, "NUM LOCK", 1},
	{0x46, "SCREEN LOCK", 1},
	{0x47, "HOME", 1},
	{0x48, "ARROW UP", 1},
	{0x49, "PAGE UP", 1},
	{'-', "(NUM) MINUS", 1},
	{0x4B, "ARROW LEFT", 1},
	{'5', "(NUM) 5", 1},
	{0x4D, "ARROW RIGHT", 1},
	{'+', "(NUM) PLUS", 1},
	{0x4F, "END", 1},
	{0x50, "ARROW DOWN", 1},
	{0x51, "PAGE DOWN", 1},
	{0x52, "INSERT", 1},
	{0x53, "DELETE", 1}
};

int keytable_len = COUNT_OF(keytable);
