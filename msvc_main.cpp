#include "precomp.hpp"

#include "Disasm.h"

#include <iostream>

BYTE* Code;
CRITICAL_SECTION g_cs;

static constexpr int CODE_SIZE = 4096;

void AllocCode()
{
	Code = (BYTE*)malloc(CODE_SIZE);
}

int main(int argc, char* argv[])
{
	::InitializeCriticalSection(&g_cs);

	std::cout << "IDR MSVC Started\n";
	AllocCode();

	MDisasm disasm;
	disasm.Init();

	int instrLen = 0;
	size_t curPos = 0;
	DWORD curAdr = 4;
	DISINFO disInfo;

	char disLine[1024];
	instrLen = disasm.Disassemble(Code + curPos, curAdr, &disInfo, disLine);

	::DeleteCriticalSection(&g_cs);

	std::cout << "Instruction length: " << instrLen << "\nDisassembled line: " << disLine << '\n';
	
	return 0;
}
