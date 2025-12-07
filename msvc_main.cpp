#include "precomp.hpp"
#include "Disasm.h"
#include <iostream>
#include "resource.h"

BYTE* Code;
CRITICAL_SECTION g_cs;

static constexpr int CODE_SIZE = 4096;

INT_PTR CALLBACK DlgProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_INITDIALOG:
        // Initialization goes here
        return TRUE;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDOK:
        case IDCANCEL:
            // close the dialog (main window)
            DestroyWindow(hWnd);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        DestroyWindow(hWnd);
        return TRUE;

    case WM_DESTROY:
        PostQuitMessage(0);
        return TRUE;
    }

    return FALSE;
}


void AllocCode()
{
	Code = (BYTE*)malloc(CODE_SIZE);
}

int main(int argc, char* argv[])
{
	HINSTANCE hInst = ::GetModuleHandle(nullptr);

	HWND hDialog = ::CreateDialogParamW(hInst, MAKEINTRESOURCE(IDD_DIALOG1), nullptr, static_cast<DLGPROC>(&DlgProc), 0);
	::ShowWindow(hDialog, SW_SHOW);

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

    MSG msg{};
    while (::GetMessage(&msg, nullptr, 0, 0))
    {
        if (!IsDialogMessage(hDialog, &msg)) {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
        }
    }

    return static_cast<int>(msg.wParam);
	
	return 0;
}
