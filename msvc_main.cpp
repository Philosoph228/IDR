#include "precomp.hpp"
#include "Disasm.h"
#include <iostream>
#include "resource.h"

BYTE*            Code;
CRITICAL_SECTION g_cs;

static constexpr int CODE_SIZE = 4096;
static const WCHAR   g_cszDisasmViewClass[] = L"__DisasmView";

HINSTANCE g_hInst;

LRESULT CALLBACK DisasmViewProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_PAINT:
    {
        PAINTSTRUCT ps{};
        HDC         hdc = ::BeginPaint(hWnd, &ps);

        static const std::wstring mnemonic = L"xor eax, eax";

        RECT rcClient;
        ::GetClientRect(hWnd, &rcClient);
        ::DrawText(hdc, mnemonic.c_str(), mnemonic.length(), &rcClient, DT_SINGLELINE);

        ::EndPaint(hWnd, &ps);
    }
        return 0;

    case WM_CREATE:
        return 0;
    }

    return ::DefWindowProc(hWnd, message, wParam, lParam);
}

BOOL RegisterDisasmViewClass()
{
    WNDCLASSEX wcex{};
    if (!::GetClassInfoEx(g_hInst, g_cszDisasmViewClass, &wcex))
    {
        std::memset(&wcex, 0, sizeof(wcex));
        wcex.cbSize = sizeof(WNDCLASSEX);
        wcex.style = CS_HREDRAW | CS_VREDRAW;
        wcex.cbClsExtra = 0;
        wcex.cbWndExtra = 0;
        wcex.lpfnWndProc = static_cast<WNDPROC>(&DisasmViewProc);
        wcex.hInstance = g_hInst;
        wcex.hIcon = nullptr;
        wcex.hCursor = ::LoadCursor(nullptr, IDC_ARROW);
        wcex.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        wcex.lpszClassName = g_cszDisasmViewClass;

        return !!RegisterClassEx(&wcex);
    }

    return TRUE;
}

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
    g_hInst = ::GetModuleHandle(nullptr);

    RegisterDisasmViewClass();

    HWND hDialog = ::CreateDialogParamW(g_hInst, MAKEINTRESOURCE(IDD_DIALOG1), nullptr, static_cast<DLGPROC>(&DlgProc), 0);
    ::ShowWindow(hDialog, SW_SHOW);

    ::InitializeCriticalSection(&g_cs);

    std::cout << "IDR MSVC Started\n";
    AllocCode();

    MDisasm disasm;
    disasm.Init();

    int     instrLen = 0;
    size_t  curPos = 0;
    DWORD   curAdr = 4;
    DISINFO disInfo;

    char disLine[1024];
    instrLen = disasm.Disassemble(Code + curPos, curAdr, &disInfo, disLine);

    ::DeleteCriticalSection(&g_cs);

    std::cout << "Instruction length: " << instrLen << "\nDisassembled line: " << disLine << '\n';

    MSG msg{};
    while (::GetMessage(&msg, nullptr, 0, 0))
    {
        if (!IsDialogMessage(hDialog, &msg))
        {
            ::TranslateMessage(&msg);
            ::DispatchMessage(&msg);
        }
    }

    return static_cast<int>(msg.wParam);

    return 0;
}
