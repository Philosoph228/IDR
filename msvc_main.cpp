#include "precomp.hpp"
#include "Disasm.h"
#include <iostream>
#include "resource.h"

#include <fstream>
#include <vector>

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

struct SectionInfo
{
    std::string name;
    uint32_t    virtualSize;
    uint32_t    virtualAddress;
    uint32_t    rawSize;
    uint32_t    rawOffset;
    uint32_t    characteristics;
};

std::vector<SectionInfo> parse_pe_sections(const std::wstring& path)
{
    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Failed to open file");

    // read DOS header
    IMAGE_DOS_HEADER dos{};
    file.read(reinterpret_cast<char*>(&dos), sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) throw std::runtime_error("Not a PE file (invalid DOS signature)");

    // Move to NT headers
    file.seekg(dos.e_lfanew, std::ios::beg);

    DWORD ntSignature{};
    file.read(reinterpret_cast<char*>(&ntSignature), sizeof(ntSignature));
    if (ntSignature != IMAGE_NT_SIGNATURE) throw std::runtime_error("Invalid NT signature");

    // Read File Header
    IMAGE_FILE_HEADER fileHeader{};
    file.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    // Read Optional Header magic to determine 32/64-bit
    WORD magic{};
    file.read(reinterpret_cast<char*>(&magic), sizeof(magic));
    file.seekg(-static_cast<std::streamoff>(sizeof(magic)), std::ios::cur);

    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER64 optional{};
        file.read(reinterpret_cast<char*>(&optional), sizeof(optional));
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
    {
        IMAGE_OPTIONAL_HEADER32 optional{};
        file.read(reinterpret_cast<char*>(&optional), sizeof(optional));
    }
    else
    {
        throw std::runtime_error("Unknown optional header format");
    }

    // Read section headers
    std::vector<SectionInfo> sections;
    sections.reserve(fileHeader.NumberOfSections);

    for (int i = 0; i < fileHeader.NumberOfSections; ++i)
    {
        IMAGE_SECTION_HEADER sh{};
        file.read(reinterpret_cast<char*>(&sh), sizeof(sh));

        SectionInfo info;
        info.name = std::string(reinterpret_cast<char*>(&sh), sizeof(sh));

        info.virtualSize = sh.Misc.VirtualSize;
        info.virtualAddress = sh.VirtualAddress;
        info.rawSize = sh.SizeOfRawData;
        info.rawOffset = sh.PointerToRawData;
        info.characteristics = sh.Characteristics;

        sections.push_back(info);
    }
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
