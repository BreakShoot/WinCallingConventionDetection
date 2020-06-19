#include "UnmanagedPointer.hpp"
#include "hde32/hde32.h"


DWORD WINAPI InitializeTest(LPVOID lpThreadParameter)
{
    DWORD dwOldProtection;
    VirtualProtect(static_cast<LPVOID>(FreeConsole), 1, PAGE_READWRITE, &dwOldProtection);
    *reinterpret_cast<PBYTE>(FreeConsole) = 0xC3;
    VirtualProtect(static_cast<LPVOID>(FreeConsole), 1, dwOldProtection, &dwOldProtection);
    AllocConsole();
    FILE* safe_handle_stream;
    SetConsoleTitle(L"Test");
    freopen_s(&safe_handle_stream, "CONIN$", "r", stdin);
    freopen_s(&safe_handle_stream, "CONOUT$", "w", stdout);
    freopen_s(&safe_handle_stream, "CONOUT$", "w", stderr);


    auto fixOffset = [](uint32_t address) -> uint32_t { return address - 0x400000 + reinterpret_cast<uint32_t>(GetModuleHandle(nullptr)); };
    UnmanagedPointer<void()> ok(fixOffset(0x11A6690));

    getchar();
	
    return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    UNREFERENCED_PARAMETER(lpReserved);

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, InitializeTest, NULL, NULL, NULL);
    case DLL_THREAD_ATTACH:

    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}