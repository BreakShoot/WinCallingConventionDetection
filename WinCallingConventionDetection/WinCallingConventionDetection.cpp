#include "UnmanagedPointer.hpp"


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


    UnmanagedPointer<int(DWORD, int)> rlua_gettop(
        "\x55\x8B\xEC\x8B\x4D\x08\x8B\x41\x14\x2B\x41\x08",
        "xxxxxxxxxxxx");

    DWORD lua_State = 0;
    rlua_gettop(lua_State, -1);

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