#include "UnmanagedPointer.hpp"

uint32_t fixOffset(uint32_t address)
{
    return address - 0x400000 + reinterpret_cast<uint32_t>(GetModuleHandle(nullptr));
}

DWORD lua_state = 0;


void MakeJMP(BYTE* pAddress, DWORD dwJumpTo)
{
    DWORD dwOldProtect, dwBkup, dwRelAddr;
    VirtualProtect(pAddress, 1, PAGE_EXECUTE_READWRITE, &dwOldProtect);
    dwRelAddr = (DWORD)(dwJumpTo - (DWORD)pAddress) - 5;
    *pAddress = 0xE9;
    *((DWORD*)(pAddress + 0x1)) = dwRelAddr;
    VirtualProtect(pAddress, 1, dwOldProtect, &dwBkup);
}


void* __stdcall fake_index2adr(int a1, int a2)
{
    lua_state = a1;
    DWORD oldp;
    VirtualProtect((LPVOID)fixOffset(0x11B53F0), 1, PAGE_EXECUTE_READWRITE, &oldp);
    memcpy((LPVOID)fixOffset(0x11B53F0), "\x55\x8B\xEC\x8B\x55", 5);
    VirtualProtect((LPVOID)fixOffset(0x11B53F0), 1, oldp, &oldp);
    return reinterpret_cast<void*(__stdcall*)(int, int)>(fixOffset(0x11B53F0))(a1, a2);
}


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

    MakeJMP((BYTE*)fixOffset(0x11B53F0), (DWORD)fake_index2adr);
    
  
    while (!lua_state)
        Sleep(1);
	
	auto getfield = UnmanagedPointer<void(uint32_t, int, const char*)>(fixOffset(0x11B5900));
	auto push = UnmanagedPointer<int(uint32_t, int)>(fixOffset(0x11B6670));
	getchar();
	getfield(lua_state, -10002, "game");
	
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