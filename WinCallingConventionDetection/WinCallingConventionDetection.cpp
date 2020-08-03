#include "UnmanagedPointer.hpp"

uint32_t fixOffset(uint32_t address)
{
	return address - 0x400000 + reinterpret_cast<uint32_t>(GetModuleHandle(nullptr));
}

DWORD lua_state = 0;


void MakeJMP(BYTE* pAddress, DWORD dwJumpTo)
{
	DWORD dwOldProtect, dwBkup, dwRelAddr;
	VirtualProtect(pAddress, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);
	dwRelAddr = static_cast<DWORD>(dwJumpTo - (DWORD)pAddress) - 5;
	*pAddress = 0xE9;
	*((DWORD*)(pAddress + 0x1)) = dwRelAddr;
	VirtualProtect(pAddress, 5, dwOldProtect, &dwBkup);
}


void* __cdecl fake_index2adr(int a1, int a2)
{
	lua_state = a1;
	DWORD oldp;
	VirtualProtect((LPVOID)fixOffset(0x11DFB70), 5, PAGE_EXECUTE_READWRITE, &oldp);
	memcpy((LPVOID)fixOffset(0x11DFB70), "\x55\x8B\xEC\x8B\x55", 5);
	VirtualProtect((LPVOID)fixOffset(0x11DFB70), 5, oldp, &oldp);
	return reinterpret_cast<void*(__stdcall*)(int, int)>(fixOffset(0x11DFB70))(a1, a2);
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

	MakeJMP((BYTE*)fixOffset(0x11DFB70), (DWORD)fake_index2adr);


	while (!lua_state)
		Sleep(1);

	auto getfield = UnmanagedPointer<void(uint32_t, int, const char*)>(fixOffset(0x11E0080));
	auto settop = UnmanagedPointer<void(uint32_t, int, const char*)>(fixOffset(0x11E1840));
	auto lua_tolstring = UnmanagedPointer<const char*(uint32_t, int, int*)>(fixOffset(0x11E1A60));


	getfield(lua_state, -10002, "game");
	getfield(lua_state, -1, "Players");
	getfield(lua_state, -1, "LocalPlayer");
	getfield(lua_state, -1, "Name");
	;
	int ok;
	printf(lua_tolstring(lua_state, -1, &ok));
	/*pushvalue(lua_state, -2);
	pcall(lua_state, 1, 0, 0);*/

	getchar();

	return 1;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
)
{
	UNREFERENCED_PARAMETER(lpReserved);

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		CreateThread(nullptr, NULL, InitializeTest, nullptr, NULL, nullptr);
	case DLL_THREAD_ATTACH:

	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}
