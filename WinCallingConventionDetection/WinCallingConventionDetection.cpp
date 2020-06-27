#include "UnmanagedPointer.hpp"


namespace Memory
{
	bool Compare(const BYTE* pData, const BYTE* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask)
			if (*szMask == 'x' && *pData != *bMask) return 0;
		return (*szMask) == NULL;
	}

	DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE* bMask, char* szMask)
	{
		for (int i = 0; i < (int)dwLen; i++)
			if (Compare((BYTE*)(dwAddress + (int)i), bMask, szMask))  return (int)(dwAddress + i);
		return 0;
	}

	int Scan(DWORD mode, char* content, char* mask, DWORD Offset = 0)
	{
		DWORD PageSize;
		SYSTEM_INFO si;
		GetNativeSystemInfo(&si);
		PageSize = si.dwPageSize;
		MEMORY_BASIC_INFORMATION mi;
		for (DWORD lpAddr = (DWORD)GetModuleHandleA(0) + Offset; lpAddr < 0x7FFFFFFF; lpAddr += PageSize)
		{
			DWORD vq = VirtualQuery((void*)lpAddr, &mi, sizeof(MEMORY_BASIC_INFORMATION));
			if (vq == ERROR_INVALID_PARAMETER || vq == 0) break;
			if (mi.Type == MEM_MAPPED) continue;
			if (mi.Protect == mode)
			{
				int addr = FindPattern(lpAddr, PageSize, (PBYTE)content, mask);
				if (addr != 0)
				{
					return addr;
				}
			}
		}
	}
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


    auto fixOffset = [](uint32_t address) -> uint32_t { return address - 0x400000 + reinterpret_cast<uint32_t>(GetModuleHandle(nullptr)); };
	/*DWORD adr = fixOffset(0x1A1F524);
	DWORD scr = Memory::Scan(PAGE_READWRITE, (char*)&adr, (char*)"xxxx");
	DWORD ls = scr + 164 + *(DWORD*)(scr + 164);*/
	
	auto getfield = UnmanagedPointer<void(uint32_t, int, const char*)>(fixOffset(0x11B5900));
	auto tolstring = UnmanagedPointer<const char* (uint32_t, int, size_t*)>(fixOffset(0x11B72A0));
	///*rlua_pushlstring(ls, "str", 3);*/
	
	
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