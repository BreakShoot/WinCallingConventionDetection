#include "CallingConventionDetector.hpp"




DWORD WINAPI InitializeTest(LPVOID lpThreadParameter)
{
	CallingClassDetector* ccd = new CallingClassDetector(0x401040, reinterpret_cast<uint32_t>(GetModuleHandle(NULL)));
    printf("%d", ccd->GetCallingConvention());

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
