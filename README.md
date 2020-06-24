# WinCallingConventionDetection

A small library written up to detect the Calling Convention of x86 processes at run time.

# Features
* x86 Calling Convention Resolving
* Completely standalone (latest update removed hde32 dependency)
* Return Check bypass
* Pointer wrapper for easily resolving x86 functions
* Optimized and multithreaded (~8ms whole .text section scan, less than ~1ms lualib scan)

# Method
1)  Dynamically resolve all XRefs within the lua library range (0x80000 bytes), or scan the whole text section. This can be set when UnmanagedPointer initializes the CallingConventionDetector class within the constructor!
2) Check if the stack is cleaned up by any callers -> __cdecl
3) Detect if edx/ecx registers are set before calls -> __fastcall
4) Decipher between stdcall and fastcall by utilizing an algorithm. 
# Examples
```
UnmanagedPointer<int(int, const char*, unsigned)> rlua_pushlstring(fixOffset(0x11A63B0));
rlua_pushlstring(ls, "str", 3);
```

