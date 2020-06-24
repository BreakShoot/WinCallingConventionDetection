#pragma once
#include "CallingConventionDetector.hpp"
#include <cstdint>
#include <utility>

template<typename t_Function>
class UnmanagedPointer
{
public:

	template<typename... t_FunctionParameters>
	auto operator()(t_FunctionParameters... params)
	{
		using result_type = decltype(std::declval<t_Function>()(std::declval<t_FunctionParameters>()...));
		using function_cdecl_ptr_t = result_type(__cdecl*)(t_FunctionParameters...);
		using function_stdcall_ptr_t = result_type(__stdcall*)(t_FunctionParameters...);
		using function_fastcall_ptr_t = result_type(_fastcall*)(t_FunctionParameters...);

		switch (this->m_CallingConvention)
		{
			case UnmanagedCdecl:
				return reinterpret_cast<function_cdecl_ptr_t>(this->m_Address)(params...);
			case UnmanagedStdcall:
				return reinterpret_cast<function_stdcall_ptr_t>(this->m_Address)(params...);
			case UnmanagedFastcall:
				return reinterpret_cast<function_fastcall_ptr_t>(this->m_Address)(params...);
			default:
				return reinterpret_cast<function_cdecl_ptr_t>(this->m_Address)(params...);
		}
	}

	auto operator()()
	{
		using result_type = decltype(std::declval<t_Function>());
		using function_cdecl_ptr_t = result_type(__cdecl*)();
		using function_stdcall_ptr_t = result_type(__stdcall*)();
		using function_fastcall_ptr_t = result_type(_fastcall*)();

		switch (this->m_CallingConvention)
		{
		case UnmanagedCdecl:
			return reinterpret_cast<function_cdecl_ptr_t>(this->m_Address)();
		case UnmanagedStdcall:
			return reinterpret_cast<function_stdcall_ptr_t>(this->m_Address)();
		case UnmanagedFastcall:
			return reinterpret_cast<function_fastcall_ptr_t>(this->m_Address)();
		default:
			return reinterpret_cast<function_cdecl_ptr_t>(this->m_Address)();
		}
	}

	UnmanagedPointer(uint32_t dwAddress, uint32_t dwBaseAddress = reinterpret_cast<uint32_t>(GetModuleHandle(NULL)), bool bRetCheck = true)
	{
		this->m_Address = dwAddress;
		auto* ccDetector = new CallingConventionDetector(this->m_Address, dwBaseAddress, true);
		this->m_CallingConvention = ccDetector->GetCallingConvention();
		if (bRetCheck)
			this->RemoveReturnCheck();
		ccDetector->PrintCallingConvention();
		delete ccDetector;
	}

	UnmanagedPointer(const char* bMask, const char* szMask, const uint32_t& dwBaseAddress = reinterpret_cast<uint32_t>(GetModuleHandle(NULL)), const uint32_t& dwLen = 0x7FFFFFF, bool bRetCheck = true)
	{
		this->m_Address = this->FindPattern(bMask, szMask, dwBaseAddress, dwLen);
		auto* ccDetector = new CallingConventionDetector(this->m_Address, dwBaseAddress, true);
		this->m_CallingConvention = ccDetector->GetCallingConvention();
		ccDetector->PrintCallingConvention();
		if (bRetCheck)
			this->RemoveReturnCheck();
		delete ccDetector;
	}

private:
	uint32_t m_Address;
	UnmanagedCallingConvention m_CallingConvention;

	static bool DataCompare(const unsigned char* pData, const unsigned char* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask)
			if (*szMask == 'x' && *pData != *bMask)
				return false;
		return (*szMask) == 0;
	}

	static uint32_t FindPattern(const char* bMask, const char* szMask, const uint32_t dwBaseAddress, const uint32_t dwLen)
	{
		for (unsigned long i = 0; i < dwLen; i++)
			if (DataCompare(reinterpret_cast<unsigned char*>(dwBaseAddress + i), (unsigned char*)(bMask), szMask))
				return static_cast<uint32_t>(dwBaseAddress + i);
		return 0;
	}

	void RemoveReturnCheck()
	{
		LPVOID   lpAllocation	= nullptr;
		size_t   szFunctionSize = 0;
		bool	 bRetcheck		= false;

		do
		{
			szFunctionSize += 0x10;
		} while (*reinterpret_cast<short*>(this->m_Address + szFunctionSize) != -29867 && *reinterpret_cast<BYTE*>(this->m_Address + szFunctionSize + 3) != 0xEC);


		lpAllocation = VirtualAlloc(NULL, szFunctionSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		memcpy(lpAllocation, reinterpret_cast<void const*>(this->m_Address), szFunctionSize);

		for (size_t i = 0; i < szFunctionSize; ++i)
		{
			const uint32_t uiRobloxAdr = this->m_Address + i;
			const uint32_t uiAllocAdr = reinterpret_cast<uint32_t>(lpAllocation) + i;

			if (*reinterpret_cast<BYTE*>(uiAllocAdr) == 0xE8)
			{
				*reinterpret_cast<uint32_t*>(uiAllocAdr + 1) = (uiRobloxAdr + *reinterpret_cast<uint32_t*>(uiRobloxAdr + 1) + 5) - uiAllocAdr - 5;
				i += 4; //don't scan rel32
			}

			if (*reinterpret_cast<short*>(uiAllocAdr) == 0x1B72 && *reinterpret_cast<BYTE*>(uiAllocAdr + 2) == 0xA1)
			{
				bRetcheck = true;
				*reinterpret_cast<short*>(uiAllocAdr - 0x6) = 0x21EB; //jmp 0x21 offset
				memset(reinterpret_cast<void*>(uiAllocAdr - 0x4), 0x90, 4); //nop 4 bytes since we overwrote a cmp
				i += 0x1C; //retcheck is 0x1C bytes so we don't need to scan those anymore
			}
		}

		if (!bRetcheck)
			VirtualFree(lpAllocation, 0, MEM_RELEASE);
		else
			this->m_Address = reinterpret_cast<uint32_t>(lpAllocation);
	}
};
