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
				throw std::exception("Attempt to call with convention UnmanagedFailure!");
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
				throw std::exception("Attempt to call with convention UnmanagedFailure!");
		}
	}

	UnmanagedPointer(uint32_t dwAddress, uint32_t dwBaseAddress = reinterpret_cast<uint32_t>(GetModuleHandle(NULL)))
	{
		this->m_Address = dwAddress;
		auto* ccDetector = new CallingConventionDetector(this->m_Address, dwBaseAddress);
		this->m_CallingConvention = ccDetector->GetCallingConvention();
		delete ccDetector;
	}

	UnmanagedPointer(const char* bMask, const char* szMask, const uint32_t& dwBaseAddress = reinterpret_cast<uint32_t>(GetModuleHandle(NULL)), const uint32_t& dwLen = 0x7FFFFFFF)
	{
		this->m_Address = this->FindPattern(bMask, szMask, dwBaseAddress, dwLen);

		if (!this->m_Address)
		{
			throw std::exception("Failed to find pattern!");
		}

		auto* ccDetector = new CallingConventionDetector(this->m_Address, dwBaseAddress);
		this->m_CallingConvention = ccDetector->GetCallingConvention();
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
};