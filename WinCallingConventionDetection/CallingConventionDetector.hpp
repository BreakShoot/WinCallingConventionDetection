#pragma once
#include "PEParser32.hpp"
#include "vector"
#include <chrono> 

enum UnmanagedCallingConvention
{
	UnmanagedCdecl,
	UnmanagedStdcall,
	UnmanagedFastcall, 
	UnmanagedFailure
};

class CallingClassDetector
{
public:
	CallingClassDetector(uint32_t uiAddress, uint32_t uiData);
	~CallingClassDetector();
	void PrintCallingConvention() const;
	
private:
	UnmanagedCallingConvention GetCallingConvention() const;
	std::vector<uint32_t> GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const;
	UnmanagedCallingConvention unmCallingConvention;
	unsigned long long m_Duration;
	uint32_t m_Address;
	uint32_t m_BaseData;
	PEParser32 *m_PEParser;
};