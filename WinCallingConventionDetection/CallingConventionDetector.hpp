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

class CallingConventionDetector
{
public:
	CallingConventionDetector(uint32_t uiAddress, uint32_t uiData, bool bWholeScan = false);
	~CallingConventionDetector();
	void PrintCallingConvention() const;
	UnmanagedCallingConvention GetCallingConvention() const;
	
private:
	UnmanagedCallingConvention GetCallingConvention(bool bWholeScan) const;
	std::vector<uint32_t> GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const;
	UnmanagedCallingConvention unmCallingConvention;
	unsigned long long m_Duration;
	uint32_t m_Address;
	uint32_t m_BaseData;
	PEParser32 *m_PEParser;
};