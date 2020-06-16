#pragma once
#include "PEParser32.hpp"
#include "vector"

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
	UnmanagedCallingConvention GetCallingConvention() const;
	
private:
	std::vector<uint32_t> GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const;	
	uint32_t m_Address;
	uint32_t m_BaseData;
	PEParser32 *m_PEParser;
};
