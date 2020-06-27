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
	CallingConventionDetector(uint32_t uiAddress, uint32_t uiData);
	~CallingConventionDetector();
	void PrintCallingConvention() const;
	UnmanagedCallingConvention GetCallingConvention() const;
	
private:
	static void FindNeedleInHayStack(const uint32_t& target, std::vector<uint32_t>* xrefs, const uint32_t& uiStartAddress, const uint32_t& uiSearchLength);
	bool SetsEdxOrEcxRegister(const uint32_t& uiAddress) const;
	static bool CallerCleansUpStack(const uint32_t& uiAddress);
	UnmanagedCallingConvention ScanForCallingConvention() const;
	std::vector<uint32_t> GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const;
	UnmanagedCallingConvention unmCallingConvention;
	uint32_t m_Address;
	uint32_t m_BaseData;
	PEParser32 *m_PEParser;
};