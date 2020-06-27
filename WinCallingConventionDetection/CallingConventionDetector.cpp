#include "CallingConventionDetector.hpp"
#include <thread>


CallingConventionDetector::CallingConventionDetector(uint32_t uiAddress, uint32_t uiData): m_BaseData(uiData)
{
	this->m_Address = uiAddress;
	this->m_PEParser = new PEParser32(uiData);
	this->unmCallingConvention = this->ScanForCallingConvention();
}

CallingConventionDetector::~CallingConventionDetector()
{
	delete this->m_PEParser;
}

bool CallingConventionDetector::SetsEdxOrEcxRegister(const uint32_t& uiAddress) const
{
	for (int i = 1; i < 6; ++i)
	{
		if (*reinterpret_cast<PBYTE>(uiAddress - i) == 0x68) /* Got push, ignore it and rerun. */
		{
			return this->SetsEdxOrEcxRegister(uiAddress - i);
		}
		if (*reinterpret_cast<PBYTE>(uiAddress - (i + 1)) == 0x8B &&
				(*reinterpret_cast<PBYTE>(uiAddress - i) == 0xCE ||
				*reinterpret_cast<PBYTE>(uiAddress  - i) == 0xC8 ||
				*reinterpret_cast<PBYTE>(uiAddress  - i) == 0xCF))
		{
			return true;
		}
	}
	
	return false;
}

bool CallingConventionDetector::CallerCleansUpStack(const uint32_t& uiAddress)
{
	uint32_t uiStartAddress = uiAddress + 5; //next statement

	while (*reinterpret_cast<PBYTE>(uiStartAddress) != 0xE8 || *reinterpret_cast<PBYTE>(uiStartAddress) != 0xC3 || *reinterpret_cast<PBYTE>(uiStartAddress) != 0xC2)  //call/ret/retn
	{
		if (*reinterpret_cast<PBYTE>(uiStartAddress++) == 0x83 && *reinterpret_cast<PBYTE>(uiStartAddress) == 0xC4) // add esp 
			return true;
	}
	
	return false;
}

UnmanagedCallingConvention CallingConventionDetector::ScanForCallingConvention() const
{
	UnmanagedCallingConvention unmCallingConvention = UnmanagedFailure;
	const PIMAGE_SECTION_HEADER pish = this->m_PEParser->GetSectionHeader(".text");
	const std::vector<uint32_t> references = GetXRefs(pish->VirtualAddress + this->m_BaseData, pish->Misc.VirtualSize);;
	
	if (!references.empty())
	{
		int counter = 0;

		for (const uint32_t& reference : references)
		{
			if (this->CallerCleansUpStack(reference))
			{
				return UnmanagedCdecl;
			}
			if (this->SetsEdxOrEcxRegister(reference))
			{
				counter++;
			}
		}

		const float percentage = static_cast<float>(counter) / static_cast<float>(references.size());
		unmCallingConvention = (percentage >= 0.2) ? UnmanagedFastcall : UnmanagedStdcall; //you can modify this yourself.
	}

	return unmCallingConvention;
}

UnmanagedCallingConvention CallingConventionDetector::GetCallingConvention() const
{
	return this->unmCallingConvention;
}

void CallingConventionDetector::FindNeedleInHayStack(const uint32_t& target, std::vector<uint32_t>* xrefs,
	const uint32_t& uiStartAddress, const uint32_t& uiSearchLength)
{
	for (uint32_t uiCurrentAddress = uiStartAddress;  uiCurrentAddress < uiStartAddress + uiSearchLength; uiCurrentAddress++)
	{
		if (*reinterpret_cast<PBYTE>(uiCurrentAddress) == 0xE8)
		{
			if (*reinterpret_cast<uint32_t*>(uiCurrentAddress + 1) == (target - uiCurrentAddress - 5))
			{
				xrefs->push_back(uiCurrentAddress);
			}
		}
	}
}

std::vector<uint32_t> CallingConventionDetector::GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const
{
	std::vector<std::thread> threads;
	std::vector<uint32_t> xrefs;
	uint32_t page_amount = 0;
	const uint32_t final_address = uiStartAddress + uiSearchLength;
	
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	page_amount = (uiSearchLength / sysInfo.dwPageSize) + 1;
	uint32_t uiThreadScanSize = sysInfo.dwPageSize * (page_amount / 5); //create 5-6 threads
	
	for (uint32_t uiCurrentAddress = uiStartAddress; uiCurrentAddress < final_address; uiCurrentAddress += uiThreadScanSize)
	{
		if (uiCurrentAddress + uiThreadScanSize > final_address)
			uiThreadScanSize = final_address - uiCurrentAddress;

		
		std::thread thread(FindNeedleInHayStack, this->m_Address, &xrefs, uiCurrentAddress, uiThreadScanSize);
		threads.push_back(std::move(thread));
	}
	
	for (std::thread& thread : threads)
		thread.join();
	
	return xrefs;
}

