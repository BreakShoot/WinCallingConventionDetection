#include "CallingConventionDetector.hpp"

#include <thread>

#include "hde32/hde32.h"


CallingConventionDetector::CallingConventionDetector(uint32_t uiAddress, uint32_t uiData, bool bWholeScan): m_BaseData(uiData)
{
	this->m_Address = uiAddress;
	this->m_PEParser = new PEParser32(uiData);

	auto chronoStart = std::chrono::high_resolution_clock::now();
	this->unmCallingConvention = this->GetCallingConvention(bWholeScan);
	auto chronoEnd = std::chrono::high_resolution_clock::now();
	this->m_Duration = std::chrono::duration_cast<std::chrono::milliseconds>(chronoEnd - chronoStart).count();
}

CallingConventionDetector::~CallingConventionDetector()
{
	delete this->m_PEParser;
}

bool CallingConventionDetector::SetsEdxOrEcxRegister(const uint32_t& uiAddress) const
{
	for (int i = 1; i < 6; ++i)
	{
		if (*reinterpret_cast<PBYTE>(uiAddress - i) == 0x68)
		{
			return this->SetsEdxOrEcxRegister(uiAddress - i);
		}
	}

	return  *reinterpret_cast<PBYTE>(uiAddress - 2) == 0x8B  &&
			(*reinterpret_cast<PBYTE>(uiAddress - 1) == 0xCE ||
			*reinterpret_cast<PBYTE>(uiAddress - 1) == 0xC8  ||
			*reinterpret_cast<PBYTE>(uiAddress - 1) == 0xCF);
}

bool CallingConventionDetector::CallerCleansUpStack(const uint32_t& uiAddress)
{
	return *reinterpret_cast<PBYTE>(uiAddress + 5) == 0x83 && *reinterpret_cast<PBYTE>(uiAddress + 6) == 0xC4;
}

UnmanagedCallingConvention CallingConventionDetector::GetCallingConvention(bool bWholeScan) const
{
	DWORD dwOldProtection;
	UnmanagedCallingConvention unmCallingConvention;
	uint32_t current_address = this->m_Address;


	VirtualProtect(reinterpret_cast<LPVOID>(this->m_Address), 1, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	while (true)
	{
		hde32s hde32 = { 0 };
		const int length = hde32_disasm(reinterpret_cast<const void*>(current_address), &hde32);

		std::vector<uint32_t> references;

		if (bWholeScan)
		{
			const PIMAGE_SECTION_HEADER pish = this->m_PEParser->GetSectionHeader(".text");
			const uint32_t uiRuntimeBaseAddress = pish->VirtualAddress + this->m_BaseData;
			references = GetXRefs(uiRuntimeBaseAddress, pish->SizeOfRawData);
		}
		else
			references = GetXRefs(this->m_Address - 0x40000, 0x80000);

		if (!references.empty())
		{
			int counter = 0;

			for (const uint32_t& reference : references)
			{
				if (this->CallerCleansUpStack(reference))
				{
					unmCallingConvention = UnmanagedCdecl;
					break;
				}
				
				if (this->SetsEdxOrEcxRegister(reference))
				{
					counter++;
				}
			}

			const float percentage = static_cast<float>(counter) / static_cast<float>(references.size());

			unmCallingConvention = (percentage >= 0.2) ? UnmanagedFastcall : UnmanagedStdcall; //you can modify this yourself.
		}
		else
			unmCallingConvention = UnmanagedFailure;
		break;

		current_address += length;
	}

	

	
	VirtualProtect(reinterpret_cast<LPVOID>(this->m_Address), 1, dwOldProtection, &dwOldProtection);

	return unmCallingConvention;
}

void CallingConventionDetector::PrintCallingConvention() const
{
	char* ccCallingConventionStr = nullptr;

	switch (this->unmCallingConvention)
	{
		case UnmanagedCdecl:
			ccCallingConventionStr = (char*)"UnmanagedCdecl";
			break;
		case UnmanagedStdcall:
			ccCallingConventionStr = (char*)"UnmanagedStdcall";
			break;
		case UnmanagedFastcall:
			ccCallingConventionStr = (char*)"UnmanagedFastcall";
			break;
		case UnmanagedFailure:
			ccCallingConventionStr = (char*)"UnmanagedFailure";
			break;
	}

	
	printf("Address = 0x%04x | Calling Convention = %s | Scan Time = %lldms\n", this->m_Address, ccCallingConventionStr, this->m_Duration);
}

UnmanagedCallingConvention CallingConventionDetector::GetCallingConvention() const
{
	return this->unmCallingConvention;
}

void CallingConventionDetector::FindNeedleInHayStack(const uint32_t& target, std::vector<uint32_t>* xrefs,
	const uint32_t& uiStartAddress, const uint32_t& uiSearchLength)
{
	uint32_t uiCurrentAddress = uiStartAddress;

	while (uiCurrentAddress < uiStartAddress + uiSearchLength)
	{
		hde32s hde32 = { 0 };
		const unsigned length = hde32_disasm(reinterpret_cast<const void*>(uiCurrentAddress), &hde32);

		if (hde32.opcode == 0xE8)
		{
			if (*reinterpret_cast<uint32_t*>(uiCurrentAddress + 1) == (target - uiCurrentAddress - 5)) //found call to target_address
			{
				xrefs->push_back(uiCurrentAddress);
			}
		}

		uiCurrentAddress += length;
	}
}

std::vector<uint32_t> CallingConventionDetector::GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const
{
	std::vector<std::thread> threads;
	std::vector<uint32_t> xrefs;
	uint32_t current_address = uiStartAddress;
	uint32_t page_amount = 0;
	DWORD dwOldProtection;

	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint32_t uiThreadScanSize = sysInfo.dwPageSize * 15;
	page_amount = (uiSearchLength / sysInfo.dwPageSize) + 1;
	
	VirtualProtect(reinterpret_cast<LPVOID>(uiStartAddress), page_amount, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	for (uint32_t i = uiStartAddress; i < (uiStartAddress + uiSearchLength); i += uiThreadScanSize)
	{
		if (i > uiStartAddress + uiSearchLength)
			i = uiStartAddress + uiSearchLength - uiThreadScanSize;
		
		std::thread thread(FindNeedleInHayStack, this->m_Address, &xrefs, i, uiThreadScanSize);
		threads.push_back(std::move(thread));
	}
	
	for (std::thread& thread : threads)
		if (thread.joinable())
			thread.join();
	
	VirtualProtect(reinterpret_cast<LPVOID>(uiStartAddress), page_amount, dwOldProtection, &dwOldProtection);
	return xrefs;
}

