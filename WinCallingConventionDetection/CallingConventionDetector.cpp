#include "CallingConventionDetector.hpp"
#include "hde32/hde32.h"


CallingClassDetector::CallingClassDetector(uint32_t uiAddress, uint32_t uiData): m_BaseData(uiData)
{
	this->m_Address = uiAddress - 0x400000 + uiData; //assuming 0x400000 is the base. Should change if needed
	this->m_PEParser = new PEParser32(uiData);
}

UnmanagedCallingConvention CallingClassDetector::GetCallingConvention() const
{
	UnmanagedCallingConvention unmCallingConvention;
	DWORD dwOldProtection;
	uint32_t current_address = this->m_Address;


	VirtualProtect(reinterpret_cast<LPVOID>(this->m_Address), 1, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	while (true)
	{
		hde32s hde32 = { 0 };
		const int length = hde32_disasm(reinterpret_cast<const void*>(current_address), &hde32);

		if (hde32.opcode == 0xC2)
		{
			unmCallingConvention = UnmanagedStdcall;
		}

		if (hde32.opcode == 0xC3)
		{			
			const PIMAGE_SECTION_HEADER pish = this->m_PEParser->GetSectionHeader(".text");

			const uint32_t uiRuntimeBaseAddress = pish->VirtualAddress + this->m_BaseData;


			/* std::vector<uint32_t> references = GetXRefs(uiRuntimeBaseAddress, pish->SizeOfRawData); */ 
			std::vector<uint32_t> references = GetXRefs(this->m_Address - 0x40000, 0x80000); //replace with the commented one if not accurate; warning, seriously slower

			if (!references.empty())
			{
				int counter = 0;

				for (const uint32_t& reference : references)
				{
					if (*reinterpret_cast<PBYTE>(reference - 2) == 0x8B &&
					   (*reinterpret_cast<PBYTE>(reference - 1) == 0xCE ||
						*reinterpret_cast<PBYTE>(reference - 1) == 0xC8))
					{
						counter++;
					}
				}

				const float percentage = static_cast<float>(counter) / static_cast<float>(references.size());

				unmCallingConvention = (percentage > 0.2) ? UnmanagedFastcall : UnmanagedCdecl; //you can modify this yourself.
			}
			else 
				unmCallingConvention = UnmanagedFailure;
			break;
		}

		current_address += length;
	}

	VirtualProtect(reinterpret_cast<LPVOID>(this->m_Address), 1, dwOldProtection, &dwOldProtection);
	return unmCallingConvention;
}

std::vector<uint32_t> CallingClassDetector::GetXRefs(const uint32_t& uiStartAddress, const uint32_t& uiSearchLength) const
{
	std::vector<uint32_t> xrefs;
	uint32_t current_address = uiStartAddress;
	DWORD dwOldProtection;
	VirtualProtect(reinterpret_cast<LPVOID>(current_address), 10, PAGE_EXECUTE_READWRITE, &dwOldProtection);

	while (current_address < (uiStartAddress + uiSearchLength))
	{
		hde32s hde32 = { 0 };
		const int length = hde32_disasm(reinterpret_cast<const void*>(current_address), &hde32);

		if (hde32.opcode == 0xE8)
		{
			if (*reinterpret_cast<uint32_t*>(current_address + 1) == (this->m_Address - current_address - 5)) //found call to target_address
			{
				xrefs.push_back(current_address);
			}
		}

		current_address += length;	
	}

	VirtualProtect(reinterpret_cast<LPVOID>(current_address), 10, dwOldProtection, &dwOldProtection);
	return xrefs;
}
