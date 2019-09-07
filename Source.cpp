#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include "utils/Native.h"
#include "utils/Hash.h"
#include "utils/Helpers.h"
#include "utils/crc32.h"
#include "utils/LengthDisasm.h"
#include <vector>
#include <assert.h>

void* ResolveJmp(void* Address, uint8_t Is64Bit)
{
	TLengthDisasm Data = { 0 };

	uint8_t Size = 0;
	uint8_t *Offset = (uint8_t*)Address;

	Size = LengthDisasm(Offset, Is64Bit, &Data);

	if ((Data.Opcode[0] == 0xE9) && (Data.Length == 5) && (Data.OpcodeSize == 1))
	{
		uint32_t delta = *(uint32_t*)((size_t)Address + Data.OpcodeSize);
		return ResolveJmp((void*)((size_t)Address + delta + Data.Length), Is64Bit);
	}

	return Address;
}

void ntdll_detection()
{
	auto ntdll = GetModuleBaseAddress(L"ntdll.dll");
	PVOID ntdll_mapped = nullptr;
	MapNativeModule("ntdll.dll", &ntdll_mapped);

	// NtYieldExecution
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtYieldExecution"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtYieldExecution"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtYieldExecution\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);
		
			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtYieldExecution\r\n");
		}

		reinterpret_cast<NtYieldExecution_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtSetInformationThread
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtSetInformationThread"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtSetInformationThread"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtSetInformationThread\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtSetInformationThread\r\n");
		}

		reinterpret_cast<NtSetInformationThread_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtSetInformationProcess
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtSetInformationProcess"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtSetInformationProcess"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtSetInformationProcess\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtSetInformationProcess\r\n");
		}

		reinterpret_cast<NtSetInformationProcess_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtQuerySystemInformation
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtQuerySystemInformation"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtQuerySystemInformation"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtQuerySystemInformation\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtQuerySystemInformation\r\n");
		}

		reinterpret_cast<NtQuerySystemInformation_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtQueryInformationProcess
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtQueryInformationProcess"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtQueryInformationProcess"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtQueryInformationProcess\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtQueryInformationProcess\r\n");
		}

		reinterpret_cast<NtQueryInformationProcess_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtQueryObject
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtQueryObject"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtQueryObject"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtQueryObject\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtQueryObject\r\n");
		}

		reinterpret_cast<NtQueryObject_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtCreateThreadEx
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtCreateThreadEx"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtCreateThreadEx"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtCreateThreadEx\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtCreateThreadEx\r\n");
		}

		reinterpret_cast<NtCreateThreadEx_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtSetDebugFilterState
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtSetDebugFilterState"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtSetDebugFilterState"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtSetDebugFilterState\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtSetDebugFilterState\r\n");
		}

		reinterpret_cast<NtSetDebugFilterState_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtClose
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtClose"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtClose"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtClose\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtClose\r\n");
		}

		reinterpret_cast<NtClose_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtQueryPerformanceCounter
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtQueryPerformanceCounter"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtQueryPerformanceCounter"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtQueryPerformanceCounter\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtQueryPerformanceCounter\r\n");
		}

		reinterpret_cast<NtQueryPerformanceCounter_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtGetContextThread
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtGetContextThread"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtGetContextThread"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtGetContextThread\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtGetContextThread\r\n");
		}

		reinterpret_cast<NtGetContextThread_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtSetContextThread
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(ntdll, "NtSetContextThread"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(ntdll_mapped, "NtSetContextThread"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] NtSetContextThread\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] NtSetContextThread\r\n");
		}

		reinterpret_cast<NtSetContextThread_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// NtQuerySystemTime
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQuerySystemTime");
		if (*static_cast<PUCHAR>(hooked_func) == 0xE9) // jmp rel32
		{
			LONG relativeOffset = *(PLONG)((ULONG_PTR)hooked_func + 1);
			hooked_func = (NtQuerySystemTime_t)((ULONG_PTR)hooked_func + relativeOffset + 5);
		}
		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQuerySystemTime");

		if (*static_cast<PUCHAR>(original_func) == 0xE9) // jmp rel32
		{
			LONG relativeOffset = *(PLONG)((ULONG_PTR)original_func + 1);
			original_func = (NtQuerySystemTime_t)((ULONG_PTR)original_func + relativeOffset + 5);
		}

		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtQuerySystemTime\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (result == func_size)
			{
				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] NtQuerySystemTime\r\n");
		}
		LARGE_INTEGER time;
		reinterpret_cast<NtQuerySystemTime_t>(hooked_func)(&time);
	}
	catch (...)
	{
	}
}

void kernelbase_detection()
{
	const auto kernelbase = GetModuleBaseAddress("kernelbase.dll");
	PVOID kernelbase_mapped = nullptr;
	MapNativeModule("kernelbase.dll", &kernelbase_mapped);

	// CheckRemoteDebuggerPresent
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(kernelbase, "CheckRemoteDebuggerPresent"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(kernelbase_mapped, "CheckRemoteDebuggerPresent"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] CheckRemoteDebuggerPresent\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] CheckRemoteDebuggerPresent\r\n");
		}

		reinterpret_cast<GetTickCount_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// GetTickCount
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(kernelbase, "GetTickCount"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(kernelbase_mapped, "GetTickCount"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] GetTickCount\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] GetTickCount\r\n");
		}

		reinterpret_cast<GetTickCount_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// GetTickCount64
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(kernelbase, "GetTickCount64"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(kernelbase_mapped, "GetTickCount64"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] GetTickCount64\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] GetTickCount64\r\n");
		}

		reinterpret_cast<GetTickCount64_t>(hooked_func_adress)();
	}
	catch (...)
	{
	}

	// OutputDebugStringA
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(kernelbase, "OutputDebugStringA"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(kernelbase_mapped, "OutputDebugStringA"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] OutputDebugStringA\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] OutputDebugStringA\r\n");
		}

		reinterpret_cast<OutputDebugStringA_t>(hooked_func_adress)("");
	}
	catch (...)
	{
	}

	// GetLocalTime
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(kernelbase, "GetLocalTime"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(kernelbase_mapped, "GetLocalTime"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] GetLocalTime\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] OutputDebugStringA\r\n");
		}

		SYSTEMTIME sm;
		reinterpret_cast<GetLocalTime_t>(hooked_func_adress)(&sm);
	}
	catch (...)
	{
	}

	// GetSystemTime
	try
	{
		auto hooked_func_adress = ResolveJmp(GetProcedureAddress(kernelbase, "GetSystemTime"), 1);
		size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
		unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

		auto original_func_adress = ResolveJmp(GetProcedureAddress(kernelbase_mapped, "GetSystemTime"), 1);
		size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
		unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

		// detect hook and restore bytes
		if (crc_original != crc_hooked)
		{
			log("[DETECTED] GetSystemTime\r\n");
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

			VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
		}
		else
		{
			log("[OK] GetSystemTime\r\n");
		}

		SYSTEMTIME sm;
		reinterpret_cast<GetSystemTime_t>(hooked_func_adress)(&sm);
	}
	catch (...)
	{
	}
}

void user32_detection()
{
	std::wstring regSubKey;
#ifdef _WIN64 // Manually switching between 32bit/64bit for the example. Use dwFlags instead.
	regSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\";
#else
	regSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\"; // TODO: support 32bit
#endif
	std::wstring regValue(L"CurrentBuildNumber");
	std::wstring CurrentBuildNumber;
	try
	{
		CurrentBuildNumber = GetStringValueFromHKLM(regSubKey, regValue);
	}
	catch (std::exception& e)
	{
		std::cerr << e.what();
	}

	if (std::stoi(CurrentBuildNumber) >= 14393)
	{
		// win32u.dll
		LoadLibrary(L"user32.dll");

		auto win32u = GetModuleBaseAddress("win32u.dll");
		PVOID win32u_mapped = nullptr;
		MapNativeModule("win32u.dll", &win32u_mapped);
		
		// BlockInput
		try
		{
			auto hooked_func_adress = ResolveJmp(GetProcedureAddress(win32u, "NtUserBlockInput"), 1);
			size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
			unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

			auto original_func_adress = ResolveJmp(GetProcedureAddress(win32u_mapped, "NtUserBlockInput"), 1);
			size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
			unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

			// detect hook and restore bytes
			if (crc_original != crc_hooked)
			{
				log("[DETECTED] NtUserBlockInput\r\n");
				DWORD oldprotect = 0;
				VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

				RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

				VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
			}
			else
			{
				log("[OK] NtUserBlockInput\r\n");
			}

			reinterpret_cast<NtUserBlockInput_t>(hooked_func_adress)(false);
		}
		catch (...)
		{
		}

		// NtUserQueryWindow
		try
		{
			auto hooked_func_adress = ResolveJmp(GetProcedureAddress(win32u, "NtUserQueryWindow"), 1);
			size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
			unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

			auto original_func_adress = ResolveJmp(GetProcedureAddress(win32u_mapped, "NtUserQueryWindow"), 1);
			size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
			unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

			// detect hook and restore bytes
			if (crc_original != crc_hooked)
			{
				log("[DETECTED] NtUserQueryWindow\r\n");
				DWORD oldprotect = 0;
				VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

				RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

				VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
			}
			else
			{
				log("[OK] NtUserQueryWindow\r\n");
			}
			HWND   a = {};
			reinterpret_cast<NtUserQueryWindow_t>(hooked_func_adress)(a, WindowProcess);
		}
		catch (...)
		{
		}

		// NtUserFindWindowEx
		try
		{
			auto hooked_func_adress = ResolveJmp(GetProcedureAddress(win32u, "NtUserFindWindowEx"), 1);
			size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
			unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

			auto original_func_adress = ResolveJmp(GetProcedureAddress(win32u_mapped, "NtUserFindWindowEx"), 1);
			size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
			unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

			// detect hook and restore bytes
			if (crc_original != crc_hooked)
			{
				log("[DETECTED] NtUserFindWindowEx\r\n");
				DWORD oldprotect = 0;
				VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

				RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

				VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
			}
			else
			{
				log("[OK] NtUserFindWindowEx\r\n");
			}
			HWND a = {};
			HWND b = {};
			reinterpret_cast<NtUserFindWindowEx_t>(hooked_func_adress)(a,b,(PUNICODE_STRING)"",(PUNICODE_STRING)"",0);
		}
		catch (...)
		{
		}

		// NtUserBuildHwndList
		try
		{
			auto hooked_func_adress = ResolveJmp(GetProcedureAddress(win32u, "NtUserBuildHwndList"), 1);
			size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
			unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

			auto original_func_adress = ResolveJmp(GetProcedureAddress(win32u_mapped, "NtUserBuildHwndList"), 1);
			size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
			unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

			// detect hook and restore bytes
			if (crc_original != crc_hooked)
			{
				log("[DETECTED] NtUserBuildHwndList\r\n");
				DWORD oldprotect = 0;
				VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

				RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

				VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
			}
			else
			{
				log("[OK] NtUserBuildHwndList\r\n");
			}
			HDESK a = {};
			HWND b = {};
			HWND *c={};
			UINT  d;
			UINT  f=0;
			reinterpret_cast<NtUserBuildHwndList_t>(hooked_func_adress)(a,b,false,0,f,c,&d);
		}
		catch (...)
		{
		}
	}
	else
	{
		LoadLibraryA("user32.dll");

		auto user_32 = GetModuleBaseAddress(L"user32.dll");
		PVOID user32_mapped = nullptr;
		MapNativeModule("user32.dll", &user32_mapped);

		// BlockInput
		try
		{
			auto hooked_func_adress = ResolveJmp(GetProcedureAddress(user_32, "BlockInput"), 1);
			size_t hooked_func_size = (size_t)GetSizeOfProc(hooked_func_adress, 1);
			unsigned int crc_hooked = crc32(hooked_func_adress, (unsigned int)hooked_func_size);

			auto original_func_adress = ResolveJmp(GetProcedureAddress(user32_mapped, "BlockInput"), 1);
			size_t original_func_size = (size_t)GetSizeOfProc(original_func_adress, 1);
			unsigned int crc_original = crc32(original_func_adress, (unsigned int)original_func_size);

			// detect hook and restore bytes
			if (crc_original != crc_hooked)
			{
				log("[DETECTED] BlockInput\r\n");
				DWORD oldprotect = 0;
				VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

				RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

				VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
			}
			else
			{
				log("[OK] BlockInput\r\n");
			}
			reinterpret_cast<BlockInput_t>(hooked_func_adress)(false);
		}
		catch (...)
		{
		}
	}
}

int main()
{
	/*ntdll*/
	ntdll_detection();
	/*kernel32 / kernelbase*/
	kernelbase_detection();
	/*user32*/
	user32_detection();

	system("pause");

	return 0;
}
