#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include "utils/Native.h"
#include "utils/Hash.h"
#include "utils/Helpers.h"
#include <vector>
#include <assert.h>

void ntdll_detection()
{
	auto ntdll = GetModuleBaseAddress(L"ntdll.dll");
	PVOID ntdll_mapped = nullptr;
	MapNativeModule("ntdll.dll", &ntdll_mapped);

	// NtYieldExecution
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtYieldExecution");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtYieldExecution");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtYieldExecution\r\n");
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
			log("[OK] NtYieldExecution\r\n");
		}

		reinterpret_cast<NtYieldExecution_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetInformationThread
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetInformationThread");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetInformationThread");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtSetInformationThread\r\n");

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
			log("[OK] NtSetInformationThread\r\n");
		}

		reinterpret_cast<NtSetInformationThread_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetInformationProcess
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetInformationProcess");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetInformationProcess");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtSetInformationProcess\r\n");
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
			log("[OK] NtSetInformationProcess\r\n");
		}

		reinterpret_cast<NtSetInformationProcess_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQuerySystemInformation
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQuerySystemInformation");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQuerySystemInformation");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtQuerySystemInformation\r\n");
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
			log("[OK] NtQuerySystemInformation\r\n");
		}

		reinterpret_cast<NtQuerySystemInformation_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQueryInformationProcess
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQueryInformationProcess");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQueryInformationProcess");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtQueryInformationProcess\r\n");
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
			log("[OK] NtQueryInformationProcess\r\n");
		}

		reinterpret_cast<NtQueryInformationProcess_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQueryObject
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQueryObject");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQueryObject");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtQueryObject\r\n");
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
			log("[OK] NtQueryObject\r\n");
		}

		reinterpret_cast<NtQueryObject_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtCreateThreadEx
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtCreateThreadEx");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtCreateThreadEx");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtCreateThreadEx\r\n");
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
			log("[OK] NtCreateThreadEx\r\n");
		}

		reinterpret_cast<NtCreateThreadEx_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetDebugFilterState
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetDebugFilterState");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetDebugFilterState");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtSetDebugFilterState\r\n");
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
			log("[OK] NtSetDebugFilterState\r\n");
		}

		reinterpret_cast<NtSetDebugFilterState_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtClose
	//try
	//{
	//	auto hooked_func = GetProcedureAddress(ntdll, "NtClose");
	//	auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
	//	auto func_size = func_data->EndAddress - func_data->BeginAddress;

	//	auto original_func = GetProcedureAddress(ntdll_mapped, "NtClose");

	//	auto result = RtlCompareMemory(hooked_func, original_func, func_size);

	//	// detect hook and restore bytes
	//	if (result != func_size)
	//	{
	//		log("[DETECTED] NtClose\r\n");
	//		DWORD oldprotect = 0;
	//		VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

	//		RtlCopyMemory(hooked_func, original_func, func_size);

	//		result = RtlCompareMemory(hooked_func, original_func, func_size);
	//		if (result == func_size)
	//		{
	//			VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
	//		}
	//	}
	//	else
	//	{
	//		log("[OK] NtClose\r\n");
	//	}

	//	reinterpret_cast<NtClose_t>(hooked_func)();
	//}
	//catch (...)
	//{
	//}

	// NtQueryPerformanceCounter
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQueryPerformanceCounter");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQueryPerformanceCounter");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtQueryPerformanceCounter\r\n");
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
			log("[OK] NtQueryPerformanceCounter\r\n");
		}

		reinterpret_cast<NtQueryPerformanceCounter_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtGetContextThread
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtGetContextThread");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtGetContextThread");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtGetContextThread\r\n");
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
			log("[OK] NtGetContextThread\r\n");
		}

		reinterpret_cast<NtGetContextThread_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetContextThread
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetContextThread");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		auto func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetContextThread");

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (result != func_size)
		{
			log("[DETECTED] NtSetContextThread\r\n");
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
			log("[OK] NtSetContextThread\r\n");
		}

		reinterpret_cast<NtSetContextThread_t>(hooked_func)();
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
		const auto hooked_func = GetProcedureAddress(kernelbase, "CheckRemoteDebuggerPresent");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "CheckRemoteDebuggerPresent");

		const auto func_size = 0x18;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (static_cast<int>(result) != func_size)
		{
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (static_cast<int>(result) == func_size)
			{
				log("[DETECTED] CheckRemoteDebuggerPresent\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] CheckRemoteDebuggerPresent\r\n");
		}

		reinterpret_cast<GetTickCount_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// GetTickCount
	try
	{
		const auto hooked_func = GetProcedureAddress(kernelbase, "GetTickCount");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "GetTickCount");

		const auto func_size = 0x18;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (static_cast<int>(result) != func_size)
		{
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (static_cast<int>(result) == func_size)
			{
				log("[DETECTED] GetTickCount\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] GetTickCount\r\n");
		}

		reinterpret_cast<GetTickCount_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// GetTickCount64
	try
	{
		const auto hooked_func = GetProcedureAddress(kernelbase, "GetTickCount64");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "GetTickCount64");

		const auto func_size = 0x18;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook
		if (static_cast<int>(result) != func_size)
		{
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (static_cast<int>(result) == func_size)
			{
				log("[DETECTED] GetTickCount64\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] GetTickCount64\r\n");
		}

		reinterpret_cast<GetTickCount64_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// OutputDebugStringA
	try
	{
		const auto hooked_func = GetProcedureAddress(kernelbase, "OutputDebugStringA");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "OutputDebugStringA");

		const auto func_size = 0x18;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (static_cast<int>(result) != func_size)
		{
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (static_cast<int>(result) == func_size)
			{
				log("[DETECTED] OutputDebugStringA\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] OutputDebugStringA\r\n");
		}

		reinterpret_cast<OutputDebugStringA_t>(hooked_func)("");
	}
	catch (...)
	{
	}

	// GetLocalTime
	try
	{
		const auto hooked_func = GetProcedureAddress(kernelbase, "GetLocalTime");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "GetLocalTime");

		const auto func_size = 0x18;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (static_cast<int>(result) != func_size)
		{
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (static_cast<int>(result) == func_size)
			{
				log("[DETECTED] GetLocalTime\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] GetLocalTime\r\n");
		}
		SYSTEMTIME sm;
		reinterpret_cast<GetLocalTime_t>(hooked_func)(&sm);
	}
	catch (...)
	{
	}

	// GetSystemTime
	try
	{
		const auto hooked_func = GetProcedureAddress(kernelbase, "GetSystemTime");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "GetSystemTime");

		const auto func_size = 0x18;

		auto result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		if (static_cast<int>(result) != func_size)
		{
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			if (static_cast<int>(result) == func_size)
			{
				log("[DETECTED] GetSystemTime\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			}
		}
		else
		{
			log("[OK] GetSystemTime\r\n");
		}
		SYSTEMTIME sm;
		reinterpret_cast<GetSystemTime_t>(hooked_func)(&sm);
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
			const auto original_func = GetProcedureAddress(win32u_mapped, "NtUserBlockInput");
			auto hooked_func = GetProcedureAddress(win32u, "NtUserBlockInput");

			const auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&win32u, nullptr);
			const auto func_size = func_data->EndAddress - func_data->BeginAddress;
			auto result = RtlCompareMemory(hooked_func, original_func, func_size);
			// detect hook and restore bytes
			if (result != func_size)
			{
				log("[DETECTED] NtUserBlockInput\r\n");
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
				log("[OK] NtUserBlockInput\r\n");
			}

			reinterpret_cast<NtUserBlockInput_t>(hooked_func)(false);
		}
		catch (...)
		{
		}

		// NtUserQueryWindow
		try
		{
			const auto original_func = GetProcedureAddress(win32u_mapped, "NtUserQueryWindow");
			auto hooked_func = GetProcedureAddress(win32u, "NtUserQueryWindow");

			const auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&win32u, nullptr);
			const auto func_size = func_data->EndAddress - func_data->BeginAddress;
			auto result = RtlCompareMemory(hooked_func, original_func, func_size);
			// detect hook and restore bytes
			if (result != func_size)
			{
				log("[DETECTED] NtUserQueryWindow\r\n");
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
				log("[OK] NtUserQueryWindow\r\n");
			}
			HWND   a = {};
			reinterpret_cast<NtUserQueryWindow_t>(hooked_func)(a, WindowProcess);
		}
		catch (...)
		{
		}

		// NtUserFindWindowEx
		try
		{
			const auto original_func = GetProcedureAddress(win32u_mapped, "NtUserFindWindowEx");
			auto hooked_func = GetProcedureAddress(win32u, "NtUserFindWindowEx");

			const auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&win32u, nullptr);
			const auto func_size = func_data->EndAddress - func_data->BeginAddress;
			auto result = RtlCompareMemory(hooked_func, original_func, func_size);
			// detect hook and restore bytes
			if (result != func_size)
			{
				log("[DETECTED] NtUserFindWindowEx\r\n");
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
				log("[OK] NtUserFindWindowEx\r\n");
			}
			HWND a = {};
			HWND b = {};
			reinterpret_cast<NtUserFindWindowEx_t>(hooked_func)(a,b,(PUNICODE_STRING)"",(PUNICODE_STRING)"",0);
		}
		catch (...)
		{
		}

		// NtUserBuildHwndList
		try
		{
			const auto original_func = GetProcedureAddress(win32u_mapped, "NtUserBuildHwndList");
			auto hooked_func = GetProcedureAddress(win32u, "NtUserBuildHwndList");

			const auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&win32u, nullptr);
			const auto func_size = func_data->EndAddress - func_data->BeginAddress;
			auto result = RtlCompareMemory(hooked_func, original_func, func_size);
			// detect hook and restore bytes
			if (result != func_size)
			{
				log("[DETECTED] NtUserBuildHwndList\r\n");
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
				log("[OK] NtUserBuildHwndList\r\n");
			}
			HDESK a = {};
			HWND b = {};
			HWND *c={};
			UINT  d;
			UINT  f=0;
			reinterpret_cast<NtUserBuildHwndList_t>(hooked_func)(a,b,false,0,f,c,&d);
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
			auto hooked_func = GetProcedureAddress(user_32, "BlockInput");
			const auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&user_32, nullptr);
			const auto func_size = func_data->EndAddress - func_data->BeginAddress;
			const auto original_func = GetProcedureAddress(user32_mapped, "BlockInput");

			auto result = RtlCompareMemory(hooked_func, original_func, func_size);
			// detect hook and restore bytes
			if (result != func_size)
			{
				log("[DETECTED] BlockInput\r\n");
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
				log("[OK] BlockInput\r\n");
			}

			reinterpret_cast<BlockInput_t>(hooked_func)(false);
		}
		catch (...)
		{
		}
	}
}

int main()
{
	/*ntdll*/
	//ntdll_detection();
	/*kernel32 / kernelbase*/
	kernelbase_detection();
	/*user32*/
	//user32_detection();

	system("pause");

	return 0;
}
