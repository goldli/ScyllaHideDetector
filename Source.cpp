#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include "utils/Obfy.h"
#include "utils/Native.h"
#include "utils/Hash.h"
#include "utils/Helpers.h"

bool ntdll_detection()
{
	OBF_BEGIN
	auto ntdll = GetModuleBaseAddress(L"ntdll.dll");
	PVOID ntdll_mapped = nullptr;
	MapNativeModule("ntdll.dll", &ntdll_mapped);

	// NtYieldExecution
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtYieldExecution");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtYieldExecution");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF (V(result) != V(func_size))
			log("[DETECTED] NtYieldExecution\r\n");
			DWORD oldprotect = N(0);
			VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, V(func_size));

			result = RtlCompareMemory(hooked_func, original_func, V(func_size));
			IF (V(result) == V(func_size))
				VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
			ENDIF
		ELSE
			log("[OK] NtYieldExecution\r\n");
		ENDIF

		reinterpret_cast<NtYieldExecution_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetInformationThread
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetInformationThread");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetInformationThread");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtSetInformationThread\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtSetInformationThread\r\n");
		ENDIF

		reinterpret_cast<NtSetInformationThread_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetInformationProcess
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetInformationProcess");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetInformationProcess");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtSetInformationProcess\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtSetInformationProcess\r\n");
		ENDIF

		reinterpret_cast<NtSetInformationProcess_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQuerySystemInformation
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQuerySystemInformation");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQuerySystemInformation");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtQuerySystemInformation\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtQuerySystemInformation\r\n");
		ENDIF

		reinterpret_cast<NtQuerySystemInformation_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQueryInformationProcess
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQueryInformationProcess");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQueryInformationProcess");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtQueryInformationProcess\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtQueryInformationProcess\r\n");
		ENDIF

		reinterpret_cast<NtQueryInformationProcess_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQueryObject
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQueryObject");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQueryObject");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtQueryObject\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtQueryObject\r\n");
		ENDIF

		reinterpret_cast<NtQueryObject_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtCreateThreadEx
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtCreateThreadEx");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtCreateThreadEx");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtCreateThreadEx\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtCreateThreadEx\r\n");
		ENDIF

		reinterpret_cast<NtCreateThreadEx_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetDebugFilterState
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetDebugFilterState");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetDebugFilterState");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtSetDebugFilterState\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtSetDebugFilterState\r\n");
		ENDIF

		reinterpret_cast<NtSetDebugFilterState_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtClose
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtClose");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtClose");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtClose\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtClose\r\n");
		ENDIF

		reinterpret_cast<NtClose_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQueryPerformanceCounter
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQueryPerformanceCounter");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQueryPerformanceCounter");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtQueryPerformanceCounter\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtQueryPerformanceCounter\r\n");
		ENDIF

		reinterpret_cast<NtQueryPerformanceCounter_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtGetContextThread
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtGetContextThread");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtGetContextThread");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtGetContextThread\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtGetContextThread\r\n");
		ENDIF

		reinterpret_cast<NtGetContextThread_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtSetContextThread
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtSetContextThread");
		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)& ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		auto original_func = GetProcedureAddress(ntdll_mapped, "NtSetContextThread");

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtSetContextThread\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtSetContextThread\r\n");
		ENDIF

		reinterpret_cast<NtSetContextThread_t>(hooked_func)();
	}
	catch (...)
	{
	}

	// NtQuerySystemTime
	try
	{
		auto hooked_func = GetProcedureAddress(ntdll, "NtQuerySystemTime");
		IF (*static_cast<PUCHAR>(hooked_func) == 0xE9) // jmp rel32
			LONG relativeOffset = *(PLONG)((ULONG_PTR)hooked_func + 1);
			hooked_func = (NtQuerySystemTime_t)((ULONG_PTR)hooked_func + relativeOffset + 5);
		ENDIF
		auto original_func = GetProcedureAddress(ntdll_mapped, "NtQuerySystemTime");

		IF (*static_cast<PUCHAR>(original_func) == 0xE9) // jmp rel32
			LONG relativeOffset = *(PLONG)((ULONG_PTR)original_func + 1);
			original_func = (NtQuerySystemTime_t)((ULONG_PTR)original_func + relativeOffset + 5);
		ENDIF

		auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&ntdll, nullptr);
		size_t func_size = func_data->EndAddress - func_data->BeginAddress;

		size_t result = RtlCompareMemory(hooked_func, original_func, func_size);

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			log("[DETECTED] NtQuerySystemTime\r\n");
		DWORD oldprotect = N(0);
		VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, V(func_size));

		result = RtlCompareMemory(hooked_func, original_func, V(func_size));
		IF(V(result) == V(func_size))
			VirtualProtect(hooked_func, V(func_size), V(oldprotect), &oldprotect);
		ENDIF
			ELSE
			log("[OK] NtQuerySystemTime\r\n");
		ENDIF

		LARGE_INTEGER time;
		reinterpret_cast<NtQuerySystemTime_t>(hooked_func)(&time);
	}
	catch (...)
	{
	}
	RETURN (TRUE);
	OBF_END
}

bool kernelbase_detection()
{
	OBF_BEGIN
	const auto kernelbase = GetModuleBaseAddress("kernelbase.dll");
	PVOID kernelbase_mapped = nullptr;
	MapNativeModule("kernelbase.dll", &kernelbase_mapped);

	// GetTickCount
	try
	{
		const auto hooked_func = GetProcedureAddress(kernelbase, "GetTickCount");

		const auto original_func = GetProcedureAddress(kernelbase_mapped, "GetTickCount");

		size_t func_size = 0x18;

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF (V(result) != V(func_size))
			DWORD oldprotect = 0;
			VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

			RtlCopyMemory(hooked_func, original_func, func_size);

			result = RtlCompareMemory(hooked_func, original_func, func_size);
			IF (V(result) == V(func_size))
				log("[DETECTED] GetTickCount\r\n");

				VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
			ENDIF
		ELSE
			log("[OK] GetTickCount\r\n");
		ENDIF

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

		size_t func_size = 0x18;

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			DWORD oldprotect = 0;
		VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, func_size);

		result = RtlCompareMemory(hooked_func, original_func, func_size);
		IF(V(result) == V(func_size))
			log("[DETECTED] GetTickCount64\r\n");

		VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
		ENDIF
			ELSE
			log("[OK] GetTickCount64\r\n");
		ENDIF

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

		size_t func_size = 0x18;

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			DWORD oldprotect = 0;
		VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, func_size);

		result = RtlCompareMemory(hooked_func, original_func, func_size);
		IF(V(result) == V(func_size))
			log("[DETECTED] OutputDebugStringA\r\n");

		VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
		ENDIF
			ELSE
			log("[OK] OutputDebugStringA\r\n");
		ENDIF

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

		size_t func_size = 0x18;

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			DWORD oldprotect = 0;
		VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, func_size);

		result = RtlCompareMemory(hooked_func, original_func, func_size);
		IF(V(result) == V(func_size))
			log("[DETECTED] GetLocalTime\r\n");

		VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
		ENDIF
			ELSE
			log("[OK] GetLocalTime\r\n");
		ENDIF

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

		size_t func_size = 0x18;

		size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));

		// detect hook and restore bytes
		IF(V(result) != V(func_size))
			DWORD oldprotect = 0;
		VirtualProtect(hooked_func, func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

		RtlCopyMemory(hooked_func, original_func, func_size);

		result = RtlCompareMemory(hooked_func, original_func, func_size);
		IF(V(result) == V(func_size))
			log("[DETECTED] GetSystemTime\r\n");

		VirtualProtect(hooked_func, func_size, oldprotect, &oldprotect);
		ENDIF
			ELSE
			log("[OK] GetSystemTime\r\n");
		ENDIF

		SYSTEMTIME sm;
		reinterpret_cast<GetSystemTime_t>(hooked_func)(&sm);
	}
	catch (...)
	{
	}
	RETURN(TRUE);
	OBF_END
}

bool user32_detection()
{
	OBF_BEGIN
	DWORD dwBuild;

#pragma warning(disable : 4996)
	DWORD dwVersion = ::GetVersion();
	// Get the build number.
	IF (dwVersion < 0x80000000)
		dwBuild = static_cast<DWORD>(HIWORD(dwVersion));
	ELSE // Windows Me/98/95
		dwBuild = 0;
	ENDIF

	IF (dwBuild >= 14393)
		// win32u.dll
	ELSE
		LoadLibraryA("user32.dll");

		auto user_32 = GetModuleBaseAddress(L"user32.dll");
		PVOID user32_mapped = nullptr;
		MapNativeModule("user32.dll", &user32_mapped);

		// BlockInput
		try
		{
			auto hooked_func = GetProcedureAddress(user_32, "BlockInput");
			const auto func_data = RtlLookupFunctionEntry((DWORD64)hooked_func, (DWORD64*)&user_32, nullptr);
			size_t func_size = func_data->EndAddress - func_data->BeginAddress;
			const auto original_func = GetProcedureAddress(user32_mapped, "BlockInput");

			size_t result = RtlCompareMemory(hooked_func, original_func, V(func_size));
			// detect hook and restore bytes
			IF (V(result) != V(func_size))
				log("[DETECTED] BlockInput\r\n");
				DWORD oldprotect = N(0);
				VirtualProtect(hooked_func, V(func_size), PAGE_EXECUTE_READWRITE, &oldprotect);

				RtlCopyMemory(hooked_func, original_func, V(func_size));

				result = RtlCompareMemory(hooked_func, original_func, V(func_size));
				IF (V(result) == V(func_size))
					VirtualProtect(hooked_func, V(func_size), oldprotect, &oldprotect);
				ENDIF
			ELSE
				log("[OK] BlockInput\r\n");
			ENDIF

			reinterpret_cast<BlockInput_t>(hooked_func)(false);
		}
		catch (...)
		{
		}
	ENDIF

	RETURN (TRUE);
	OBF_END
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
