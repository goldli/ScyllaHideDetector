#include <Windows.h>
#include <winternl.h>
#include <iostream>
#define AHOOK_LOG
#define JM_XORSTR_DISABLE_AVX_INTRINSICS // amd fix
#include "utils/xorstr.hpp"
#include "utils/Native.hpp"
#include "utils/Hash.hpp"
#include "utils/Helpers.hpp"
#include "utils/crc32.hpp"
#include "utils/LengthDisasm.hpp"
#include <vector>

void ntdll_restore(const char* func_name)
{
  const auto ntdll = GET_MODULE_BASE_ADDRESS(L"ntdll.dll");
  PVOID ntdll_mapped = nullptr;
  MAP_NATIVE_MODULE("ntdll.dll", &ntdll_mapped);

  const auto hooked_func_adress = resolve_jmp(get_proc_address(ntdll,HASHSTR(func_name)), 1);
  const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
  const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

  const auto original_func_adress = resolve_jmp(get_proc_address(ntdll_mapped,HASHSTR(func_name)), 1);
  const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
  const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

  // detect hook and restore bytes
  if (crc_original != crc_hooked)
  {
#ifndef AHOOK_LOG
    log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif

    DWORD oldprotect = 0;
    VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
    memcpy(hooked_func_adress,original_func_adress,hooked_func_size);
    VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
  }
  else
  {
#ifndef AHOOK_LOG
    log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
  }
}

void kernelbase_restore(const char* func_name)
{
  const auto kernelbase = GET_MODULE_BASE_ADDRESS("kernelbase.dll");
  PVOID kernelbase_mapped = nullptr;
  MAP_NATIVE_MODULE("kernelbase.dll", &kernelbase_mapped);

  const auto hooked_func_adress = resolve_jmp(get_proc_address(kernelbase,HASHSTR(func_name)), 1);
  const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
  const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

  const auto original_func_adress = resolve_jmp(get_proc_address(kernelbase_mapped,HASHSTR(func_name)), 1);
  const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
  const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

  // detect hook and restore bytes
  if (crc_original != crc_hooked)
  {
#ifndef AHOOK_LOG
    log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif

    DWORD oldprotect = 0;
    VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
    memcpy(hooked_func_adress,original_func_adress,hooked_func_size);
    VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
  }
  else
  {
#ifndef AHOOK_LOG
    log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
  }
}

void user32_restore(const char* func_name)
{
  // TODO: Test on Win7,8
  if (getSysOpType() == 10)
  {
    const auto h_module = LoadLibraryW(xorstr_(L"user32.dll"));

    const auto win32_u = GET_MODULE_BASE_ADDRESS("win32u.dll");
    PVOID win32_u_mapped = nullptr;
    MAP_NATIVE_MODULE("win32u.dll", &win32_u_mapped);

    const auto hooked_func_adress = resolve_jmp(get_proc_address(win32_u,HASHSTR(func_name)), 1);
    const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
    const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

    const auto original_func_adress = resolve_jmp(get_proc_address(win32_u_mapped,HASHSTR(func_name)), 1);
    const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
    const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

    // detect hook and restore bytes
    if (crc_original != crc_hooked)
    {
#ifndef AHOOK_LOG
      log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif

      DWORD oldprotect = 0;
      VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
      memcpy(hooked_func_adress,original_func_adress,hooked_func_size);
      VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
    }
    else
    {
#ifndef AHOOK_LOG
      log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
    }

    FreeLibrary(h_module);
  }
  else
  {
    const auto h_module = LoadLibraryW(xorstr_(L"user32.dll"));

    const auto user_32 = GET_MODULE_BASE_ADDRESS(L"user32.dll");
    PVOID user32_mapped = nullptr;
    MAP_NATIVE_MODULE("user32.dll", &user32_mapped);

    const auto hooked_func_adress = resolve_jmp(get_proc_address(user_32,HASHSTR(func_name)), 1);
    const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
    const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

    const auto original_func_adress = resolve_jmp(get_proc_address(user32_mapped,HASHSTR(func_name)), 1);
    const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
    const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

    // detect hook and restore bytes
    if (crc_original != crc_hooked)
    {
#ifndef AHOOK_LOG
      log("[Detect] " + static_cast<std::string>(func_name) + "\r\n");
#endif

      DWORD oldprotect = 0;
      VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);
      memcpy(hooked_func_adress,original_func_adress,hooked_func_size);
      VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
    }
    else
    {
#ifndef AHOOK_LOG
      log("[Ok] " + static_cast<std::string>(func_name) + "\r\n");
#endif
    }

    FreeLibrary(h_module);
  }
}

int main()
{
  ntdll_restore(xorstr_("NtYieldExecution"));
  ntdll_restore(xorstr_("NtSetInformationThread"));
  ntdll_restore(xorstr_("NtSetInformationProcess"));
  ntdll_restore(xorstr_("NtQuerySystemInformation"));
  ntdll_restore(xorstr_("NtQueryInformationProcess"));
  ntdll_restore(xorstr_("NtQueryObject"));
  ntdll_restore(xorstr_("NtCreateThreadEx"));
  ntdll_restore(xorstr_("NtSetDebugFilterState"));
  ntdll_restore(xorstr_("NtClose"));
  ntdll_restore(xorstr_("NtQueryPerformanceCounter"));
  ntdll_restore(xorstr_("NtGetContextThread"));
  ntdll_restore(xorstr_("NtSetContextThread"));

  //TODO: make this workable
  //ntdll_restore("NtQuerySystemTime");

  kernelbase_restore(xorstr_("GetTickCount"));
  kernelbase_restore(xorstr_("GetTickCount64"));
  kernelbase_restore(xorstr_("OutputDebugStringA"));
  kernelbase_restore(xorstr_("GetLocalTime"));
  kernelbase_restore(xorstr_("GetSystemTime"));

  user32_restore(xorstr_("NtUserBlockInput"));
  user32_restore(xorstr_("NtUserQueryWindow"));
  user32_restore(xorstr_("NtUserFindWindowEx"));
  user32_restore(xorstr_("NtUserBuildHwndList"));

  // additional
  user32_restore(xorstr_("BlockInput"));
  kernelbase_restore(xorstr_("CheckRemoteDebuggerPresent"));
  kernelbase_restore(xorstr_("OutputDebugString"));
  kernelbase_restore(xorstr_("OutputDebugStringW"));

  system("pause");

  return 0;
}
