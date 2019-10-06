#include <Windows.h>
#include <winternl.h>
#include <iostream>
//#define AHOOK_LOG
#include "utils/Native.h"
#include "utils/Hash.h"
#include "utils/Helpers.h"
#include "utils/crc32.h"
#include "utils/LengthDisasm.h"
#include <vector>

void* ResolveJmp(void* Address, uint8_t Is64Bit)
{
  TLengthDisasm data = {0};

  if (data.Opcode[0] == 0xE9 && data.Length == 5 && data.OpcodeSize == 1)
  {
    const auto delta = *reinterpret_cast<uint32_t*>(reinterpret_cast<size_t>(Address) + data.OpcodeSize);
    return ResolveJmp(reinterpret_cast<void*>(reinterpret_cast<size_t>(Address) + delta + data.Length), Is64Bit);
  }

  return Address;
}

void ntdll_restore(const char* fn)
{
  const auto ntdll = GetModuleBaseAddress(L"ntdll.dll");
  PVOID ntdll_mapped = nullptr;
  MapNativeModule("ntdll.dll", &ntdll_mapped);

  const auto hooked_func_adress = ResolveJmp(GetProcAddress_(ntdll,HASHSTR(fn)), 1);
  const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
  const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

  const auto original_func_adress = ResolveJmp(GetProcAddress_(ntdll_mapped,HASHSTR(fn)), 1);
  const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
  const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

  // detect hook and restore bytes
  if (crc_original != crc_hooked)
  {
#ifndef AHOOK_LOG
    log("[Detect] " + static_cast<std::string>(fn) + "\r\n");
#endif

    DWORD oldprotect = 0;
    VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

    RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

    VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
  }
  else
  {
#ifndef AHOOK_LOG
    log("[Ok] " + static_cast<std::string>(fn) + "\r\n");
#endif
  }
}

void kernelbase_restore(const char* fn)
{
  const auto kernelbase = GetModuleBaseAddress("kernelbase.dll");
  PVOID kernelbase_mapped = nullptr;
  MapNativeModule("kernelbase.dll", &kernelbase_mapped);

  const auto hooked_func_adress = ResolveJmp(GetProcAddress_(kernelbase,HASHSTR(fn)), 1);
  const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
  const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

  const auto original_func_adress = ResolveJmp(GetProcAddress_(kernelbase_mapped,HASHSTR(fn)), 1);
  const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
  const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

  // detect hook and restore bytes
  if (crc_original != crc_hooked)
  {
#ifndef AHOOK_LOG
    log("[Detect] " + static_cast<std::string>(fn) + "\r\n");
#endif

    DWORD oldprotect = 0;
    VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

    RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

    VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
  }
  else
  {
#ifndef AHOOK_LOG
    log("[Ok] " + static_cast<std::string>(fn) + "\r\n");
#endif
  }
}

void user32_restore(const char* fn)
{
  // TODO: another method for detect build
  std::wstring regSubKey;
#ifdef _WIN64
  regSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\";
#else
    regSubKey = L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\";
#endif
  const std::wstring regValue(L"CurrentBuildNumber");
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
    HINSTANCE hModule=nullptr;
    hModule=LoadLibrary(L"user32.dll");

    const auto win32u = GetModuleBaseAddress("win32u.dll");
    PVOID win32u_mapped = nullptr;
    MapNativeModule("win32u.dll", &win32u_mapped);

    const auto hooked_func_adress = ResolveJmp(GetProcAddress_(win32u,HASHSTR(fn)), 1);
    const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
    const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

    const auto original_func_adress = ResolveJmp(GetProcAddress_(win32u_mapped,HASHSTR(fn)), 1);
    const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
    const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

    // detect hook and restore bytes
    if (crc_original != crc_hooked)
    {
#ifndef AHOOK_LOG
      log("[Detect] " + static_cast<std::string>(fn) + "\r\n");
#endif

      DWORD oldprotect = 0;
      VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

      RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

      VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
    }
    else
    {
#ifndef AHOOK_LOG
      log("[Ok] " + static_cast<std::string>(fn) + "\r\n");
#endif
    }

    FreeLibrary(hModule);
  }
  else
  {
    HINSTANCE hModule=nullptr;
    hModule=LoadLibraryA("user32.dll");

    const auto user_32 = GetModuleBaseAddress(L"user32.dll");
    PVOID user32_mapped = nullptr;
    MapNativeModule("user32.dll", &user32_mapped);

    const auto hooked_func_adress = ResolveJmp(GetProcAddress_(user_32,HASHSTR(fn)), 1);
    const auto hooked_func_size = static_cast<size_t>(GetSizeOfProc(hooked_func_adress, 1));
    const auto crc_hooked = crc32(hooked_func_adress, static_cast<unsigned int>(hooked_func_size));

    const auto original_func_adress = ResolveJmp(GetProcAddress_(user32_mapped,HASHSTR(fn)), 1);
    const auto original_func_size = static_cast<size_t>(GetSizeOfProc(original_func_adress, 1));
    const auto crc_original = crc32(original_func_adress, static_cast<unsigned int>(original_func_size));

    // detect hook and restore bytes
    if (crc_original != crc_hooked)
    {
#ifndef AHOOK_LOG
      log("[Detect] " + static_cast<std::string>(fn) + "\r\n");
#endif

      DWORD oldprotect = 0;
      VirtualProtect(hooked_func_adress, hooked_func_size, PAGE_EXECUTE_READWRITE, &oldprotect);

      RtlCopyMemory(hooked_func_adress, original_func_adress, hooked_func_size);

      VirtualProtect(hooked_func_adress, hooked_func_size, oldprotect, &oldprotect);
    }
    else
    {
#ifndef AHOOK_LOG
      log("[Ok] " + static_cast<std::string>(fn) + "\r\n");
#endif
    }

    FreeLibrary(hModule);
  }
}

int main()
{
  ntdll_restore("NtYieldExecution");
  ntdll_restore("NtSetInformationThread");
  ntdll_restore("NtSetInformationProcess");
  ntdll_restore("NtQuerySystemInformation");
  ntdll_restore("NtQueryInformationProcess");
  ntdll_restore("NtQueryObject");
  ntdll_restore("NtCreateThreadEx");
  ntdll_restore("NtSetDebugFilterState");
  ntdll_restore("NtClose");
  ntdll_restore("NtQueryPerformanceCounter");
  ntdll_restore("NtGetContextThread");
  ntdll_restore("NtSetContextThread");

  //TODO: make this workable
  //ntdll_restore("NtQuerySystemTime");

  kernelbase_restore("GetTickCount");
  kernelbase_restore("GetTickCount64");
  kernelbase_restore("OutputDebugStringA");
  kernelbase_restore("GetLocalTime");
  kernelbase_restore("GetSystemTime");

  user32_restore("NtUserBlockInput");
  user32_restore("NtUserQueryWindow");
  user32_restore("NtUserFindWindowEx");
  user32_restore("NtUserBuildHwndList");

  // additional
  user32_restore("BlockInput");
  kernelbase_restore("CheckRemoteDebuggerPresent");
  kernelbase_restore("OutputDebugString");
  kernelbase_restore("OutputDebugStringW");

  system("pause");

  return 0;
}
