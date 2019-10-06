#pragma once
#include <string>

inline void log()
{
}

template <typename First, typename ...Rest>
void log(First&& message, Rest&& ...rest)
{
  std::cout << std::forward<First>(message);
  log(std::forward<Rest>(rest)...);
}


template <const hash_t::value_type ModuleHash>

PVOID _GetModuleHandle() noexcept
{
  const auto pPeb = reinterpret_cast<nt::PPEB>(__readgsqword(0x60));

  if (pPeb)
  {
    for (auto pListEntry = pPeb->Ldr->InLoadOrderModuleList.Flink;
         pListEntry != &pPeb->Ldr->InLoadOrderModuleList;
         pListEntry = pListEntry->Flink)
    {
      const auto pEntry = CONTAINING_RECORD(pListEntry, nt::LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

      if (ModuleHash == NULL || GetHash(pEntry->BaseDllName) == ModuleHash)
        return pEntry->DllBase;
    }
  }

  return nullptr;
}

inline PVOID get_proc_address(const PVOID module_base_address, const hash_t::value_type FunctionHash) noexcept
{
  const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base_address);
  PIMAGE_EXPORT_DIRECTORY export_directory;

  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    return nullptr;

  auto nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(static_cast<LPBYTE>(module_base_address) + dos_header
    ->e_lfanew);
  auto nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<LPBYTE>(module_base_address) + dos_header
    ->e_lfanew);

  if (nt32->Signature != IMAGE_NT_SIGNATURE)
    return nullptr;

  if (nt32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
  {
    export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(module_base_address) +
      nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  }
  else
  {
    export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(module_base_address) +
      nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  }

  const auto function_table = reinterpret_cast<LPDWORD>(static_cast<LPBYTE>(module_base_address) + export_directory->
    AddressOfFunctions);
  const auto name_table = reinterpret_cast<LPDWORD>(static_cast<LPBYTE>(module_base_address) + export_directory->
    AddressOfNames);
  const auto ordinal_table = reinterpret_cast<LPWORD>(static_cast<LPBYTE>(module_base_address) + export_directory->
    AddressOfNameOrdinals);

  for (SIZE_T i = 0; i < export_directory->NumberOfNames; ++i)
  {
    const auto function_name = reinterpret_cast<PCCH>(module_base_address) + static_cast<DWORD_PTR>(name_table[i]);
    if (GetHash(function_name) == FunctionHash)
      return reinterpret_cast<LPVOID>(static_cast<LPBYTE>(module_base_address) + function_table[ordinal_table[i]]);
  }

  return nullptr;
}

template <const hash_t::value_type FunctionHash>
PVOID _GetProcAddress(const PVOID module_base_address) noexcept
{
  const auto dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(module_base_address);
  PIMAGE_NT_HEADERS32 nt32 = nullptr;
  PIMAGE_NT_HEADERS64 nt64 = nullptr;
  PIMAGE_EXPORT_DIRECTORY export_directory = nullptr;

  LPWORD ordinal_table = nullptr;
  LPDWORD name_table = nullptr;
  LPDWORD function_table = nullptr;

  if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
    return nullptr;

  nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(static_cast<LPBYTE>(module_base_address) + dos_header->e_lfanew);
  nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(static_cast<LPBYTE>(module_base_address) + dos_header->e_lfanew);

  if (nt32->Signature != IMAGE_NT_SIGNATURE)
    return nullptr;

  if (nt32->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
  {
    export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(module_base_address) +
      nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  }
  else
  {
    export_directory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(static_cast<LPBYTE>(module_base_address) +
      nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
  }

  function_table = reinterpret_cast<LPDWORD>(static_cast<LPBYTE>(module_base_address) + export_directory->
    AddressOfFunctions);
  name_table = reinterpret_cast<LPDWORD>(static_cast<LPBYTE>(module_base_address) + export_directory->AddressOfNames);
  ordinal_table = reinterpret_cast<LPWORD>(static_cast<LPBYTE>(module_base_address) + export_directory->
    AddressOfNameOrdinals);

  for (SIZE_T i = 0; i < export_directory->NumberOfNames; ++i)
  {
    const auto function_name = reinterpret_cast<PCCH>(module_base_address) + static_cast<DWORD_PTR>(name_table[i]);
    if (GetHash(function_name) == FunctionHash)
      return reinterpret_cast<LPVOID>(static_cast<LPBYTE>(module_base_address) + function_table[ordinal_table[i]]);
  }

  return nullptr;
}

template <hash_t::value_type ModuleHash>
NTSTATUS RemapNtModule(PVOID* BaseAddress) noexcept
{
  auto status = STATUS_NOT_SUPPORTED;
  HANDLE sectionHandle = nullptr;
  SIZE_T viewSize = NULL;
  UNICODE_STRING usSectionName{};
  OBJECT_ATTRIBUTES objAttrib{};

  switch (ModuleHash)
  {
  case HASHSTR("kernel32.dll"):
    RtlInitUnicodeString(&usSectionName, L"\\KnownDlls\\kernel32.dll");
    break;
  case HASHSTR("kernelbase.dll"):
    RtlInitUnicodeString(&usSectionName, L"\\KnownDlls\\kernelbase.dll");
    break;
  case HASHSTR("ntdll.dll"):
    RtlInitUnicodeString(&usSectionName, L"\\KnownDlls\\ntdll.dll");
    break;
  case HASHSTR("win32u.dll"):
    RtlInitUnicodeString(&usSectionName, L"\\KnownDlls\\win32u.dll");
    break;
  case HASHSTR("user32.dll"):
    RtlInitUnicodeString(&usSectionName, L"\\KnownDlls\\user32.dll");
    break;
  default:
    return status;
  }

  InitializeObjectAttributes(&objAttrib, &usSectionName, OBJ_CASE_INSENSITIVE, NULL, NULL);

  status = NtFunctionCall(NtOpenSection)(&sectionHandle, SECTION_MAP_READ, &objAttrib);
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  status = NtFunctionCall(NtMapViewOfSection)(sectionHandle, NtCurrentProcess(), BaseAddress, NULL, NULL, nullptr,
                                              &viewSize, nt::SECTION_INHERIT::ViewShare, NULL, PAGE_READONLY);
  if (!NT_SUCCESS(status))
  {
    return status;
  }

  if (sectionHandle)
  {
    status = NtClose(sectionHandle);
    if (!NT_SUCCESS(status))
    {
      return status;
    }
  }

  return status;
}

std::wstring GetStringValueFromHKLM(const std::wstring& regSubKey, const std::wstring& regValue)
{
  size_t bufferSize = 0xFFF; // If too small, will be resized down below.
  std::wstring valueBuf; // Contiguous buffer since C++11.
  valueBuf.resize(bufferSize);
  auto cbData = static_cast<DWORD>(bufferSize);
  auto rc = RegGetValueW(
    HKEY_LOCAL_MACHINE,
    regSubKey.c_str(),
    regValue.c_str(),
    RRF_RT_REG_SZ,
    nullptr,
    static_cast<void*>(&valueBuf.at(0)),
    &cbData
  );
  while (rc == ERROR_MORE_DATA)
  {
    // Get a buffer that is big enough.
    cbData /= sizeof(wchar_t);
    if (cbData > static_cast<DWORD>(bufferSize))
    {
      bufferSize = static_cast<size_t>(cbData);
    }
    else
    {
      bufferSize *= 2;
      cbData = static_cast<DWORD>(bufferSize);
    }
    valueBuf.resize(bufferSize);
    rc = RegGetValueW(
      HKEY_LOCAL_MACHINE,
      regSubKey.c_str(),
      regValue.c_str(),
      RRF_RT_REG_SZ,
      nullptr,
      static_cast<void*>(&valueBuf.at(0)),
      &cbData
    );
  }
  if (rc == ERROR_SUCCESS)
  {
    valueBuf.resize(static_cast<size_t>(cbData / sizeof(wchar_t)));
    return valueBuf;
  }
  else
  {
    throw std::runtime_error("Windows system error code: " + std::to_string(rc));
  }
}
