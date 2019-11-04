#pragma once

#include <string>

#include "LengthDisasm.hpp"
#include "../winapi_hash/hash_work.hpp"

// Super Hide String
#include "hidestr/hide_str.hpp"

#include "Hash.hpp"
#include "Native.hpp"

typedef struct _LDR_DATA_TABLE_ENTRY_custom
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;                             // Base address of the module
  PVOID EntryPoint;
  ULONG SizeOfImage;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
  ULONG  Flags;
  USHORT LoadCount;
  USHORT TlsIndex;
  LIST_ENTRY HashLinks;
  PVOID SectionPointer;
  ULONG CheckSum;
  ULONG TimeDateStamp;
  PVOID LoadedImports;
  PVOID EntryPointActivationContext;
  PVOID PatchInformation;
  PVOID Unknown1;
  PVOID Unknown2;
  PVOID Unknown3;

} LDR_DATA_TABLE_ENTRY_custom, * PLDR_DATA_TABLE_ENTRY_custom;
typedef struct _PEB_LDR_DATA_custom
{
  ULONG Length;
  BOOLEAN Initialized;
  HANDLE SsHandle;
  LIST_ENTRY InLoadOrderModuleList;               // Points to the loaded modules (main EXE usually)
  LIST_ENTRY InMemoryOrderModuleList;             // Points to all modules (EXE and all DLLs)
  LIST_ENTRY InInitializationOrderModuleList;
  PVOID      EntryInProgress;

} PEB_LDR_DATA_custom, * PPEB_LDR_DATA_custom;

typedef struct _PEB_custom
{
  BOOLEAN InheritedAddressSpace;      // These four fields cannot change unless the
  BOOLEAN ReadImageFileExecOptions;   //
  BOOLEAN BeingDebugged;              //
  BOOLEAN SpareBool;                  //
  HANDLE Mutant;                      // INITIAL_PEB structure is also updated.

  PVOID ImageBaseAddress;
  PPEB_LDR_DATA_custom Ldr;
  PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PVOID FastPebLockRoutine;
  PVOID FastPebUnlockRoutine;
  ULONG EnvironmentUpdateCount;
  PVOID KernelCallbackTable;
  HANDLE SystemReserved;
  PVOID  AtlThunkSListPtr32;
  //PPEB_FREE_BLOCK FreeList;
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[2];         // relates to TLS_MINIMUM_AVAILABLE
  PVOID ReadOnlySharedMemoryBase;
  PVOID ReadOnlySharedMemoryHeap;
  PVOID *ReadOnlyStaticServerData;
  PVOID AnsiCodePageData;
  PVOID OemCodePageData;
  PVOID UnicodeCaseTableData;

  //
  // Useful information for LdrpInitialize

  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;

  //
  // Passed up from MmCreatePeb from Session Manager registry key
  //

  LARGE_INTEGER CriticalSectionTimeout;
  ULONG HeapSegmentReserve;
  ULONG HeapSegmentCommit;
  ULONG HeapDeCommitTotalFreeThreshold;
  ULONG HeapDeCommitFreeBlockThreshold;

  //
  // Where heap manager keeps track of all heaps created for a process
  // Fields initialized by MmCreatePeb.  ProcessHeaps is initialized
  // to point to the first free byte after the PEB and MaximumNumberOfHeaps
  // is computed from the page size used to hold the PEB, less the fixed
  // size of this data structure.
  //

  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID *ProcessHeaps;

  //
  //
  PVOID GdiSharedHandleTable;
  PVOID ProcessStarterHelper;
  PVOID GdiDCAttributeList;
  PVOID LoaderLock;

  //
  // Following fields filled in by MmCreatePeb from system values and/or
  // image header. These fields have changed since Windows NT 4.0,
  // so use with caution
  //

  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  USHORT OSBuildNumber;
  USHORT OSCSDVersion;
  ULONG OSPlatformId;
  ULONG ImageSubsystem;
  ULONG ImageSubsystemMajorVersion;
  ULONG ImageSubsystemMinorVersion;
  ULONG ImageProcessAffinityMask;
  ULONG GdiHandleBuffer[GDI_HANDLE_BUFFER_SIZE];

} PEB_custom, * PPEB_custom;

__forceinline int xwcsicmp(wchar_t *s1, wchar_t *s2)
{
  wchar_t f, l;
  do
  {
    f = ((*s1 <= 'Z') && (*s1 >= 'A')) ? *s1 + 'a' - 'A' : *s1;
    l = ((*s2 <= 'Z') && (*s2 >= 'A')) ? *s2 + 'a' - 'A' : *s2;
    s1++;
    s2++;
  } while ((f) && (f == l));
  return (int)(f - l);
}
__forceinline void log()
{
}

template <typename First, typename ...Rest>
__forceinline void log(First &&message, Rest &&...rest)
{
  std::cout << std::forward<First>(message);
  log(std::forward<Rest>(rest)...);
}

#pragma warning (disable : 4996)
__forceinline const wchar_t *GetWC(const char *c)
{
  const size_t cSize = strlen(c) + 1;
  wchar_t *wc = new wchar_t[cSize];
  mbstowcs(wc, c, cSize);
  return wc;
}

__forceinline PVOID get_module_handle(const wchar_t *ModuleName) noexcept
{
#ifdef _WIN64
  PPEB_custom p_peb = (PPEB_custom)__readgsqword(0x60);
#else
  PPEB_custom p_peb = (PPEB_custom)__readfsdword(0x30);
#endif
  if (p_peb)
  {
    PLDR_DATA_TABLE_ENTRY_custom Entry;
    PLIST_ENTRY Next;
    Next = p_peb->Ldr->InMemoryOrderModuleList.Flink;
    while (Next != &p_peb->Ldr->InMemoryOrderModuleList)
    {
      Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY_custom, InMemoryOrderLinks);
      if (!xwcsicmp(Entry->BaseDllName.Buffer, (wchar_t *)ModuleName))
      {
        return Entry->DllBase;
      }
      Next = Next->Flink;
    }
  }
  return nullptr;
}

__forceinline PVOID get_proc_address(const PVOID module_base_address, const hash_t::value_type FunctionHash) noexcept
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
    if (get_hash(function_name) == FunctionHash)
      return reinterpret_cast<LPVOID>(static_cast<LPBYTE>(module_base_address) + function_table[ordinal_table[i]]);
  }
  return nullptr;
}

template <const hash_t::value_type FunctionHash>
__forceinline PVOID _GetProcAddress(const PVOID module_base_address) noexcept
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
    if (get_hash(function_name) == FunctionHash)
      return reinterpret_cast<LPVOID>(static_cast<LPBYTE>(module_base_address) + function_table[ordinal_table[i]]);
  }
  return nullptr;
}

template <hash_t::value_type ModuleHash>
__forceinline NTSTATUS remap_nt_module(PVOID *BaseAddress) noexcept
{
  auto status = STATUS_NOT_SUPPORTED;
  HANDLE section_handle = nullptr;
  SIZE_T view_size = NULL;
  UNICODE_STRING us_section_name{};
  OBJECT_ATTRIBUTES obj_attrib;
  switch (ModuleHash)
  {
    case HASHSTR("kernel32.dll"):
      hash_RtlInitUnicodeString(&us_section_name, GetWC((LPCSTR)PRINT_HIDE_STR("\\KnownDlls\\kernel32.dll")));
      break;
    case HASHSTR("kernelbase.dll"):
      hash_RtlInitUnicodeString(&us_section_name, GetWC((LPCSTR)PRINT_HIDE_STR("\\KnownDlls\\kernelbase.dll")));
      break;
    case HASHSTR("ntdll.dll"):
      hash_RtlInitUnicodeString(&us_section_name, GetWC((LPCSTR)PRINT_HIDE_STR("\\KnownDlls\\ntdll.dll")));
      break;
    case HASHSTR("win32u.dll"):
      hash_RtlInitUnicodeString(&us_section_name, GetWC((LPCSTR)PRINT_HIDE_STR("\\KnownDlls\\win32u.dll")));
      break;
    case HASHSTR("user32.dll"):
      hash_RtlInitUnicodeString(&us_section_name, GetWC((LPCSTR)PRINT_HIDE_STR("\\KnownDlls\\user32.dll")));
      break;
    default:
      return status;
  }
  InitializeObjectAttributes(&obj_attrib, &us_section_name, OBJ_CASE_INSENSITIVE, NULL, NULL);
  status = NT_FUNCTION_CALL(NtOpenSection)(&section_handle, SECTION_MAP_READ, &obj_attrib);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  status = NT_FUNCTION_CALL(NtMapViewOfSection)(section_handle, NT_CURRENT_PROCESS(), BaseAddress, NULL, NULL, nullptr,
           &view_size, nt::SECTION_INHERIT::ViewShare, NULL, PAGE_READONLY);
  if (!NT_SUCCESS(status))
  {
    return status;
  }
  if (section_handle)
  {
    status = hash_NtClose(section_handle);
    if (!NT_SUCCESS(status))
    {
      return status;
    }
  }
  return status;
}

__forceinline int getSysOpType()
{
  int ret = (int)0.0;
  NTSTATUS (WINAPI * RtlGetVersion)(LPOSVERSIONINFOEXW);
  OSVERSIONINFOEXW osInfo;
  const auto ntdll = get_module_handle(L"ntdll.dll");
  *(PVOID *)&RtlGetVersion = get_proc_address(ntdll, HASHSTR((LPCSTR)PRINT_HIDE_STR("RtlGetVersion")));
  if (NULL != RtlGetVersion)
  {
    osInfo.dwOSVersionInfoSize = sizeof osInfo;
    RtlGetVersion(&osInfo);
    ret = osInfo.dwMajorVersion;
  }
  return ret;
}

__forceinline void *resolve_jmp(void *address, const uint8_t is64_bit)
{
  TLengthDisasm data = {0};
  if (data.Opcode[0] == 0xE9 && data.Length == 5 && data.OpcodeSize == 1)
  {
    const auto delta = *reinterpret_cast<uint32_t *>(reinterpret_cast<size_t>(address) + data.OpcodeSize);
    return resolve_jmp(reinterpret_cast<void *>(reinterpret_cast<size_t>(address) + delta + data.Length), is64_bit);
  }
  return address;
}
