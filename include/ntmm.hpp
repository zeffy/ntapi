#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <type_traits>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

namespace nt::mm
{
  class protect_memory
  {
  private:
    PVOID _BaseAddress;
    SIZE_T _RegionSize;
    ULONG _OldProtect;

  public:
    protect_memory() = delete;
    protect_memory(protect_memory &) = delete;

    template <class T, typename = std::enable_if_t<std::is_pod_v<T>>>
    protect_memory(T *BaseAddress, ULONG Protect)
    {
      _BaseAddress = BaseAddress;
      _RegionSize = sizeof(T);
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(NtCurrentProcess(), &_BaseAddress, &_RegionSize, Protect, &_OldProtect));
    }

    protect_memory(PVOID BaseAddress, SIZE_T RegionSize, ULONG Protect)
    {
      _BaseAddress = BaseAddress;
      _RegionSize = RegionSize;
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(NtCurrentProcess(), &_BaseAddress, &_RegionSize, Protect, &_OldProtect));
    }

    ~protect_memory()
    {
      THROW_IF_NTSTATUS_FAILED(NtProtectVirtualMemory(NtCurrentProcess(), &_BaseAddress, &_RegionSize, _OldProtect, &_OldProtect));
    }
  };
}
