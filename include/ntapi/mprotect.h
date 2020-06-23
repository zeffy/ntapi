#pragma once
#include <phnt_windows.h>
#include <phnt.h>

namespace ntapi
{
  class mprotect
  {
    void *ptr;
    size_t size;
    unsigned long protect;
    long status;

  public:
    mprotect(void *ptr, size_t size, unsigned long protect)
      : ptr(ptr), size(size), protect(protect), status(NtProtectVirtualMemory(NtCurrentProcess(), &ptr, &size, protect, &protect))
    {
    }

    ~mprotect()
    {
      NtProtectVirtualMemory(NtCurrentProcess(), &ptr, &size, protect, &protect);
    }

    operator bool() const
    {
      return NT_SUCCESS(status);
    }
  };
}
