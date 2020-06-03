#pragma once
#include <ntdll.h>
#include <cstdint>

namespace ntapi
{
  class critsec : public RTL_CRITICAL_SECTION
  {
  public:
    using native_handle_type = RTL_CRITICAL_SECTION *;

  public:
    critsec() {
      RtlInitializeCriticalSection(this);
    }

    critsec(unsigned long spinCount) {
      RtlInitializeCriticalSectionAndSpinCount(this, spinCount);
    }

    void lock()
    {
      RtlEnterCriticalSection(this);
    }

    bool try_lock()
    {
      return RtlTryEnterCriticalSection(this);
    }

    void unlock()
    {
      RtlLeaveCriticalSection(this);
    }

    native_handle_type native_handle()
    {
      return this;
    }
  };
}
