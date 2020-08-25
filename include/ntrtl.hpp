#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <span>
#include <iterator>
#include <type_traits>
#include <memory>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

namespace nt::rtl
{
  class critical_section : public _RTL_CRITICAL_SECTION
  {
  public:
    using native_handle_type = struct _RTL_CRITICAL_SECTION *;

    critical_section()
    {
      RtlInitializeCriticalSection(this);
    }

    critical_section(unsigned long spinCount)
    {
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

  class unicode_string_view : public _UNICODE_STRING
  {
  public:
    using value_type = WCHAR;
    using pointer = PWCH;
    using const_pointer = PCWSTR;
    using reference = WCHAR &;
    using const_reference = CONST WCHAR &;
    using iterator = pointer;
    using const_iterator = const_pointer;

    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    using size_type = USHORT;
    using difference_type = SHORT;

  public:
    unicode_string_view() = delete;

    unicode_string_view(const unicode_string_view &SourceString) = delete;

    unicode_string_view(const_pointer SourceString)
    {
      THROW_IF_NTSTATUS_FAILED(RtlInitUnicodeStringEx(this, SourceString));
    }

    unicode_string_view(const_pointer SourceString, size_type Length)
    {
      this->Buffer = const_cast<pointer>(SourceString);
      this->Length = Length;
      this->MaximumLength = Length;
    }

    const_reference operator[](size_t index) const
    {
      return this->Buffer[index];
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool starts_with(const T &String) const
    {
      auto s1 = this->begin();
      auto s2 = String.Buffer;
      const auto n = this->size_bytes();

      if ( String.Length < n )
        return false;

      const auto end = this->end();
      while ( s1 < end ) {
        if ( *s1++ != *s2++ )
          return false;
      }
      return true;
    }

    bool starts_with(PCWSTR String) const
    {
      return this->starts_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool istarts_with(const T &String) const
    {
      return RtlPrefixUnicodeString(const_cast<T *>(std::addressof(String)), const_cast<unicode_string_view *>(this), TRUE);
    }

    bool istarts_with(PCWSTR String) const
    {
      return this->istarts_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool ends_with(const T &String) const
    {
      if ( this->size_bytes() < String.Length )
        return false;

      return unicode_string_view(this->data() + (this->size_bytes() - String.Length), String.Length).equals(String);
    }

    bool ends_with(PCWSTR String) const
    {
      return this->ends_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool iends_with(const T &String) const
    {
      if ( this->size_bytes() < String.Length )
        return false;

      return unicode_string_view(this->data() + (this->size_bytes() - String.Length), String.Length).iequals(String);
    }

    bool iends_with(PCWSTR String) const
    {
      return this->iends_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool equals(const T &String) const
    {
      auto s1 = this->begin();
      auto s2 = String.Buffer;

      const auto n1 = this->size_bytes();
      const auto n2 = String.Length;

      if ( n1 != n2 )
        return false;

      while ( n1 >= sizeof(std::uintptr_t) ) {
        if ( *reinterpret_cast<const std::uintptr_t *>(&*s1) != *reinterpret_cast<const std::uintptr_t *>(&*s2) )
          break;

        s1 += sizeof(std::uintptr_t) / sizeof(*s1);
        s2 += sizeof(std::uintptr_t) / sizeof(*s2);
      }

      const auto end = this->end();
      while ( s1 < end ) {
        if ( *s1++ != *s2++ )
          return false;
      }
      return true;
    }

    bool equals(PCWSTR String) const
    {
      return this->equals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool iequals(const T &String) const
    {
      return RtlEqualUnicodeString(const_cast<unicode_string_view *>(this), const_cast<T *>(std::addressof(String)), TRUE);
    }

    bool iequals(PCWSTR String) const
    {
      return this->iequals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long compare(const T &String) const
    {
      auto s1 = this->begin();
      auto s2 = String.Buffer;

      const auto n1 = this->size_bytes();
      const auto n2 = String.Length;

      const auto end = this->end();
      while ( s1 < end ) {
        if ( *s1 != *s2 )
          return static_cast<long>(*s1) - static_cast<long>(*s2);
        ++s1;
        ++s2;
      }
      return n1 - n2;
    }

    long compare(PCWSTR String) const
    {
      return this->compare(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long icompare(const T &String) const
    {
      return RtlCompareUnicodeString(const_cast<unicode_string_view *>(this), const_cast<T *>(std::addressof(String)), TRUE);
    }

    long icompare(PCWSTR String) const
    {
      return this->icompare(unicode_string_view(String));
    }

    const_pointer data() const
    {
      return this->Buffer;
    }

    size_type capacity() const
    {
      return this->MaximumLength;
    }

    size_type size_bytes() const
    {
      return this->Length;
    }

    size_type size() const
    {
      return this->size_bytes() / sizeof(value_type);
    }

    bool empty() const
    {
      return !this->size_bytes();
    }

    const_reference front() const
    {
      return this->operator[](0);
    }

    const_reference back() const
    {
      return this->operator[](this->size() - 1);
    }

    const_iterator begin() const
    {
      return this->Buffer;
    }

    const_iterator end() const
    {
      return const_iterator(reinterpret_cast<const UCHAR *>(this->Buffer) + this->size_bytes());
    }

    const_reverse_iterator rbegin() const
    {
      return std::make_reverse_iterator(this->end());
    }

    const_reverse_iterator rend() const
    {
      return std::make_reverse_iterator(this->begin());
    }
  };

  class unicode_string : public _UNICODE_STRING
  {
  public:
    using value_type = WCHAR;
    using pointer = PWCH;
    using const_pointer = PCWSTR;
    using reference = WCHAR &;
    using const_reference = CONST WCHAR &;
    using iterator = pointer;
    using const_iterator = const_pointer;

    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    using size_type = USHORT;
    using difference_type = SHORT;

  public:
    unicode_string()
    {
      this->Length = 0;
      this->MaximumLength = 0;
      this->Buffer = nullptr;
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    unicode_string(const T &SourceString)
    {
      THROW_IF_NTSTATUS_FAILED(RtlDuplicateUnicodeString(RTL_DUPLICATE_UNICODE_STRING_NULL_TERMINATE, const_cast<T *>(std::addressof(SourceString)), this));
    }

    unicode_string(PCWSTR SourceString)
    {
      if ( !RtlCreateUnicodeString(this, SourceString) )
        throw std::bad_alloc();
    }

    ~unicode_string()
    {
      if ( this->Buffer )
        RtlFreeUnicodeString(this);
    }

    unicode_string to_upper() const
    {
      unicode_string DestinationString;

      THROW_IF_NTSTATUS_FAILED(RtlUpcaseUnicodeString(&DestinationString, const_cast<unicode_string *>(this), TRUE));
      return DestinationString;
    }

    unicode_string to_lower() const
    {
      unicode_string DestinationString;

      THROW_IF_NTSTATUS_FAILED(RtlDowncaseUnicodeString(&DestinationString, const_cast<unicode_string *>(this), TRUE));
      return DestinationString;
    }

    reference operator[](size_t index)
    {
      return this->Buffer[index];
    }

    const_reference operator[](size_t index) const
    {
      return this->Buffer[index];
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool starts_with(const T &String) const
    {
      auto s1 = this->begin();
      auto s2 = String.Buffer;
      const auto n = this->size_bytes();

      if ( String.Length < n )
        return false;

      const auto end = this->end();
      while ( s1 < end ) {
        if ( *s1++ != *s2++ )
          return false;
      }
      return true;
    }

    bool starts_with(PCWSTR String) const
    {
      return this->starts_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool istarts_with(const T &String) const
    {
      return RtlPrefixUnicodeString(const_cast<T *>(std::addressof(String)), const_cast<unicode_string *>(this), TRUE);
    }

    bool istarts_with(PCWSTR String) const
    {
      return this->istarts_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool ends_with(const T &String) const
    {
      if ( this->size_bytes() < String.Length )
        return false;

      return unicode_string_view(this->data() + (this->size_bytes() - String.Length), String.Length).equals(String);
    }

    bool ends_with(PCWSTR String) const
    {
      return this->ends_with(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool iends_with(const T &String) const
    {
      if ( this->size_bytes() < String.Length )
        return false;

      return unicode_string_view(this->data() + (this->size_bytes() - String.Length), String.Length).iequals(String);
    }

    bool iends_with(PCWSTR String) const
    {
      return this->iends_with(unicode_string_view(String));
    }

    void clear()
    {
      if ( this->data() == nullptr || this->capacity() == 0 )
        return;

      std::memset(this->data(), 0, this->capacity());
      this->Length = 0;
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool equals(const T &String) const
    {
      auto s1 = this->begin();
      auto s2 = String.Buffer;

      const auto n1 = this->size_bytes();
      const auto n2 = String.Length;

      if ( n1 != n2 )
        return false;

      while ( n1 >= sizeof(std::uintptr_t) ) {
        if ( *reinterpret_cast<const std::uintptr_t *>(&*s1) != *reinterpret_cast<const std::uintptr_t *>(&*s2) )
          break;

        s1 += sizeof(std::uintptr_t) / sizeof(*s1);
        s2 += sizeof(std::uintptr_t) / sizeof(*s2);
      }

      const auto end = this->end();
      while ( s1 < end ) {
        if ( *s1++ != *s2++ )
          return false;
      }
      return true;
    }

    bool equals(PCWSTR String) const
    {
      return this->equals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool iequals(const T &String) const
    {
      return RtlEqualUnicodeString(const_cast<unicode_string *>(this), const_cast<T *>(std::addressof(String)), TRUE);
    }

    bool iequals(PCWSTR String) const
    {
      return this->iequals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long compare(const T &String) const
    {

      auto s1 = this->begin();
      auto s2 = String.Buffer;

      const auto n1 = this->size_bytes();
      const auto n2 = String.Length;

      const auto end = this->end();
      while ( s1 < end ) {
        if ( *s1 != *s2 )
          return static_cast<long>(*s1) - static_cast<long>(*s2);
        ++s1;
        ++s2;
      }
      return n1 - n2;
    }

    long compare(PCWSTR String) const
    {
      return this->compare(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long icompare(const T &String) const
    {
      return RtlCompareUnicodeString(const_cast<unicode_string *>(this), const_cast<T *>(std::addressof(String)), TRUE);
    }

    long icompare(PCWSTR String) const
    {
      return this->icompare(unicode_string_view(String));
    }

    pointer data()
    {
      return this->Buffer;
    }

    const_pointer data() const
    {
      return this->Buffer;
    }

    size_type capacity() const
    {
      return this->MaximumLength;
    }

    size_type size_bytes() const
    {
      return this->Length;
    }

    size_type size() const
    {
      return this->size_bytes() / sizeof(value_type);
    }

    bool empty() const
    {
      return !this->size_bytes();
    }

    reference front()
    {
      return this->operator[](0);
    }

    const_reference front() const
    {
      return this->operator[](0);
    }

    reference back()
    {
      return this->operator[](this->size() - 1);
    }

    const_reference back() const
    {
      return this->operator[](this->size() - 1);
    }

    iterator begin()
    {
      return this->Buffer;
    }

    const_iterator begin() const
    {
      return this->Buffer;
    }

    iterator end()
    {
      return iterator(reinterpret_cast<UCHAR *>(this->Buffer) + this->size_bytes());
    }

    const_iterator end() const
    {
      return const_iterator(reinterpret_cast<const UCHAR *>(this->Buffer) + this->size_bytes());
    }

    reverse_iterator rbegin()
    {
      return std::make_reverse_iterator(this->end());
    }

    const_reverse_iterator rbegin() const
    {
      return std::make_reverse_iterator(this->end());
    }

    reverse_iterator rend()
    {
      return std::make_reverse_iterator(this->begin());
    }

    const_reverse_iterator rend() const
    {
      return std::make_reverse_iterator(this->begin());
    }
  };

  inline unicode_string to_unicode_string(const struct _STRING &SourceString)
  {
    unicode_string DestinationString;

    THROW_IF_NTSTATUS_FAILED(RtlAnsiStringToUnicodeString(&DestinationString, const_cast<struct _STRING *>(std::addressof(SourceString)), TRUE));
    return DestinationString;
  }

  inline unicode_string to_unicode_string(PCSZ SourceString)
  {
    struct _STRING AnsiString;

    THROW_IF_NTSTATUS_FAILED(RtlInitAnsiStringEx(&AnsiString, SourceString));
    return to_unicode_string(AnsiString);
  }

  inline unicode_string to_unicode_string(ULONGLONG Value, ULONG Base)
  {
    unicode_string DestinationString;

    THROW_IF_NTSTATUS_FAILED(RtlInt64ToUnicodeString(Value, Base, &DestinationString));
    return DestinationString;
  }

  inline unicode_string to_unicode_string(ULONG Value, ULONG Base)
  {
    unicode_string DestinationString;

    THROW_IF_NTSTATUS_FAILED(RtlIntegerToUnicodeString(Value, Base, &DestinationString));
    return DestinationString;
  }

  inline PIMAGE_NT_HEADERS image_nt_headers(PVOID Base)
  {
    if ( Base != nullptr && Base != reinterpret_cast<PVOID>(-1) ) {
      const auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);
      if ( DosHeader->e_magic == IMAGE_DOS_SIGNATURE ) {
        const auto NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
          reinterpret_cast<ULONG_PTR>(Base) + DosHeader->e_lfanew);
        if ( NtHeaders->Signature == IMAGE_NT_SIGNATURE )
          return NtHeaders;
      }
    }
    return nullptr;
  }

  inline PIMAGE_SECTION_HEADER image_rva_to_section(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva)
  {
    if ( NtHeaders ) {
      const auto NtSections = std::span{IMAGE_FIRST_SECTION(NtHeaders), NtHeaders->FileHeader.NumberOfSections};
      const auto Iter = std::find_if(NtSections.begin(), NtSections.end(), [Rva](const IMAGE_SECTION_HEADER &NtSection) {
        return Rva >= NtSection.VirtualAddress && Rva < NtSection.VirtualAddress + NtSection.SizeOfRawData;
      });
      if ( Iter != NtSections.end() )
        return std::addressof(*Iter);
    }
  }

  inline PIMAGE_SECTION_HEADER image_rva_to_section(PVOID Base, ULONG Rva)
  {
    return image_rva_to_section(image_nt_headers(Base), Base, Rva);
  }

  template<class T = VOID, typename = std::enable_if_t<std::is_void_v<T> || std::is_pod_v<T> || std::is_function_v<T>>>
  inline std::add_pointer_t<T> image_rva_to_va(PIMAGE_NT_HEADERS NtHeaders, PVOID Base, ULONG Rva)
  {
    const auto NtSection = image_rva_to_section(NtHeaders, Base, Rva);
    if ( NtSection ) {
      return reinterpret_cast<std::add_pointer_t<T>>(
        (reinterpret_cast<UINT_PTR>(Base) + (Rva - NtSection->VirtualAddress) + NtSection->PointerToRawData));
    }
    return nullptr;
  }

  template<class T = VOID, typename = std::enable_if_t<std::is_void_v<T> || std::is_pod_v<T> || std::is_function_v<T>>>
  inline std::add_pointer_t<T> image_rva_to_va(PVOID Base, ULONG Rva)
  {
    return image_rva_to_va<T>(image_nt_headers(Base), Base, Rva);
  }

  inline std::span<IMAGE_RUNTIME_FUNCTION_ENTRY> lookup_function_table(PVOID ControlPc, PVOID *ImageBase)
  {
    const auto Lock = std::lock_guard{*static_cast<critical_section *>(NtCurrentPeb()->LoaderLock)};
    const auto ModuleList = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList;
    for ( auto Next = ModuleList->Flink; Next != ModuleList; Next = Next->Flink ) {
      const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
      if ( (reinterpret_cast<ULONG_PTR>(ControlPc) >= reinterpret_cast<ULONG_PTR>(Entry->DllBase))
          && (reinterpret_cast<ULONG_PTR>(ControlPc) < reinterpret_cast<ULONG_PTR>(Entry->DllBase) + Entry->SizeOfImage) ) {

        const auto NtHeaders = image_nt_headers(Entry->DllBase);
        if ( NtHeaders->OptionalHeader.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXCEPTION ) {
          const auto Ptr = image_rva_to_va<IMAGE_RUNTIME_FUNCTION_ENTRY>(NtHeaders,
                                                                         Entry->DllBase,
                                                                         NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress);
          const auto Size = NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
          if ( ImageBase )
            *ImageBase = Entry->DllBase;
          return std::span{Ptr, Size};
        }
      }
    }
    return {};
  }

  inline PIMAGE_RUNTIME_FUNCTION_ENTRY lookup_function_entry(PVOID ControlPc, PVOID *ImageBase)
  {
    const auto FunctionTable = lookup_function_table(ControlPc, ImageBase);
    if ( !FunctionTable.empty() ) {
      const auto RelativePc = reinterpret_cast<ULONG_PTR>(ControlPc) - reinterpret_cast<ULONG_PTR>(*ImageBase);
      const auto Iter = std::lower_bound(FunctionTable.begin(), FunctionTable.end(), ControlPc, [](const IMAGE_RUNTIME_FUNCTION_ENTRY &FunctionEntry,
                                                                                                   const ULONG &RelativePc) {
        return FunctionEntry.BeginAddress >= RelativePc && RelativePc < FunctionEntry.EndAddress;
      });
      if ( Iter != FunctionTable.end() )
        return std::addressof(*Iter);
    }
    return nullptr;
  }
}
