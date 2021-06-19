#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <cstddef>
#include <iterator>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <string_view>
#include <type_traits>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

namespace nt::rtl
{
  template<typename Ty>
  struct allocator
  {
    using value_type = Ty;
    using size_type = safe_size_t;
    using difference_type = safe_ptrdiff_t;
    using propagate_on_container_move_assignment = std::true_type;

    allocator() noexcept {}

    allocator(const allocator &) noexcept = default;

    template <class Other>
    allocator(const allocator<Other> &) noexcept {}

    ~allocator() = default;

    allocator &operator=(const allocator &) = default;

    void deallocate(Ty *const Ptr, [[maybe_unused]] const size_type Count)
    {
      (VOID)RtlFreeHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Ptr);
    }

    [[nodiscard]] __declspec(allocator) Ty *allocate(const size_type Count)
    {
      const size_type Size = sizeof(Ty) * Count;
      return static_cast<Ty *>(RtlAllocateHeap(RtlProcessHeap(), HEAP_GENERATE_EXCEPTIONS | HEAP_ZERO_MEMORY, Size));
    }
  };

  class critical_section : public RTL_CRITICAL_SECTION
  {
  public:
    using native_handle_type = PRTL_CRITICAL_SECTION;

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

  class loader_lock
  {
  public:
    using native_handle_type = PVOID;

    void lock()
    {
      (VOID)LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, nullptr, &Cookie);
    }

    bool try_lock()
    {
      ULONG Disposition;
      (VOID)LdrLockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS | LDR_LOCK_LOADER_LOCK_FLAG_TRY_ONLY, &Disposition, &Cookie);
      return Disposition == LDR_LOCK_LOADER_LOCK_DISPOSITION_LOCK_ACQUIRED;
    }

    void unlock()
    {
      (VOID)LdrUnlockLoaderLock(LDR_LOCK_LOADER_LOCK_FLAG_RAISE_ON_ERRORS, Cookie);
    }

    native_handle_type native_handle()
    {
      return Cookie;
    }

  private:
    PVOID Cookie;
  };

  template <class T, typename = std::enable_if_t<std::is_convertible_v<T, UNICODE_STRING> || std::is_convertible_v<T, ANSI_STRING>>>
  class basic_string_view : public T
  {
  public:
    using value_type = typename std::remove_pointer_t<decltype(T::Buffer)>;
    using pointer = value_type *;
    using const_pointer = CONST value_type *;
    using reference = value_type &;
    using const_reference = CONST value_type &;
    using iterator = pointer;
    using const_iterator = const_pointer;

    using reverse_iterator = std::reverse_iterator<iterator>;
    using const_reverse_iterator = std::reverse_iterator<const_iterator>;

    using size_type = typename decltype(T::Length);
    using difference_type = std::make_signed_t<size_type>;

  public:
    basic_string_view() = delete;

    template<typename = std::enable_if_t<std::is_convertible_v<T, ANSI_STRING>>>
    basic_string_view(const ANSI_STRING &String)
    {
      this->Length = String.Length;
      this->MaximumLength = String.MaximumLength;
      this->Buffer = String.Buffer;
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, UNICODE_STRING>>>
    basic_string_view(const UNICODE_STRING &String)
    {
      this->Length = String.Length;
      this->MaximumLength = String.MaximumLength;
      this->Buffer = String.Buffer;
    }

    basic_string_view(const_pointer SourceString)
    {
      this->Length = 0;
      this->MaximumLength = 0;
      this->Buffer = const_cast<pointer>(SourceString);
      if ( SourceString ) {
        const auto Length = std::char_traits<value_type>::length(SourceString) * sizeof(value_type);

        if ( Length > (std::numeric_limits<size_type>::max() - sizeof(value_type)) )
          THROW_NTSTATUS(STATUS_NAME_TOO_LONG);

        this->Length = static_cast<size_type>(Length);
        this->MaximumLength = static_cast<size_type>(Length + sizeof(value_type));
      }
    }

    basic_string_view(const_pointer SourceString, size_type Length)
    {
      this->Length = Length * sizeof(value_type);
      this->MaximumLength = Length * sizeof(value_type);
      this->Buffer = const_cast<pointer>(SourceString);
    }

    const_reference operator[](size_t index) const
    {
      return this->Buffer[index];
    }

    const_pointer data() const
    {
      return this->Buffer;
    }

    size_type capacity_bytes() const
    {
      return this->MaximumLength;
    }

    size_type capacity() const
    {
      return capacity_bytes() / sizeof(value_type);
    }

    size_type size_bytes() const
    {
      return this->Length;
    }

    size_type size() const
    {
      return size_bytes() / sizeof(value_type);
    }

    bool empty() const
    {
      return !size_bytes();
    }

    const_reference front() const
    {
      return operator[](0);
    }

    const_reference back() const
    {
      return operator[](size() - 1);
    }

    const_iterator begin() const
    {
      return &this->Buffer[0];
    }

    const_iterator end() const
    {
      return const_iterator{reinterpret_cast<const UCHAR *>(&this->Buffer[0]) + size_bytes()};
    }

    const_reverse_iterator rbegin() const
    {
      return std::make_reverse_iterator(end());
    }

    const_reverse_iterator rend() const
    {
      return std::make_reverse_iterator(begin());
    }

    long compare(const basic_string_view &String) const
    {
      auto s1 = begin();
      auto s2 = String.begin();

      const auto n1 = size_bytes();
      const auto n2 = String.size_bytes();

      while ( s1 < end() ) {
        if ( *s1 != *s2 )
          return static_cast<long>(*s1) - static_cast<long>(*s2);
        ++s1;
        ++s2;
      }
      return n1 - n2;
    }

    long compare(const_pointer String) const
    {
      return compare(basic_string_view{String});
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, ANSI_STRING>>>
    long icompare(const ANSI_STRING &String) const
    {
      return ::RtlCompareString(const_cast<basic_string_view *>(this),
        const_cast<PANSI_STRING>(std::addressof(String)), TRUE);
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, UNICODE_STRING>>>
    long icompare(const UNICODE_STRING &String) const
    {
      return ::RtlCompareUnicodeString(const_cast<basic_string_view *>(this),
        const_cast<PUNICODE_STRING>(std::addressof(String)), TRUE);
    }

    long icompare(const_pointer String) const
    {
      return icompare(basic_string_view{String});
    }

    bool equals(const T &String) const
    {
      auto s1 = begin();
      auto s2 = String.Buffer;

      const auto n1 = size_bytes();
      const auto n2 = String.Length;

      if ( n1 != n2 )
        return false;

      while ( n1 >= sizeof(ULONG_PTR) ) {
        if ( *reinterpret_cast<const ULONG_PTR *>(std::addressof(*s1)) != *reinterpret_cast<const ULONG_PTR *>(std::addressof(*s2)) )
          break;

        s1 += sizeof(ULONG_PTR) / sizeof(*s1);
        s2 += sizeof(ULONG_PTR) / sizeof(*s2);
      }

      while ( s1 < end() ) {
        if ( *s1++ != *s2++ )
          return false;
      }
      return true;
    }

    bool equals(const_pointer String) const
    {
      return equals(basic_string_view{String});
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, ANSI_STRING>>>
    bool iequals(const ANSI_STRING &String) const
    {
      return ::RtlEqualString(const_cast<basic_string_view *>(this),
        const_cast<PANSI_STRING>(std::addressof(String)), TRUE);
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, UNICODE_STRING>>>
    bool iequals(const UNICODE_STRING &String) const
    {
      return ::RtlEqualUnicodeString(const_cast<basic_string_view *>(this),
        const_cast<PUNICODE_STRING>(std::addressof(String)), TRUE);
    }

    bool iequals(const_pointer String) const
    {
      return iequals(basic_string_view{String});
    }

    bool starts_with(const T &String) const
    {
      auto s1 = begin();
      auto s2 = String.Buffer;
      const auto n = String.Length;

      if ( size_bytes() < n )
        return false;

      const auto end = reinterpret_cast<PWCH>(reinterpret_cast<PUCHAR>(s2) + n);
      while ( s2 < end ) {
        if ( *s1++ != *s2++ )
          return false;
      }
      return true;
    }

    bool starts_with(const_pointer String) const
    {
      return starts_with(basic_string_view{String});
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, ANSI_STRING>>>
    bool istarts_with(const ANSI_STRING &String) const
    {
      return ::RtlPrefixString(const_cast<PANSI_STRING>(std::addressof(String)),
        const_cast<basic_string_view *>(this), TRUE);
    }

    template<typename = std::enable_if_t<std::is_convertible_v<T, UNICODE_STRING>>>
    bool istarts_with(const UNICODE_STRING &String) const
    {
      return ::RtlPrefixUnicodeString(const_cast<PUNICODE_STRING>(std::addressof(String)),
        const_cast<basic_string_view *>(this), TRUE);
    }

    bool istarts_with(const_pointer String) const
    {
      return istarts_with(basic_string_view{String});
    }

    bool ends_with(const T &String) const
    {
      if ( size_bytes() < String.Length )
        return false;

      return basic_string_view{data() + (size_bytes() - String.Length), String.Length}.equals(String);
    }

    bool ends_with(const_pointer String) const
    {
      return ends_with(basic_string_view{String});
    }

    bool iends_with(const T &String) const
    {
      if ( size_bytes() < String.Length )
        return false;

      return basic_string_view{data() + (size_bytes() - String.Length), String.Length}.iequals(String);
    }

    bool iends_with(const_pointer String) const
    {
      return iends_with(basic_string_view{String});
    }

    bool is_valid() const
    {
      return (size_bytes() & 1) == 0
        && (capacity_bytes() & 1) == 0
        && size_bytes() <= capacity_bytes()
        && capacity_bytes() < std::numeric_limits<size_type>::max()
        && (data() || (!size_bytes() && !capacity_bytes));
    }

    operator bool() const
    {
      return is_valid();
    }

    std::string string() const
    {
      std::string str;

      if constexpr ( std::is_convertible_v<T, ANSI_STRING> ) {
        str.reserve(size() + sizeof(ANSI_NULL));
        std::copy(begin(), end(), std::back_inserter(str));
      } else if constexpr ( std::is_convertible_v<T, UNICODE_STRING> ) {
        ANSI_STRING DestinationString;
        THROW_IF_NTSTATUS_FAILED(RtlUnicodeStringToAnsiString(&DestinationString, this, TRUE));
        str.reserve(DestinationString.Length);
        std::copy(DestinationString.Buffer, DestinationString.Buffer + DestinationString.Length, std::back_inserter(str));
        RtlFreeAnsiString(&DestinationString);
      }
      return str;
    }

    std::wstring wstring() const
    {
      std::wstring wstr;

      if constexpr ( std::is_convertible_v<T, ANSI_STRING> ) {
        UNICODE_STRING DestinationString;
        THROW_IF_NTSTATUS_FAILED(RtlAnsiStringToUnicodeString(&DestinationString, this, TRUE));
        wstr.reserve(DestinationString.Length >> 1);
        std::copy(DestinationString.Buffer, (PWCH)((PCHAR)DestinationString.Buffer + DestinationString.Length), std::back_inserter(wstr));
        RtlFreeUnicodeString(&DestinationString);
      } else if constexpr ( std::is_convertible_v<T, UNICODE_STRING> ) {
        wstr.reserve(size() + sizeof(UNICODE_NULL));
        std::copy(begin(), end(), std::back_inserter(wstr));
      }
      return wstr;
    }
  };

  using ansi_string_view = basic_string_view<ANSI_STRING>;
  using unicode_string_view = basic_string_view<UNICODE_STRING>;

  template<class T = void, typename = std::enable_if_t<std::is_void_v<T> || std::is_pod_v<T> || std::is_function_v<T>>>
  inline T *image_rva_to_va(PVOID Base, ULONG_PTR Rva)
  {
    if ( !Base )
      Base = NtCurrentPeb()->ImageBaseAddress;

    return Rva ? reinterpret_cast<T *>(reinterpret_cast<PUCHAR>(Base) + Rva) : nullptr;
  }

  inline PIMAGE_NT_HEADERS image_nt_headers(PVOID Base)
  {
    if ( !Base )
      Base = NtCurrentPeb()->ImageBaseAddress;

    const auto DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(Base);
    if ( DosHeader->e_magic != IMAGE_DOS_SIGNATURE )
      return nullptr;

    const auto NtHeaders = image_rva_to_va<IMAGE_NT_HEADERS>(Base, DosHeader->e_lfanew);
    if ( !NtHeaders
      || NtHeaders->Signature != IMAGE_NT_SIGNATURE
      || !NtHeaders->FileHeader.SizeOfOptionalHeader )
      return nullptr;

    return NtHeaders;
  }

  template<class T = UCHAR, typename = std::enable_if_t<std::is_pod_v<T>>>
  inline T *image_directory_entry_to_data(PVOID Base, USHORT DirectoryEntry, ULONG *Count = nullptr)
  {
    const auto NtHeaders = nt::rtl::image_nt_headers(Base);
    if ( !NtHeaders
      || NtHeaders->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC )
      return nullptr;

    if ( DirectoryEntry >= NtHeaders->OptionalHeader.NumberOfRvaAndSizes
      || !NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress
      || !NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size )
      return nullptr;

    if ( Count )
      *Count = NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].Size / sizeof(T);

    return image_rva_to_va<T>(Base, NtHeaders->OptionalHeader.DataDirectory[DirectoryEntry].VirtualAddress);
  }

  inline PVOID image_entry_point(PVOID Base)
  {
    const auto NtHeaders = nt::rtl::image_nt_headers(Base);
    if ( !NtHeaders ) return nullptr;

    const auto ClrHeader = nt::rtl::image_directory_entry_to_data<IMAGE_COR20_HEADER>(Base, IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
    if ( ClrHeader ) {
      const auto hClr = GetModuleHandleW(L"mscoree.dll");
      return hClr ? GetProcAddress(hClr, "_CorExeMain") : nullptr;
    }
    return image_rva_to_va(Base, NtHeaders->OptionalHeader.AddressOfEntryPoint);
  }

  inline ULONG image_size(PVOID Base)
  {
    const auto NtHeaders = nt::rtl::image_nt_headers(Base);
    return NtHeaders ? NtHeaders->OptionalHeader.SizeOfImage : 0;
  }

  inline PVOID pc_to_image_base(PVOID PcValue)
  {
    MEMORY_BASIC_INFORMATION mbi;

    if ( !PcValue
      || VirtualQuery(PcValue, &mbi, sizeof(MEMORY_BASIC_INFORMATION)) == 0
      || (mbi.State != MEM_COMMIT || (mbi.Protect & 0xff) == PAGE_NOACCESS || (mbi.Protect & PAGE_GUARD)) )
      return nullptr;

    return mbi.AllocationBase;
  }

  inline PLDR_DATA_TABLE_ENTRY pc_to_ldr_data_table_entry(PVOID PcValue)
  {
    if ( !PcValue )
      return nullptr;

    const std::lock_guard Lock{*static_cast<critical_section *>(NtCurrentPeb()->LoaderLock)};
    const auto ModuleList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    for ( auto Next = ModuleList->Flink; Next != ModuleList; Next = Next->Flink ) {
      const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
      const auto Low = reinterpret_cast<UCHAR *>(Entry->DllBase);
      if ( PcValue >= Low && PcValue < Low + Entry->SizeOfImage )
        return Entry;
    }
    return nullptr;
  }

  inline std::span<IMAGE_SECTION_HEADER> image_sections(PVOID Base)
  {
    const auto NtHeaders = image_nt_headers(Base);
    const auto Ptr = reinterpret_cast<PIMAGE_SECTION_HEADER>(
      reinterpret_cast<ULONG_PTR>(NtHeaders) + offsetof(IMAGE_NT_HEADERS, OptionalHeader) + NtHeaders->FileHeader.SizeOfOptionalHeader);

    return {Ptr, NtHeaders->FileHeader.NumberOfSections};
  }

  inline auto find_image_section_by_name(const std::span<IMAGE_SECTION_HEADER> &Sections, PCSTR Name)
  {
    return std::find_if(Sections.begin(), Sections.end(), [&](const IMAGE_SECTION_HEADER &Section) {
      if ( !Name )
        return true;

      SIZE_T Size;
      for ( Size = 0; Size < IMAGE_SIZEOF_SHORT_NAME; ++Size ) {
        if ( !Section.Name[Size] )
          break;
      }
      return std::string_view{reinterpret_cast<PCSTR>(Section.Name), Size} == Name;
    });
  }

  inline std::span<IMAGE_RUNTIME_FUNCTION_ENTRY> lookup_function_table(PVOID ControlPc, PVOID *DllBase = nullptr)
  {
    const std::lock_guard Lock{*static_cast<critical_section *>(NtCurrentPeb()->LoaderLock)};
    const auto ModuleList = &NtCurrentPeb()->Ldr->InLoadOrderModuleList;
    for ( auto Next = ModuleList->Flink; Next != ModuleList; Next = Next->Flink ) {
      const auto Entry = CONTAINING_RECORD(Next, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);
      if ( (ControlPc >= Entry->DllBase)
        && (ControlPc < reinterpret_cast<PUCHAR>(Entry->DllBase) + Entry->SizeOfImage) ) {

        if ( DllBase )
          *DllBase = Entry->DllBase;

        ULONG Count;
        const auto FunctionTable = image_directory_entry_to_data<IMAGE_RUNTIME_FUNCTION_ENTRY>(Entry->DllBase, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &Count);
        if ( FunctionTable )
          return {FunctionTable, Count};
        return {};
      }
    }
    return {};
  }
}
