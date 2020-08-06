#pragma once
#include <phnt_windows.h>
#include <phnt.h>

#include <iterator>

#include <wil/result.h>
#include <wil/resource.h>
#include <wil/win32_helpers.h>

namespace nt::rtl
{
  class critical_section : public _RTL_CRITICAL_SECTION
  {
  public:
    using native_handle_type = struct _RTL_CRITICAL_SECTION *;

  public:
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
      size_type Length = 0;
      this->Length = 0;
      this->Buffer = const_cast<pointer>(SourceString);
      if ( SourceString ) {
        while ( *SourceString++ )
          Length += sizeof(value_type);

        this->Length = Length;
        this->MaximumLength = Length + sizeof(UNICODE_NULL);
      } else {
        this->MaximumLength = 0;
      }
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
      return RtlPrefixUnicodeString(const_cast<T *>(std::addressof(String)), const_cast<unicode_string *>(this), FALSE);
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

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool equals(const T &String) const
    {
      return RtlEqualUnicodeString(const_cast<T *>(this), const_cast<unicode_string *>(std::addressof(String)), FALSE);
    }

    bool equals(PCWSTR String) const
    {
      return this->equals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool iequals(const T &String) const
    {
      return RtlEqualUnicodeString(const_cast<unicode_string *>(this), const_cast<unicode_string *>(std::addressof(String)), TRUE);
    }

    bool iequals(PCWSTR String) const
    {
      return this->iequals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long compare(const T &String) const
    {
      return RtlCompareUnicodeString(const_cast<unicode_string *>(this), const_cast<unicode_string *>(std::addressof(String)), FALSE);
    }

    bool compare(PCWSTR String) const
    {
      return this->compare(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long icompare(const T &String) const
    {
      return RtlCompareUnicodeString(const_cast<unicode_string *>(this), const_cast<unicode_string *>(std::addressof(String)), TRUE);
    }

    bool icompare(PCWSTR String) const
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

    reverse_iterator rbegin() const
    {
      return std::make_reverse_iterator(this->end());
    }

    reverse_iterator rend() const
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
      RtlCreateUnicodeString(this, SourceString);
    }

    unicode_string(PCSTR SourceString)
    {
      RtlCreateUnicodeStringFromAsciiz(this, SourceString);
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
      return RtlPrefixUnicodeString(const_cast<T *>(std::addressof(String)), const_cast<unicode_string *>(this), FALSE);
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
      RtlEraseUnicodeString(this);
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool equals(const T &String) const
    {
      return RtlEqualUnicodeString(const_cast<T *>(this), const_cast<unicode_string *>(std::addressof(String)), FALSE);
    }

    bool equals(PCWSTR String) const
    {
      return this->equals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    bool iequals(const T &String) const
    {
      return RtlEqualUnicodeString(const_cast<unicode_string *>(this), const_cast<unicode_string *>(std::addressof(String)), TRUE);
    }

    bool iequals(PCWSTR String) const
    {
      return this->iequals(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long compare(const T &String) const
    {
      return RtlCompareUnicodeString(const_cast<unicode_string *>(this), const_cast<unicode_string *>(std::addressof(String)), FALSE);
    }

    bool compare(PCWSTR String) const
    {
      return this->compare(unicode_string_view(String));
    }

    template<class T, typename = std::enable_if_t<std::is_convertible_v<T, struct _UNICODE_STRING>>>
    long icompare(const T &String) const
    {
      return RtlCompareUnicodeString(const_cast<unicode_string *>(this), const_cast<unicode_string *>(std::addressof(String)), TRUE);
    }

    bool icompare(PCWSTR String) const
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

    reverse_iterator rbegin() const
    {
      return std::make_reverse_iterator(this->end());
    }

    reverse_iterator rend()
    {
      return std::make_reverse_iterator(this->begin());
    }

    reverse_iterator rend() const
    {
      return std::make_reverse_iterator(this->begin());
    }
  };
}
