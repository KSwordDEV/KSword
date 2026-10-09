#pragma once

#include "Win32.h"

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace ks::r3::common {

// NonCopyable is the common base for small RAII wrappers. There are no inputs;
// processing deletes copy operations; subclasses decide their own return values.
class NonCopyable {
protected:
    NonCopyable() = default;
    ~NonCopyable() = default;

public:
    NonCopyable(const NonCopyable&) = delete;
    NonCopyable& operator=(const NonCopyable&) = delete;
};

// UniqueHandle owns a Win32 HANDLE. Inputs are handles returned by Win32 APIs;
// processing closes any valid handle on reset/destruction; get() returns the raw
// handle without transferring ownership.
class UniqueHandle final : public NonCopyable {
public:
    UniqueHandle() noexcept;
    explicit UniqueHandle(HANDLE handle) noexcept;
    ~UniqueHandle();

    UniqueHandle(UniqueHandle&& other) noexcept;
    UniqueHandle& operator=(UniqueHandle&& other) noexcept;

    void reset(HANDLE handle = nullptr) noexcept;
    HANDLE release() noexcept;
    HANDLE get() const noexcept;
    bool valid() const noexcept;

private:
    HANDLE handle_;
};

// LastErrorMessage converts a Win32 error code into a display string. Input is
// an error code, processing calls FormatMessageW, and output is never empty.
std::wstring LastErrorMessage(DWORD errorCode);

// LastErrorMessage returns GetLastError() as text. There is no input; processing
// uses the thread-local Win32 error; output is a human-readable string.
std::wstring LastErrorMessage();

} // namespace ks::r3::common
