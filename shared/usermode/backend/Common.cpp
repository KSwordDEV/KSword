#include "Common.h"

namespace ks::r3::common {

UniqueHandle::UniqueHandle() noexcept : handle_(nullptr) {}

UniqueHandle::UniqueHandle(HANDLE handle) noexcept : handle_(handle) {}

UniqueHandle::~UniqueHandle() {
    reset();
}

UniqueHandle::UniqueHandle(UniqueHandle&& other) noexcept : handle_(other.release()) {}

UniqueHandle& UniqueHandle::operator=(UniqueHandle&& other) noexcept {
    if (this != &other) {
        reset(other.release());
    }
    return *this;
}

void UniqueHandle::reset(HANDLE handle) noexcept {
    if (handle_ && handle_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(handle_);
    }
    handle_ = handle;
}

HANDLE UniqueHandle::release() noexcept {
    HANDLE out = handle_;
    handle_ = nullptr;
    return out;
}

HANDLE UniqueHandle::get() const noexcept {
    return handle_;
}

bool UniqueHandle::valid() const noexcept {
    return handle_ && handle_ != INVALID_HANDLE_VALUE;
}

std::wstring LastErrorMessage(DWORD errorCode) {
    wchar_t* buffer = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD count = ::FormatMessageW(flags, nullptr, errorCode, 0, reinterpret_cast<wchar_t*>(&buffer), 0, nullptr);
    std::wstring text;
    if (count > 0 && buffer) {
        text.assign(buffer, count);
        while (!text.empty() && (text.back() == L'\r' || text.back() == L'\n' || text.back() == L' ')) {
            text.pop_back();
        }
    }
    if (buffer) {
        ::LocalFree(buffer);
    }
    if (text.empty()) {
        text = L"Win32 error " + std::to_wstring(errorCode);
    }
    return text;
}

std::wstring LastErrorMessage() {
    return LastErrorMessage(::GetLastError());
}

} // namespace ks::r3::common
