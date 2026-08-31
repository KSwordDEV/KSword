#pragma once

#include "../../Core/Win32Lean.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace Ksword::Features::Memory {

// DriverMemoryReadRequest stores the validated inputs for one driver-backed
// memory read. The UI supplies processId/address/length as text; model helpers
// parse those strings into this structure; the client receives it as immutable
// request data and returns a DriverMemoryReadResult.
struct DriverMemoryReadRequest {
    DWORD processId = 0;
    std::uint64_t address = 0;
    std::size_t length = 0;
};

// DriverMemoryWriteRequest stores the validated inputs for one driver-backed
// memory write. The UI supplies processId/address plus hex bytes; model helpers
// parse the bytes into this vector; the client receives it as immutable request
// data and returns a DriverMemoryWriteResult.
struct DriverMemoryWriteRequest {
    DWORD processId = 0;
    std::uint64_t address = 0;
    std::vector<std::uint8_t> bytes;
};

// DriverMemoryReadResult describes the result of a driver-backed memory read.
// The client fills success/error/status and, on success, the bytes returned by
// the driver. The view displays statusText and formats bytes through
// FormatHexBytesForDisplay.
struct DriverMemoryReadResult {
    bool success = false;
    DWORD win32Error = ERROR_SUCCESS;
    std::uint32_t protocolStatus = 0;
    std::uint32_t copyStatus = 0;
    std::uint32_t fieldFlags = 0;
    std::wstring statusText;
    std::vector<std::uint8_t> bytes;
};

// DriverMemoryWriteResult describes the result of a driver-backed memory write.
// The client fills success/error/status and the number of bytes accepted by the
// driver. The view displays only the status text in this first-stage surface.
struct DriverMemoryWriteResult {
    bool success = false;
    DWORD win32Error = ERROR_SUCCESS;
    std::uint32_t protocolStatus = 0;
    std::uint32_t copyStatus = 0;
    std::uint32_t fieldFlags = 0;
    std::wstring statusText;
    std::size_t bytesWritten = 0;
};

// ParseUnsignedInteger parses decimal or 0x-prefixed hexadecimal text. Inputs
// are the raw edit-control string, an inclusive upper bound and a field name for
// diagnostics; processing trims whitespace and validates the whole string;
// output is true with value set on success, false with errorText set on failure.
bool ParseUnsignedInteger(const std::wstring& text,
    std::uint64_t maxValue,
    const wchar_t* fieldName,
    std::uint64_t& value,
    std::wstring& errorText);

// ParseReadRequest validates PID, address and length text for a driver memory
// read. Inputs are raw edit-control strings; processing performs range checks;
// output is true with request set on success, false with errorText set on
// failure.
bool ParseReadRequest(const std::wstring& processIdText,
    const std::wstring& addressText,
    const std::wstring& lengthText,
    DriverMemoryReadRequest& request,
    std::wstring& errorText);

// ParseWriteRequest validates PID, address and hex text for a driver memory
// write. Inputs are raw edit-control strings; processing parses all byte tokens;
// output is true with request set on success, false with errorText set on
// failure.
bool ParseWriteRequest(const std::wstring& processIdText,
    const std::wstring& addressText,
    const std::wstring& hexText,
    DriverMemoryWriteRequest& request,
    std::wstring& errorText);

// ParseHexBytes parses human-entered hexadecimal bytes. Input accepts whitespace
// separators and optional 0x prefixes; processing requires each token to be one
// byte; output is true with bytes set on success, false with errorText set on
// failure.
bool ParseHexBytes(const std::wstring& text, std::vector<std::uint8_t>& bytes, std::wstring& errorText);

// FormatHexBytesForDisplay converts bytes into grouped uppercase hex text.
// Input is any byte vector; processing inserts spaces and line breaks every
// bytesPerLine bytes; output is suitable for the multiline edit control.
std::wstring FormatHexBytesForDisplay(const std::vector<std::uint8_t>& bytes, std::size_t bytesPerLine = 16);

} // namespace Ksword::Features::Memory
