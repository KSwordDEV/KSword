#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ksword::ark { class DriverClient; }

namespace ks::r3::kernel {

// A baseline is returned only when the file and loaded PE identities agree,
// the driver's cached CI and loaded-module evidence is complete, and every
// requested byte is backed by a safely normalized file range.
struct TrustedImageBaseline {
    std::uint64_t moduleBase = 0;
    std::uint32_t moduleSize = 0;
    std::uint32_t signingLevel = 0;
    std::wstring ntPath;
    std::wstring localPath;
    std::wstring sha256;
    std::vector<std::uint8_t> bytes;
};

bool ReadKernelExact(const ksword::ark::DriverClient& client, std::uint64_t address,
                     std::uint32_t length, std::vector<std::uint8_t>& bytes);
bool ReadTrustedImageBaseline(const ksword::ark::DriverClient& client,
                              std::uint64_t address, std::uint32_t length,
                              TrustedImageBaseline& result, std::wstring& error);
}
