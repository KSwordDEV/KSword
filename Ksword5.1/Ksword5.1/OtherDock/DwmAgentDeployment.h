#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace ks::dwm_order::transport
{
    struct PreparedAgent
    {
        // Fully qualified path; independent of the remote process current directory.
        std::wstring path;
        // Holds the managed directories and verified DLL against replacement.
        std::shared_ptr<void> lease;
    };

    std::uint32_t ReadProcessUserSid(void* process, std::vector<unsigned char>& sid);
    // Relative source paths are resolved once against the caller's current directory.
    std::uint32_t PrepareAgentCopy(const std::wstring& sourcePath,
        const std::vector<unsigned char>& readerSid, PreparedAgent& prepared);
}
