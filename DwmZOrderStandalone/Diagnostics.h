#pragma once
#include "DwmZOrderClient.h"
#include <filesystem>
#include <string>
#include <vector>

namespace standalone
{
    struct Operation
    {
        ks::dwm_order::Request request;
        ks::dwm_order::Reply reply;
        std::wstring time;
    };
    struct Diagnostic
    {
        std::wstring summary;
        std::wstring details;
        std::filesystem::path udwm;
        std::wstring udwmHash;
        bool modelMatched = false;
        bool complete = false;
    };
    std::filesystem::path ExecutableDirectory();
    bool IsAdministrator();
    std::wstring Timestamp();
    Diagnostic Inspect(); // Reads the on-disk system image; never loads or injects it.
    std::wstring StatusText(ks::dwm_order::Status status);
    std::wstring FormatOperation(const Operation& operation);
    std::filesystem::path SaveReport(const std::filesystem::path& parent, const Diagnostic& diagnostic,
        const std::vector<Operation>& operations, const std::wstring& observation,
        const std::wstring& notes, bool includeSystemImage);
    int SelfTest(const std::filesystem::path& directory);
}
