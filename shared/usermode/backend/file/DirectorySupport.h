#pragma once
#include "Directory.h"
namespace ks::r3::file::detail {
inline std::wstring MakeStatusText(DWORD errorCode) {
    if (errorCode == ERROR_SUCCESS) {
        return L"OK";
    }
    return L"错误 " + std::to_wstring(errorCode);
}
inline bool FileTimeIsZero(const FILETIME& value) {
    return value.dwLowDateTime == 0 && value.dwHighDateTime == 0;
}
inline bool EntryLess(const FileEntry& left, const FileEntry& right) {
    if (left.kind != right.kind) {
        return static_cast<int>(left.kind) < static_cast<int>(right.kind);
    }
    return ::CompareStringOrdinal(left.name.c_str(), -1, right.name.c_str(), -1, TRUE) == CSTR_LESS_THAN;
}
}
