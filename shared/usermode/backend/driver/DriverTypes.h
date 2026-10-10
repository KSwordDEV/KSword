#pragma once
#include "../Win32.h"
#include <cfgmgr32.h>
#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
namespace ks::r3::driver {
struct DriverSignatureEvidence {
    bool pathResolved = false,fileAccessible = false,evaluated = false;
    DWORD fileError = ERROR_SUCCESS;
    LONG trustStatus = 0;
    std::wstring localPath;
};
struct DriverOverviewRow {
    std::wstring driverName;       // driverName: driver base name or display name.
    std::wstring baseAddressText;   // baseAddressText: hex base address text.
    std::wstring memoryRangeText;   // memoryRangeText: start-end kernel image range derived from module base and size.
    std::wstring sizeText;         // sizeText: formatted image size text.
    std::wstring pathText;         // pathText: full module path.
    std::wstring signatureText;    // signatureText: R3 Authenticode/trust status for the module image when the path resolves.
    std::wstring statusText;       // statusText: load/diagnostic status.
    std::wstring anomalyText;      // anomalyText: R0 integrity risk flags or graceful unavailable/partial text.
    std::wstring capabilityHint;   // capabilityHint: future analysis hint.
    std::uint64_t baseAddress = 0;
    DWORD imageSize = 0,flags = 0;
    USHORT loadOrder = 0,initOrder = 0,loadCount = 0;
    bool baseKnown = false,sizeKnown = false,nameKnown = false,pathKnown = false,rangeValid = true;
    DWORD nameError = ERROR_SUCCESS,pathError = ERROR_SUCCESS;
    DriverSignatureEvidence signature;
};
struct DriverObjectRow {
    std::wstring directoryPathText;    // directoryPathText: source directory such as \Driver.
    std::wstring objectNameText;       // objectNameText: entry name.
    std::wstring objectTypeText;       // objectTypeText: object type text.
    std::wstring referenceCountText;   // referenceCountText: reference/pointer count text.
    std::wstring handleCountText;      // handleCountText: handle count text.
    std::wstring fullPathText;        // fullPathText: joined object path.
    std::wstring targetPathText;     // targetPathText: symbolic-link target when available.
    std::wstring statusText;         // statusText: enumeration/diagnostic status.
    std::wstring capabilityHint;     // capabilityHint: Chinese next-step hint.
    bool isDirectory = false;          // isDirectory: true when the object is a directory.
    bool isSymbolicLink = false;       // isSymbolicLink: true when the object is a symlink.
    bool querySucceeded = false;      // querySucceeded: true when the row was successfully built.
};
std::wstring FormatHexAddress(std::uint64_t value, std::size_t width = sizeof(void*) * 2u);
std::wstring FormatByteSize(std::uint64_t bytes);
}
