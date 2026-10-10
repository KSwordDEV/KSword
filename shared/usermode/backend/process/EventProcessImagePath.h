#pragma once
#include "../Common.h"
#include <cstdint>
namespace ks::r3::process {
struct ProcessImageEvidence {bool opened=false,timeAttempted=false,timeKnown=false,matched=true,queryAttempted=false,available=false,limited=false,malformed=false,closeAttempted=false,closed=false;DWORD openError=0,timeError=0,queryError=0,closeError=0,capacity=0,returnedChars=0;ULONGLONG creationTime=0;std::wstring path;};
std::wstring SampleProcessImage(std::uint32_t processId,DWORD capacity,ULONGLONG expectedCreationTime,ProcessImageEvidence& evidence);
std::wstring QueryEventProcessImagePath(std::uint32_t processId,ProcessImageEvidence* evidence=nullptr,ULONGLONG expectedCreationTime=0);
}
