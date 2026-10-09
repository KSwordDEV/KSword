#pragma once
#include "../../../shared/usermode/backend/system/IoctlDecoder.h"
namespace Ksword::Features::SysTools {
using ks::r3::system_tools::IoctlDecodeState;
using ks::r3::system_tools::IoctlDecodedFields;
using ks::r3::system_tools::DecodeIoctlCode;
using ks::r3::system_tools::IoctlAccessName;
using ks::r3::system_tools::IoctlMethodName;
using ks::r3::system_tools::FormatIoctlCode;
using ks::r3::system_tools::BuildIoctlDecodedReport;
}
