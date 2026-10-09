#pragma once
#include "../../../shared/usermode/backend/process/ProcessEnumerator.h"
namespace Ksword::Features::Process {
using ks::r3::process::ProcessSnapshotRow;
using ks::r3::process::ProcessEnumerationResult;
using ks::r3::process::EnumerateProcessesByNtQuerySystemInformation;
using ks::r3::process::QueryProcessImagePath;
}
