#pragma once

#include "../../../shared/usermode/KernelDumpThreadStack.h"

// 在后台用同目录正式 CLI 展开离线转储，隔离主程序早已载入的 DbgHelp。
ks::kernel_dump::ThreadStackResult RunKernelDumpStackCli(const ks::kernel_dump::ThreadStackRequest& request);
