#pragma once
#include <functional>
#include <QString>

// RunWorkbenchPseudocodeContractTests：使用合成字节检查共享 C 页的安全与导航契约。
// require 接收断言和说明；不连接真实进程，不下载或启动真实 Ghidra。
void RunWorkbenchPseudocodeContractTests(const std::function<void(bool, const char*)>& require);

// 单独执行实际 Show/Hide/valueChanged 重入探针；caseName 为空时覆盖全部。
void RunWorkbenchPseudocodeProgressReentryTests(const std::function<void(bool, const char*)>& require,
    const QString& caseName = QString());
