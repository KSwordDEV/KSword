#pragma once

#include <cstdint>

class QTabWidget;

// 在内部结构的子导航中添加只读 EPROCESS 页；首次选中时异步查询指定进程。
void AddProcessEprocessPage(QTabWidget& parent, std::uint32_t pid, std::uint64_t creationTime);
