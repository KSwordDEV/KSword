#pragma once

// ============================================================
// KernelDockAtomWorker.h
// 作用说明：
// 1) 提供原子表枚举后台任务；
// 2) 提供按名称校验原子是否存在的工具函数。
// ============================================================

#include "KernelDock.h"

#include <cstdint> // std::uint16_t：Atom 值类型。
#include <vector>  // std::vector：结果容器。

// runAtomTableSnapshotTask：
// - 作用：遍历全局原子范围并输出可见原子条目。
// - 调用：建议在后台线程执行。
// - 入参 rowsOut：传出原子行结果（函数内会先清空）。
// - 入参 errorTextOut：传出错误文本（成功时清空）。
// - 返回：true=任务完成（允许结果为空）；false=出现致命错误。
bool runAtomTableSnapshotTask(std::vector<KernelAtomEntry>& rowsOut, QString& errorTextOut);

// verifyGlobalAtomByName：
// - 作用：调用 GlobalFindAtomW 验证指定名称是否存在于全局原子表。
// - 入参 atomNameText：要校验的原子名称。
// - 传出 atomValueOut：命中时返回 Atom 值。
// - 传出 detailTextOut：详情文本（用于详情面板）。
// - 返回：true=命中；false=未命中或参数无效。
bool verifyGlobalAtomByName(
    const QString& atomNameText,
    std::uint16_t& atomValueOut,
    ks::ui::FieldDocument& detailDocumentOut);
