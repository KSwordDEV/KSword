#pragma once

// ============================================================
// IntegrityRiskPresentation.h
// 作用说明：
// 1) Driver Integrity 证据的“类别文字 / 风险位文字 / 风险分级 / 整行高亮”统一出口；
// 2) 此前 KernelDescriptorTableTab、HardwareR0EvidencePage、DriverDock 各抄了一份
//    riskText / classText，新增风险位只补进其中一份，其余几页就会显示空的风险单元格；
// 3) 带 HIDDEN_HOOK 位的行（二级指针被劫持而一级检查看起来干净）必须让用户一眼看出来：
//    整行 Danger 高亮，风险文字以“存在隐藏行为”开头，tooltip 解释为什么只查一级地址会漏。
// 4) 只做展示，不访问驱动，不改变任何检测结论。
// ============================================================

#include <QString>
#include <QtGlobal>

class QTableWidget;

namespace ks::ui::integrity
{
    // 证据类文字，覆盖 KSWORD_ARK_DRIVER_INTEGRITY_CLASS_* 全部取值（含 GDT_DESCRIPTOR/START_IO/INTERRUPT_OBJECT），
    // 未知类回退成 "Class(N)"。
    QString classText(quint32 evidenceClass);

    // 风险位文字：全部已知位都要认得（包括最新四个 IDT 位和新的 HIDDEN_HOOK/OBJTYPE_PROC_NON_CORE/PROC_DETOUR/
    // LAYOUT_UNVERIFIED），多个位用统一分隔符连接；有未识别的残余位时追加十六进制兜底；riskFlags==0 返回"正常"。
    // 带 HIDDEN_HOOK 时，文字必须**以"存在隐藏行为"开头**。
    QString riskText(quint32 riskFlags);

    enum class Tier { Clean, Notice, Danger };

    // 分级：
    // - Danger：HIDDEN_HOOK / OWNER_MISMATCH / OUTSIDE_DRIVER_IMAGE / TARGET_NON_EXEC / IDT_BASELINE_CHANGED /
    //   IDT_TABLE_DIVERGED / IDT_TABLE_RELOCATED / DESCRIPTOR_INVALID / DEVICE_LOOP / ATTACHED_LOOP /
    //   CROSS_DRIVER_ATTACH / PROC_DETOUR 中任意一位；
    // - Notice：其余任何非零位，除了“只带 LAYOUT_UNVERIFIED”（那是这一项检查在本机做不了，归 Clean，
    //   但 riskText 仍会写出来）；
    // - Clean：0。
    Tier tierOf(quint32 riskFlags);

    // 整行高亮：对该行每一列设前景色+底色，tooltip 设成 detailText（空则用 riskText）。
    // Tier::Clean 必须把该行每个单元格的 Foreground/Background 清回 QBrush()，
    // 这样表格被重建、行被复用时不会残留旧颜色，交替行底色也能透出来。
    //
    // 使用约定（本实现的补充说明，签名不变）：
    // - 调用时机：该行所有单元格已 setItem 之后；表格若开着排序，请先 setSortingEnabled(false)，
    //   否则改到排序列的单元格会触发重排、使 row 失效（三处现有调用点都是先关排序再重建）；
    // - tooltip：本函数拿不到 riskFlags，因此 detailText 为空时无法回退到 riskText，而是把该行 tooltip 清空
    //   （这样复用行不会残留上一轮“存在隐藏行为”的旧提示）。需要 riskText 兜底请改用 applyRiskRowHighlight；
    // - 调用方自己要保留的 tooltip 请在本函数之后再设。
    void applyRowHighlight(QTableWidget* table, int row, Tier tier, const QString& detailText = QString());

    // ---- 以下是契约之外的追加接口（只增不改，R2 不必使用）----

    // 行 tooltip 文字：riskText(riskFlags)；带 HIDDEN_HOOK 时再追加一句解释——一级地址（IDT 网关 / 对象类型地址）
    // 看起来是干净的，但沿它走到的二级指针被改到了别处，只核对一级地址的检测会漏掉这一项。
    QString tooltipText(quint32 riskFlags);

    // 便捷入口：等价于 applyRowHighlight(table, row, tierOf(riskFlags), tooltipText(riskFlags))，
    // 只是 riskFlags==0 的行不挂 tooltip（每格都弹一句“正常”只是噪音）。
    // 有 riskFlags 在手的调用点优先用它，这样隐藏行为的 tooltip 解释不会漏。
    void applyRiskRowHighlight(QTableWidget* table, int row, quint32 riskFlags);
}
