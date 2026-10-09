#pragma once

// ============================================================
// DumpMemoryView.h
// 作用：
// - 提供转储文件的按虚拟地址只读内存查看器；
// - 只使用解析阶段验证过的 DumpMemoryRange，不对未捕获地址猜测内容；
// - 读取时重新只读打开原始 DMP，并核对文件大小/修改时间，避免把已更换的
//   同路径文件解释为旧解析结果。
// 调用方式：
// - MinidumpDock::renderResult 在解析成功后调用 setDumpData(result)；
// - 用户输入虚拟地址或“模块名+偏移”，通过读取、上一页、下一页浏览。
// ============================================================

#include <QWidget>
#include "../UI/StructuredFieldView.h"

#include <cstdint>
#include <vector>

class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
namespace ks::ui
{
    class HexView;
}

namespace ks::ui
{
    class SnapshotWorkbenchWidget;
}

namespace ks::minidump
{
    struct DumpMemoryRange;
    struct DumpParseResult;
    struct MemoryRegionEntry;
    struct ModuleEntry;
}

// DumpMemoryView：转储内已捕获虚拟内存的只读浏览页。
class DumpMemoryView final : public QWidget
{
public:
    // 构造函数作用：创建地址输入、分页工具条、说明区与统一十六进制控件。
    explicit DumpMemoryView(QWidget* parent = nullptr);

    // setDumpData 作用：替换当前转储的已验证内存范围并定位一个默认地址。
    // 参数 result：解析器的自包含结果；本对象只复制轻量元数据，不保留文件映射。
    void setDumpData(const ks::minidump::DumpParseResult& result);

    // clearData 作用：移除当前转储关联，避免前一次结果留在新解析页面中。
    void clearData();

    // retranslateUi 作用：按当前语言更新固定文案，并保持已加载的字节不变。
    void retranslateUi();

private:
    // readAddressText 作用：解析用户输入的“地址”或“模块名+偏移”。
    // 返回 true 时写入 addressOut；模块名按完整路径与基本文件名进行不区分大小写匹配。
    bool readAddressText(const QString& text, std::uint64_t* addressOut) const;

    // findRangeIndex 作用：定位覆盖地址的捕获范围下标，找不到时返回 -1。
    int findRangeIndex(std::uint64_t address) const;

    // findPreferredInitialAddress 作用：为首次打开选择含有效字节的已捕获范围。
    // 先保留故障地址优先级；否则只读抽样每个范围，避免默认展示全零页而误导用户
    // 以为查看器读取失败。没有非零字节时仍回退到第一个范围。
    std::uint64_t findPreferredInitialAddress() const;

    // loadCurrentInput 作用：读取地址输入框内容并将结果显示到十六进制控件。
    void loadCurrentInput();

    // loadAddress 作用：从已验证范围读取最多 64 KiB 的连续字节。
    // 读取失败时保留错误原因，绝不显示部分或越界数据。
    bool loadAddress(std::uint64_t address);

    // goPreviousPage / goNextPage：在当前或相邻捕获范围中按读取大小翻页。
    void goPreviousPage();
    void goNextPage();

    // selectedReadBytes 作用：读取用户选择的单次读取长度，限制到 64 KiB。
    std::uint64_t selectedReadBytes() const;

    // setDiagnostic：把一条读取诊断投影成模型说明。
    void setDiagnostic(const QString& text);

    // formatHex 作用：统一渲染地址/文件偏移为 0x 大写十六进制。
    static QString formatHex(std::uint64_t value);

    // m_addressLabel/m_addressEdit：目标虚拟地址或模块名+偏移输入。
    QLabel* m_addressLabel = nullptr;
    QLineEdit* m_addressEdit = nullptr;
    QLabel* m_readSizeLabel = nullptr;
    QComboBox* m_readSizeCombo = nullptr;
    QPushButton* m_readButton = nullptr;
    QPushButton* m_previousButton = nullptr;
    QPushButton* m_nextButton = nullptr;
    ks::ui::StructuredFieldView* m_messageView = nullptr; // m_messageView：可复制的读取状态和映射说明。
    ks::ui::SnapshotWorkbenchWidget* m_memoryEditor = nullptr; // 已捕获字节的只读多视图。
    ks::ui::HexView* m_hexEditor = nullptr; // 保留十六进制查找、复制和导出入口。

    QString m_filePath;                 // m_filePath：解析时的原始 DMP 路径。
    std::uint64_t m_expectedFileSize = 0; // m_expectedFileSize：解析时文件大小。
    std::int64_t m_expectedFileLastModifiedUtcMs = -1; // 解析时的 UTC 修改时间戳。
    std::vector<ks::minidump::DumpMemoryRange> m_ranges; // m_ranges：按虚拟地址排序的可读范围。
    std::vector<ks::minidump::ModuleEntry> m_modules; // m_modules：模块名+偏移输入与归属提示。
    std::vector<ks::minidump::MemoryRegionEntry> m_memoryRegions; // m_memoryRegions：地址属性提示。
    std::uint32_t m_pointerSize = 8; // 从转储元数据取得目标指针宽度。
    bool m_architectureInitialized = false; // 翻页保留手动选择的架构。
    std::uint64_t m_currentAddress = 0; // m_currentAddress：当前页首地址。
    std::uint64_t m_currentReadBytes = 0; // m_currentReadBytes：当前页实际加载字节数。
    int m_currentRangeIndex = -1;       // m_currentRangeIndex：当前页所属捕获范围。
};
