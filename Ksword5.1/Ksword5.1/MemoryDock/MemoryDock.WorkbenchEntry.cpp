#include "MemoryDock.Internal.h"
#include "MemoryDock.WorkbenchServices.h"
#include "WorkbenchServicesMapping.h" // DecideModuleJumpPin：模块表跳转要不要钉住预览进程。

#include "../Internationalization/LanguageManager.h"
#include "../UI/MemoryWorkbench/AddressBookStore.h"
#include "../UI/MemoryWorkbench/MemoryWorkbenchView.h"
#include "../UI/MemoryWorkbench/WorkbenchBookIntake.h"
#include "../UI/MemoryWorkbench/WorkbenchNavigation.h"
#include "../UI/MemoryWorkbench/WorkbenchShared.h"
#include "../UI/MemoryWorkbench/WorkbenchTarget.h"


// ============================================================
// MemoryDock.WorkbenchEntry.cpp
// 作用：
// - 3b"入口切换"里属于 MemoryDock 的那一半：把旧页面的入口接到内存工作台上。
//   2) jumpToModuleBase / viewRegionViaDriver：模块表、区域表的两个专用入口；
//   3) openAddressInWorkbench / canOpenInWorkbench / addOpenInWorkbenchAction：证据页右键"在内存工作台打开"；
//   4) addSearchResultsToAddressBook：搜索结果"加入地址簿"（用户明确触发，绝不自动灌入）；
//   5) workbenchFocusAddress：PTE 页取工作台插入点作默认地址。
// - 通用的"跳到地址"分发器 jumpToAddress 与视图创建/接线在 MemoryDock.Workbench.cpp。
// ============================================================

namespace
{
    // parseHexAddress：解析证据表地址列的 "0x0000..." 文本。
    // 传入：text 单元格文本；address 解析结果。传出：是否为合法十六进制（带不带 0x 前缀都收）。
    bool parseHexAddress(QString text, std::uint64_t& address)
    {
        text = text.trimmed();
        if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
        {
            text = text.mid(2);
        }
        bool converted = false;
        const qulonglong value = text.toULongLong(&converted, 16);
        if (!converted)
        {
            return false;
        }
        address = static_cast<std::uint64_t>(value);
        return true;
    }

    // findOwningMemoryDock：沿父链找到包含某控件的 MemoryDock；找不到返回空指针。
    MemoryDock* findOwningMemoryDock(QWidget* start)
    {
        for (QWidget* widget = start; widget != nullptr; widget = widget->parentWidget())
        {
            if (MemoryDock* const dock = dynamic_cast<MemoryDock*>(widget))
            {
                return dock;
            }
        }
        return nullptr;
    }

}

// canOpenInWorkbench：统一工作台容器就绪后提供显式地址打开入口。
bool MemoryDock::canOpenInWorkbench() const
{
    return m_tabWorkbench != nullptr;
}

// openAddressInWorkbench：见头文件。
bool MemoryDock::openAddressInWorkbench(const std::uint64_t address, const bool kernelAddress)
{
    if (!canOpenInWorkbench())
    {
        return false;
    }
    ks::ui::NavRequest request;
    request.scope = kernelAddress
        ? ksword::memwb::Scope::KernelVirtual
        : ksword::memwb::Scope::ProcessVirtual;
    request.address = address;
    request.origin = ks::ui::NavOrigin::Evidence;
    // 进程地址不指定 pid：证据页属于本 Dock 附加的进程，工作台跟随 Dock 即可。
    return navigateWorkbench(request);
}

// jumpToModuleBase：模块表双击/右键的跳转。
// 模块表可以预览一个并未附加的进程：此时模块基址属于预览进程，不属于 Dock 附加的进程。
// 预览进程与附加进程不同时带上它的 pid 与创建时间钉住它（创建时间用来核对仍是同一个进程实例）；
// 相同时 pid 留空，工作台跟随 Dock。内嵌窗口的工作台锁定跟随 Dock，钉住请求会被策略拒绝
// （原因写在状态条里），不会静默去看错误的进程。
void MemoryDock::jumpToModuleBase(const std::uint64_t baseAddress)
{
    ks::ui::NavRequest request;
    request.scope = ksword::memwb::Scope::ProcessVirtual;
    request.address = baseAddress;
    request.origin = ks::ui::NavOrigin::ModuleTable;
    const ksword::memwb_services_detail::ModuleJumpPin pin = ksword::memwb_services_detail::DecideModuleJumpPin(
        m_moduleCachePid, m_moduleCacheCreateTime, m_attachedPid);
    request.pid = pin.pid;
    request.createTime = pin.createTime100ns;

    kLogEvent moduleJumpEvent;
    info << moduleJumpEvent
        << "[MemoryDock] 模块基址交给内存工作台, previewPid="
        << m_moduleCachePid
        << ", attachedPid="
        << m_attachedPid
        << ", pin="
        << (request.pid != 0U ? "true" : "false")
        << eol;
    (void)navigateWorkbench(request);
}

// viewRegionViaDriver：区域表"R0读取此区域"统一在工作台用标准驱动通道打开区域起点。
// 显式指定通道，不沿用会话当前通道；读取范围由工作台的真实地址空间和窗口管理。
void MemoryDock::viewRegionViaDriver(const std::uint64_t regionBase, const std::uint64_t bytesToRead)
{
    ks::ui::NavRequest request;
    request.scope = ksword::memwb::Scope::ProcessVirtual;
    request.address = regionBase;
    request.channel = ksword::memwb::Channel::StandardDriver;
    request.origin = ks::ui::NavOrigin::RegionTable;

    kLogEvent regionDriverEvent;
    info << regionDriverEvent
        << "[MemoryDock] 区域起点交给内存工作台（标准驱动通道）, base="
        << formatAddress(regionBase).toStdString()
        << ", legacyBytes="
        << bytesToRead
        << eol;
    (void)navigateWorkbench(request);
}

// workbenchFocusAddress：见头文件。工作台没有创建、
// 钉在别的进程/内核/物理范围、或画布没有插入点时返回空，调用方回退到自己的默认值。
std::optional<std::uint64_t> MemoryDock::workbenchFocusAddress() const
{
    if (m_workbenchView == nullptr || m_attachedPid == 0U)
    {
        return std::nullopt;
    }
    const auto& session = m_workbenchView->target().session();
    if (session.scope != ksword::memwb::Scope::ProcessVirtual || session.pid != m_attachedPid)
    {
        return std::nullopt;
    }
    return m_workbenchView->focusAddress();
}

// addSearchResultsToAddressBook：见头文件。
// 目标键用附加进程的 pid 与创建时间（与工作台视图生成的键同一函数、同一取时间方式），
// 所以加入的条目会出现在工作台里"当前目标"的地址簿视图中。
void MemoryDock::addSearchResultsToAddressBook(const std::vector<std::uint64_t>& addresses)
{
    if (addresses.empty())
    {
        return;
    }
    if (m_attachedPid == 0U)
    {
        if (m_scanStatusLabel != nullptr)
        {
            m_scanStatusLabel->setText(QStringLiteral("请先附加进程，再把搜索结果加入地址簿。"));
        }
        return;
    }

    // 共享对象必须先配置（幂等）：之后才能安全访问共享地址簿。
    ks::ui::workbench_dock::ConfigureShared();

    // createTime：与工作台目标锚点同一取法（降权句柄 GetProcessTimes）；取不到为 0。
    const ks::ui::AnchorInfo anchor = ks::ui::AcquireAnchorForPid(m_attachedPid);
    const std::uint64_t createTime = anchor.createTime100ns;
    ks::ui::ReleaseAnchorHandle(anchor.handle);

    // toBookValueType：把搜索页的值类型换算成地址簿的值解释类型（SearchValueType 是本类的嵌套
    // 类型，只能在成员函数里写出它的名字）。数组/字符串没有对应的数值类型，按"8 字节十六进制"
    // （地址簿默认）显示。
    const auto toBookValueType = [](const SearchValueType searchValueType) {
        using ksword::memwb::ValueType;
        switch (searchValueType)
        {
        case SearchValueType::Byte: return ValueType::U8;
        case SearchValueType::Int16: return ValueType::I16;
        case SearchValueType::Int32: return ValueType::I32;
        case SearchValueType::Int64: return ValueType::I64;
        case SearchValueType::Float32: return ValueType::F32;
        case SearchValueType::Float64: return ValueType::F64;
        case SearchValueType::ByteArray:
        case SearchValueType::StringAscii:
        case SearchValueType::StringUnicode:
        default:
            return ValueType::Hex8;
        }
    };

    const std::string targetKey =
        ks::ui::workbench_intake::BuildProcessTargetKey(m_attachedPid, createTime);
    const ks::ui::workbench_intake::IntakeResult result = ks::ui::workbench_intake::AddAddressesToBook(
        ks::ui::WorkbenchShared::Instance().AddressBook(),
        targetKey,
        addresses,
        toBookValueType(m_lastSearchValueType));

    QString statusText = QStringLiteral("已加入地址簿 %1 条").arg(result.added);
    if (result.duplicates > 0U)
    {
        statusText += QStringLiteral("，%1 条已在地址簿中").arg(result.duplicates);
    }
    if (result.refusedByCap > 0U)
    {
        statusText += QStringLiteral("，地址簿已满（上限 %1），%2 条未加入")
            .arg(ks::ui::workbench_intake::kAddressBookCap)
            .arg(result.refusedByCap);
    }
    if (m_scanStatusLabel != nullptr)
    {
        m_scanStatusLabel->setText(statusText);
    }

    kLogEvent intakeEvent;
    info << intakeEvent
        << "[MemoryDock] 搜索结果加入地址簿, requested="
        << result.requested
        << ", added="
        << result.added
        << ", duplicates="
        << result.duplicates
        << ", refusedByCap="
        << result.refusedByCap
        << eol;
}

namespace ksword::memory_dock_internal
{
    // addOpenInWorkbenchAction：见 MemoryDock.Internal.h。
    QAction* addOpenInWorkbenchAction(
        QMenu& menu,
        QTableWidget* const table,
        const int row,
        const int addressColumn,
        const bool kernelAddress)
    {
        MemoryDock* const dock = findOwningMemoryDock(table);
        if (dock == nullptr || !dock->canOpenInWorkbench())
        {
            return nullptr;
        }
        // address：点击行地址列的文本解析结果；没有行/解析失败时动作置灰而不是隐藏，用户能看到它存在。
        std::uint64_t address = 0;
        bool hasAddress = false;
        if (table != nullptr && row >= 0 && row < table->rowCount())
        {
            const QTableWidgetItem* const item = table->item(row, addressColumn);
            hasAddress = (item != nullptr) && parseHexAddress(item->text(), address);
        }

        QAction* const action = menu.addAction(
            QIcon(QStringLiteral(":/Icon/memwb_tab_hex.svg")), QStringLiteral("在内存工作台打开"));
        action->setToolTip(QStringLiteral("切到内存工作台，并跳到这一行的地址"));
        action->setEnabled(hasAddress);
        // 触发发生在 menu.exec 的事件循环里：table 与 dock 此时都还活着，用 QPointer 兜底。
        const QPointer<MemoryDock> guardedDock(dock);
        QObject::connect(action, &QAction::triggered, action, [guardedDock, address, kernelAddress]() {
            if (guardedDock != nullptr)
            {
                (void)guardedDock->openAddressInWorkbench(address, kernelAddress);
            }
        });
        return action;
    }
}
