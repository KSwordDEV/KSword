#include "MemoryDock.Internal.h"
#include "MemoryDock.WorkbenchServices.h"

#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/MemoryWorkbench/AddressBookStore.h"
#include "../UI/MemoryWorkbench/MemoryWorkbenchView.h"
#include "../UI/MemoryWorkbench/WorkbenchBookIntake.h"
#include "../UI/MemoryWorkbench/WorkbenchNavigation.h"
#include "../UI/MemoryWorkbench/WorkbenchShared.h"
#include "../UI/MemoryWorkbench/WorkbenchTarget.h"

#include <QItemSelectionModel>
#include <limits>


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
    // processHandleMatchesModuleTarget：验证附加句柄仍属于调用方冻结的进程实例。
    // 输入句柄、PID 和创建时间；输出是否身份完整且仍存活，不接受弱身份。
    bool processHandleMatchesModuleTarget(HANDLE handle, std::uint32_t pid, std::uint64_t creationTime)
    {
        if (handle == nullptr || ::GetProcessId(handle) != pid)
        {
            return false;
        }
        const auto anchor = ks::ui::AcquireAnchorFromDockHandle(handle); // 仅用于本次身份核对。
        const bool matches = !anchor.identityWeak && anchor.createTime100ns == creationTime
            && ks::ui::QueryAnchorAlive(anchor.handle) == std::optional<bool>(true);
        ks::ui::ReleaseAnchorHandle(anchor.handle);
        return matches;
    }

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

// openProcessMemoryRange：模块菜单携带明确实例与范围，附加和页面切换共用原离开守卫。
void MemoryDock::openProcessMemoryRange(const std::uint32_t pid, const std::uint64_t creationTime,
    const std::uint64_t address, const std::uint64_t size, const ProcessMemoryDestination destination,
    ks::ui::LeaveCompletion completion)
{
    const QPointer<MemoryDock> owner(this); // 模态错误提示和离开守卫期间允许宿主销毁。
    const auto navigation = ++m_processMemoryNavigationGeneration; // 后到请求覆盖旧目标页意图。
    m_pendingModuleRegionFocus.reset();
    const auto reject = [owner, completion](const QString& message)
    {
        if (owner)
        {
            QMessageBox::warning(owner, ks::i18n::packedSourceText(QStringLiteral("模块内存导航")), message);
        }
        if (owner && completion)
        {
            completion(false);
        }
    };

    // 保留降权锚点直到附加完成，禁止零创建时间和溢出范围悄悄指向复用 PID。
    if (pid == 0 || creationTime == 0 || size == 0
        || size - 1 > std::numeric_limits<std::uint64_t>::max() - address)
    {
        reject(ks::i18n::packedSourceText(QStringLiteral("模块地址范围或进程身份无效。")));
        return;
    }
    const auto anchor = std::shared_ptr<ks::ui::AnchorInfo>(new ks::ui::AnchorInfo(ks::ui::AcquireAnchorForPid(pid)),
        [](ks::ui::AnchorInfo* value)
        {
            ks::ui::ReleaseAnchorHandle(value->handle);
            delete value;
        });
    if (anchor->identityWeak || anchor->createTime100ns != creationTime
        || ks::ui::QueryAnchorAlive(anchor->handle) != std::optional<bool>(true))
    {
        reject(ks::i18n::packedSourceText(QStringLiteral("目标进程已退出、身份已变化或无法校验，请刷新模块列表。")));
        return;
    }

    // 同步和异步附加都进入这一收口；一次性值门禁防止完成回调重复执行后续动作。
    const auto completed = std::make_shared<bool>(false); // 回调仅在 GUI 线程消费。
    const auto attached = [owner, anchor, navigation, pid, creationTime, address, size,
        destination, completion, reject, completed](const bool allowed)
    {
        if (!owner || *completed)
        {
            return;
        }
        *completed = true;
        if (owner->m_processMemoryNavigationGeneration != navigation)
        {
            if (completion)
            {
                completion(false);
            }
            return;
        }
        if (!allowed)
        {
            if (completion)
            {
                completion(false);
            }
            return;
        }
        if (owner->m_attachedPid != pid
            || !processHandleMatchesModuleTarget(owner->m_attachedProcessHandle, pid, creationTime)
            || ks::ui::QueryAnchorAlive(anchor->handle) != std::optional<bool>(true))
        {
            reject(ks::i18n::packedSourceText(QStringLiteral("未能附加原进程实例，模块内存操作已取消。")));
            return;
        }

        // 工作台固定使用当前附加进程的虚拟地址，不沿用内核或钉住其它进程的范围。
        bool accepted = false; // 只有目标页完成准备才允许调用方继续 dump 等后续动作。
        if (destination == ProcessMemoryDestination::Workbench)
        {
            accepted = owner->openAddressInWorkbench(address);
        }
        else if (destination == ProcessMemoryDestination::Regions)
        {
            if (owner->ensureLazyPage(QStringLiteral("regions")) && owner)
            {
                owner->m_pendingModuleRegionFocus = ModuleRegionFocus{
                    address, owner->m_processAttachmentGeneration.load() };
                owner->m_regionFilterEdit->clear();
                if (!owner) { return; }
                owner->m_regionCommittedOnlyCheck->setChecked(false);
                if (!owner) { return; }
                owner->m_regionImageOnlyCheck->setChecked(false);
                if (!owner) { return; }
                owner->m_regionReadableOnlyCheck->setChecked(false);
                if (!owner) { return; }
                owner->m_tabWidget->setCurrentWidget(owner->m_tabRegions);
                if (owner)
                {
                    owner->applyRegionFilterAndRebuildTable();
                    if (!owner) { return; }
                    // 显式跨页定位刷新一次现场；冷附加已在枚举时直接等待既有任务。
                    if (!owner->m_regionRefreshJob && !owner->m_regionRefreshPendingJob)
                    {
                        owner->refreshMemoryRegionList(true);
                    }
                    if (!owner) { return; }
                    owner->applyPendingModuleRegionFocus();
                    accepted = true;
                }
            }
        }
        else if (destination == ProcessMemoryDestination::Search)
        {
            if (owner->m_scanInProgress.load())
            {
                reject(ks::i18n::packedSourceText(QStringLiteral("内存扫描正在运行，请先停止扫描后再切换模块搜索范围。")));
                return;
            }
            if (owner->ensureLazyPage(QStringLiteral("search")) && owner)
            {
                owner->m_searchRangeCombo->setCurrentIndex(1);
                if (!owner) { return; }
                owner->m_searchRangeStartEdit->setText(MemoryDock::formatAddress(address));
                if (!owner) { return; }
                owner->m_searchRangeEndEdit->setText(MemoryDock::formatAddress(address + size - 1));
                if (!owner) { return; }
                owner->m_searchImageOnlyCheck->setChecked(true);
                if (!owner) { return; }
                owner->m_searchHeapOnlyCheck->setChecked(false);
                if (!owner) { return; }
                owner->m_searchStackOnlyCheck->setChecked(false);
                if (!owner) { return; }
                owner->m_tabWidget->setCurrentWidget(owner->m_tabSearch);
                accepted = true;
            }
        }
        if (owner && completion)
        {
            completion(accepted && owner->m_processMemoryNavigationGeneration == navigation);
        }
    };

    // 已附加同一实例时不分离，保留工作台当前补丁、搜索结果与会话配置。
    if (m_attachedPid == pid && processHandleMatchesModuleTarget(m_attachedProcessHandle, pid, creationTime))
    {
        attached(true);
        return;
    }
    const QString processName = QFileInfo(QString::fromStdString(ks::process::QueryProcessPathByPid(pid))).fileName();
    const auto status = attachToProcess(pid, processName, false, attached);
    if (owner && status != ks::ui::LeaveEntryStatus::Pending)
    {
        attached(status == ks::ui::LeaveEntryStatus::Completed);
    }
}

// applyPendingModuleRegionFocus：在最新区域模型中按数值范围匹配，排序后不借用缓存行号。
void MemoryDock::applyPendingModuleRegionFocus()
{
    // 刷新期间不能消费旧投影：区域可能拆分或改大小，最终按地址重新定位。
    if (m_regionRefreshJob || m_regionRefreshPendingJob)
    {
        return;
    }
    if (!m_pendingModuleRegionFocus || !m_regionTable || !coreProjectionIsCurrent(CoreKind::Regions))
    {
        return;
    }
    const auto request = *m_pendingModuleRegionFocus; // 选择回调可能重入，先固定这次范围。
    if (request.attachmentGeneration != m_processAttachmentGeneration.load())
    {
        m_pendingModuleRegionFocus.reset();
        return;
    }
    const QPointer<MemoryDock> owner(this); // 选中和滚动信号允许关闭宿主。
    for (int row = 0; row < m_regionTable->model()->rowCount(); ++row)
    {
        const QModelIndex baseItem = m_regionTable->model()->index(row, 0); // 模型中的真实基址。
        const auto base = baseItem.data(Qt::UserRole).toULongLong();
        const auto length = m_regionTable->model()->index(row, 1).data(Qt::UserRole).toULongLong();
        if (request.address >= base && request.address - base < length)
        {
            m_pendingModuleRegionFocus.reset();
            m_regionTable->setCurrentIndex(baseItem);
            if (owner)
            {
                m_regionTable->selectionModel()->select(baseItem, QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
            }
            if (owner)
            {
                m_regionTable->scrollTo(baseItem, QAbstractItemView::PositionAtCenter);
            }
            return;
        }
    }
    // 冷附加的空投影先等待区域枚举；最终没有落点时不在以后刷新中意外抢回选区。
    if (!m_regionRefreshJob && !m_regionRefreshPendingJob)
    {
        m_pendingModuleRegionFocus.reset();
        if (m_regionStatusLabel)
        {
            m_regionStatusLabel->setText(ks::i18n::packedSourceText(QStringLiteral("未找到包含模块地址的内存区域，请刷新后重试。")));
        }
    }
}

// jumpToModuleBase：模块表双击/右键的跳转。
// 模块表可以预览一个并未附加的进程：此时模块基址属于预览进程，不属于 Dock 附加的进程。
// 先复用正常附加与离开守卫；只有打开失败才使用已加载的标准驱动通道。
void MemoryDock::jumpToModuleBase(const std::uint64_t baseAddress)
{
    const QPointer<MemoryDock> owner(this);
    const auto navigation = ++m_processMemoryNavigationGeneration;
    // 附加会清空/刷新模块缓存；所有后续回调只能使用这次点击冻结的实例和加载基址。
    const auto pid = m_moduleCachePid;
    const auto creationTime = m_moduleCacheCreateTime;
    const auto module = std::find_if(m_moduleCache->begin(), m_moduleCache->end(),
        [baseAddress](const ModuleEntry& entry) { return entry.baseAddress == baseAddress && entry.sizeBytes != 0; });
    const auto reject = [owner](const QString& message) {
        if (owner) QMessageBox::warning(owner, ks::i18n::packedSourceText(QStringLiteral("模块内存导航")), message);
    };
    if (pid == 0 || creationTime == 0 || baseAddress == 0 || module == m_moduleCache->end())
    {
        reject(ks::i18n::packedSourceText(QStringLiteral("模块地址范围或进程身份无效。")));
        return;
    }
    const auto anchor = std::shared_ptr<ks::ui::AnchorInfo>(new ks::ui::AnchorInfo(ks::ui::AcquireAnchorForPid(pid)),
        [](ks::ui::AnchorInfo* value) { ks::ui::ReleaseAnchorHandle(value->handle); delete value; });
    if (anchor->identityWeak || anchor->createTime100ns != creationTime
        || ks::ui::QueryAnchorAlive(anchor->handle) != std::optional<bool>(true))
    {
        reject(ks::i18n::packedSourceText(QStringLiteral("目标进程已退出、身份已变化或无法校验，请刷新模块列表。")));
        return;
    }
    const auto process = std::find_if(m_processCache->begin(), m_processCache->end(),
        [pid](const ProcessEntry& entry) { return entry.pid == pid; });
    const QString processName = process != m_processCache->end() ? process->processName : QString::number(pid);
    const auto stillCurrent = [owner, anchor, navigation]() {
        return owner && owner->m_processMemoryNavigationGeneration == navigation
            && ks::ui::QueryAnchorAlive(anchor->handle) == std::optional<bool>(true);
    };
    const auto attached = [owner, stillCurrent, pid, creationTime, baseAddress](bool allowed) {
        if (!allowed || !stillCurrent()) return;
        if (owner->m_attachedPid != pid
            || !processHandleMatchesModuleTarget(owner->m_attachedProcessHandle, pid, creationTime)) return;
        ks::ui::NavRequest request;
        request.scope = ksword::memwb::Scope::ProcessVirtual;
        request.address = baseAddress;
        request.origin = ks::ui::NavOrigin::ModuleTable;
        request.channel = ksword::memwb::Channel::UserMode;
        (void)owner->navigateWorkbench(request); // 正常附加后跟随 Dock，不沿用其它目标或通道。
    };
    const auto openFailed = [owner, stillCurrent, reject, pid, creationTime, baseAddress](std::uint32_t error) {
        if (!stillCurrent()) return;
        // 只检查既有设备，不自动加载驱动；R0 地址仍是该进程的模块加载 VA。
        const ksword::ark::DriverClient client;
        const auto driver = client.openSilently();
        if (!driver.isValid())
        {
            reject(ks::i18n::packedSourceText(QStringLiteral("附加进程失败（错误 %1），且 R0 驱动未加载或不可访问。"))
                .arg(error));
            return;
        }
        // 再次获取强身份，不能让工作台把期望实例静默降为仅 PID 的弱锚点。
        const auto verified = ks::ui::AcquireAnchorForPid(pid);
        const bool matches = !verified.identityWeak && verified.createTime100ns == creationTime
            && ks::ui::QueryAnchorAlive(verified.handle) == std::optional<bool>(true);
        ks::ui::ReleaseAnchorHandle(verified.handle);
        if (!matches || !stillCurrent())
        {
            reject(ks::i18n::packedSourceText(QStringLiteral("目标进程已退出、身份已变化或无法校验，请刷新模块列表。")));
            return;
        }
        ks::ui::NavRequest request;
        request.scope = ksword::memwb::Scope::ProcessVirtual;
        request.pid = pid;
        request.createTime = creationTime;
        request.address = baseAddress;
        request.channel = ksword::memwb::Channel::StandardDriver;
        request.origin = ks::ui::NavOrigin::ModuleTable;
        owner->probeModuleDriverJump(request, owner->m_processMemoryNavigationGeneration);
    };
    if (m_attachedPid == pid && processHandleMatchesModuleTarget(m_attachedProcessHandle, pid, creationTime))
    {
        attached(true);
        return;
    }
    const auto status = attachToProcess(pid, processName, false, attached, openFailed);
    if (owner && status != ks::ui::LeaveEntryStatus::Pending)
        attached(status == ks::ui::LeaveEntryStatus::Completed);
}

// 模块基址先实际读取成功才允许切页；后台只持值，失败/退出/过期回执均不导航。
void MemoryDock::probeModuleDriverJump(const ks::ui::NavRequest& request, const std::uint64_t navigationGeneration)
{
    if (!m_moduleNavigationOperation) m_moduleNavigationOperation = new ks::ui::AsyncOperation(this);
    const QPointer<MemoryDock> owner(this);
    const auto attachment = m_processAttachmentGeneration.load();
    struct Result
    {
        bool identityValid = false;
        std::shared_ptr<ks::ui::AnchorInfo> anchor; // 独立进程租约保留到 UI 接纳回执。
        ksword::ark::VirtualMemoryReadResult read;
    };
    const auto current = [owner, attachment, navigationGeneration]() {
        return owner && owner->m_processMemoryNavigationGeneration == navigationGeneration
            && owner->m_processAttachmentGeneration.load() == attachment;
    };
    m_moduleNavigationOperation->submit<ks::ui::NavRequest, Result>(request,
        [](const ks::ui::NavRequest& job, const ks::ui::AsyncOperationToken& token) {
            Result result;
            if (token.isCanceled()) return result;
            result.anchor = std::shared_ptr<ks::ui::AnchorInfo>(new ks::ui::AnchorInfo(ks::ui::AcquireAnchorForPid(job.pid)),
                [](ks::ui::AnchorInfo* value) { ks::ui::ReleaseAnchorHandle(value->handle); delete value; });
            const auto& anchor = result.anchor;
            if (anchor->identityWeak || anchor->createTime100ns != job.createTime
                || ks::ui::QueryAnchorAlive(anchor->handle) != std::optional<bool>(true)) return result;
            result.identityValid = true;
            const ksword::ark::DriverClient client;
            auto driver = client.openSilently();
            if (!driver.isValid())
            {
                result.read.io.win32Error = ::GetLastError();
                return result;
            }
            result.read = client.readVirtualMemory(job.pid, job.address, 1, 0, &driver); // 不请求未读区域补零或启用驱动。
            result.identityValid = !token.isCanceled()
                && ks::ui::QueryAnchorAlive(anchor->handle) == std::optional<bool>(true);
            return result;
        },
        [owner, current, request](const Result& result, std::uint64_t) {
            if (!current()) return true;
            if (!result.identityValid || !result.anchor
                || ks::ui::QueryAnchorAlive(result.anchor->handle) != std::optional<bool>(true))
            {
                QMessageBox::warning(owner, ks::i18n::packedSourceText(QStringLiteral("模块内存导航")),
                    ks::i18n::packedSourceText(QStringLiteral("目标进程已退出、身份已变化或无法校验，请刷新模块列表。")));
                return true;
            }
            const auto& read = result.read;
            if (!read.io.ok || read.readStatus != KSWORD_ARK_MEMORY_READ_STATUS_OK || read.copyStatus < 0
                || read.lookupStatus < 0 || read.bytesRead != 1 || read.data.size() != 1
                || read.processId != request.pid || read.requestedBaseAddress != request.address || read.requestedBytes != 1)
            {
                QMessageBox::warning(owner, ks::i18n::packedSourceText(QStringLiteral("模块内存导航")),
                    ks::i18n::packedSourceText(QStringLiteral("R0 读取模块失败（Win32=%1，NTSTATUS=0x%2，状态=%3），已取消跳转。"))
                        .arg(read.io.win32Error).arg(static_cast<unsigned long>(read.copyStatus), 8, 16, QLatin1Char('0'))
                        .arg(read.readStatus));
                return true;
            }
            (void)owner->navigateWorkbench(request);
            return true;
        },
        [owner, current](std::exception_ptr) {
            if (current()) QMessageBox::warning(owner, ks::i18n::packedSourceText(QStringLiteral("模块内存导航")),
                ks::i18n::packedSourceText(QStringLiteral("R0 模块读取检查失败，已取消跳转。")));
        });
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
        QTableView* const table,
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
        if (table != nullptr && row >= 0 && table->model() && row < table->model()->rowCount())
        {
            const QModelIndex item = table->model()->index(row, addressColumn);
            hasAddress = item.isValid() && parseHexAddress(item.data(Qt::DisplayRole).toString(), address);
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
