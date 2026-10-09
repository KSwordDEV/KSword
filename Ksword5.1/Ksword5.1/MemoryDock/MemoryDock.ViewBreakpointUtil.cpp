#include "MemoryDock.Internal.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"
#include "../../../shared/evidence/NumericTextParse.h"

// 说明：由原聚合式实现迁移为独立 .cpp，成员函数实现保持原样。
using namespace ksword::memory_dock_internal;

// ============================================================
// MemoryDock.ViewBreakpointUtil.cpp
// 作用：
// - 负责内存查看器、断点与书签、通用格式化和解析工具函数。
// - 聚焦“可视化读写 + 调试辅助 + 文本转换”能力。
// ============================================================

void MemoryDock::jumpToAddressFromUi()
{
    // 地址跳转入口日志：记录用户输入原文。
    kLogEvent jumpFromUiEvent;
    info << jumpFromUiEvent
        << "[MemoryDock] jumpToAddressFromUi: 请求跳转, text="
        << m_viewAddressEdit->text().trimmed().toStdString()
        << eol;

    // 地址栏支持十进制或 0x 十六进制。
    std::uint64_t targetAddress = 0;
    if (!parseAddressText(m_viewAddressEdit->text().trimmed(), targetAddress))
    {
        kLogEvent jumpFromUiParseFailEvent;
        warn << jumpFromUiParseFailEvent
            << "[MemoryDock] jumpToAddressFromUi: 地址解析失败。"
            << eol;
        QMessageBox::warning(this, "地址跳转", "地址格式无效。");
        return;
    }
    // 旧地址框只服务旧内存查看器，不经工作台分发器（3a 并存阶段旧入口保持原样）。
    jumpToAddressLegacy(targetAddress);
}

// jumpToAddressLegacy：原 jumpToAddress 的函数体，原样保留；统一入口 jumpToAddress
// （分发器）在 MemoryDock.Workbench.cpp。
void MemoryDock::jumpToAddressLegacy(const std::uint64_t address)
{
    if (!confirmDiscardMemoryViewerChanges())
    {
        m_viewAddressEdit->setText(formatAddress(m_currentViewerAddress));
        return;
    }

    // 跳转日志：记录目标地址并切换页面。
    kLogEvent jumpAddressEvent;
    info << jumpAddressEvent
        << "[MemoryDock] jumpToAddress: 跳转到地址="
        << formatAddress(address).toStdString()
        << eol;

    // 记录当前查看基址，供滚动、编辑、状态栏等多个逻辑复用。
    m_currentViewerAddress = address;
    m_viewAddressEdit->setText(formatAddress(address));

    // 跳转时自动切换到 Tab4，符合“模块/区域/搜索结果双击即查看”的预期。
    m_tabWidget->setCurrentWidget(m_tabViewer);
    reloadMemoryViewerPage();
}

void MemoryDock::reloadMemoryViewerPage()
{
    if (!confirmDiscardMemoryViewerChanges())
    {
        return;
    }

    // 页面重载日志：输出当前查看地址。
    kLogEvent reloadViewerStartEvent;
    dbg << reloadViewerStartEvent
        << "[MemoryDock] reloadMemoryViewerPage: 开始刷新, baseAddress="
        << formatAddress(m_currentViewerAddress).toStdString()
        << eol;

    // 没有附加目标进程时，查看器仅显示提示，不尝试读内存。
    if (m_attachedProcessHandle == nullptr)
    {
        m_currentViewerPageBytes.clear();
        clearMemoryViewerSnapshot();
        m_viewProtectLabel->setText("保护属性: -");
        m_viewerStatusLabel->setText("未附加进程。");
        kLogEvent reloadViewerNoAttachEvent;
        warn << reloadViewerNoAttachEvent
            << "[MemoryDock] reloadMemoryViewerPage: 未附加进程，结束刷新。"
            << eol;
        return;
    }

    // 每页固定读取 512 字节，兼顾可读性与刷新性能。缓冲区由门面分配：三条通道
    // 的字节数各自由各自的实现决定，这里再准备一个固定长度的缓冲只会多出一个
    // "看起来读满了"的假象。
    SIZE_T bytesRead = 0;

    // DDMA 后端不经过 ReadProcessMemory：逐页翻译成物理地址后走磁盘 DMA，
    // 因此能看到被 SLAT 重定向的内容。翻译失败的页由后端门面补 00 并置 partial。
    if (currentViewerBackend() == ksword::memory_backend::MemoryAccessBackend::Ddma)
    {
        const ksword::memory_backend::AccessOutcome ddmaOutcome =
            ksword::memory_backend::readVirtual(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                currentDdmaSession(),
                m_attachedPid,
                m_currentViewerAddress,
                kHexPageBytes);
        if (!ddmaOutcome.ok)
        {
            m_currentViewerPageBytes.clear();
            clearMemoryViewerSnapshot();
            m_viewerStatusLabel->setText(
                QStringLiteral("DDMA 读取失败：%1").arg(ddmaOutcome.failureText));
            return;
        }

        m_currentViewerPageBytes = ddmaOutcome.data;
        m_viewerSnapshotProcessCreateTime100ns = 0; // DDMA 快照不建立进程调试导航授权。
        loadMemoryViewerSnapshot(false);
        QString ddmaStatusText = QStringLiteral("DDMA 读取完成：%1 字节（只读展示）。")
            .arg(m_currentViewerPageBytes.size());
        if (ddmaOutcome.partial)
        {
            ddmaStatusText += QStringLiteral(" 有页无法翻译成物理地址，已按 00 填充。");
        }
        if (ddmaOutcome.scratchDirty)
        {
            ddmaStatusText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        m_viewerStatusLabel->setText(ddmaStatusText);
        m_viewProtectLabel->setText(QStringLiteral("保护属性: DDMA 通道不查询"));
        return;
    }

    // R3 与 R0 都走同一个门面，只是枚举值不同。**不做自动回退**：这三条通道
    // 摆在下拉框里的意义就是"同一个地址各自能读到什么"，一条失败时偷偷换另一条
    // 去读，屏幕上的字节就不再对应用户选的通道，差异也就再也看不出来了。
    const ksword::memory_backend::MemoryAccessBackend selectedBackend =
        currentViewerBackend();
    // 在实际读取前取得原句柄的创建时间；装载/重绘旧快照时不再查询当前附加对象。
    const HANDLE navigationHandle = m_attachedProcessHandle;
    const std::uint32_t navigationPid = m_attachedPid;
    const std::uint64_t navigationGeneration = m_processAttachmentGeneration.load();
    FILETIME created{}, exited{}, kernel{}, user{};
    std::uint64_t navigationCreation = 0; // 读取前无法证明身份时只禁用导航，不阻止读字节。
    if (!ksword::memory_backend::isKernelVirtualAddress(m_currentViewerAddress)
        && ::GetProcessId(navigationHandle) == navigationPid
        && ::GetProcessTimes(navigationHandle, &created, &exited, &kernel, &user) != FALSE)
    {
        navigationCreation = (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
    }
    const ksword::memory_backend::AccessOutcome readOutcome =
        ksword::memory_backend::readVirtual(
            selectedBackend,
            currentDdmaSession(),
            m_attachedPid,
            m_currentViewerAddress,
            kHexPageBytes);
    const QString channelText =
        ksword::memory_backend::backendDisplayName(selectedBackend);

    if (!readOutcome.ok)
    {
        m_currentViewerPageBytes.clear();
        clearMemoryViewerSnapshot();

        // 失败时必须把**这个地址在目标进程里到底是什么状态**查出来。原先
        // VirtualQueryEx 只在成功路径上跑，于是报错只有一个 win32 错误码，
        // 而 299 同时兼容好几种完全不同的成因：附加的根本不是那个进程、
        // 那段内存已经被释放、或者是栈的 PAGE_GUARD 页。这几种靠错误码一种都
        // 分不出来，只能靠猜——而猜出来的机制不是判据。区域状态一摆出来就分完了。
        MEMORY_BASIC_INFORMATION failMbi{};
        const SIZE_T failQuerySize = ::VirtualQueryEx(
            m_attachedProcessHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(m_currentViewerAddress)),
            &failMbi,
            sizeof(failMbi));
        QString regionText;
        if (failQuerySize == sizeof(failMbi))
        {
            regionText = QString("区域 %1 大小 %2 状态 %3 保护 %4")
                .arg(formatAddress(reinterpret_cast<std::uint64_t>(failMbi.BaseAddress)))
                .arg(static_cast<qulonglong>(failMbi.RegionSize))
                .arg(stateToText(static_cast<std::uint32_t>(failMbi.State)))
                .arg(protectToText(static_cast<std::uint32_t>(failMbi.Protect)));

            // MEM_FREE 的含义是"这里根本没有内存"，不是"读不到"。三条通道谁都
            // 变不出不存在的东西，所以此时继续在读取通道上排查一定是白费。
            // 最常见的成因是附加到了同名的另一个进程：像 QQ 这种一开十个同名
            // 进程的程序，从别处抄来的地址属于其中某一个，附加到另一个上就正好
            // 是这个现象。同名进程数是现成的，直接点出来，别让人去猜。
            if (failMbi.State == MEM_FREE)
            {
                int sameNameCount = 0;
                for (const ProcessEntry& entry : m_processCache)
                {
                    if (entry.processName.compare(m_attachedProcessName, Qt::CaseInsensitive) == 0)
                    {
                        ++sameNameCount;
                    }
                }
                regionText += QStringLiteral("。该地址在这个进程里根本没有内存（MEM_FREE），不是读不到——换任何通道都一样");
                if (sameNameCount > 1)
                {
                    regionText += QString("。本机有 %1 个都叫 %2 的进程，地址很可能属于其中另一个，请核对 PID")
                        .arg(sameNameCount)
                        .arg(m_attachedProcessName);
                }
            }
        }
        else
        {
            regionText = QStringLiteral("区域查询也失败，该地址在本进程中不存在");
        }

        // 低 64 KB 是每个进程的空指针保护区，系统从不在那里映射任何东西，
        // 所以这一段永远读不到，跟目标进程、权限、后端通道都无关。把它单独
        // 判出来，是因为它的真实成因几乎总在读取之外：地址本身就不对。
        constexpr std::uint64_t kNullGuardEnd = 0x10000ULL;
        const QString guardText = (m_currentViewerAddress < kNullGuardEnd)
            ? QStringLiteral("该地址落在进程的空指针保护区（低 64 KB）内，任何进程都不会在这里映射内存，请检查地址是否写少了位数。")
            : QString();
        m_viewerStatusLabel->setText(
            QString("%1 读取失败：地址=%2（PID %3）。%4%5。%6")
            .arg(channelText)
            .arg(formatAddress(m_currentViewerAddress))
            .arg(m_attachedPid)
            .arg(guardText)
            .arg(readOutcome.failureText)
            .arg(regionText));
        kLogEvent reloadViewerReadFailEvent;
        err << reloadViewerReadFailEvent
            << "[MemoryDock] reloadMemoryViewerPage: 读取失败, backend="
            << channelText.toStdString()
            << ", address="
            << formatAddress(m_currentViewerAddress).toStdString()
            << ", pid="
            << m_attachedPid
            << ", reason="
            << readOutcome.failureText.toStdString()
            << ", region="
            << regionText.toStdString()
            << eol;
        return;
    }

    m_currentViewerPageBytes = readOutcome.data;
    // 若读取期间发生分离/重新附加，即使句柄数值或 PID 相同也不能把旧字节绑定新身份。
    m_viewerSnapshotProcessCreateTime100ns = navigationHandle == m_attachedProcessHandle
        && navigationPid == m_attachedPid && navigationGeneration == m_processAttachmentGeneration.load()
            ? navigationCreation : 0;
    bytesRead = static_cast<SIZE_T>(m_currentViewerPageBytes.size());
    const bool partialRead = readOutcome.partial || (bytesRead < kHexPageBytes);

    // 三种视图使用同一份快照，修改先保存在缓存，Apply 才写回目标。
    loadMemoryViewerSnapshot(
        !ksword::memory_backend::isKernelVirtualAddress(m_currentViewerAddress)
        && (selectedBackend != ksword::memory_backend::MemoryAccessBackend::UserMode
            || m_canReadWriteMemory));

    // 更新当前地址保护属性显示，帮助用户判断是否可写/可执行。
    MEMORY_BASIC_INFORMATION mbi{};
    const SIZE_T querySize = ::VirtualQueryEx(
        m_attachedProcessHandle,
        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(m_currentViewerAddress)),
        &mbi,
        sizeof(mbi));
    if (querySize == sizeof(mbi))
    {
        m_viewProtectLabel->setText(
            QString("保护属性: %1 | 状态: %2 | 类型: %3")
            .arg(protectToText(static_cast<std::uint32_t>(mbi.Protect)))
            .arg(stateToText(static_cast<std::uint32_t>(mbi.State)))
            .arg(typeToText(static_cast<std::uint32_t>(mbi.Type))));

        // 可写可执行的页是最值得警惕的组合，用语义色直接标出来，
        // 免得用户在一长串属性文本里自己找。这里每次跳转都会重新下发，
        // 所以用快照 token 取色是安全的。
        const std::uint32_t baseProtect = static_cast<std::uint32_t>(mbi.Protect) & 0xFFU;
        const bool executable = (baseProtect == PAGE_EXECUTE
            || baseProtect == PAGE_EXECUTE_READ
            || baseProtect == PAGE_EXECUTE_READWRITE
            || baseProtect == PAGE_EXECUTE_WRITECOPY);
        const bool writable = (baseProtect == PAGE_READWRITE
            || baseProtect == PAGE_WRITECOPY
            || baseProtect == PAGE_EXECUTE_READWRITE
            || baseProtect == PAGE_EXECUTE_WRITECOPY);
        QString protectColor = KswordTheme::TextSecondaryHex();
        if (executable && writable)
        {
            protectColor = KswordTheme::ErrorHex();   // RWX：最高风险。
        }
        else if (executable)
        {
            protectColor = KswordTheme::WarningHex(); // 可执行但不可写。
        }
        else if (writable)
        {
            protectColor = KswordTheme::SuccessHex(); // 普通可读写数据页。
        }
        m_viewProtectLabel->setStyleSheet(QString("color:%1;").arg(protectColor));
    }
    else
    {
        m_viewProtectLabel->setText("保护属性: (查询失败)");
        m_viewProtectLabel->setStyleSheet(
            QString("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    }

    // 只读到一部分时必须说出来。少了这句，用户看到的是一屏正常的十六进制，
    // 却不知道这一页在某个字节之后就是未映射区，剩下的内容压根不存在。
    // 通道名也要写出来：同一个地址在驱动通道和 RPM 下读到的东西可能不一样，
    // 不写就分不清屏幕上这一页到底是谁给的。
    if (partialRead)
    {
        m_viewerStatusLabel->setText(
            QString("地址 %1 经%2只读到 %3 / %4 字节：其余部分不可读，内容不存在。")
            .arg(formatAddress(m_currentViewerAddress))
            .arg(channelText)
            .arg(bytesRead)
            .arg(kHexPageBytes));
    }
    else
    {
        m_viewerStatusLabel->setText(
            QString("地址 %1 经%2读取 %3 字节。")
            .arg(formatAddress(m_currentViewerAddress))
            .arg(channelText)
            .arg(bytesRead));
    }

    if (!readOutcome.failureText.isEmpty())
        m_viewerStatusLabel->setText(m_viewerStatusLabel->text()
            + QStringLiteral(" ") + readOutcome.failureText);

    // 刷新完成日志：记录本页成功读取字节数。
    kLogEvent reloadViewerFinishEvent;
    dbg << reloadViewerFinishEvent
        << "[MemoryDock] reloadMemoryViewerPage: 刷新完成, bytesRead="
        << bytesRead
        << eol;
}

bool MemoryDock::confirmDiscardMemoryViewerChanges()
{
    if (m_viewerMemoryEditor == nullptr || !m_viewerMemoryEditor->hasChanges())
    {
        return true;
    }
    if (QMessageBox::question(
            this, QStringLiteral("内存编辑"),
            QStringLiteral("当前缓存存在未应用的改动。是否丢弃改动并读取新快照？"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
    {
        return false;
    }
    discardMemoryViewerChanges();
    return true;
}

bool MemoryDock::confirmDiscardMemoryEditsForProcessChange()
{
    const bool viewerChanged = m_viewerMemoryEditor != nullptr && m_viewerMemoryEditor->hasChanges();
    const bool driverChanged = m_driverMemoryEditor != nullptr && m_driverMemoryEditor->hasChanges();
    if (viewerChanged || driverChanged)
    {
        if (QMessageBox::question(this, QStringLiteral("内存编辑"),
            QStringLiteral("丢弃已读取的缓存与未应用的改动"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        {
            return false;
        }
    }
    // 旧缓存检查通过之后再问一次内存工作台的离开守卫（暂存补丁/未还原 int3，只问一次）：
    // 工作台视图尚未创建时没有任何东西要问，直接放行。
    return workbenchAllowsProcessChange();
}

void MemoryDock::loadMemoryViewerSnapshot(const bool editable, const bool preserveArchitecture)
{
    if (m_viewerMemoryEditor == nullptr)
    {
        return;
    }
    BOOL wow64 = FALSE;
    const bool isX86 = m_attachedProcessHandle != nullptr
        && ::IsWow64Process(m_attachedProcessHandle, &wow64) != FALSE
        && wow64 != FALSE
        && !ksword::memory_backend::isKernelVirtualAddress(m_currentViewerAddress);
    m_viewerSnapshotPid = m_attachedPid;
    m_viewerSnapshotAttachmentGeneration = m_processAttachmentGeneration.load();
    m_viewerSnapshotBackend = currentViewerBackend();
    m_viewerSnapshotDdmaSession = currentDdmaSession();
    const auto architecture = preserveArchitecture ? m_viewerMemoryEditor->currentArchitecture()
        : (isX86 ? ks::ui::DisassemblyArchitecture::X86 : ks::ui::DisassemblyArchitecture::X64);
    m_viewerMemoryEditor->setSnapshot(
        m_currentViewerPageBytes, m_currentViewerAddress,
        architecture,
        m_currentViewerAddress,
        QStringLiteral("memory_viewer_%1_%2_%3_%4").arg(m_viewerSnapshotPid)
            .arg(m_viewerSnapshotAttachmentGeneration).arg(static_cast<int>(m_viewerSnapshotBackend))
            .arg(ksword::memory_backend::ddmaSessionGeneration()));
    const bool processVirtual = m_viewerSnapshotBackend != ksword::memory_backend::MemoryAccessBackend::Ddma
        && !ksword::memory_backend::isKernelVirtualAddress(m_currentViewerAddress);
    // 装载与写回回读沿用读取时冻结的身份，不从后来附加的同号进程补授旧字节。
    m_viewerMemoryEditor->setProcessContext(
        processVirtual ? toDwordPid(m_viewerSnapshotPid) : 0U,
        processVirtual ? m_viewerSnapshotProcessCreateTime100ns : 0ULL);
    m_viewerMemoryEditor->setEditable(editable);
    updateMemoryViewerEditState();
}

void MemoryDock::clearMemoryViewerSnapshot()
{
    m_currentViewerPageBytes.clear();
    m_viewerSnapshotPid = 0;
    m_viewerSnapshotProcessCreateTime100ns = 0;
    if (m_viewerMemoryEditor != nullptr)
    {
        m_viewerMemoryEditor->clear();
        m_viewerMemoryEditor->setEditable(false);
    }
    updateMemoryViewerEditState();
}

void MemoryDock::updateMemoryViewerEditState()
{
    const bool changed = m_viewerMemoryEditor != nullptr && m_viewerMemoryEditor->hasChanges();
    if (m_viewerApplyButton != nullptr)
    {
        m_viewerApplyButton->setEnabled(changed && m_hexEditorWidget->isEditable());
    }
    if (m_viewerDiscardButton != nullptr)
    {
        m_viewerDiscardButton->setEnabled(changed);
    }
    if (changed && m_viewerStatusLabel != nullptr)
    {
        m_viewerStatusLabel->setText(QStringLiteral(
            "缓存已修改，应用差异后才会写入真实内存。"));
    }
}

void MemoryDock::discardMemoryViewerChanges()
{
    if (m_viewerMemoryEditor != nullptr)
    {
        m_viewerMemoryEditor->discardChanges();
    }
    updateMemoryViewerEditState();
    if (m_viewerStatusLabel != nullptr)
    {
        m_viewerStatusLabel->setText(QStringLiteral("已丢弃未应用的改动。"));
    }
}

void MemoryDock::applyMemoryViewerChanges()
{
    if (m_viewerMemoryEditor == nullptr || !m_viewerMemoryEditor->hasChanges())
    {
        return;
    }
    using namespace ksword::memory_backend;
    DWORD targetExitCode = 0;
    if (m_attachedProcessHandle == nullptr || m_viewerSnapshotPid != m_attachedPid
        || m_viewerSnapshotAttachmentGeneration != m_processAttachmentGeneration.load()
        || m_viewerSnapshotBackend != currentViewerBackend()
        || m_viewerSnapshotBackend == MemoryAccessBackend::Ddma
        || isKernelVirtualAddress(m_currentViewerAddress)
        || ::GetExitCodeProcess(m_attachedProcessHandle, &targetExitCode) == FALSE
        || targetExitCode != STILL_ACTIVE)
    {
        QMessageBox::warning(this, QStringLiteral("内存编辑"),
            QStringLiteral("目标进程或访问后端已改变，请重新读取后再应用改动。"));
        return;
    }
    const auto blocks = m_viewerMemoryEditor->diffBlocks();
    const auto snapshotPid = m_viewerSnapshotPid;
    const auto snapshotGeneration = m_viewerSnapshotAttachmentGeneration;
    const auto snapshotBase = m_currentViewerAddress;
    const auto snapshotBackend = m_viewerSnapshotBackend;
    const QByteArray snapshotOriginal = m_viewerMemoryEditor->originalBytes();
    const QByteArray snapshotEdited = m_viewerMemoryEditor->data();
    const auto stillCurrent = [&]() {
        DWORD exitCode = 0;
        return m_viewerSnapshotPid == snapshotPid && m_attachedPid == snapshotPid
            && m_viewerSnapshotAttachmentGeneration == snapshotGeneration
            && m_processAttachmentGeneration.load() == snapshotGeneration
            && m_currentViewerAddress == snapshotBase
            && m_viewerSnapshotBackend == snapshotBackend && currentViewerBackend() == snapshotBackend
            && m_viewerMemoryEditor->originalBytes() == snapshotOriginal
            && m_viewerMemoryEditor->data() == snapshotEdited
            && m_attachedProcessHandle != nullptr
            && ::GetExitCodeProcess(m_attachedProcessHandle, &exitCode) != FALSE
            && exitCode == STILL_ACTIVE;
    };
    // 写入前逐块复核基线；任一块变化就不开始提交，避免覆盖外部工具的最新修改。
    for (const auto& block : blocks)
    {
        const AccessOutcome live = readVirtual(m_viewerSnapshotBackend,
            m_viewerSnapshotDdmaSession, m_viewerSnapshotPid,
            block.address, static_cast<std::uint64_t>(block.originalBytes.size()));
        if (!live.ok || live.partial || live.data != block.originalBytes)
        {
            const QString reason = live.ok
                ? QStringLiteral("目标字节已改变，请重新读取后再编辑。")
                : live.failureText;
            QMessageBox::warning(this, QStringLiteral("内存编辑"), reason);
            return;
        }
    }

    std::uint64_t written = 0;
    QString failureText;
    bool forceApproved = false;
    for (const auto& block : blocks)
    {
        AccessOutcome outcome = writeVirtual(m_viewerSnapshotBackend,
            m_viewerSnapshotDdmaSession, m_viewerSnapshotPid,
            block.address, block.bytes, forceApproved);
        if (outcome.forceRequired && !forceApproved
            && confirmForceDriverMemoryWrite(block.address,
                static_cast<std::uint32_t>(block.bytes.size()), outcome.failureText, snapshotPid))
        {
            if (!stillCurrent())
            {
                QMessageBox::warning(this, QStringLiteral("内存编辑"),
                    QStringLiteral("目标进程或访问后端已改变，请重新读取后再应用改动。"));
                return;
            }
            forceApproved = true;
            outcome = writeVirtual(m_viewerSnapshotBackend,
                m_viewerSnapshotDdmaSession, m_viewerSnapshotPid,
                block.address, block.bytes, true);
        }
        written += outcome.bytesDone;
        if (!outcome.ok || outcome.bytesDone != static_cast<std::uint64_t>(block.bytes.size()))
        {
            failureText = outcome.failureText.isEmpty()
                ? QStringLiteral("写入未完成。") : outcome.failureText;
            break;
        }
        ::FlushInstructionCache(m_attachedProcessHandle,
            reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(block.address)),
            static_cast<SIZE_T>(block.bytes.size()));
        const AccessOutcome verified = readVirtual(m_viewerSnapshotBackend,
            m_viewerSnapshotDdmaSession, m_viewerSnapshotPid,
            block.address, static_cast<std::uint64_t>(block.bytes.size()));
        if (!verified.ok || verified.partial || verified.data != block.bytes)
        {
            failureText = QStringLiteral("写入后的回读结果与编辑缓存不一致。");
            break;
        }
    }

    if (!stillCurrent())
    {
        QMessageBox::warning(this, QStringLiteral("内存编辑"),
            QStringLiteral("目标进程或访问后端已改变，请重新读取后再应用改动。"));
        return;
    }
    // 完整回读后建立实际内存基线；部分写入失败也不得把编辑缓存当作成功结果。
    const AccessOutcome actual = readVirtual(m_viewerSnapshotBackend,
        m_viewerSnapshotDdmaSession, m_viewerSnapshotPid,
        m_currentViewerAddress, static_cast<std::uint64_t>(m_currentViewerPageBytes.size()));
    if (actual.ok && !actual.partial)
    {
        for (const auto& block : blocks)
        {
            const qsizetype offset = static_cast<qsizetype>(block.address - m_currentViewerAddress);
            if (actual.data.mid(offset, block.bytes.size()) != block.bytes)
            {
                failureText = QStringLiteral("写入后的回读结果与编辑缓存不一致。");
                break;
            }
        }
    }
    if (actual.ok && !actual.partial && !actual.data.isEmpty())
    {
        m_currentViewerPageBytes = actual.data;
        loadMemoryViewerSnapshot(true, true);
    }
    else
    {
        clearMemoryViewerSnapshot();
    }
    if (!failureText.isEmpty() || !actual.ok || actual.partial || actual.data.isEmpty())
    {
        const QString text = QStringLiteral("应用未完成：已写入 %1 字节。%2")
            .arg(static_cast<qulonglong>(written))
            .arg(!failureText.isEmpty() ? failureText
                : (actual.failureText.isEmpty()
                    ? QStringLiteral("写入后的回读结果与编辑缓存不一致。") : actual.failureText));
        m_viewerStatusLabel->setText(text);
        if (!ks::ui::promptForPrivilegeFailure(this, QStringLiteral("编辑进程内存"), text))
        {
            QMessageBox::warning(this, QStringLiteral("内存编辑"), text);
        }
        return;
    }
    m_viewerStatusLabel->setText(QStringLiteral("应用完成并已回读：%1 字节。")
        .arg(static_cast<qulonglong>(written)));
}

bool MemoryDock::addBreakpointByAddress(
    const std::uint64_t address,
    const QString& description,
    QString& errorTextOut)
{
    // 添加断点入口日志：记录地址和描述来源。
    kLogEvent addBreakpointStartEvent;
    info << addBreakpointStartEvent
        << "[MemoryDock] addBreakpointByAddress: 请求添加断点, address="
        << formatAddress(address).toStdString()
        << ", description="
        << description.toStdString()
        << eol;

    // 软件断点依赖 0xCC 写入，因此必须具备写内存权限。
    if (m_attachedProcessHandle == nullptr)
    {
        errorTextOut = "请先附加进程。";
        kLogEvent addBreakpointNoAttachEvent;
        warn << addBreakpointNoAttachEvent
            << "[MemoryDock] addBreakpointByAddress: 未附加进程。"
            << eol;
        return false;
    }
    if (!m_canReadWriteMemory)
    {
        errorTextOut = "当前为只读句柄，无法设置断点。";
        kLogEvent addBreakpointReadonlyEvent;
        warn << addBreakpointReadonlyEvent
            << "[MemoryDock] addBreakpointByAddress: 句柄只读。"
            << eol;
        return false;
    }

    // 避免重复写入相同地址断点，提升断点缓存一致性。
    for (const BreakpointEntry& cachedBp : m_breakpointCache)
    {
        if (cachedBp.address == address)
        {
            errorTextOut = "该地址已存在断点。";
            kLogEvent addBreakpointDuplicateEvent;
            warn << addBreakpointDuplicateEvent
                << "[MemoryDock] addBreakpointByAddress: 重复断点地址。"
                << eol;
            return false;
        }
    }

    std::uint8_t originalByte = 0;
    SIZE_T bytesRead = 0;
    const BOOL readOk = ::ReadProcessMemory(
        m_attachedProcessHandle,
        reinterpret_cast<LPCVOID>(static_cast<std::uintptr_t>(address)),
        &originalByte,
        sizeof(originalByte),
        &bytesRead);
    if (readOk == FALSE || bytesRead != sizeof(originalByte))
    {
        errorTextOut = QString("读取原始字节失败，错误码=%1").arg(::GetLastError());
        kLogEvent addBreakpointReadFailEvent;
        err << addBreakpointReadFailEvent
            << "[MemoryDock] addBreakpointByAddress: 读取原字节失败, error="
            << ::GetLastError()
            << eol;
        return false;
    }

    const std::uint8_t int3Byte = 0xCC;
    SIZE_T bytesWritten = 0;
    const BOOL writeOk = ::WriteProcessMemory(
        m_attachedProcessHandle,
        reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(address)),
        &int3Byte,
        sizeof(int3Byte),
        &bytesWritten);
    if (writeOk == FALSE || bytesWritten != sizeof(int3Byte))
    {
        errorTextOut = QString("写入 0xCC 失败，错误码=%1").arg(::GetLastError());
        kLogEvent addBreakpointWriteFailEvent;
        err << addBreakpointWriteFailEvent
            << "[MemoryDock] addBreakpointByAddress: 写入0xCC失败, error="
            << ::GetLastError()
            << eol;
        return false;
    }

    BreakpointEntry bpEntry{};
    bpEntry.address = address;
    bpEntry.originalByte = originalByte;
    bpEntry.enabled = true;
    bpEntry.hitCount = 0;
    bpEntry.description = description;
    m_breakpointCache.push_back(std::move(bpEntry));

    kLogEvent addBreakpointFinishEvent;
    info << addBreakpointFinishEvent
        << "[MemoryDock] addBreakpointByAddress: 添加成功, totalBreakpointCount="
        << m_breakpointCache.size()
        << eol;
    return true;
}

bool MemoryDock::removeBreakpointByRow(const int row)
{
    if (row < 0 || row >= static_cast<int>(m_breakpointCache.size()))
    {
        kLogEvent removeBreakpointInvalidRowEvent;
        warn << removeBreakpointInvalidRowEvent
            << "[MemoryDock] removeBreakpointByRow: row越界, row="
            << row
            << eol;
        return false;
    }

    // 删除前若断点处于启用状态，先恢复原字节，避免目标进程留脏。
    if (m_breakpointCache[static_cast<std::size_t>(row)].enabled)
    {
        if (!setBreakpointEnabledByRow(row, false))
        {
            kLogEvent removeBreakpointDisableFailEvent;
            warn << removeBreakpointDisableFailEvent
                << "[MemoryDock] removeBreakpointByRow: 禁用断点失败, row="
                << row
                << eol;
            return false;
        }
    }

    m_breakpointCache.erase(m_breakpointCache.begin() + row);
    kLogEvent removeBreakpointFinishEvent;
    info << removeBreakpointFinishEvent
        << "[MemoryDock] removeBreakpointByRow: 删除成功, remainCount="
        << m_breakpointCache.size()
        << eol;
    return true;
}

bool MemoryDock::setBreakpointEnabledByRow(const int row, const bool enabled)
{
    if (row < 0 || row >= static_cast<int>(m_breakpointCache.size()))
    {
        kLogEvent setBreakpointInvalidRowEvent;
        warn << setBreakpointInvalidRowEvent
            << "[MemoryDock] setBreakpointEnabledByRow: row越界, row="
            << row
            << eol;
        return false;
    }
    if (m_attachedProcessHandle == nullptr || !m_canReadWriteMemory)
    {
        kLogEvent setBreakpointNoPermissionEvent;
        warn << setBreakpointNoPermissionEvent
            << "[MemoryDock] setBreakpointEnabledByRow: 句柄不可写, row="
            << row
            << eol;
        return false;
    }

    BreakpointEntry& bpEntry = m_breakpointCache[static_cast<std::size_t>(row)];
    if (bpEntry.enabled == enabled)
    {
        kLogEvent setBreakpointNoopEvent;
        dbg << setBreakpointNoopEvent
            << "[MemoryDock] setBreakpointEnabledByRow: 状态未变, row="
            << row
            << ", enabled="
            << (enabled ? "true" : "false")
            << eol;
        return true;
    }

    const std::uint8_t targetByte = enabled ? 0xCC : bpEntry.originalByte;
    SIZE_T bytesWritten = 0;
    const BOOL writeOk = ::WriteProcessMemory(
        m_attachedProcessHandle,
        reinterpret_cast<LPVOID>(static_cast<std::uintptr_t>(bpEntry.address)),
        &targetByte,
        sizeof(targetByte),
        &bytesWritten);
    if (writeOk == FALSE || bytesWritten != sizeof(targetByte))
    {
        kLogEvent setBreakpointWriteFailEvent;
        err << setBreakpointWriteFailEvent
            << "[MemoryDock] setBreakpointEnabledByRow: 写入断点字节失败, row="
            << row
            << ", error="
            << ::GetLastError()
            << eol;
        return false;
    }

    bpEntry.enabled = enabled;
    kLogEvent setBreakpointFinishEvent;
    info << setBreakpointFinishEvent
        << "[MemoryDock] setBreakpointEnabledByRow: 切换成功, row="
        << row
        << ", enabled="
        << (enabled ? "true" : "false")
        << eol;
    return true;
}

void MemoryDock::rebuildBreakpointTable()
{
    // 重建断点表日志：记录当前断点数量。
    kLogEvent rebuildBreakpointEvent;
    dbg << rebuildBreakpointEvent
        << "[MemoryDock] rebuildBreakpointTable: 重建断点表, count="
        << m_breakpointCache.size()
        << eol;

    // 断点表直接由 m_breakpointCache 投影，避免 UI 与业务数据分叉。
    m_breakpointTable->setRowCount(static_cast<int>(m_breakpointCache.size()));
    for (int row = 0; row < static_cast<int>(m_breakpointCache.size()); ++row)
    {
        const BreakpointEntry& entry = m_breakpointCache[static_cast<std::size_t>(row)];
        m_breakpointTable->setItem(row, 0, new QTableWidgetItem(formatAddress(entry.address)));
        m_breakpointTable->setItem(row, 1, new QTableWidgetItem(
            QString("0x%1").arg(entry.originalByte, 2, 16, QChar('0')).toUpper()));
        m_breakpointTable->setItem(
            row,
            2,
            new QTableWidgetItem(ks::i18n::sourceText(
                entry.enabled ? QStringLiteral("启用") : QStringLiteral("禁用"))));
        m_breakpointTable->setItem(row, 3, new QTableWidgetItem(QString::number(entry.hitCount)));
        m_breakpointTable->setItem(row, 4, new QTableWidgetItem(entry.description));
    }
}

void MemoryDock::addBookmarkByAddress(const std::uint64_t address, const QString& noteText)
{
    // 添加书签入口日志：记录地址与备注。
    kLogEvent addBookmarkStartEvent;
    info << addBookmarkStartEvent
        << "[MemoryDock] addBookmarkByAddress: 请求添加书签, address="
        << formatAddress(address).toStdString()
        << ", note="
        << noteText.toStdString()
        << eol;

    // 已存在同地址书签时仅更新备注，不重复插入。
    for (BookmarkEntry& bookmark : m_bookmarkCache)
    {
        if (bookmark.address == address)
        {
            bookmark.noteText = noteText;
            kLogEvent addBookmarkUpdateEvent;
            dbg << addBookmarkUpdateEvent
                << "[MemoryDock] addBookmarkByAddress: 已存在地址，更新备注。"
                << eol;
            return;
        }
    }

    BookmarkEntry bookmark{};
    bookmark.id = ++m_nextBookmarkId;
    bookmark.address = address;
    bookmark.noteText = noteText;
    bookmark.addTimeText = QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss");

    // 初始值也由所选后端异步读取，不能先用 R3 值冒充其它后端的结果。
    m_bookmarkCache.push_back(std::move(bookmark));
    refreshBookmarkValues();
    kLogEvent addBookmarkFinishEvent;
    info << addBookmarkFinishEvent
        << "[MemoryDock] addBookmarkByAddress: 添加完成, totalBookmarkCount="
        << m_bookmarkCache.size()
        << eol;
}

void MemoryDock::rebuildBookmarkTable()
{
    if (m_bookmarkTable == nullptr) return;
    const QPointer<MemoryDock> safeThis(this);
    if (ks::ui::DeferTableUiCommitIfContextMenuOpen(
        this, QStringLiteral("memory-bookmark-table"), { m_bookmarkTable },
        [safeThis]() { if (!safeThis.isNull()) safeThis->rebuildBookmarkTable(); }))
    {
        return;
    }
    // 重建书签表日志：记录当前书签数量。
    kLogEvent rebuildBookmarkEvent;
    dbg << rebuildBookmarkEvent
        << "[MemoryDock] rebuildBookmarkTable: 重建书签表, count="
        << m_bookmarkCache.size()
        << eol;

    // 书签表每次全量重建，逻辑清晰且数量通常不大，维护成本最低。
    const QTableWidgetItem* const selectedAddress = m_bookmarkTable->item(m_bookmarkTable->currentRow(), 0);
    const std::uint64_t selectedId = selectedAddress != nullptr
        ? selectedAddress->data(Qt::UserRole).toULongLong() : 0;
    const bool sortingEnabled = m_bookmarkTable->isSortingEnabled();
    m_bookmarkTable->setSortingEnabled(false);
    m_bookmarkTable->setRowCount(static_cast<int>(m_bookmarkCache.size()));
    for (int row = 0; row < static_cast<int>(m_bookmarkCache.size()); ++row)
    {
        const BookmarkEntry& bookmark = m_bookmarkCache[static_cast<std::size_t>(row)];
        auto* const addressItem = new QTableWidgetItem(formatAddress(bookmark.address));
        addressItem->setData(Qt::UserRole, static_cast<qulonglong>(bookmark.id));
        m_bookmarkTable->setItem(row, 0, addressItem);

        // 书签“当前值”默认按十六进制字节串展示，通用于未知变量类型。
        QString valueText;
        switch (bookmark.valueState)
        {
        case BookmarkValueState::Ready:
            valueText = bytesToDisplayString(bookmark.lastValueBytes, SearchValueType::ByteArray);
            if (!bookmark.readDetail.isEmpty())
                valueText += ks::i18n::sourceText(QStringLiteral("（后端告警）"));
            break;
        case BookmarkValueState::Failed:
            valueText = ks::i18n::sourceText(QStringLiteral("读取失败"));
            break;
        case BookmarkValueState::Partial:
            valueText = ks::i18n::sourceText(QStringLiteral("读取不完整"));
            break;
        case BookmarkValueState::NoProcess:
            valueText = ks::i18n::sourceText(QStringLiteral("未附加进程"));
            break;
        default:
            valueText = ks::i18n::sourceText(QStringLiteral("等待刷新"));
            break;
        }
        if (bookmark.scratchDirty)
            valueText += ks::i18n::sourceText(QStringLiteral("（暂存扇区未还原）"));
        auto* const valueItem = new QTableWidgetItem(valueText);
        valueItem->setToolTip(ks::i18n::sourceText(QStringLiteral(
            "后端：%1；PID：%2；读取时间：%3\n%4"))
            .arg(ks::i18n::sourceText(ksword::memory_backend::backendDisplayName(currentBookmarkBackend())))
            .arg(m_attachedPid).arg(bookmark.readTimeText)
            .arg(ks::i18n::sourceText(bookmark.readDetail)));
        m_bookmarkTable->setItem(row, 1, valueItem);
        m_bookmarkTable->setItem(row, 2, new QTableWidgetItem(bookmark.noteText));
        m_bookmarkTable->setItem(row, 3, new QTableWidgetItem(bookmark.addTimeText));
    }
    m_bookmarkTable->setSortingEnabled(sortingEnabled);
    for (int row = 0; row < m_bookmarkTable->rowCount(); ++row)
    {
        if (m_bookmarkTable->item(row, 0)->data(Qt::UserRole).toULongLong() == selectedId)
        {
            m_bookmarkTable->setCurrentCell(row, 0);
            break;
        }
    }
}

void MemoryDock::refreshBookmarkValues()
{
    using namespace ksword::memory_backend;
    const QPointer<MemoryDock> safeThis(this);
    const std::uint64_t attachmentGeneration = m_processAttachmentGeneration.load();
    const std::uint32_t targetPid = m_attachedPid;
    const MemoryAccessBackend backend = currentBookmarkBackend();
    const std::uint64_t ddmaGeneration = backend == MemoryAccessBackend::Ddma
        ? ddmaSessionGeneration() : 0;
    const bool contextChanged = m_bookmarkContextGeneration != attachmentGeneration
        || m_bookmarkContextPid != targetPid || m_bookmarkContextBackend != backend
        || m_bookmarkContextDdmaGeneration != ddmaGeneration;

    // 先使缓存失效，再等待旧任务或菜单关闭；旧值不能跨进程/后端继续有效。
    if (contextChanged || targetPid == 0)
    {
        ++m_bookmarkContextTicket;
        m_bookmarkContextGeneration = attachmentGeneration;
        m_bookmarkContextPid = targetPid;
        m_bookmarkContextBackend = backend;
        m_bookmarkContextDdmaGeneration = ddmaGeneration;
        for (BookmarkEntry& bookmark : m_bookmarkCache)
        {
            bookmark.lastValueBytes.clear();
            bookmark.valueState = targetPid == 0
                ? BookmarkValueState::NoProcess : BookmarkValueState::Pending;
            bookmark.readDetail.clear();
            bookmark.readTimeText.clear();
            bookmark.scratchDirty = false;
        }
        rebuildBookmarkTable();
    }
    if (targetPid == 0 || m_bookmarkCache.empty())
    {
        m_bookmarkRefreshPending = false;
        return;
    }
    if (backend == MemoryAccessBackend::Ddma && m_bookmarkDdmaReadBlocked
        && m_bookmarkDdmaFaultGeneration == ddmaGeneration)
    {
        for (BookmarkEntry& bookmark : m_bookmarkCache)
        {
            bookmark.lastValueBytes.clear();
            bookmark.valueState = BookmarkValueState::Failed;
            bookmark.readDetail = QStringLiteral(
                "当前 DDMA 会话的书签读取已停止：暂存扇区未能还原，请检查并重新配置会话。");
            bookmark.scratchDirty = true;
        }
        m_bookmarkRefreshPending = false;
        rebuildBookmarkTable();
        return;
    }
    if (m_bookmarkRefreshInProgress)
    {
        m_bookmarkRefreshPending = true;
        return;
    }
    m_bookmarkRefreshInProgress = true;
    m_bookmarkRefreshPending = false;
    const DdmaSession session = currentDdmaSession();
    const std::vector<BookmarkEntry> requests = m_bookmarkCache;
    const std::uint64_t contextTicket = m_bookmarkContextTicket;

    // Worker 只持有按值上下文，不使用 UI 或可被分离关闭的进程句柄。
    QThreadPool::globalInstance()->start([safeThis, attachmentGeneration, targetPid,
        backend, ddmaGeneration, session, requests, contextTicket]()
    {
        struct BookmarkReadResult
        {
            std::uint64_t id;
            AccessOutcome outcome;
            QString readTimeText;
        };
        std::vector<BookmarkReadResult> results;
        results.reserve(requests.size());
        bool stopForDirtyScratch = false;
        for (const BookmarkEntry& request : requests)
        {
            AccessOutcome outcome;
            if (stopForDirtyScratch)
                outcome.failureText = QStringLiteral("暂存扇区未能还原，本轮后续书签读取已停止。");
            else
                outcome = readVirtual(backend, session, targetPid, request.address, 8);
            stopForDirtyScratch = stopForDirtyScratch
                || (backend == MemoryAccessBackend::Ddma && outcome.scratchDirty);
            results.push_back({ request.id, std::move(outcome),
                QDateTime::currentDateTime().toString("yyyy-MM-dd HH:mm:ss") });
        }

        QMetaObject::invokeMethod(qApp, [safeThis, attachmentGeneration, targetPid,
            backend, ddmaGeneration, contextTicket, session, results = std::move(results)]()
        {
            // 磁盘还原故障与书签是否仍存在无关，不能随过期内存结果一起丢弃。
            const bool dirtyScratch = backend == MemoryAccessBackend::Ddma
                && std::any_of(results.begin(), results.end(),
                    [](const BookmarkReadResult& result) { return result.outcome.scratchDirty; });
            if (dirtyScratch && (safeThis.isNull() || !safeThis->m_bookmarkDdmaReadBlocked
                || safeThis->m_bookmarkDdmaFaultGeneration != ddmaGeneration))
            {
                if (!safeThis.isNull())
                {
                    safeThis->m_bookmarkDdmaReadBlocked = true;
                    safeThis->m_bookmarkDdmaFaultGeneration = ddmaGeneration;
                }
                QMessageBox::critical(safeThis.data(),
                    ks::i18n::sourceText(QStringLiteral("DDMA 书签读取告警")),
                    ks::i18n::sourceText(QStringLiteral(
                        "DDMA 书签读取后未能还原磁盘 %1 的暂存扇区（LBA %2）。已停止此会话的书签读取，请检查暂存区并重新配置 DDMA 会话。"))
                        .arg(session.diskIndex).arg(static_cast<qulonglong>(session.scratchLba)));
            }
            if (safeThis.isNull()) return;
            const auto commit = [safeThis, attachmentGeneration, targetPid,
                backend, ddmaGeneration, contextTicket, dirtyScratch, results]()
            {
                if (safeThis.isNull()) return;
                MemoryDock* const dock = safeThis.data();
                dock->m_bookmarkRefreshInProgress = false;
                // 菜单可能延迟提交，提交这一刻也必须复核上下文。
                if (contextTicket != dock->m_bookmarkContextTicket
                    || attachmentGeneration != dock->m_processAttachmentGeneration.load()
                    || targetPid != dock->m_attachedPid || backend != dock->currentBookmarkBackend()
                    || (backend == MemoryAccessBackend::Ddma
                        && ddmaGeneration != ddmaSessionGeneration()))
                {
                    dock->refreshBookmarkValues();
                    return;
                }
                for (const BookmarkReadResult& result : results)
                {
                    const auto found = std::find_if(dock->m_bookmarkCache.begin(), dock->m_bookmarkCache.end(),
                        [&result](const BookmarkEntry& bookmark) { return bookmark.id == result.id; });
                    if (found == dock->m_bookmarkCache.end()) continue;
                    BookmarkEntry& bookmark = *found;
                    const AccessOutcome& outcome = result.outcome;
                    const bool complete = outcome.ok && !outcome.partial
                        && outcome.bytesDone == 8 && outcome.data.size() == 8;
                    bookmark.lastValueBytes = complete ? outcome.data : QByteArray();
                    bookmark.valueState = complete ? BookmarkValueState::Ready
                        : (outcome.partial || outcome.bytesDone != 0 || !outcome.data.isEmpty()
                            ? BookmarkValueState::Partial : BookmarkValueState::Failed);
                    bookmark.readDetail = outcome.failureText;
                    if (!complete && bookmark.valueState == BookmarkValueState::Partial)
                    {
                        bookmark.readDetail = ks::i18n::sourceText(QStringLiteral(
                            "读取不完整：请求 8 字节，收到 %1 字节。%2"))
                            .arg(outcome.data.size()).arg(ks::i18n::sourceText(outcome.failureText));
                    }
                    bookmark.readTimeText = result.readTimeText;
                    bookmark.scratchDirty = outcome.scratchDirty;
                }
                dock->rebuildBookmarkTable();
                if (dock->m_bookmarkRefreshPending || dirtyScratch) dock->refreshBookmarkValues();
            };
            if (!ks::ui::DeferTableUiCommitIfContextMenuOpen(
                safeThis.data(), QStringLiteral("memory-bookmark-read-commit"),
                { safeThis->m_bookmarkTable }, commit)) commit();
        }, Qt::QueuedConnection);
    });
}

void MemoryDock::updateStatusBarText()
{
    // 状态栏刷新日志：记录当前 PID 与权限状态。
    kLogEvent statusUpdateEvent;
    dbg << statusUpdateEvent
        << "[MemoryDock] updateStatusBarText: attachedPid="
        << m_attachedPid
        << ", canReadWrite="
        << (m_canReadWriteMemory ? "true" : "false")
        << eol;

    // 状态栏由三段组成：进程名、PID、读写状态，任何状态变化都统一经此函数刷新。
    if (m_attachedPid == 0 || m_attachedProcessHandle == nullptr)
    {
        m_statusProcessLabel->setText("进程: 未附加");
        m_statusPidLabel->setText("PID: -");
        m_statusMemoryIoLabel->setText("内存读写: 未就绪");
        if (m_dockHeaderStatusLabel != nullptr)
        {
            m_dockHeaderStatusLabel->setText("未附加进程，请先选择目标并点击“附加”。");
        }
        // 附加状态变了，语义色要跟着回到“未附加”的次要色。
        applyMemoryDockSemanticStyles();
        return;
    }

    m_statusProcessLabel->setText(QString("进程: %1").arg(m_attachedProcessName));
    m_statusPidLabel->setText(QString("PID: %1").arg(m_attachedPid));
    m_statusMemoryIoLabel->setText(
        QString("内存读写: %1").arg(m_canReadWriteMemory ? "可读可写" : "只读"));
    if (m_dockHeaderStatusLabel != nullptr)
    {
        m_dockHeaderStatusLabel->setText(
            QString("已附加 %1 (PID %2)，内存%3。")
                .arg(m_attachedProcessName)
                .arg(m_attachedPid)
                .arg(m_canReadWriteMemory ? "可读可写" : "只读"));
    }
    applyMemoryDockSemanticStyles();
}

bool MemoryDock::parseAddressText(const QString& text, std::uint64_t& valueOut)
{
    // 地址解析日志：保留输入文本用于定位格式问题。
    kLogEvent parseAddressEvent;
    dbg << parseAddressEvent
        << "[MemoryDock] parseAddressText: text="
        << text.trimmed().toStdString()
        << eol;

    // 地址的无前缀默认进制是**十六进制**，与下面的通用数值解析不是一套规则。
    // 原先两者共用一个"先试十进制、失败再试十六进制"的解析器，而那条十六进制
    // 回退只对含 a–f 的串生效：纯数字串的十进制解析永远成立。于是在这个所有
    // 地址都以 0x 回显的界面里，输入 1233 会跳到十进制 1233（= 0x4D1），
    // 不报错、不提示，只是读到了别处。
    const auto parsed = ksword::evidence::ParseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::Hexadecimal);
    if (!parsed.ok)
    {
        return false;
    }
    valueOut = parsed.value;
    return true;
}

bool MemoryDock::parseUnsignedNumber(const QString& text, std::uint64_t& valueOut)
{
    // 这里是"数量"语义（搜索的字节值、长度等），无前缀按十进制——数量本来就是
    // 按十进制念的，不能跟着地址一起改。0x 前缀仍然恒为十六进制。
    const auto parsed = ksword::evidence::ParseNumericText(
        text.trimmed().toStdString(),
        ksword::evidence::NumericTextDefaultRadix::Decimal);
    if (!parsed.ok)
    {
        return false;
    }
    valueOut = parsed.value;
    return true;
}

QString MemoryDock::formatAddress(const std::uint64_t address)
{
    // 统一输出 16 位十六进制，便于 32/64 位地址在表格中对齐阅读。
    const QString hexText = QString("%1").arg(
        static_cast<qulonglong>(address),
        16,
        16,
        QChar('0')).toUpper();
    return QString("0x%1").arg(hexText);
}

QString MemoryDock::formatSize(const std::uint64_t sizeBytes)
{
    // 字节数可读化显示：B / KB / MB / GB 自动切换，保留两位小数。
    constexpr double kKB = 1024.0;
    constexpr double kMB = 1024.0 * 1024.0;
    constexpr double kGB = 1024.0 * 1024.0 * 1024.0;

    const double sizeValue = static_cast<double>(sizeBytes);
    if (sizeValue >= kGB)
    {
        return QString("%1 GB").arg(sizeValue / kGB, 0, 'f', 2);
    }
    if (sizeValue >= kMB)
    {
        return QString("%1 MB").arg(sizeValue / kMB, 0, 'f', 2);
    }
    if (sizeValue >= kKB)
    {
        return QString("%1 KB").arg(sizeValue / kKB, 0, 'f', 2);
    }
    return QString("%1 B").arg(sizeBytes);
}

QString MemoryDock::protectToText(const std::uint32_t protect)
{
    // PAGE_* 主值仅保留低 8 位；高位是 PAGE_GUARD/NOCACHE 等修饰位。
    const std::uint32_t baseProtect = protect & 0xFF;
    QString baseText;
    switch (baseProtect)
    {
    case PAGE_NOACCESS:          baseText = "---"; break;
    case PAGE_READONLY:          baseText = "R--"; break;
    case PAGE_READWRITE:         baseText = "RW-"; break;
    case PAGE_WRITECOPY:         baseText = "RC-"; break;
    case PAGE_EXECUTE:           baseText = "--X"; break;
    case PAGE_EXECUTE_READ:      baseText = "R-X"; break;
    case PAGE_EXECUTE_READWRITE: baseText = "RWX"; break;
    case PAGE_EXECUTE_WRITECOPY: baseText = "RCX"; break;
    default:                     baseText = "UNK"; break;
    }

    // 叠加修饰标记，帮助用户识别 Guard/NoCache/WriteCombine 特性。
    if ((protect & PAGE_GUARD) != 0)
    {
        baseText += "|G";
    }
    if ((protect & PAGE_NOCACHE) != 0)
    {
        baseText += "|NC";
    }
    if ((protect & PAGE_WRITECOMBINE) != 0)
    {
        baseText += "|WC";
    }

    return baseText;
}

QString MemoryDock::stateToText(const std::uint32_t state)
{
    switch (state)
    {
    case MEM_COMMIT:  return "MEM_COMMIT";
    case MEM_RESERVE: return "MEM_RESERVE";
    case MEM_FREE:    return "MEM_FREE";
    default:          return QString("UNKNOWN(0x%1)").arg(state, 0, 16);
    }
}

QString MemoryDock::typeToText(const std::uint32_t type)
{
    switch (type)
    {
    case MEM_IMAGE:   return "IMAGE";
    case MEM_MAPPED:  return "MAPPED";
    case MEM_PRIVATE: return "PRIVATE";
    case 0:           return "-";
    default:          return QString("UNKNOWN(0x%1)").arg(type, 0, 16);
    }
}

QString MemoryDock::bytesToDisplayString(const QByteArray& bytes, const SearchValueType valueType)
{
    // 空字节统一显示短横线，避免表格出现空白造成歧义。
    if (bytes.isEmpty())
    {
        return "-";
    }

    switch (valueType)
    {
    case SearchValueType::Byte:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::uint8_t))) return "-";
        std::uint8_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString("%1 (0x%2)")
            .arg(value)
            .arg(value, 2, 16, QChar('0')).toUpper();
    }
    case SearchValueType::Int16:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int16_t))) return "-";
        std::int16_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::Int32:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int32_t))) return "-";
        std::int32_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::Int64:
    {
        if (bytes.size() < static_cast<int>(sizeof(std::int64_t))) return "-";
        std::int64_t value = 0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value);
    }
    case SearchValueType::Float32:
    {
        if (bytes.size() < static_cast<int>(sizeof(float))) return "-";
        float value = 0.0f;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value, 'f', 6);
    }
    case SearchValueType::Float64:
    {
        if (bytes.size() < static_cast<int>(sizeof(double))) return "-";
        double value = 0.0;
        std::memcpy(&value, bytes.constData(), sizeof(value));
        return QString::number(value, 'f', 8);
    }
    case SearchValueType::StringAscii:
    {
        return QString::fromLatin1(bytes);
    }
    case SearchValueType::StringUnicode:
    {
        // UTF-16 字节长度需为偶数，不足时截断最后 1 字节防止越界。
        const int alignedLength = bytes.size() - (bytes.size() % 2);
        if (alignedLength <= 0)
        {
            return "-";
        }
        return QString::fromUtf16(
            reinterpret_cast<const char16_t*>(bytes.constData()),
            alignedLength / 2);
    }
    case SearchValueType::ByteArray:
    default:
    {
        // 默认按十六进制字节串展示，兼容未知类型与书签显示。
        QStringList parts;
        parts.reserve(bytes.size());
        for (int index = 0; index < bytes.size(); ++index)
        {
            const auto byteValue = static_cast<unsigned char>(bytes.at(index));
            parts.push_back(QString("%1").arg(byteValue, 2, 16, QChar('0')).toUpper());
        }
        return parts.join(' ');
    }
    }
}
