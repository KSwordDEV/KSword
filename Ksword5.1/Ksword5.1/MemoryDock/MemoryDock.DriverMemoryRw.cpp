#include "MemoryDock.h"
#include "MemoryDock.Internal.h"
#include "../SettingsDock/AppearanceSettings.h"

#include "../ArkDriverClient/ArkDriverClient.h"
#include "../UI/HexEditorWidget.h"

#include <QByteArray>
#include <QComboBox>
#include <QFileInfo>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QVariant>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

namespace
{
    // DriverNavigationIdentityLease：读取前持有进程对象，读取后核验同一对象仍存活。
    // 输入 pid：本次用户态 VA 读取的原目标；缺权限只禁用导航，不阻止 R0 证据读取。
    class DriverNavigationIdentityLease final
    {
    public:
        explicit DriverNavigationIdentityLease(std::uint32_t pid) : m_pid(pid)
        {
            if (m_pid != 0)
            {
                m_process = ::OpenProcess(
                    PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, FALSE, m_pid);
                m_created = observeCreation();
            }
        }
        ~DriverNavigationIdentityLease()
        {
            if (m_process != nullptr)
            {
                ::CloseHandle(m_process);
            }
        }
        DriverNavigationIdentityLease(const DriverNavigationIdentityLease&) = delete;
        DriverNavigationIdentityLease& operator=(const DriverNavigationIdentityLease&) = delete;

        // verifiedCreation：返回跨本次读取核验的原创建时间；退出或身份变化返回零。
        std::uint64_t verifiedCreation() const
        {
            const std::uint64_t current = observeCreation(); // 同一持有对象的读取后观察。
            return m_created != 0 && current == m_created ? m_created : 0;
        }

    private:
        // observeCreation：只查持有句柄，不按 PID 重开新对象，不补授其他进程的身份。
        std::uint64_t observeCreation() const
        {
            FILETIME created{}, exited{}, kernel{}, user{}; // 进程时间字段，仅使用创建时间。
            if (m_process == nullptr || ::GetProcessId(m_process) != m_pid
                || ::WaitForSingleObject(m_process, 0) != WAIT_TIMEOUT
                || !::GetProcessTimes(m_process, &created, &exited, &kernel, &user))
            {
                return 0;
            }
            return (static_cast<std::uint64_t>(created.dwHighDateTime) << 32) | created.dwLowDateTime;
        }

        std::uint32_t m_pid = 0; // 读取请求指定的 PID。
        HANDLE m_process = nullptr; // 从读取前到读取后的对象持有见证，析构时释放。
        std::uint64_t m_created = 0; // 读取前核验的创建时间；零表示没有可靠见证。
    };

    QString driverMemoryReadStatusText(const std::uint32_t readStatus)
    {
        // 输入：驱动返回的 KSWORD_ARK_MEMORY_READ_STATUS_* 枚举值。
        // 处理：转换成 UI 可直接显示的中文诊断，避免用户只看到数字状态。
        // 返回：状态说明字符串；未知枚举保留原值，方便定位协议不匹配。
        switch (readStatus)
        {
        case KSWORD_ARK_MEMORY_READ_STATUS_OK:
            return QStringLiteral("读取成功");
        case KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY:
            return QStringLiteral("部分读取成功");
        case KSWORD_ARK_MEMORY_READ_STATUS_PROCESS_LOOKUP_FAILED:
            return QStringLiteral("目标进程查找失败");
        case KSWORD_ARK_MEMORY_READ_STATUS_COPY_FAILED:
            return QStringLiteral("内存复制失败");
        case KSWORD_ARK_MEMORY_READ_STATUS_RANGE_REJECTED:
            return QStringLiteral("地址范围被拒绝");
        case KSWORD_ARK_MEMORY_READ_STATUS_BUFFER_TOO_SMALL:
            return QStringLiteral("响应缓冲区不足");
        case KSWORD_ARK_MEMORY_READ_STATUS_ZERO_FILLED:
            return QStringLiteral("目标范围不可读，已被驱动补零");
        case KSWORD_ARK_MEMORY_READ_STATUS_UNAVAILABLE:
        default:
            return QStringLiteral("未知读取状态(%1)").arg(readStatus);
        }
    }

    QString driverMemoryNtStatusText(const long status)
    {
        // 输入：驱动透传的 NTSTATUS。
        // 处理：固定按 8 位十六进制展示，便于和内核日志/WinDbg 对齐。
        // 返回：形如 0xC0000005 的字符串。
        return QStringLiteral("0x%1")
            .arg(static_cast<unsigned long>(status), 8, 16, QChar('0'))
            .toUpper();
    }

    QString driverMemoryIoMessageText(const std::string& messageText)
    {
        // 输入：ArkDriverClient 返回的原始 io.message。
        // 处理：将 DeviceIoControl/unsupported/空消息等底层文本转换为用户可读说明。
        // 返回：用于状态栏、弹窗和失败详情的中文文本。
        if (messageText.empty())
        {
            return QStringLiteral("无额外驱动消息");
        }

        const QString rawText = QString::fromStdString(messageText).trimmed();
        if (rawText.isEmpty())
        {
            return QStringLiteral("无额外驱动消息");
        }
        if (rawText.contains(QStringLiteral("DeviceIoControl"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动接口调用失败或当前驱动版本不支持该内存读写入口");
        }
        if (rawText.contains(QStringLiteral("unsupported"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("not implemented"), Qt::CaseInsensitive))
        {
            return QStringLiteral("当前驱动版本尚未提供该内存读写入口");
        }
        if (rawText.contains(QStringLiteral("too small"), Qt::CaseInsensitive) ||
            rawText.contains(QStringLiteral("invalid"), Qt::CaseInsensitive))
        {
            return QStringLiteral("驱动返回数据格式不完整，未更新当前内存快照");
        }
        return rawText;
    }

    bool driverMemoryReadStatusHasUsableBytes(const std::uint32_t readStatus)
    {
        // 输入：驱动读取状态。
        // 处理：只有完整读取或部分读取才允许刷新 Hex 缓存；全补零不再伪装成成功。
        // 返回：true 表示 response->data 可作为真实读取结果展示。
        return readStatus == KSWORD_ARK_MEMORY_READ_STATUS_OK ||
            readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY;
    }

    bool driverMemoryAddressLooksKernelVa(const std::uint64_t address)
    {
        // 输入：用户最终请求的虚拟地址。
        // 处理：Windows x64 内核地址通常位于 canonical high-half；这里仅用于
        // R3 自动选择 IOCTL flag，R0 仍会再次校验地址范围。
        // 返回：true 表示应按内核虚拟地址读取，不再按目标进程用户 VA 解释。
        return address >= 0xFFFF000000000000ULL;
    }
}

// ============================================================
// MemoryDock.DriverMemoryRw.cpp
// 作用：
// - 负责“驱动内存读写”页的 R0 读取、R3 缓存编辑和差异写入；
// - 作为独立编译单元维护，避免新增功能继续依赖聚合包含。
// ============================================================
void MemoryDock::updateDriverMemoryBaseComboFromProcessCache()
{
    // 控件未初始化时直接返回；构造早期和析构后期都可能走到这里。
    if (m_driverMemoryBaseCombo == nullptr)
    {
        return;
    }

    // 内核模块异步回填也会重建此模型；弹层生命周期结束前只登记一次待刷新。
    if (isComboPopupVisible(m_driverMemoryBaseCombo))
    {
        m_driverMemoryBaseComboRefreshPending = true;
        return;
    }
    m_driverMemoryBaseComboRefreshPending = false;

    // 刷新前保存用户输入文本和当前 PID，避免进程列表刷新破坏正在编辑的基址。
    const QString previousText = m_driverMemoryBaseCombo->currentText().trimmed();
    const int previousIndex = m_driverMemoryBaseCombo->currentIndex();
    const std::uint32_t previousPid = (previousIndex >= 0) ?
        static_cast<std::uint32_t>(m_driverMemoryBaseCombo->itemData(previousIndex, Qt::UserRole).toUInt()) :
        0U;

    // 重建下拉期间阻断信号；该控件用于筛选和读取，不应在刷新进程列表时误触发读取。
    QSignalBlocker blocker(m_driverMemoryBaseCombo);
    m_driverMemoryBaseCombo->clear();
    m_driverMemoryBaseCombo->addItem("0", QVariant::fromValue(static_cast<uint>(0U)));
    m_driverMemoryBaseCombo->setItemData(0, QString(), Qt::UserRole + 1);

    // 下拉项保存 PID 与进程名；显示文本沿用顶部进程框格式，方便直接按 PID 识别。
    for (const ProcessEntry& entry : m_processCache)
    {
        if (entry.pid == 0U)
        {
            continue;
        }

        const QString itemText = QString("%1 [PID:%2]").arg(entry.processName).arg(entry.pid);
        m_driverMemoryBaseCombo->addItem(itemText, QVariant::fromValue(static_cast<uint>(entry.pid)));
        const int row = m_driverMemoryBaseCombo->count() - 1;
        m_driverMemoryBaseCombo->setItemData(row, entry.processName, Qt::UserRole + 1);
    }

    // 内核模块项排在进程项之后，显示文本直接写成可解析的“模块名+0”表达式，
    // 用户选中即可读取模块头，再手动改偏移就能定位模块内任意位置。
    if (!m_kernelModuleCache.empty())
    {
        m_driverMemoryBaseCombo->insertSeparator(m_driverMemoryBaseCombo->count());
        for (const KernelModuleEntry& kernelEntry : m_kernelModuleCache)
        {
            if (kernelEntry.moduleName.isEmpty() || kernelEntry.baseAddress == 0ULL)
            {
                continue;
            }

            const QString itemText = QString("%1+0").arg(kernelEntry.moduleName);
            // PID 位保持 0：进程匹配逻辑据此跳过内核模块项，不会把模块名误判成进程。
            m_driverMemoryBaseCombo->addItem(itemText, QVariant::fromValue(static_cast<uint>(0U)));
            const int kernelRow = m_driverMemoryBaseCombo->count() - 1;
            m_driverMemoryBaseCombo->setItemData(kernelRow, QString(), Qt::UserRole + 1);
            m_driverMemoryBaseCombo->setItemData(
                kernelRow,
                QVariant::fromValue(static_cast<qulonglong>(kernelEntry.baseAddress)),
                driverMemoryKernelModuleBaseRole());
            m_driverMemoryBaseCombo->setItemData(
                kernelRow,
                QString("内核模块 %1\n基址: 0x%2\n大小: %3 字节\n路径: %4")
                    .arg(kernelEntry.moduleName)
                    .arg(formatAddress(kernelEntry.baseAddress))
                    .arg(kernelEntry.sizeBytes)
                    .arg(kernelEntry.ntPath),
                Qt::ToolTipRole);
        }
    }

    // 优先按上一次明确选择的 PID 恢复；恢复失败再按输入文本恢复。
    int restoreIndex = -1;
    if (previousPid != 0U)
    {
        restoreIndex = m_driverMemoryBaseCombo->findData(
            QVariant::fromValue(static_cast<uint>(previousPid)),
            Qt::UserRole);
    }
    if (restoreIndex < 0 &&
        !previousText.isEmpty() &&
        previousText.compare("0", Qt::CaseInsensitive) != 0 &&
        !previousText.startsWith("0x", Qt::CaseInsensitive))
    {
        (void)findDriverMemoryProcessComboMatch(previousText, restoreIndex);
    }

    // 还原最终展示文本；0/空恢复默认基址，0x 文本保留为用户输入的数值基址。
    if (restoreIndex >= 0)
    {
        m_driverMemoryBaseCombo->setCurrentIndex(restoreIndex);
    }
    else if (previousText.isEmpty() || previousText.compare("0", Qt::CaseInsensitive) == 0)
    {
        m_driverMemoryBaseCombo->setCurrentIndex(0);
    }
    else
    {
        m_driverMemoryBaseCombo->setEditText(previousText);
    }
}

bool MemoryDock::findDriverMemoryProcessComboMatch(
    const QString& filterText,
    int& comboIndexOut) const
{
    // 输出索引默认无效，调用方据此判断是否需要提示用户重新选择。
    comboIndexOut = -1;
    if (m_driverMemoryBaseCombo == nullptr)
    {
        return false;
    }

    const QString needle = filterText.trimmed();
    if (needle.isEmpty())
    {
        return false;
    }

    // 第一轮做精确匹配：PID、进程名、完整显示文本都可直接命中。
    for (int index = 0; index < m_driverMemoryBaseCombo->count(); ++index)
    {
        const std::uint32_t pid = static_cast<std::uint32_t>(
            m_driverMemoryBaseCombo->itemData(index, Qt::UserRole).toUInt());
        if (pid == 0U)
        {
            continue;
        }

        const QString itemText = m_driverMemoryBaseCombo->itemText(index);
        const QString processName = m_driverMemoryBaseCombo->itemData(index, Qt::UserRole + 1).toString();
        const QString pidText = QString::number(pid);
        if (pidText.compare(needle, Qt::CaseInsensitive) == 0 ||
            processName.compare(needle, Qt::CaseInsensitive) == 0 ||
            itemText.compare(needle, Qt::CaseInsensitive) == 0)
        {
            comboIndexOut = index;
            return true;
        }
    }

    // 第二轮做模糊筛选：非 0x 输入会按进程名或下拉显示文本包含关系选中第一项。
    for (int index = 0; index < m_driverMemoryBaseCombo->count(); ++index)
    {
        const std::uint32_t pid = static_cast<std::uint32_t>(
            m_driverMemoryBaseCombo->itemData(index, Qt::UserRole).toUInt());
        if (pid == 0U)
        {
            continue;
        }

        const QString itemText = m_driverMemoryBaseCombo->itemText(index);
        const QString processName = m_driverMemoryBaseCombo->itemData(index, Qt::UserRole + 1).toString();
        if (itemText.contains(needle, Qt::CaseInsensitive) ||
            processName.contains(needle, Qt::CaseInsensitive))
        {
            comboIndexOut = index;
            return true;
        }
    }

    return false;
}

bool MemoryDock::resolveDriverMemoryModuleExpression(
    const QString& expressionText,
    std::uint64_t& resolvedBaseOut,
    QString& errorTextOut) const
{
    resolvedBaseOut = 0ULL;
    errorTextOut.clear();

    // 使用最后一个加号分隔模块与偏移，兼容模块路径中偶尔包含加号的情况。
    const QString trimmedExpression = expressionText.trimmed();
    const int plusIndex = trimmedExpression.lastIndexOf(QLatin1Char('+'));
    if (plusIndex <= 0 || plusIndex >= trimmedExpression.size() - 1)
    {
        errorTextOut = QStringLiteral(
            "模块偏移格式无效。请使用“模块名+十六进制偏移”，例如 client.dll+C125D9。");
        return false;
    }

    QString moduleToken = trimmedExpression.left(plusIndex).trimmed();
    QString offsetToken = trimmedExpression.mid(plusIndex + 1).trimmed();
    if (moduleToken.size() >= 2 &&
        ((moduleToken.startsWith(QLatin1Char('"')) && moduleToken.endsWith(QLatin1Char('"'))) ||
         (moduleToken.startsWith(QLatin1Char('\'')) && moduleToken.endsWith(QLatin1Char('\'')))))
    {
        moduleToken = moduleToken.mid(1, moduleToken.size() - 2).trimmed();
    }
    if (offsetToken.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
    {
        offsetToken.remove(0, 2);
    }

    // 模块偏移遵循调试器常用写法：无论是否带 0x，始终按十六进制解析。
    bool offsetOk = false;
    const qulonglong parsedOffset = offsetToken.toULongLong(&offsetOk, 16);
    if (moduleToken.isEmpty() || offsetToken.isEmpty() || !offsetOk)
    {
        errorTextOut = QStringLiteral(
            "模块偏移格式无效。偏移必须是十六进制数，例如 client.dll+C125D9 或 client.dll+0xC125D9。");
        return false;
    }

    const std::uint64_t moduleOffset = static_cast<std::uint64_t>(parsedOffset);

    // 内核虚拟内存来源下，模块名一律按内核模块解析，不去碰进程模块缓存。
    if (currentDriverMemorySourceMode() == DriverMemorySourceMode::KernelVirtual)
    {
        return resolveDriverMemoryKernelModuleExpression(
            moduleToken, moduleOffset, resolvedBaseOut, errorTextOut);
    }

    // 进程来源下若还没附加进程，直接回退到内核模块解析：
    // 这样用户不必先附加任何进程也能输入 CI.dll+1A2B 这类内核表达式。
    if (m_attachedPid == 0U)
    {
        QString kernelErrorText;
        if (resolveDriverMemoryKernelModuleExpression(
                moduleToken, moduleOffset, resolvedBaseOut, kernelErrorText))
        {
            return true;
        }
        errorTextOut = QStringLiteral(
            "解析模块偏移前请先附加目标进程；若要定位内核模块，请把“来源”切换为内核虚拟内存。（%1）")
            .arg(kernelErrorText);
        return false;
    }
    if (m_moduleRefreshInProgress.load())
    {
        errorTextOut = QStringLiteral("当前进程的模块列表仍在刷新，请等待刷新完成后重试。");
        return false;
    }
    if (m_moduleCache.empty())
    {
        errorTextOut = QStringLiteral("当前进程没有可用的模块缓存，请先在“进程与模块”页刷新模块。");
        return false;
    }

    QString normalizedInputPath = moduleToken;
    normalizedInputPath.replace(QLatin1Char('/'), QLatin1Char('\\'));
    const bool inputContainsPath = normalizedInputPath.contains(QLatin1Char('\\'));
    const QString inputFileName = QFileInfo(moduleToken).fileName();
    std::vector<const ModuleEntry*> matches;
    for (const ModuleEntry& entry : m_moduleCache)
    {
        QString normalizedModulePath = entry.fullPath;
        normalizedModulePath.replace(QLatin1Char('/'), QLatin1Char('\\'));
        const bool matched = inputContainsPath
            ? normalizedModulePath.compare(normalizedInputPath, Qt::CaseInsensitive) == 0
            : entry.moduleName.compare(inputFileName, Qt::CaseInsensitive) == 0;
        if (matched)
        {
            matches.push_back(&entry);
        }
    }

    if (matches.empty())
    {
        // 用户态模块没命中时再试一次内核模块：很多排查场景是在附加着某个进程时查内核符号。
        QString kernelErrorText;
        if (resolveDriverMemoryKernelModuleExpression(
                moduleToken, moduleOffset, resolvedBaseOut, kernelErrorText))
        {
            return true;
        }
        errorTextOut = QString("当前附加进程 PID=%1 与已加载内核模块中都未找到模块：%2。请刷新模块列表并确认模块名。")
            .arg(m_attachedPid)
            .arg(moduleToken);
        return false;
    }
    if (matches.size() > 1U)
    {
        errorTextOut = QString("模块名 %1 匹配到 %2 个模块，请输入模块完整路径以消除歧义。")
            .arg(moduleToken)
            .arg(static_cast<qulonglong>(matches.size()));
        return false;
    }

    const ModuleEntry& matchedModule = *matches.front();
    if (matchedModule.baseAddress > (std::numeric_limits<std::uint64_t>::max)() - moduleOffset)
    {
        errorTextOut = QStringLiteral("模块基址与偏移相加发生地址回绕，已拒绝。");
        return false;
    }

    resolvedBaseOut = matchedModule.baseAddress + moduleOffset;
    return true;
}

bool MemoryDock::resolveDriverMemoryRequestFromUi(
    std::uint32_t& targetPidOut,
    QString& targetNameOut,
    std::uint64_t& offsetBaseOut,
    std::uint64_t& centerAddressOut,
    std::uint64_t& effectiveCenterAddressOut,
    QString& errorTextOut)
{
    // 先清空输出，保证失败路径不会留下上一次解析结果。
    targetPidOut = 0U;
    targetNameOut.clear();
    offsetBaseOut = 0ULL;
    centerAddressOut = 0ULL;
    effectiveCenterAddressOut = 0ULL;
    errorTextOut.clear();

    // 偏移基址为空或 0 时表示不加基址；还支持数值基址、目标进程和模块+偏移。
    const QString baseText = (m_driverMemoryBaseCombo == nullptr) ?
        QStringLiteral("0") :
        m_driverMemoryBaseCombo->currentText().trimmed();
    bool moduleExpressionResolved = false;
    if (baseText.isEmpty() || baseText.compare("0", Qt::CaseInsensitive) == 0)
    {
        offsetBaseOut = 0ULL;
    }
    else if (baseText.startsWith("0x", Qt::CaseInsensitive))
    {
        if (!parseUnsignedNumber(baseText, offsetBaseOut))
        {
            errorTextOut = "偏移基址格式无效，应输入 0 或 0x 开头的十六进制地址。";
            return false;
        }
    }
    else if (baseText.contains(QLatin1Char('+')))
    {
        if (!resolveDriverMemoryModuleExpression(
            baseText,
            offsetBaseOut,
            errorTextOut))
        {
            return false;
        }

        targetPidOut = m_attachedPid;
        targetNameOut = m_attachedProcessName;
        moduleExpressionResolved = true;
    }
    else
    {
        // 非 0x 输入按进程筛选，命中后把下拉框切到真实进程项。
        int matchedIndex = -1;
        if (!findDriverMemoryProcessComboMatch(baseText, matchedIndex))
        {
            errorTextOut = QString("未找到匹配进程：%1。请输入 0、0x基址、模块名+偏移，或进程名/PID。").arg(baseText);
            return false;
        }

        QSignalBlocker blocker(m_driverMemoryBaseCombo);
        m_driverMemoryBaseCombo->setCurrentIndex(matchedIndex);
        targetPidOut = static_cast<std::uint32_t>(
            m_driverMemoryBaseCombo->itemData(matchedIndex, Qt::UserRole).toUInt());
        targetNameOut = m_driverMemoryBaseCombo->itemData(matchedIndex, Qt::UserRole + 1).toString();
        offsetBaseOut = 0ULL;
    }

    // 如果基址框没有显式选进程，则优先使用已附加 PID，再回退到顶部当前选择。
    if (targetPidOut == 0U && m_attachedPid != 0U)
    {
        targetPidOut = m_attachedPid;
        targetNameOut = m_attachedProcessName;
    }
    if (targetPidOut == 0U && m_processCombo != nullptr)
    {
        const int processIndex = m_processCombo->currentIndex();
        if (processIndex >= 0)
        {
            targetPidOut = static_cast<std::uint32_t>(
                m_processCombo->itemData(processIndex, Qt::UserRole).toUInt());
            targetNameOut = m_processCombo->itemData(processIndex, Qt::UserRole + 1).toString();
        }
    }
    // 模块表达式已经提供完整定位时允许中心地址留空，等价于额外偏移 0。
    const QString centerAddressText = (m_driverMemoryAddressEdit == nullptr)
        ? QString()
        : m_driverMemoryAddressEdit->text().trimmed();
    if (moduleExpressionResolved && centerAddressText.isEmpty())
    {
        centerAddressOut = 0ULL;
    }
    else if (!parseAddressText(centerAddressText, centerAddressOut))
    {
        errorTextOut = moduleExpressionResolved
            ? QStringLiteral("中心地址格式无效；可留空，或输入要叠加到模块偏移上的数值。")
            : QStringLiteral("中心地址格式无效。");
        return false;
    }
    if (centerAddressOut > (std::numeric_limits<std::uint64_t>::max)() - offsetBaseOut)
    {
        errorTextOut = "偏移基址与中心地址相加发生地址回绕，已拒绝。";
        return false;
    }

    effectiveCenterAddressOut = offsetBaseOut + centerAddressOut;
    if (driverMemoryAddressLooksKernelVa(effectiveCenterAddressOut))
    {
        targetPidOut = 0U;
        targetNameOut = QStringLiteral("Kernel VA");
        return true;
    }
    if (targetPidOut == 0U)
    {
        errorTextOut = "请选择有效目标进程；R0 读用户态 VA 需要 PID。若要读内核地址，请输入 0xFFFF... 高半区地址。";
        return false;
    }
    return true;
}

void MemoryDock::prepareDriverMemoryReadAtAddress(
    const std::uint64_t absoluteAddress,
    const std::uint64_t preferredBytes,
    const bool triggerRead)
{
    // 输入：来自内存区域/模块/搜索结果等已知有效来源的进程虚拟地址。
    // 处理：切到驱动读写页，填入绝对地址，并把读取窗口调整为从该地址向后读。
    // 返回：无返回值；可选立即触发 driverReadMemoryFromUi。
    if (m_tabWidget != nullptr && m_tabDriverMemoryRw != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_tabDriverMemoryRw);
    }
    if (m_driverMemoryBaseCombo != nullptr)
    {
        const int pidIndex = m_driverMemoryBaseCombo->findData(
            QVariant::fromValue(static_cast<uint>(m_attachedPid)),
            Qt::UserRole);
        if (pidIndex >= 0)
        {
            m_driverMemoryBaseCombo->setCurrentIndex(pidIndex);
        }
    }
    if (m_driverMemoryAddressEdit != nullptr)
    {
        m_driverMemoryAddressEdit->setText(formatAddress(absoluteAddress));
    }

    if (preferredBytes > 0ULL &&
        m_driverMemoryBeforeSpin != nullptr &&
        m_driverMemoryAfterSpin != nullptr)
    {
        const std::uint64_t cappedBytes = std::min<std::uint64_t>(
            preferredBytes,
            static_cast<std::uint64_t>(KSWORD_ARK_MEMORY_READ_MAX_BYTES));
        m_driverMemoryBeforeSpin->setValue(0);
        m_driverMemoryAfterSpin->setValue(static_cast<int>(cappedBytes));
    }

    if (m_driverMemoryRangeLabel != nullptr)
    {
        m_driverMemoryRangeLabel->setText(QStringLiteral("范围: 已填入 %1，准备 R0 读取。")
            .arg(formatAddress(absoluteAddress)));
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(QStringLiteral("已从内存区域填入有效地址；点击 R0读取，或等待自动读取。"));
    }

    if (triggerRead)
    {
        driverReadMemoryFromUi();
    }
}

void MemoryDock::driverReadMemoryFromUi()
{
    if (m_driverMemoryEditor->hasChanges())
    {
        if (QMessageBox::question(this, QStringLiteral("驱动内存读写"),
            QStringLiteral("当前缓存存在未应用的改动。是否丢弃改动并读取新快照？"),
            QMessageBox::Yes | QMessageBox::No, QMessageBox::No) != QMessageBox::Yes)
        {
            return;
        }
        m_driverMemoryEditor->discardChanges();
    }
    // 物理内存是一条完全独立的通道：不解析进程、模块与偏移基址，直接走物理读实现。
    if (currentDriverMemorySourceMode() == DriverMemorySourceMode::Physical)
    {
        driverReadPhysicalMemoryFromUi();
        return;
    }

    const QString baseInputText = (m_driverMemoryBaseCombo == nullptr)
        ? QString()
        : m_driverMemoryBaseCombo->currentText().trimmed();

    // 读取入口日志：记录当前附加 PID 和地址文本。
    kLogEvent readStartEvent;
    info << readStartEvent
        << "[MemoryDock] driverReadMemoryFromUi: 开始读取, attachedPid="
        << m_attachedPid
        << ", baseText="
        << baseInputText.toStdString()
        << ", text="
        << m_driverMemoryAddressEdit->text().trimmed().toStdString()
        << eol;

    // R0 内存读写接口需要 PID，不需要 R3 先 OpenProcess/Attach；这里解析独立目标。
    std::uint32_t targetPid = 0U;
    QString targetProcessName;
    std::uint64_t offsetBase = 0ULL;
    std::uint64_t centerAddressInput = 0ULL;
    std::uint64_t centerAddress = 0ULL;
    QString resolveErrorText;
    if (!resolveDriverMemoryRequestFromUi(
        targetPid,
        targetProcessName,
        offsetBase,
        centerAddressInput,
        centerAddress,
        resolveErrorText))
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(resolveErrorText);
        }
        QMessageBox::warning(this, "驱动内存读写", resolveErrorText);
        return;
    }

    // 计算读取范围：
    // - before/after 是中心地址左右两侧的字节预算；
    // - 使用半开区间 [baseAddress, endAddress)，避免旧逻辑多读 1 字节；
    // - 低地址下溢时把起点夹到 0，但仍会保留清晰诊断，避免看起来“按钮没反应”。
    const std::uint64_t beforeBytes =
        static_cast<std::uint64_t>(m_driverMemoryBeforeSpin->value());
    const std::uint64_t afterBytes =
        static_cast<std::uint64_t>(m_driverMemoryAfterSpin->value());
    const std::uint64_t baseAddress =
        (centerAddress >= beforeBytes) ? (centerAddress - beforeBytes) : 0ULL;
    const bool kernelAddressRead = driverMemoryAddressLooksKernelVa(centerAddress);
    if (afterBytes > (std::numeric_limits<std::uint64_t>::max)() - centerAddress)
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText("读取范围发生地址回绕，已拒绝。");
        }
        QMessageBox::warning(this, "驱动内存读写", "读取范围发生地址回绕。");
        return;
    }
    const std::uint64_t endAddress = centerAddress + afterBytes;
    if (endAddress <= baseAddress)
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText("读取范围为空或发生地址回绕，已拒绝。");
        }
        if (m_driverMemoryRangeLabel != nullptr)
        {
            m_driverMemoryRangeLabel->setText("范围: 读取请求无效");
        }
        QMessageBox::warning(this, "驱动内存读写", "读取范围为空或发生地址回绕。");
        return;
    }

    // totalBytes 是 R0 单次读取长度，受共享协议上限约束。
    const std::uint64_t totalBytes64 = endAddress - baseAddress;
    if (totalBytes64 == 0ULL || totalBytes64 > KSWORD_ARK_MEMORY_READ_MAX_BYTES)
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText("读取范围超过驱动单次请求上限。");
        }
        if (m_driverMemoryRangeLabel != nullptr)
        {
            m_driverMemoryRangeLabel->setText(QString("范围: %1 - %2 | 请求长度: %3 字节，超过上限")
                .arg(formatAddress(baseAddress))
                .arg(formatAddress(endAddress - 1ULL))
                .arg(totalBytes64));
        }
        QMessageBox::warning(this, "驱动内存读写", "读取范围超过驱动单次请求上限。");
        return;
    }

    // 调用 ArkDriverClient，Dock 不直接 DeviceIoControl。
    QString requestRangeText = QString("范围: %1 - %2 | 请求: %3 字节 | %4 | 中心: %5")
        .arg(formatAddress(baseAddress))
        .arg(formatAddress(endAddress - 1ULL))
        .arg(totalBytes64)
        .arg(kernelAddressRead
            ? QStringLiteral("内核地址")
            : QStringLiteral("PID: %1%2")
                .arg(targetPid)
                .arg(targetProcessName.isEmpty() ? QString() : QString(" (%1)").arg(targetProcessName)))
        .arg(formatAddress(centerAddress));
    if (baseInputText.contains(QLatin1Char('+')))
    {
        requestRangeText += QString(" | 模块定位: %1 -> %2")
            .arg(baseInputText)
            .arg(formatAddress(offsetBase));
    }
    if (m_driverMemoryRangeLabel != nullptr)
    {
        m_driverMemoryRangeLabel->setText(requestRangeText + QStringLiteral(" | R0读取中..."));
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText("正在通过 R0 读取内存...");
    }

    // R3 与 HVM 必须走用户选择的真实后端，不能静默使用标准 R0 代替。
    const auto selectedBackend = currentDriverMemoryBackend();
    // 导航身份在读取前冻结；R0-only 目标即使无法打开句柄，也继续沿原读取通路采集。
    const DriverNavigationIdentityLease navigationIdentity(
        !kernelAddressRead && selectedBackend != ksword::memory_backend::MemoryAccessBackend::Ddma
            ? targetPid : 0U);
    if (selectedBackend == ksword::memory_backend::MemoryAccessBackend::UserMode
        || selectedBackend == ksword::memory_backend::MemoryAccessBackend::Hvm)
    {
        const auto outcome = ksword::memory_backend::readVirtual(selectedBackend,
            currentDdmaSession(), kernelAddressRead ? 0U : targetPid,
            baseAddress, totalBytes64);
        if (!outcome.ok || outcome.data.isEmpty())
        {
            resetDriverMemoryRwState();
            m_driverMemoryStatusLabel->setText(outcome.failureText);
            QMessageBox::warning(this, QStringLiteral("驱动内存读写"), outcome.failureText);
            return;
        }
        m_driverMemoryBaseAddress = baseAddress;
        m_driverMemoryOffsetBase = offsetBase;
        m_driverMemoryCenterAddress = centerAddress;
        m_driverMemorySnapshotPid = kernelAddressRead ? 0U : targetPid;
        m_driverMemorySnapshotProcessCreateTime100ns = navigationIdentity.verifiedCreation();
        m_driverMemorySnapshotProcessName = targetProcessName;
        m_driverMemorySnapshotIsPhysical = false;
        m_driverMemoryOriginalBytes = outcome.data;
        m_driverMemoryEditedBytes = outcome.data;
        m_driverMemoryHasSnapshot = true;
        loadDriverMemoryEditorSnapshot();
        m_driverMemoryApplyButton->setEnabled(false);
        m_driverMemoryRangeLabel->setText(requestRangeText);
        m_driverMemoryStatusLabel->setText(QStringLiteral("%1 读取完成：%2 字节%3")
            .arg(ksword::memory_backend::backendDisplayName(selectedBackend))
            .arg(outcome.data.size())
            .arg(outcome.partial ? QStringLiteral("；部分内容不可读。") : QStringLiteral("。")));
        if (!outcome.failureText.isEmpty())
            m_driverMemoryStatusLabel->setText(m_driverMemoryStatusLabel->text()
                + QStringLiteral(" ") + outcome.failureText);
        return;
    }

    // DDMA 后端是一条完全不同的通路：逐页 VA → PA 翻译后走磁盘 DMA，
    // 响应模型也不是 VirtualMemoryReadResult，因此单独分支处理并直接返回，
    // 不去改动下面那段已经稳定的标准通道解析逻辑。
    if (currentDriverMemoryBackend() == ksword::memory_backend::MemoryAccessBackend::Ddma)
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(
                QStringLiteral("正在通过 DDMA 逐页翻译并读取内存..."));
        }
        const ksword::memory_backend::AccessOutcome ddmaOutcome =
            ksword::memory_backend::readVirtual(
                ksword::memory_backend::MemoryAccessBackend::Ddma,
                currentDdmaSession(),
                kernelAddressRead ? 0U : targetPid,
                baseAddress,
                totalBytes64);
        if (!ddmaOutcome.ok)
        {
            resetDriverMemoryRwState();
            if (m_driverMemoryRangeLabel != nullptr)
            {
                m_driverMemoryRangeLabel->setText(requestRangeText + QStringLiteral(" | DDMA失败"));
            }
            if (m_driverMemoryStatusLabel != nullptr)
            {
                m_driverMemoryStatusLabel->setText(
                    QStringLiteral("DDMA 读取失败：%1").arg(ddmaOutcome.failureText));
            }
            QMessageBox::warning(this, "驱动内存读写", ddmaOutcome.failureText);
            return;
        }

        m_driverMemoryBaseAddress = baseAddress;
        m_driverMemoryOffsetBase = offsetBase;
        m_driverMemoryCenterAddress = centerAddress;
        m_driverMemorySnapshotPid = kernelAddressRead ? 0U : targetPid;
        m_driverMemorySnapshotProcessCreateTime100ns = 0; // DDMA 字节不授权进程调试导航。
        m_driverMemorySnapshotProcessName = targetProcessName;
        m_driverMemoryOriginalBytes = ddmaOutcome.data;
        m_driverMemoryEditedBytes = m_driverMemoryOriginalBytes;
        m_driverMemoryHasSnapshot = true;
        // 虚拟地址通道读到的快照按虚拟地址写回，写回时再按后端选择通路。
        m_driverMemorySnapshotIsPhysical = false;

        loadDriverMemoryEditorSnapshot();

        m_driverMemoryApplyButton->setEnabled(false);
        if (m_driverMemoryRangeLabel != nullptr)
        {
            m_driverMemoryRangeLabel->setText(requestRangeText + QStringLiteral(" | DDMA读取完成"));
        }
        QString ddmaStatusText = QStringLiteral("DDMA 读取完成：返回 %1 字节。")
            .arg(m_driverMemoryEditedBytes.size());
        if (ddmaOutcome.partial)
        {
            ddmaStatusText += QStringLiteral(
                " 有页无法翻译成物理地址，这些页已按 00 填充。");
        }
        if (ddmaOutcome.scratchDirty)
        {
            ddmaStatusText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(ddmaStatusText);
        }
        return;
    }

    ksword::ark::DriverClient driverClient;
    const ksword::ark::VirtualMemoryReadResult readResult =
        driverClient.readVirtualMemory(
            targetPid,
            baseAddress,
            static_cast<std::uint32_t>(totalBytes64),
            KSWORD_ARK_MEMORY_READ_FLAG_ZERO_FILL_UNREADABLE |
            (kernelAddressRead ? KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS : 0UL));
    if (!readResult.io.ok)
    {
        resetDriverMemoryRwState();
        const QString readableIoMessage = driverMemoryIoMessageText(readResult.io.message);
        // privilegePromptHandled：记录 IOCTL 权限错误是否已由恢复提示处理。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
            this,
            QStringLiteral("R0读取进程内存"),
            readResult.io.win32Error);
        if (m_driverMemoryRangeLabel != nullptr)
        {
            m_driverMemoryRangeLabel->setText(requestRangeText + QStringLiteral(" | IOCTL失败"));
        }
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(QString("R0读取失败：%1").arg(readableIoMessage));
        }
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(
                this,
                "驱动内存读写",
                QString("R0读取失败：\n%1").arg(readableIoMessage));
        }
        return;
    }

    const QString readStatusText = driverMemoryReadStatusText(readResult.readStatus);
    const QString copyStatusText = driverMemoryNtStatusText(readResult.copyStatus);
    if (!driverMemoryReadStatusHasUsableBytes(readResult.readStatus))
    {
        // privilegePromptHandled：记录 NTSTATUS 权限错误是否已由恢复提示处理。
        const bool privilegePromptHandled = ks::ui::promptForPrivilegeNtStatus(
            this,
            QStringLiteral("R0读取进程内存"),
            static_cast<long>(readResult.copyStatus));
        const QString failureText = QString(
            "R0读取未取得可用字节：%1。\n\n"
            "目标=%2\n"
            "请求范围=%4 - %5\n"
            "请求长度=%6 字节\n"
            "copyStatus=%7\n\n"
            "提示：用户态 VA 请先在“内存区域”页选中 MEM_COMMIT 区域；内核 VA 请输入 0xFFFF... 高半区有效地址。")
            .arg(readStatusText)
            .arg(kernelAddressRead
                ? QStringLiteral("内核地址")
                : QStringLiteral("PID=%1%2")
                    .arg(targetPid)
                    .arg(targetProcessName.isEmpty() ? QString() : QString(" (%1)").arg(targetProcessName)))
            .arg(formatAddress(baseAddress))
            .arg(formatAddress(endAddress - 1ULL))
            .arg(totalBytes64)
            .arg(copyStatusText);

        resetDriverMemoryRwState();
        if (m_driverMemoryRangeLabel != nullptr)
        {
            m_driverMemoryRangeLabel->setText(requestRangeText + QStringLiteral(" | 未读到可用字节"));
        }
        if (m_driverMemoryStatusLabel != nullptr)
        {
            QString compactFailureText = failureText;
            compactFailureText.replace(QLatin1Char('\n'), QLatin1Char(' '));
            m_driverMemoryStatusLabel->setText(compactFailureText);
        }
        if (!privilegePromptHandled)
        {
            QMessageBox::warning(this, "驱动内存读写", failureText);
        }
        return;
    }

    // R0 按要求把不可读区域补 00，因此 UI 只要求数据长度和请求长度一致。
    if (readResult.data.empty())
    {
        const QString emptyResponseText = QString(
            "R0响应无数据：readStatus=%1(%2)，source=%3，fieldFlags=0x%4，bytesRead=%5，bytesReturned=%6，copyStatus=%7，io=%8")
            .arg(readResult.readStatus)
            .arg(readStatusText)
            .arg(readResult.source)
            .arg(readResult.fieldFlags, 8, 16, QChar('0'))
            .arg(readResult.bytesRead)
            .arg(readResult.io.bytesReturned)
            .arg(copyStatusText)
            .arg(driverMemoryIoMessageText(readResult.io.message));
        resetDriverMemoryRwState();
        if (m_driverMemoryRangeLabel != nullptr)
        {
            m_driverMemoryRangeLabel->setText(requestRangeText + QStringLiteral(" | 响应无数据，详见状态栏"));
        }
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(emptyResponseText);
        }
        QMessageBox::warning(this, "驱动内存读写", emptyResponseText);
        return;
    }

    // 缓存原始备份与编辑副本；后续差异只和 original 比对。
    m_driverMemoryBaseAddress = readResult.requestedBaseAddress;
    m_driverMemoryOffsetBase = offsetBase;
    m_driverMemoryCenterAddress = centerAddress;
    m_driverMemorySnapshotPid = targetPid;
    m_driverMemorySnapshotProcessCreateTime100ns = navigationIdentity.verifiedCreation();
    m_driverMemorySnapshotProcessName = targetProcessName;
    m_driverMemoryOriginalBytes = QByteArray(
        reinterpret_cast<const char*>(readResult.data.data()),
        static_cast<int>(readResult.data.size()));
    m_driverMemoryEditedBytes = m_driverMemoryOriginalBytes;
    m_driverMemoryHasSnapshot = true;
    // 虚拟内存通道读到的快照永远不是物理快照，写回时据此选择通道。
    m_driverMemorySnapshotIsPhysical = false;

    loadDriverMemoryEditorSnapshot();

    // 刷新状态标签和按钮状态。
    m_driverMemoryApplyButton->setEnabled(false);
    m_driverMemoryApplyButton->setToolTip(kernelAddressRead
        ? QStringLiteral("将差异写回内核虚拟地址；需要二次确认和 Force。")
        : QString());
    m_driverMemoryRangeLabel->setText(
        QString("范围: %1 - %2 | 长度: %3 字节 | PID: %4%5 | 基址: %6 | 中心: %7")
        .arg(formatAddress(m_driverMemoryBaseAddress))
        .arg(formatAddress(m_driverMemoryBaseAddress + static_cast<std::uint64_t>(m_driverMemoryEditedBytes.size()) - 1ULL))
        .arg(m_driverMemoryEditedBytes.size())
        .arg(kernelAddressRead ? 0U : targetPid)
        .arg(kernelAddressRead
            ? QStringLiteral(" (Kernel VA)")
            : (targetProcessName.isEmpty() ? QString() : QString(" (%1)").arg(targetProcessName)))
        .arg(formatAddress(offsetBase))
        .arg(formatAddress(centerAddress)));
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText(
            QString("R0读取完成：%1，请求=%2 字节，返回=%3 字节，状态=%4(%5)，copyStatus=%6。输入中心=%7%8")
            .arg(kernelAddressRead ? QStringLiteral("内核地址") : QStringLiteral("PID=%1").arg(targetPid))
            .arg(readResult.requestedBytes)
            .arg(readResult.data.size())
            .arg(readResult.readStatus)
            .arg(readStatusText)
            .arg(copyStatusText)
            .arg(formatAddress(centerAddressInput))
            .arg(readResult.readStatus == KSWORD_ARK_MEMORY_READ_STATUS_PARTIAL_COPY
                ? QStringLiteral("；部分不可读字节已按 00 填充。")
                : QStringLiteral("。")));
    }

    // 读取完成日志：记录范围与协议状态。
    kLogEvent readFinishEvent;
    info << readFinishEvent
        << "[MemoryDock] driverReadMemoryFromUi: 读取完成, base="
        << formatAddress(m_driverMemoryBaseAddress).toStdString()
        << ", pid="
        << targetPid
        << ", bytes="
        << m_driverMemoryEditedBytes.size()
        << ", status="
        << readResult.readStatus
        << eol;
}

bool MemoryDock::verifyDriverMemoryWrittenBlocks(
    const std::vector<DriverDiffBlock>& blocks, QString& failureText)
{
    using namespace ksword::memory_backend;
    const auto actual = m_driverMemorySnapshotIsPhysical
        ? readPhysical(m_driverMemorySnapshotBackend, currentDdmaSession(),
            m_driverMemoryBaseAddress, static_cast<std::uint64_t>(m_driverMemoryOriginalBytes.size()))
        : readVirtual(m_driverMemorySnapshotBackend, currentDdmaSession(),
            isKernelVirtualAddress(m_driverMemoryBaseAddress) ? 0U : m_driverMemorySnapshotPid,
            m_driverMemoryBaseAddress, static_cast<std::uint64_t>(m_driverMemoryOriginalBytes.size()));
    const auto appendFailure = [&](const QString& text) {
        if (!failureText.isEmpty())
        {
            failureText += QStringLiteral(" ");
        }
        failureText += text;
    };
    if (!actual.ok || actual.partial || actual.data.size() != m_driverMemoryOriginalBytes.size())
    {
        appendFailure(actual.failureText.isEmpty()
            ? QStringLiteral("写入后的回读结果与编辑缓存不一致。") : actual.failureText);
        resetDriverMemoryRwState();
        return false;
    }
    bool matches = true;
    for (const auto& block : blocks)
    {
        const qsizetype offset = static_cast<qsizetype>(block.address - m_driverMemoryBaseAddress);
        if (actual.data.mid(offset, block.bytes.size()) != block.bytes)
        {
            appendFailure(QStringLiteral("写入后的回读结果与编辑缓存不一致。"));
            matches = false;
            break;
        }
    }
    // 无论写入是否完成，都展示完整回读的实际内存，保留手选架构和当前地址。
    const auto architecture = m_driverMemoryEditor->currentArchitecture();
    const auto address = m_driverMemoryHexEditor->selectedAbsoluteAddress();
    m_driverMemoryOriginalBytes = actual.data;
    m_driverMemoryEditedBytes = actual.data;
    m_driverMemoryEditor->setSnapshot(actual.data, m_driverMemoryBaseAddress, architecture, address,
        QStringLiteral("driver_memory_%1_%2_%3_%4_%5").arg(static_cast<int>(m_driverMemorySnapshotBackend))
            .arg(m_driverMemorySnapshotPid).arg(m_driverMemorySnapshotIsPhysical ? 1 : 0)
            .arg(m_driverMemorySnapshotDdmaGeneration).arg(m_driverMemorySnapshotProcessCreateTime100ns));
    return matches;
}

void MemoryDock::driverApplyMemoryDiffFromUi()
{
    // 应用入口日志：记录是否有快照与当前缓存大小。
    kLogEvent applyStartEvent;
    info << applyStartEvent
        << "[MemoryDock] driverApplyMemoryDiffFromUi: 开始应用差异, hasSnapshot="
        << (m_driverMemoryHasSnapshot ? "true" : "false")
        << ", cacheBytes="
        << m_driverMemoryEditedBytes.size()
        << eol;

    // 物理快照没有 PID 也没有内核 VA 特征，必须单独放行并走独立的写回通道。
    const bool physicalSnapshot = m_driverMemorySnapshotIsPhysical;
    const bool kernelAddressSnapshot =
        !physicalSnapshot && driverMemoryAddressLooksKernelVa(m_driverMemoryBaseAddress);
    if ((!kernelAddressSnapshot && !physicalSnapshot && m_driverMemorySnapshotPid == 0U)
        || !m_driverMemoryHasSnapshot)
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText("没有可应用的 R0 读取快照。");
        }
        QMessageBox::warning(this, "驱动内存读写", "没有可应用的 R0 读取快照。");
        return;
    }

    if (m_driverMemorySnapshotBackend != currentDriverMemoryBackend()
        || (m_driverMemorySnapshotBackend == ksword::memory_backend::MemoryAccessBackend::Ddma
            && m_driverMemorySnapshotDdmaGeneration != ksword::memory_backend::ddmaSessionGeneration()))
    {
        QMessageBox::warning(this, QStringLiteral("驱动内存读写"),
            QStringLiteral("访问后端或 DDMA 会话已改变，请重新读取后再应用改动。"));
        return;
    }

    // 以 HexEditor 当前数据为准，避免遗漏直接粘贴/编辑导致的缓存变化。
    m_driverMemoryEditedBytes = m_driverMemoryHexEditor->data();
    std::vector<DriverDiffBlock> diffBlocks;
    collectDriverMemoryDiffBlocks(diffBlocks);
    if (diffBlocks.empty())
    {
        m_driverMemoryApplyButton->setEnabled(false);
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText("没有检测到差异，无需写入。");
        }
        return;
    }

    const auto snapshotBase = m_driverMemoryBaseAddress;
    const auto snapshotPid = m_driverMemorySnapshotPid;
    const auto snapshotBackend = m_driverMemorySnapshotBackend;
    const QByteArray snapshotOriginal = m_driverMemoryOriginalBytes;
    const QByteArray snapshotEdited = m_driverMemoryEditedBytes; // 本轮实际批准写入的完整编辑快照
    const auto snapshotDdmaGeneration = m_driverMemorySnapshotDdmaGeneration;
    const auto attachmentGeneration = m_processAttachmentGeneration.load(); // 同 PID 重附加也作废旧请求
    const QPointer<MemoryDock> self(this); // 确认/提权对话框可在嵌套事件循环中销毁宿主
    const auto identityUnchanged = [&]() {
        return self && m_driverMemoryHasSnapshot && m_driverMemoryBaseAddress == snapshotBase
            && m_driverMemorySnapshotPid == snapshotPid
            && m_driverMemorySnapshotIsPhysical == physicalSnapshot
            && m_driverMemorySnapshotBackend == snapshotBackend
            && currentDriverMemoryBackend() == snapshotBackend
            && m_driverMemorySnapshotDdmaGeneration == snapshotDdmaGeneration
            && m_processAttachmentGeneration.load() == attachmentGeneration
            && (snapshotBackend != ksword::memory_backend::MemoryAccessBackend::Ddma
                || snapshotDdmaGeneration == ksword::memory_backend::ddmaSessionGeneration());
    };
    const auto requireFrozenSnapshot = [&]() {
        if (!self) { return false; }
        if (!identityUnchanged() || m_driverMemoryOriginalBytes != snapshotOriginal
            || m_driverMemoryEditedBytes != snapshotEdited
            || m_driverMemoryHexEditor == nullptr || m_driverMemoryHexEditor->data() != snapshotEdited)
        {
            QMessageBox::warning(this, QStringLiteral("驱动内存读写"),
                QStringLiteral("访问后端或 DDMA 会话已改变，请重新读取后再应用改动。"));
            return false;
        }
        return true;
    };
    // 完整回读已 setSnapshot 为实际目标字节；仅接受仍等于批准快照的缓存，不清掉新编辑。
    const auto acceptWrittenSnapshot = [&]() {
        if (identityUnchanged() && m_driverMemoryEditedBytes == snapshotEdited
            && m_driverMemoryHexEditor != nullptr && m_driverMemoryHexEditor->data() == snapshotEdited)
        {
            m_driverMemoryOriginalBytes = snapshotEdited;
            m_driverMemoryEditor->acceptChanges();
        }
    };
    // 危险确认策略只允许跳过重复模态框；R0 确认标志、快照比对和写后状态仍然执行。
    const bool suppressDangerousConfirmation =
        ks::settings::dangerousActionConfirmationsSuppressed();
    if (!suppressDangerousConfirmation)
    {
        const QMessageBox::StandardButton confirmResult = QMessageBox::question(
            this,
            "应用内存差异",
            QString(
                "将通过 %3 写入 %1 个差异块到 %2。\n"
                "内核或进程内存修改可能立即造成数据损坏、权限边界失效、进程崩溃或系统蓝屏。\n"
                "只写入和原始备份不同的字节，是否继续？")
            .arg(diffBlocks.size())
            .arg(physicalSnapshot
                ? QStringLiteral("物理内存（无事务、无回滚）")
                : (kernelAddressSnapshot
                    ? QStringLiteral("内核虚拟地址")
                    : QStringLiteral("PID=%1%2")
                        .arg(m_driverMemorySnapshotPid)
                        .arg(m_driverMemorySnapshotProcessName.isEmpty()
                            ? QString()
                            : QString(" (%1)").arg(m_driverMemorySnapshotProcessName))))
            .arg(ksword::memory_backend::backendDisplayName(m_driverMemorySnapshotBackend)),
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No);
        if (!self) { return; }
        if (confirmResult != QMessageBox::Yes)
        {
            if (m_driverMemoryStatusLabel != nullptr)
            {
                m_driverMemoryStatusLabel->setText("用户取消应用差异。");
            }
            return;
        }
    }
    else
    {
        kLogEvent suppressedConfirmationEvent;
        warn << suppressedConfirmationEvent
            << "[MemoryDock] dangerous confirmation suppressed by persistent setting; "
               "R0 snapshot verification and audit remain active, target="
            << (physicalSnapshot
                ? "physical"
                : (kernelAddressSnapshot ? "kernel-va" : "process-va"))
            << ", blocks="
            << diffBlocks.size()
            << eol;
    }

    // 确认弹窗运行嵌套事件循环，返回后再次核验快照和通道身份。
    if (!requireFrozenSnapshot())
    {
        return;
    }
    // 所有通道都在用户确认完成后复核差异区间，再开始提交。
    for (const auto& block : diffBlocks)
    {
        const qsizetype offset = static_cast<qsizetype>(block.address - snapshotBase);
        const QByteArray expected = snapshotOriginal.mid(offset, block.bytes.size());
        const auto live = physicalSnapshot
            ? ksword::memory_backend::readPhysical(m_driverMemorySnapshotBackend,
                currentDdmaSession(), block.address, static_cast<std::uint64_t>(block.bytes.size()))
            : ksword::memory_backend::readVirtual(m_driverMemorySnapshotBackend,
                currentDdmaSession(), kernelAddressSnapshot ? 0U : m_driverMemorySnapshotPid,
                block.address, static_cast<std::uint64_t>(block.bytes.size()));
        if (!live.ok || live.partial || live.data != expected)
        {
            QMessageBox::warning(this, QStringLiteral("驱动内存读写"),
                live.ok ? QStringLiteral("目标字节已改变，请重新读取后再编辑。") : live.failureText);
            return;
        }
    }

    // 物理内存写回是一条独立通道：按 4KB 切片提交，没有事务，也没有失败回滚。
    if (physicalSnapshot)
    {
        QString physicalFailureText;
        const bool physicalWriteOk = applyDriverMemoryPhysicalDiff(diffBlocks, physicalFailureText);
        if (!self || !requireFrozenSnapshot()) { return; }
        const bool physicalVerified = verifyDriverMemoryWrittenBlocks(diffBlocks, physicalFailureText);
        if (!self) { return; }
        if (physicalWriteOk && physicalVerified)
        {
            if (!identityUnchanged()) { return; }
            // 全部成功后把编辑缓存提升为新的基线，后续差异从这里重新计算。
            acceptWrittenSnapshot();
            if (!self) { return; }
            if (m_driverMemoryApplyButton != nullptr)
            {
                m_driverMemoryApplyButton->setEnabled(m_driverMemoryHexEditor != nullptr
                    && m_driverMemoryHexEditor->data() != m_driverMemoryOriginalBytes);
            }
            if (m_driverMemoryStatusLabel != nullptr)
            {
                // 成功路径也可能带告警（DDMA 的脏扇区与读-改-写窗口），
                // 这里必须把 physicalFailureText 一起显示，不能因为返回了 true 就丢掉。
                QString doneText =
                    QStringLiteral("物理内存写入完成，已提交 %1 个差异块。").arg(diffBlocks.size());
                if (!physicalFailureText.isEmpty())
                {
                    doneText += QStringLiteral(" ") + physicalFailureText;
                }
                m_driverMemoryStatusLabel->setText(doneText);
            }
            refreshDriverMemoryViewsFromSnapshot();
            return;
        }

        // 写入失败仍回读实际内存；失败信息必须保留，不能因回读成功改称写入成功。
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(QStringLiteral("物理内存写入失败。"));
        }
        QMessageBox::warning(this, "驱动内存读写", physicalFailureText);
        return;
    }

    if (m_driverMemorySnapshotBackend == ksword::memory_backend::MemoryAccessBackend::UserMode
        || m_driverMemorySnapshotBackend == ksword::memory_backend::MemoryAccessBackend::Hvm)
    {
        const std::uint32_t pid = kernelAddressSnapshot ? 0U : snapshotPid;
        const auto backend = snapshotBackend;
        std::uint64_t totalWritten = 0;
        QString failureText;
        for (const auto& block : diffBlocks)
        {
            const auto outcome = ksword::memory_backend::writeVirtual(backend,
                currentDdmaSession(), pid, block.address, block.bytes, false);
            totalWritten += outcome.bytesDone;
            if (!outcome.ok || outcome.bytesDone != static_cast<std::uint64_t>(block.bytes.size()))
            {
                failureText = outcome.failureText.isEmpty()
                    ? QStringLiteral("写入未完成。") : outcome.failureText;
                break;
            }
            const auto verified = ksword::memory_backend::readVirtual(backend,
                currentDdmaSession(), pid, block.address, static_cast<std::uint64_t>(block.bytes.size()));
            if (!verified.ok || verified.partial || verified.data != block.bytes)
            {
                failureText = QStringLiteral("写入后的回读结果与编辑缓存不一致。");
                break;
            }
        }
        if (!requireFrozenSnapshot()) { return; }
        verifyDriverMemoryWrittenBlocks(diffBlocks, failureText);
        if (!self) { return; }
        if (!failureText.isEmpty())
        {
            m_driverMemoryStatusLabel->setText(QStringLiteral("应用未完成：已写入 %1 字节。%2")
                .arg(static_cast<qulonglong>(totalWritten)).arg(failureText));
            const bool privilegeHandled = ks::ui::promptForPrivilegeFailure(this,
                QStringLiteral("编辑进程内存"), failureText);
            if (!self) { return; }
            if (!privilegeHandled)
            {
                QMessageBox::warning(this, QStringLiteral("驱动内存读写"),
                    m_driverMemoryStatusLabel->text());
            }
            return;
        }
        if (!identityUnchanged()) { return; }
        acceptWrittenSnapshot();
        if (!self) { return; }
        m_driverMemoryApplyButton->setEnabled(m_driverMemoryHexEditor != nullptr
            && m_driverMemoryHexEditor->data() != m_driverMemoryOriginalBytes);
        m_driverMemoryStatusLabel->setText(QStringLiteral("应用完成并已回读：%1 字节。")
            .arg(static_cast<qulonglong>(totalWritten)));
        return;
    }

    // DDMA 后端整条通路都不一样：不走 R0 的虚拟写，也没有内核字节事务与回滚，
    // 而是逐页翻译成物理地址后做磁盘 DMA。单独分支并直接返回，避免把下面那段
    // 已经带事务与回滚的标准写回逻辑改成两用。
    if (currentDriverMemoryBackend() == ksword::memory_backend::MemoryAccessBackend::Ddma)
    {
        const std::uint32_t ddmaTargetPid =
            kernelAddressSnapshot ? 0U : snapshotPid;
        std::uint64_t ddmaWrittenTotal = 0ULL;
        bool ddmaScratchDirty = false;
        bool ddmaLostUpdate = false;
        bool ddmaForceApproved = false;

        for (const DriverDiffBlock& block : diffBlocks)
        {
            if (!requireFrozenSnapshot()) { return; }
            ksword::memory_backend::AccessOutcome blockOutcome =
                ksword::memory_backend::writeVirtual(
                    ksword::memory_backend::MemoryAccessBackend::Ddma,
                    currentDdmaSession(),
                    ddmaTargetPid,
                    block.address,
                    block.bytes,
                    ddmaForceApproved);

            // 首个块触发 force 确认后，本轮后续块复用同一次同意。
            if (blockOutcome.forceRequired && !ddmaForceApproved)
            {
                const bool forceConfirmed = confirmForceDriverMemoryWrite(
                        block.address,
                        static_cast<std::uint32_t>(block.bytes.size()),
                        blockOutcome.failureText, snapshotPid);
                if (!self || !requireFrozenSnapshot()) { return; }
                if (!forceConfirmed)
                {
                    QString failureText = QStringLiteral("用户取消了 DDMA 强制写入。");
                    verifyDriverMemoryWrittenBlocks(diffBlocks, failureText);
                    if (!self) { return; }
                    if (m_driverMemoryStatusLabel != nullptr)
                    {
                        m_driverMemoryStatusLabel->setText(
                            QStringLiteral("应用未完成：已写入 %1 字节。%2")
                                .arg(static_cast<qulonglong>(ddmaWrittenTotal)).arg(failureText));
                    }
                    return;
                }
                // 二次确认期间目标字节也可能变化；强制写前按批准时的原始块再次回读。
                const auto beforeForce = ksword::memory_backend::readVirtual(snapshotBackend,
                    currentDdmaSession(), ddmaTargetPid, block.address, static_cast<std::uint64_t>(block.bytes.size()));
                const QByteArray expectedBefore = snapshotOriginal.mid(
                    static_cast<qsizetype>(block.address - snapshotBase), block.bytes.size());
                if (!beforeForce.ok || beforeForce.partial || beforeForce.data != expectedBefore)
                {
                    QMessageBox::warning(this, QStringLiteral("驱动内存读写"),
                        QStringLiteral("目标字节已改变，请重新读取后再编辑。"));
                    return;
                }
                ddmaForceApproved = true;
                blockOutcome = ksword::memory_backend::writeVirtual(
                    ksword::memory_backend::MemoryAccessBackend::Ddma,
                    currentDdmaSession(),
                    ddmaTargetPid,
                    block.address,
                    block.bytes,
                    true);
            }

            ddmaScratchDirty = ddmaScratchDirty || blockOutcome.scratchDirty;
            ddmaLostUpdate = ddmaLostUpdate || blockOutcome.lostUpdateWindow;
            ddmaWrittenTotal += blockOutcome.bytesDone;

            if (!blockOutcome.ok)
            {
                // DDMA 写没有事务也没有回滚，失败即停并如实报告已写入量。
                QString failureText = QStringLiteral(
                    "DDMA 写入失败。\n%1\n本轮累计已写入 %2 字节，失败前的改动不会自动回滚。")
                    .arg(blockOutcome.failureText)
                    .arg(ddmaWrittenTotal);
                if (ddmaScratchDirty)
                {
                    failureText += QStringLiteral(
                        "\n严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
                }
                verifyDriverMemoryWrittenBlocks(diffBlocks, failureText);
                if (!self) { return; }
                if (m_driverMemoryStatusLabel != nullptr)
                {
                    m_driverMemoryStatusLabel->setText(failureText);
                }
                QMessageBox::warning(this, "驱动内存读写", failureText);
                return;
            }
        }

        QString verificationFailure;
        if (!requireFrozenSnapshot()) { return; }
        if (!verifyDriverMemoryWrittenBlocks(diffBlocks, verificationFailure))
        {
            if (!self) { return; }
            m_driverMemoryStatusLabel->setText(verificationFailure);
            QMessageBox::warning(this, QStringLiteral("驱动内存读写"), verificationFailure);
            return;
        }

        if (!self || !identityUnchanged()) { return; }
        acceptWrittenSnapshot();
        if (!self) { return; }
        if (m_driverMemoryApplyButton != nullptr)
        {
            m_driverMemoryApplyButton->setEnabled(m_driverMemoryHexEditor != nullptr
                && m_driverMemoryHexEditor->data() != m_driverMemoryOriginalBytes);
        }
        QString ddmaDoneText = QStringLiteral(
            "DDMA 写入完成，已提交 %1 个差异块，共 %2 字节。")
            .arg(diffBlocks.size())
            .arg(ddmaWrittenTotal);
        if (ddmaLostUpdate)
        {
            ddmaDoneText += QStringLiteral(
                " 含非整页写入，驱动做了读-改-写，同页其它字节存在覆盖窗口。");
        }
        if (ddmaScratchDirty)
        {
            ddmaDoneText += QStringLiteral(
                " 严重告警：暂存扇区未能还原，磁盘上留下了脏扇区。");
        }
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(ddmaDoneText);
        }
        refreshDriverMemoryViewsFromSnapshot();
        return;
    }

    // 按块调用驱动写入，单块超过驱动上限时拆分。
    ksword::ark::DriverClient driverClient;
    std::uint64_t totalRequested = 0;
    std::uint64_t totalWritten = 0;
    int failedBlockCount = 0;
    bool forceWriteApproved = false;
    struct KernelMutationChunk
    {
        std::uint64_t transactionId = 0U;
        std::uint64_t address = 0U;
        std::vector<std::uint8_t> beforeBytes;
    };
    std::vector<KernelMutationChunk> kernelMutationChunks;
    std::uint64_t rollbackVerifiedBytes = 0U;
    int rollbackFailedCount = 0;
    // privilegePromptHandled：跨写入块记录是否已经展示过一次权限恢复提示。
    bool privilegePromptHandled = false;
    QString lastFailureText;

    for (const DriverDiffBlock& block : diffBlocks)
    {
        int offset = 0;
        while (offset < block.bytes.size())
        {
            if (!requireFrozenSnapshot()) { return; }
            const int chunkBytes = std::min<int>(
                block.bytes.size() - offset,
                static_cast<int>(
                    kernelAddressSnapshot
                        ? KSWORD_ARK_MUTATION_MAX_BYTES
                        : KSWORD_ARK_MEMORY_WRITE_MAX_BYTES));
            std::vector<std::uint8_t> chunk;
            chunk.resize(static_cast<std::size_t>(chunkBytes));
            std::copy_n(
                reinterpret_cast<const std::uint8_t*>(block.bytes.constData() + offset),
                static_cast<std::size_t>(chunkBytes),
                chunk.begin());

            const std::uint64_t chunkAddress =
                block.address + static_cast<std::uint64_t>(offset);
            totalRequested += static_cast<std::uint64_t>(chunkBytes);

            if (kernelAddressSnapshot)
            {
                const std::uint64_t snapshotOffset =
                    chunkAddress - m_driverMemoryBaseAddress;
                if (snapshotOffset
                        > static_cast<std::uint64_t>(
                            m_driverMemoryOriginalBytes.size())
                    || static_cast<std::uint64_t>(chunkBytes)
                        > static_cast<std::uint64_t>(
                            m_driverMemoryOriginalBytes.size())
                            - snapshotOffset)
                {
                    ++failedBlockCount;
                    lastFailureText = QStringLiteral(
                        "内核字节事务的 expected-before 超出原始快照边界。");
                    break;
                }

                std::vector<std::uint8_t> expectedBefore(
                    static_cast<std::size_t>(chunkBytes));
                std::copy_n(
                    reinterpret_cast<const std::uint8_t*>(
                        m_driverMemoryOriginalBytes.constData()
                        + static_cast<qsizetype>(
                            snapshotOffset)),
                    static_cast<std::size_t>(chunkBytes),
                    expectedBefore.begin());

                ksword::ark::MutationPrepareInput prepareInput{};
                prepareInput.flags =
                    KSWORD_ARK_MUTATION_FLAG_DRY_RUN |
                    KSWORD_ARK_MUTATION_FLAG_EXPECTED_BEFORE_PRESENT;
                prepareInput.targetKind =
                    KSWORD_ARK_MUTATION_TARGET_KERNEL_VIRTUAL_BYTES_SMALL;
                prepareInput.bytes =
                    static_cast<std::uint32_t>(chunkBytes);
                prepareInput.targetAddress = chunkAddress;
                prepareInput.afterBytes = chunk;
                prepareInput.expectedBeforeBytes = expectedBefore;
                const ksword::ark::MutationResponseResult prepareResult =
                    driverClient.prepareMutation(prepareInput);
                if (!prepareResult.io.ok
                    || prepareResult.status
                        != KSWORD_ARK_MUTATION_STATUS_PREPARED
                    || prepareResult.transactionId == 0U
                    || prepareResult.bytes
                        != static_cast<std::uint32_t>(chunkBytes)
                    || prepareResult.beforeBytes.size()
                        < static_cast<std::size_t>(chunkBytes)
                    || !std::equal(
                        expectedBefore.cbegin(),
                        expectedBefore.cend(),
                        prepareResult.beforeBytes.cbegin()))
                {
                    privilegePromptHandled =
                        ks::ui::promptForPrivilegeFailure(
                            this,
                            QStringLiteral("R0内核字节事务 PREPARE"),
                            prepareResult.io.win32Error);
                    if (!self) { return; }
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务 PREPARE 失败：地址=%1 请求=%2 状态=%3 NT=%4 信息=%5")
                        .arg(formatAddress(chunkAddress))
                        .arg(chunkBytes)
                        .arg(prepareResult.status)
                        .arg(driverMemoryNtStatusText(
                            prepareResult.lastStatus))
                        .arg(driverMemoryIoMessageText(
                            prepareResult.io.message));
                    break;
                }

                KernelMutationChunk mutationChunk;
                mutationChunk.transactionId =
                    prepareResult.transactionId;
                mutationChunk.address = chunkAddress;
                mutationChunk.beforeBytes = expectedBefore;
                kernelMutationChunks.push_back(
                    std::move(mutationChunk));

                const ksword::ark::MutationResponseResult dryRunResult =
                    driverClient.commitMutation(
                        prepareResult.transactionId,
                        KSWORD_ARK_MUTATION_FLAG_DRY_RUN);
                if (!dryRunResult.io.ok
                    || dryRunResult.status
                        != KSWORD_ARK_MUTATION_STATUS_DRY_RUN)
                {
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务 dry-run 失败：地址=%1 tx=%2 状态=%3 NT=%4 信息=%5")
                        .arg(formatAddress(chunkAddress))
                        .arg(prepareResult.transactionId)
                        .arg(dryRunResult.status)
                        .arg(driverMemoryNtStatusText(
                            dryRunResult.lastStatus))
                        .arg(driverMemoryIoMessageText(
                            dryRunResult.io.message));
                    break;
                }

                const ksword::ark::MutationResponseResult commitResult =
                    driverClient.commitMutation(
                        prepareResult.transactionId,
                        KSWORD_ARK_MUTATION_FLAG_FORCE |
                        KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
                if (!commitResult.io.ok
                    || commitResult.status
                        != KSWORD_ARK_MUTATION_STATUS_COMMITTED)
                {
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务 FORCE 提交失败：地址=%1 tx=%2 状态=%3 NT=%4 信息=%5")
                        .arg(formatAddress(chunkAddress))
                        .arg(prepareResult.transactionId)
                        .arg(commitResult.status)
                        .arg(driverMemoryNtStatusText(
                            commitResult.lastStatus))
                        .arg(driverMemoryIoMessageText(
                            commitResult.io.message));
                    break;
                }

                const ksword::ark::VirtualMemoryReadResult verifyResult =
                    driverClient.readVirtualMemory(
                        0U,
                        chunkAddress,
                        static_cast<std::uint32_t>(chunkBytes),
                        KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
                if (!verifyResult.io.ok
                    || verifyResult.readStatus
                        != KSWORD_ARK_MEMORY_READ_STATUS_OK
                    || verifyResult.data.size()
                        != static_cast<std::size_t>(chunkBytes)
                    || !std::equal(
                        chunk.cbegin(),
                        chunk.cend(),
                        verifyResult.data.cbegin()))
                {
                    ++failedBlockCount;
                    lastFailureText = QString(
                        "内核字节事务提交后 R3 复读不一致：地址=%1 tx=%2 读取状态=%3 NT=%4")
                        .arg(formatAddress(chunkAddress))
                        .arg(prepareResult.transactionId)
                        .arg(verifyResult.readStatus)
                        .arg(driverMemoryNtStatusText(
                            verifyResult.copyStatus));
                    break;
                }

                totalWritten +=
                    static_cast<std::uint64_t>(chunkBytes);
                offset += chunkBytes;
                continue;
            }

            unsigned long writeFlags = 0UL;
            if (forceWriteApproved)
            {
                writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE;
            }
            ksword::ark::VirtualMemoryWriteResult writeResult =
                driverClient.writeVirtualMemory(
                    snapshotPid,
                    chunkAddress,
                    chunk,
                    writeFlags);

            if (writeResult.io.ok &&
                writeResult.writeStatus == KSWORD_ARK_MEMORY_WRITE_STATUS_FORCE_REQUIRED)
            {
                const QString forcePromptText =
                    QString("驱动拒绝了普通内存写入请求。\n地址=%1\n请求=%2 字节\nR0 信息：%3")
                    .arg(formatAddress(chunkAddress))
                    .arg(chunkBytes)
                    .arg(driverMemoryIoMessageText(writeResult.io.message));
                const bool forceConfirmed = confirmForceDriverMemoryWrite(
                    chunkAddress,
                    static_cast<std::uint32_t>(chunkBytes),
                    forcePromptText, snapshotPid);
                if (!self || !requireFrozenSnapshot()) { return; }
                if (!forceConfirmed)
                {
                    ++failedBlockCount;
                    lastFailureText = QString("用户未强制继续，地址=%1 请求=%2。")
                        .arg(formatAddress(chunkAddress))
                        .arg(chunkBytes);
                    break;
                }

                // 逐块强制确认之后重新核对 expected-before，禁止覆盖弹窗期间的新目标数据。
                const auto beforeForce = ksword::memory_backend::readVirtual(snapshotBackend,
                    currentDdmaSession(), snapshotPid, chunkAddress, static_cast<std::uint64_t>(chunkBytes));
                const QByteArray expectedBefore = snapshotOriginal.mid(
                    static_cast<qsizetype>(chunkAddress - snapshotBase), chunkBytes);
                if (!beforeForce.ok || beforeForce.partial || beforeForce.data != expectedBefore)
                {
                    QMessageBox::warning(this, QStringLiteral("驱动内存读写"),
                        QStringLiteral("目标字节已改变，请重新读取后再编辑。"));
                    return;
                }

                forceWriteApproved = true;
                writeFlags |= KSWORD_ARK_MEMORY_WRITE_FLAG_FORCE;
                writeResult = driverClient.writeVirtualMemory(
                    snapshotPid,
                    chunkAddress,
                    chunk,
                    writeFlags);
            }

            totalWritten += static_cast<std::uint64_t>(writeResult.bytesWritten);
            if (!writeResult.io.ok ||
                writeResult.writeStatus != KSWORD_ARK_MEMORY_WRITE_STATUS_OK ||
                writeResult.bytesWritten != static_cast<std::uint32_t>(chunkBytes))
            {
                privilegePromptHandled = ks::ui::promptForPrivilegeFailure(
                    this,
                    QStringLiteral("R0写入进程内存"),
                    writeResult.io.win32Error);
                if (!self) { return; }
                if (!privilegePromptHandled)
                {
                    privilegePromptHandled = ks::ui::promptForPrivilegeNtStatus(
                        this,
                        QStringLiteral("R0写入进程内存"),
                        static_cast<long>(writeResult.copyStatus));
                    if (!self) { return; }
                }
                ++failedBlockCount;
                lastFailureText = QString("地址=%1 请求=%2 写入=%3 状态=%4 NT=0x%5 信息=%6")
                    .arg(formatAddress(chunkAddress))
                    .arg(chunkBytes)
                    .arg(writeResult.bytesWritten)
                    .arg(writeResult.writeStatus)
                    .arg(static_cast<unsigned long>(writeResult.copyStatus), 8, 16, QChar('0'))
                    .arg(driverMemoryIoMessageText(writeResult.io.message));
                break;
            }

            offset += chunkBytes;
        }

        if (failedBlockCount > 0)
        {
            break;
        }
    }

    if (kernelAddressSnapshot && failedBlockCount != 0)
    {
        for (auto transaction =
                 kernelMutationChunks.crbegin();
             transaction != kernelMutationChunks.crend();
             ++transaction)
        {
            bool restored = false;
            const auto readExpectedBefore = [&driverClient,
                                             &transaction,
                                             &restored]()
            {
                const ksword::ark::VirtualMemoryReadResult readResult =
                    driverClient.readVirtualMemory(
                        0U,
                        transaction->address,
                        static_cast<std::uint32_t>(
                            transaction->beforeBytes.size()),
                        KSWORD_ARK_MEMORY_READ_FLAG_KERNEL_ADDRESS);
                restored =
                    readResult.io.ok
                    && readResult.readStatus
                        == KSWORD_ARK_MEMORY_READ_STATUS_OK
                    && readResult.data.size()
                        == transaction->beforeBytes.size()
                    && std::equal(
                        transaction->beforeBytes.cbegin(),
                        transaction->beforeBytes.cend(),
                        readResult.data.cbegin());
            };
            readExpectedBefore();
            if (!restored)
            {
                const ksword::ark::MutationResponseResult rollbackResult =
                    driverClient.rollbackMutation(
                        transaction->transactionId,
                        KSWORD_ARK_MUTATION_FLAG_FORCE |
                        KSWORD_ARK_MUTATION_FLAG_UI_CONFIRMED);
                if (rollbackResult.io.ok
                    && (rollbackResult.status
                            == KSWORD_ARK_MUTATION_STATUS_ROLLED_BACK
                        || rollbackResult.status
                            == KSWORD_ARK_MUTATION_STATUS_ALREADY_AT_BEFORE))
                {
                    readExpectedBefore();
                }
            }
            if (restored)
            {
                rollbackVerifiedBytes +=
                    transaction->beforeBytes.size();
            }
            else
            {
                ++rollbackFailedCount;
            }
        }
        lastFailureText += QString(
            "；回滚复核恢复=%1 字节，未恢复事务=%2")
            .arg(static_cast<qulonglong>(
                rollbackVerifiedBytes))
            .arg(rollbackFailedCount);
    }

    // 失败/回滚完成后也必须回读实际状态；原写入错误仍决定本轮失败。
    if (!requireFrozenSnapshot()) { return; }
    if (!verifyDriverMemoryWrittenBlocks(diffBlocks, lastFailureText) && failedBlockCount == 0)
    {
        failedBlockCount = 1;
    }
    if (!self || (failedBlockCount == 0 && !identityUnchanged())) { return; }

    // 成功写入的情况下，把当前编辑缓存提升为新备份，避免重复应用同一差异。
    if (failedBlockCount == 0)
    {
        acceptWrittenSnapshot();
        if (!self) { return; }
        m_driverMemoryApplyButton->setEnabled(m_driverMemoryHexEditor != nullptr
            && m_driverMemoryHexEditor->data() != m_driverMemoryOriginalBytes);
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(
                QString("应用完成：差异块=%1，请求写入=%2 字节，实际写入=%3 字节。")
                .arg(diffBlocks.size())
                .arg(static_cast<qulonglong>(totalRequested))
                .arg(static_cast<qulonglong>(totalWritten)));
        }
    }
    else
    {
        if (m_driverMemoryStatusLabel != nullptr)
        {
            m_driverMemoryStatusLabel->setText(
                QString("应用部分失败：请求=%1 字节，已写=%2 字节，失败块=%3，%4")
                .arg(static_cast<qulonglong>(totalRequested))
                .arg(static_cast<qulonglong>(totalWritten))
                .arg(failedBlockCount)
                .arg(lastFailureText));
            if (!privilegePromptHandled)
            {
                QMessageBox::warning(this, "驱动内存读写", m_driverMemoryStatusLabel->text());
            }
        }
    }
}

void MemoryDock::resetDriverMemoryRwState()
{
    // 清空缓存日志：记录清空前状态。
    kLogEvent resetEvent;
    dbg << resetEvent
        << "[MemoryDock] resetDriverMemoryRwState: 清空驱动读写页缓存。"
        << eol;

    m_driverMemoryBaseAddress = 0;
    m_driverMemoryOffsetBase = 0;
    m_driverMemoryCenterAddress = 0;
    m_driverMemorySnapshotPid = 0;
    m_driverMemorySnapshotProcessCreateTime100ns = 0;
    m_driverMemorySnapshotProcessName.clear();
    m_driverMemoryOriginalBytes.clear();
    m_driverMemoryEditedBytes.clear();
    m_driverMemoryHasSnapshot = false;
    m_driverMemorySnapshotIsPhysical = false;

    if (m_driverMemoryHexEditor != nullptr)
    {
        m_driverMemoryHexEditor->clearData();
        m_driverMemoryHexEditor->setEditable(false);
    }
    if (m_driverMemoryApplyButton != nullptr)
    {
        m_driverMemoryApplyButton->setEnabled(false);
    }
    if (m_driverMemoryRangeLabel != nullptr)
    {
        m_driverMemoryRangeLabel->setText("范围: 未读取");
    }
    if (m_driverMemoryStatusLabel != nullptr)
    {
        m_driverMemoryStatusLabel->setText("缓存已清空。");
    }

    if (m_driverMemoryEditor != nullptr)
    {
        m_driverMemoryEditor->clear();
        m_driverMemoryEditor->setEditable(false);
    }
}

bool MemoryDock::confirmForceDriverMemoryWrite(
    const std::uint64_t blockAddress,
    const std::uint32_t requestedBytes,
    const QString& failureText,
    const std::uint32_t targetPid)
{
    // 这里不受“跳过危险操作重复确认”开关影响：
    // 该开关承诺的是省掉用户已经答过一遍的重复询问，而走到本函数意味着
    // R0 刚刚拒绝了这次普通写入，是否越过该保护属于全新决策，必须逐次询问。
    // 自动返回 true 等于替用户同意了一次驱动已经否决的写入。

    // 强制确认入口：普通写入被 R0 拒绝后才会走到这里。
    // 嵌套事件循环期间父 Dock 可能被销毁，Qt 只能删除堆分配的子对话框。
    const QPointer<MemoryDock> self(this);
    QPointer<QMessageBox> warningBox = new QMessageBox(this);
    warningBox->setIcon(QMessageBox::Warning);
    warningBox->setWindowTitle(QStringLiteral("强制写入确认"));
    warningBox->setText(QStringLiteral("R0 已拒绝普通内存写入请求。"));
    warningBox->setInformativeText(
        QStringLiteral("目标 PID=%1\n目标地址=%2\n请求长度=%3 字节\n\n%4\n\n强制继续会绕过本次普通请求保护，只应在确认目标进程和地址无误时使用。")
        .arg(targetPid)
        .arg(formatAddress(blockAddress))
        .arg(requestedBytes)
        .arg(failureText));
    warningBox->setStandardButtons(QMessageBox::Cancel);
    warningBox->setDefaultButton(QMessageBox::Cancel);

    // 自定义按钮用于明确表达 force 语义，避免把普通 Yes/Ok 误当成强制写入。
    QPushButton* const forceButton =
        warningBox->addButton(QStringLiteral("强制继续"), QMessageBox::DestructiveRole);
    warningBox->exec();

    if (!self || !warningBox)
    {
        return false;
    }
    const bool forceConfirmed = warningBox->clickedButton() == forceButton;
    delete warningBox.data();

    // 返回值只在用户点中强制按钮时为 true；关闭窗口或取消均停止写入。
    return forceConfirmed;
}

void MemoryDock::collectDriverMemoryDiffBlocks(std::vector<DriverDiffBlock>& diffBlocksOut) const
{
    // 差异收集入口：输出容器由调用方持有，这里先清空。
    diffBlocksOut.clear();
    if (!m_driverMemoryHasSnapshot ||
        m_driverMemoryOriginalBytes.size() != m_driverMemoryEditedBytes.size())
    {
        return;
    }

    // 扫描整段缓存，把相邻变化字节合并为连续块，减少 IOCTL 次数。
    int index = 0;
    while (index < m_driverMemoryOriginalBytes.size())
    {
        if (m_driverMemoryOriginalBytes.at(index) == m_driverMemoryEditedBytes.at(index))
        {
            ++index;
            continue;
        }

        const int blockStart = index;
        while (index < m_driverMemoryOriginalBytes.size() &&
            m_driverMemoryOriginalBytes.at(index) != m_driverMemoryEditedBytes.at(index))
        {
            ++index;
        }

        DriverDiffBlock block{};
        block.address = m_driverMemoryBaseAddress + static_cast<std::uint64_t>(blockStart);
        block.bytes = m_driverMemoryEditedBytes.mid(blockStart, index - blockStart);
        diffBlocksOut.push_back(std::move(block));
    }
}

