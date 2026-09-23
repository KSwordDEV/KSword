// ============================================================
// ContextMenuCleanerTab.Latency.cpp
// 作用：
// 1) 逐条测量右键菜单里每一项的"耗时贡献"——Shell 不提供单条耗时，只能用差值法：
//    先测基准（菜单完整弹出耗时），再对每一项临时禁用后复测，基准与复测之差即该项贡献；
// 2) 判定"在算 vs 在等"：采样窗口内 explorer 进程的 CPU 占挂钟比例，高=在算，低=在等外部对象；
// 3) 把结果写回耗时列（超过阈值标红）并把完整报告写进详情编辑器。
//
// 安全约束：
// - 临时禁用走 HKCU 覆盖（处理器改默认值置空、verb 加 LegacyDisable），**绝不删除原有键值**，
//   测完立刻按原值还原；开始测量前还会整份导出当前菜单为文件备份；
// - kProgress 没有取消接口，因此自带 std::atomic 停止标志；
// - 后台线程不触碰任何 Qt 控件，结果统一回到 UI 线程应用。
// ============================================================

#include "ContextMenuCleanerTab.h"

#include "ContextMenuCleanerTab.Internal.h"

#include "../../ksword/window/context_menu_probe.h"
#include "../../theme.h"
#include "../../UI/CodeEditorWidget.h"
#include "../../UI/VisibleTableWidget.h"

#include <QBrush>
#include <QColor>
#include <QDateTime>
#include <QFont>
#include <QHash>
#include <QLabel>
#include <QLineEdit>
#include <QMetaObject>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QThreadPool>

#include <algorithm>
#include <array>
#include <vector>

namespace ks::misc
{

using namespace context_menu_cleaner_detail;

namespace
{
    // kMaxProbeItems：逐条阶段最多测多少条（还会被时间预算进一步截断）。
    constexpr int kMaxProbeItems = 24;

    // kBaselineSamples：开局基准采样次数。
    // 用多次采样算出"噪声底噪"（最长 − 最短），低于底噪的差异不能当成某条菜单项的贡献。
    constexpr int kBaselineSamples = 5;

    // kItemBracketSamples / kItemMutedSamples：单项采样次数。
    // 每项固定 3 次弹出：禁用前基准 1 次 → 禁用期间 1 次 → 禁用后基准 1 次。
    // 为什么必须紧邻着取基准（而不是只用一个"全局参考值"）：这台机器的菜单耗时会被
    // "阵发性卡顿"整体抬高约 2.6 秒，而它自己来自己走。若参考值是几分钟前测的，
    // 某个条目恰好在卡顿离开的窗口里被测到，就会凭空"认领"那段卡顿（实测出现过
    // 普通动词被报成 1212 ms，正好等于另一个慢扩展的延迟）。
    // 用紧邻的前后基准取最小值，漂移窗口里算出来的差值天然趋近 0。
    constexpr int kItemBracketSamples = 1;
    constexpr int kItemMutedSamples = 1;

    // kProbeGapMs：采样之间的静默间隔。
    // 取 0：探针内部已经轮询到菜单窗口消失才返回，再死等只是白花时间。
    constexpr int kProbeGapMs = 0;

    // kLatencyShortThresholdMs：门限下限。
    // 贡献低于门限的一律按"很短"显示（不给用户一串无意义的毫秒数），也不计入可归因合计。
    constexpr double kLatencyShortThresholdMs = 50.0;

    // kLatencyBudgetMs：逐条阶段的总时长预算。
    // 按基准测出的"单次菜单开销 × 每项 3 次弹出"反推本次能测几条，避免慢机器上把整轮拖成好几分钟；
    // 被预算砍掉的条数会写进报告，用户也可以随时点「停止测量」。
    constexpr int kLatencyBudgetMs = 90000;

    // resolveExplorerPid：取外壳进程 PID（菜单由它弹出，CPU 归因也看它）。
    // 入参：无；返回：PID，取不到返回 0。
    unsigned long resolveExplorerPid()
    {
        HWND tray = ::FindWindowW(L"Shell_TrayWnd", nullptr);
        if (tray == nullptr)
        {
            return 0;
        }
        DWORD processId = 0;
        ::GetWindowThreadProcessId(tray, &processId);
        return processId;
    }

    // latencyContextForArea：把"是否为桌面背景分类"映射到探针上下文。
    // 入参 isDesktopBackgroundArea：true 表示当前分类是桌面右键菜单（唯一可程序化触发的菜单）；
    //      outContext：输出上下文。
    // 返回：存在可程序化触发的菜单返回 true。
    // 说明：只有"空白处右键"能靠消息触发。文件/格式菜单需要先选中目标项（要写目标进程内存），
    //       IE 已废弃且需 IE 窗口，URL 绑定/打开方式/资源管理器主页根本不是菜单——
    //       这些一律返回 false，由调用方给出明确提示，绝不假装能测。
    // 注意：这里刻意用 bool 而不是 MenuArea —— MenuArea 是类的私有嵌套枚举，自由函数无权使用。
    bool latencyContextForArea(const bool isDesktopBackgroundArea,
        ks::window::MenuProbeContext* outContext)
    {
        if (isDesktopBackgroundArea)
        {
            if (outContext != nullptr)
            {
                *outContext = ks::window::MenuProbeContext::DesktopBackground;
            }
            return true;
        }
        return false;
    }

    // applyTemporaryDisable：以 HKCU 覆盖方式临时禁用一条菜单项。
    // 入参 subKeyPath：相对根键的完整子键路径（HKLM 项也写同样的 HKCU 路径形成覆盖）；
    //      isHandler：true=ContextMenuHandlers 处理器（默认值是 CLSID，置空即禁用），
    //                 false=shell verb（默认值不是 CLSID，改用 LegacyDisable）；
    //      originalValueOut：输出被覆盖前的默认值（空表示原本不存在该 HKCU 键）；
    //      keyCreatedOut：输出本次是否新建了 HKCU 键（还原时需要据此删除）。
    // 返回：成功 true。**只写不删**，任何原有数据都通过 originalValue 保留。
    bool applyTemporaryDisable(
        const QString& subKeyPath,
        const bool isHandler,
        QString* originalValueOut,
        bool* keyCreatedOut)
    {
        if (originalValueOut != nullptr)
        {
            originalValueOut->clear();
        }
        if (keyCreatedOut != nullptr)
        {
            *keyCreatedOut = false;
        }

        HKEY key = nullptr;
        DWORD disposition = 0;
        const LSTATUS openStatus = ::RegCreateKeyExW(HKEY_CURRENT_USER,
            subKeyPath.toStdWString().c_str(), 0, nullptr, REG_OPTION_NON_VOLATILE,
            KEY_READ | KEY_WRITE, nullptr, &key, &disposition);
        if (openStatus != ERROR_SUCCESS)
        {
            return false;
        }
        if (keyCreatedOut != nullptr)
        {
            *keyCreatedOut = disposition == REG_CREATED_NEW_KEY;
        }

        // 先记下原值：处理器需要保留原 CLSID，verb 需要知道 LegacyDisable 是否本来就有。
        DWORD type = 0;
        DWORD size = 0;
        if (::RegQueryValueExW(key, L"", nullptr, &type, nullptr, &size) == ERROR_SUCCESS && size > 0)
        {
            std::vector<wchar_t> buffer(size / sizeof(wchar_t) + 1U, L'\0');
            if (::RegQueryValueExW(key, L"", nullptr, &type,
                    reinterpret_cast<BYTE*>(buffer.data()), &size) == ERROR_SUCCESS)
            {
                if (originalValueOut != nullptr)
                {
                    *originalValueOut = QString::fromWCharArray(buffer.data());
                }
            }
        }

        LSTATUS status = ERROR_SUCCESS;
        if (isHandler)
        {
            // 处理器：把默认值（CLSID）置空，Shell 会因 CLSID 无效而跳过该处理器。
            const wchar_t empty[] = L"";
            status = ::RegSetValueExW(key, L"", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(empty), sizeof(empty));
        }
        else
        {
            // verb：加 LegacyDisable，Shell 会隐藏该动词。
            const wchar_t empty[] = L"";
            status = ::RegSetValueExW(key, L"LegacyDisable", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(empty), sizeof(empty));
        }
        ::RegCloseKey(key);
        return status == ERROR_SUCCESS;
    }

    // revertTemporaryDisable：还原 applyTemporaryDisable 造成的改动。
    // 入参 subKeyPath/isHandler/originalValue/keyCreated：与禁用时一致。
    // 返回：成功 true（失败会在报告里记为"未还原"，提醒用户用文件备份兜底）。
    bool revertTemporaryDisable(
        const QString& subKeyPath,
        const bool isHandler,
        const QString& originalValue,
        const bool keyCreated)
    {
        HKEY key = nullptr;
        if (::RegOpenKeyExW(HKEY_CURRENT_USER, subKeyPath.toStdWString().c_str(), 0,
                KEY_READ | KEY_WRITE, &key) != ERROR_SUCCESS)
        {
            return true; // 键已经不存在，视为已还原。
        }

        LSTATUS status = ERROR_SUCCESS;
        if (isHandler)
        {
            if (originalValue.isEmpty() && keyCreated)
            {
                // 这个 HKCU 键是我们为了本次测量新建的，且原本没有值：直接删掉它。
                ::RegCloseKey(key);
                status = ::RegDeleteKeyExW(HKEY_CURRENT_USER, subKeyPath.toStdWString().c_str(),
                    0, 0);
                return status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND;
            }
            const std::wstring restored = originalValue.toStdWString();
            status = ::RegSetValueExW(key, L"", 0, REG_SZ,
                reinterpret_cast<const BYTE*>(restored.c_str()),
                static_cast<DWORD>((restored.size() + 1) * sizeof(wchar_t)));
        }
        else
        {
            // verb：删掉我们加的 LegacyDisable；若该键是本次新建且已空，则连键一起删。
            status = ::RegDeleteValueW(key, L"LegacyDisable");
            if (status == ERROR_FILE_NOT_FOUND)
            {
                status = ERROR_SUCCESS;
            }
        }
        ::RegCloseKey(key);

        if (status == ERROR_SUCCESS && !isHandler && keyCreated)
        {
            // 清完 LegacyDisable 后再试删空键：非空（用户本来就有内容）会失败，属正常。
            ::RegDeleteKeyExW(HKEY_CURRENT_USER, subKeyPath.toStdWString().c_str(), 0, 0);
        }
        return status == ERROR_SUCCESS;
    }

    // formatMilliseconds：统一的耗时文本。
    // 入参 value：毫秒；返回：保留一位小数的毫秒文本。
    QString formatMilliseconds(const double value)
    {
        return QStringLiteral("%1 ms").arg(value, 0, 'f', 1);
    }

    // verdictText：把探针给出的英文判定转成中文结论。
    // 入参 verdict：computing / waiting / unknown；返回：面向用户的一句结论。
    QString verdictText(const std::string& verdict)
    {
        if (verdict == "computing")
        {
            return QStringLiteral("像是有组件真在计算（CPU 占比高），方向是查菜单扩展");
        }
        if (verdict == "waiting")
        {
            return QStringLiteral("不像扩展在算 —— 更像在等外部对象（IPC / 网络 / 服务超时），逐条禁用扩展意义不大");
        }
        return QStringLiteral("无法判定");
    }
}  // namespace

// 注意：返回类型写在限定名之前，此时还没进入类作用域，必须写成 ContextMenuCleanerTab::MenuArea。
ContextMenuCleanerTab::MenuArea ContextMenuCleanerTab::currentArea() const
{
    // 子页签顺序与 initializeUi 里的建页顺序一致。
    const std::array<MenuArea, 7> ordered{
        MenuArea::InternetExplorer, MenuArea::Desktop, MenuArea::File, MenuArea::UrlBinding,
        MenuArea::OpenWith, MenuArea::FormatMenu, MenuArea::ExplorerHome };

    const int index = m_areaTabWidget != nullptr ? m_areaTabWidget->currentIndex() : 0;
    if (index < 0 || index >= static_cast<int>(ordered.size()))
    {
        return MenuArea::File;
    }
    return ordered[static_cast<std::size_t>(index)];
}

bool ContextMenuCleanerTab::areaSupportsLatencyProbe(const MenuArea area)
{
    ks::window::MenuProbeContext context = ks::window::MenuProbeContext::DesktopBackground;
    return latencyContextForArea(area == MenuArea::Desktop, &context);
}

QVector<ContextMenuCleanerTab::LatencyProbeItem> ContextMenuCleanerTab::collectLatencyProbeItems(
    const MenuArea area, int* truncatedCountOut) const
{
    if (truncatedCountOut != nullptr)
    {
        *truncatedCountOut = 0;
    }

    const AreaWidgets* areaWidgets = widgetsForArea(area);
    QVector<LatencyProbeItem> items;
    if (areaWidgets == nullptr)
    {
        return items;
    }

    // 先按 CLSID 归组：同一个扩展常被注册到多个位置（例如同时挂在 Directory\Background
    // 与 DesktopBackground）。只禁用其中一处时，另一处仍会加载它并照样慢，
    // 差值就会被算成 0 —— 这是"重复注册导致假阴性"的根因，必须整组一起禁用。
    QHash<QString, QStringList> pathsByClsid;
    for (const ContextMenuEntry& entry : areaWidgets->entries)
    {
        if (!entry.clsidText.isEmpty() && !entry.subKeyPath.isEmpty())
        {
            QStringList& paths = pathsByClsid[entry.clsidText.toUpper()];
            if (!paths.contains(entry.subKeyPath))
            {
                paths.append(entry.subKeyPath);
            }
        }
    }

    // 两轮筛选：先收处理器（shellex，最可能在菜单构建时做重活），再收静态动词。
    const auto collectPass = [&](const bool handlerPass)
    {
        for (int index = 0; index < areaWidgets->entries.size(); ++index)
        {
            const ContextMenuEntry& entry = areaWidgets->entries.at(index);
            // 只有 ContextMenuHandlers 里的处理器才用"把默认值（CLSID）置空"来禁用；
            // 其余（静态动词、带 DelegateExecute 的动词、IE MenuExt）都用 LegacyDisable。
            // 注意：不能只看 clsidText 是否为空 —— DelegateExecute 动词也带 CLSID，
            // 若按处理器处理就会"改了默认值但其实没禁用"，那条永远只会测出「很短」（假阴性）。
            const bool isHandler = entry.entryKind.contains(QStringLiteral("shellex"), Qt::CaseInsensitive);
            if (isHandler != handlerPass)
            {
                continue;
            }

            LatencyProbeItem item;
            item.entryIndex = index;
            item.itemName = entry.itemName;
            item.displayName = entry.displayName.isEmpty() ? entry.itemName : entry.displayName;
            item.subKeyPath = entry.subKeyPath;
            item.kind = entry.entryKind;
            item.isHandler = isHandler;
            // 处理器：把同 CLSID 的所有注册路径都带上；动词没有 CLSID，只测它自己。
            if (isHandler && !entry.clsidText.isEmpty())
            {
                item.aliasPaths = pathsByClsid.value(entry.clsidText.toUpper());
            }
            if (item.aliasPaths.isEmpty() && !item.subKeyPath.isEmpty())
            {
                item.aliasPaths.append(item.subKeyPath);
            }
            if (!item.subKeyPath.isEmpty())
            {
                items.push_back(item);
            }
        }
    };
    collectPass(true);
    collectPass(false);

    if (items.size() > kMaxProbeItems)
    {
        if (truncatedCountOut != nullptr)
        {
            *truncatedCountOut = items.size() - kMaxProbeItems;
        }
        items.resize(kMaxProbeItems);
    }
    return items;
}

void ContextMenuCleanerTab::startLatencyMeasurement()
{
    // 已经在跑就不重复启动。
    if (m_latencyRunning.load())
    {
        return;
    }

    const MenuArea area = currentArea();
    ks::window::MenuProbeContext probeContext = ks::window::MenuProbeContext::DesktopBackground;
    if (!latencyContextForArea(area == MenuArea::Desktop, &probeContext))
    {
        QMessageBox::information(this, QStringLiteral("测量菜单耗时"),
            QStringLiteral("当前分类没有可程序化触发的右键菜单，无法测量：\n\n"
                           "· 桌面右键菜单：可测（对应桌面空白处右键）\n"
                           "· 文件 / 格式右键菜单：需要先选中具体文件，本版不支持自动测量\n"
                           "· IE 右键菜单：IE 已废弃且需要 IE 窗口\n"
                           "· URL 绑定 / 文件打开方式 / 资源管理器主页：这些是关联或命名空间，不是右键菜单"));
        return;
    }

    const unsigned long explorerPid = resolveExplorerPid();
    if (explorerPid == 0)
    {
        QMessageBox::warning(this, QStringLiteral("测量菜单耗时"),
            QStringLiteral("找不到资源管理器进程，无法测量。"));
        return;
    }

    // 用户确认：测量会短暂弹出菜单，并且会临时改注册表（测完立刻还原）。
    const QMessageBox::StandardButton confirm = QMessageBox::question(
        this,
        QStringLiteral("测量菜单耗时"),
        QStringLiteral("测量过程会：\n1) 自动导出整份右键菜单注册表备份（防意外）；\n2) 反复短暂弹出桌面右键菜单并自动关闭（不注入鼠标键盘）；\n3) 逐条临时禁用菜单项后复测，随后立即还原。\n\n耗时取决于菜单本身快慢：整轮有总时长预算（约 3 分钟），预算内测不完的条目会列入未测，不再拖长时间。开始吗？"),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::Yes);
    if (confirm != QMessageBox::Yes)
    {
        return;
    }

    // 开测前先落一份文件备份：这是崩溃兜底的关键一步。
    const QString backupPath = backupContextMenuToFile(false);

    int truncatedCount = 0;
    const QVector<LatencyProbeItem> items = collectLatencyProbeItems(area, &truncatedCount);
    if (items.isEmpty())
    {
        QMessageBox::information(this, QStringLiteral("测量菜单耗时"),
            QStringLiteral("当前分类还没有可测条目，请先点「刷新」枚举一次。"));
        return;
    }

    m_latencyCancelRequested.store(false);
    m_latencyRunning.store(true);
    setLatencyUiRunning(true);

    // kProgress 需要在 UI 线程建卡片；set 自带锁，后台线程可以更新它。
    m_latencyProgressPid = kPro.add(this, "Shell 菜单耗时测量",
        "准备基准测量");

    kLogEvent event;
    info << event << "[ContextMenuCleanerTab] 开始菜单耗时测量: area="
         << areaTitle(area).toStdString() << ", items=" << items.size()
         << ", 备份=" << backupPath.toStdString() << eol;

    QPointer<ContextMenuCleanerTab> guardThis(this);
    QThreadPool::globalInstance()->start(
        [guardThis, area, probeContext, explorerPid, items, truncatedCount, backupPath]()
        {
            // ---- 后台线程：只做测量与数据拼装，不碰任何 Qt 控件 ----
            // 报告刻意保持简短：逐条明细在表格的「耗时」列里，这里只给结论和关键数字。
            QStringList report;
            report.push_back(QStringLiteral("右键菜单耗时测量报告（%1，%2）")
                .arg(QDateTime::currentDateTime().toString(QStringLiteral("yyyy-MM-dd HH:mm:ss")),
                     area == ContextMenuCleanerTab::MenuArea::Desktop
                         ? QStringLiteral("桌面右键菜单") : QStringLiteral("其它分类")));
            if (!backupPath.isEmpty())
            {
                report.push_back(QStringLiteral("已先备份整份菜单：%1").arg(backupPath));
            }

            // 基准：菜单完整弹出耗时（含显示阶段）+ 进程 CPU 归因。
            const ks::window::MenuProbeMeasurement baseline = ks::window::MeasureMenuOpenLatency(
                probeContext, explorerPid,
                ks::window::MenuProbeOptions{ kBaselineSamples, 8000, kProbeGapMs });

            // 用最小值当基准：外部干扰只会让耗时变长，最小值最接近"这菜单本来要多久"。
            const double baselineMs = baseline.minMs;
            // 门限 = max(50 ms, 本次实测的噪声底噪)。低于门限的差异分不出真假，
            // 一律按「很短」处理 —— 不显示数值，也不计入可归因合计。
            // 这一步直接解决"一片 100 ms+"的问题：那些数字本来就是抖动，不是贡献。
            const double noiseSpreadMs = std::max(0.0, baseline.maxMs - baseline.minMs);
            const double thresholdMs = std::max(kLatencyShortThresholdMs, noiseSpreadMs);

            report.push_back(QStringLiteral("基准：最短 %1 / 中位 %2 / 最长 %3（弹出 %4 次）")
                .arg(formatMilliseconds(baseline.minMs))
                .arg(formatMilliseconds(baseline.medianMs))
                .arg(formatMilliseconds(baseline.maxMs))
                .arg(baseline.samples.size()));
            if (baseline.processCpuMeasured)
            {
                report.push_back(QStringLiteral("判定：%1（explorer CPU 占挂钟 %2%）")
                    .arg(verdictText(baseline.verdict))
                    .arg(baseline.cpuRatio * 100.0, 0, 'f', 1));
            }
            else
            {
                report.push_back(QStringLiteral("判定：%1").arg(verdictText(baseline.verdict)));
            }
            report.push_back(QStringLiteral("门限：%1（低于它的条目在表格里显示为「很短」）")
                .arg(formatMilliseconds(thresholdMs)));
            if (!baseline.diagnostic.empty())
            {
                report.push_back(QStringLiteral("注意：%1")
                    .arg(QString::fromStdString(baseline.diagnostic)));
            }

            // ---- 逐条差值：每条固定 3 次弹出（禁用前基准 → 禁用期间 → 禁用后基准）----
            // 为什么必须紧邻取基准：这台机器的菜单会被"阵发性卡顿"整体抬高约 2.6 秒，而它自己来自己走。
            // 曾经为了提速只用一个全局参考值，结果某个普通动词恰好在卡顿离开的窗口里被测到，
            // 凭空认领了 1212 ms（正好等于另一个慢扩展的延迟）。紧邻的前后基准能把这类漂移抵消掉，
            // 而 3 次弹出仍比最初的 4 次（禁用期间测 2 次）更快。
            QVector<double> contributions;
            contributions.resize(items.size());
            for (int i = 0; i < contributions.size(); ++i)
            {
                contributions[i] = -1.0;
            }

            const int total = items.size();

            // 时间预算：常规条目只弹出 1 次，按基准单次开销反推本次能测几条。
            const double perItemEstimateMs = std::max(1.0, (baselineMs + static_cast<double>(kProbeGapMs))
                * static_cast<double>(kItemBracketSamples * 2 + kItemMutedSamples));
            int plannedItems = static_cast<int>(
                static_cast<double>(kLatencyBudgetMs) / perItemEstimateMs);
            plannedItems = std::clamp(plannedItems, 1, total);

            int significantCount = 0;   // significantCount：确认后有显著贡献的条目数。
            double attributableMs = 0.0; // attributableMs：可归因到具体条目的耗时合计。
            int aliasGroupCount = 0;    // aliasGroupCount：与其它位置共用同一扩展的条目数。
            int unstableCount = 0;      // unstableCount：因前后基准对不上而被判为"不稳定"的条目数。
            QStringList unreverted;

            // DisabledEntry：一条被临时禁用的注册项及其还原所需信息。
            struct DisabledEntry
            {
                QString path;            // path：被改动的 HKCU 覆盖路径。
                QString originalValue;   // originalValue：改动前的默认值（空表示原本没有值）。
                bool keyCreated = false; // keyCreated：该 HKCU 键是否本次新建。
            };

            // 把"禁用整组 → 测量 → 还原整组"收成一个 lambda，常规轮与确认轮共用。
            const auto measureWithItemDisabled =
                [&](const ContextMenuCleanerTab::LatencyProbeItem& item,
                    const int mutedSamples,
                    double* mutedMsOut,
                    int* disabledPathCountOut,
                    bool* aliasGroupUsedOut) -> bool
            {
                QVector<DisabledEntry> disabledEntries;
                for (const QString& aliasPath : item.aliasPaths)
                {
                    DisabledEntry record;
                    record.path = aliasPath;
                    if (applyTemporaryDisable(aliasPath, item.isHandler,
                            &record.originalValue, &record.keyCreated))
                    {
                        disabledEntries.push_back(record);
                    }
                }
                if (disabledEntries.isEmpty())
                {
                    return false; // 一处都没禁用成功 → 本条不改判定。
                }
                if (disabledPathCountOut != nullptr)
                {
                    *disabledPathCountOut = disabledEntries.size();
                }
                if (aliasGroupUsedOut != nullptr && disabledEntries.size() > 1)
                {
                    *aliasGroupUsedOut = true;
                }

                const ks::window::MenuProbeMeasurement muted = ks::window::MeasureMenuOpenLatency(
                    probeContext, explorerPid,
                    ks::window::MenuProbeOptions{ mutedSamples, 8000, kProbeGapMs });

                // 无论测量结果如何都必须还原：这是"绝不留下残疾菜单"的底线。
                for (const DisabledEntry& record : disabledEntries)
                {
                    if (!revertTemporaryDisable(record.path, item.isHandler,
                            record.originalValue, record.keyCreated))
                    {
                        unreverted.push_back(record.path);
                    }
                }

                if (!muted.attempted || muted.samples.empty())
                {
                    return false;
                }
                if (mutedMsOut != nullptr)
                {
                    *mutedMsOut = muted.minMs;
                }
                return true;
            };

            // publishResult：把一条结果立刻推回 UI 线程 —— "测完一条填一条"。
            const auto publishResult = [&](const int entryIndex, const double valueMs)
            {
                if (guardThis.isNull())
                {
                    return;
                }
                QMetaObject::invokeMethod(guardThis, [guardThis, area, entryIndex, valueMs]()
                    {
                        if (!guardThis.isNull())
                        {
                            guardThis->applySingleLatencyResult(area, entryIndex, valueMs);
                        }
                    }, Qt::QueuedConnection);
            };


            for (int index = 0; index < plannedItems; ++index)
            {
                if (guardThis.isNull())
                {
                    break;
                }
                if (guardThis->m_latencyCancelRequested.load())
                {
                    break;
                }

                const ContextMenuCleanerTab::LatencyProbeItem& item = items.at(index);
                if (guardThis->m_latencyProgressPid > 0)
                {
                    kPro.set(guardThis->m_latencyProgressPid,
                        QStringLiteral("正在测：%1 (%2/%3)")
                            .arg(item.displayName).arg(index + 1).arg(plannedItems).toStdString(),
                        0, static_cast<float>(index) / static_cast<float>(plannedItems));
                }

                // A：禁用前的基准（紧邻参照之一）。
                const ks::window::MenuProbeMeasurement before = ks::window::MeasureMenuOpenLatency(
                    probeContext, explorerPid,
                    ks::window::MenuProbeOptions{ kItemBracketSamples, 8000, kProbeGapMs });

                double mutedMs = 0.0;
                int disabledPathCount = 0;
                bool aliasGroupUsed = false;
                if (!measureWithItemDisabled(item, kItemMutedSamples, &mutedMs,
                        &disabledPathCount, &aliasGroupUsed))
                {
                    continue;
                }
                if (aliasGroupUsed)
                {
                    ++aliasGroupCount;
                }

                // B：禁用后的基准（紧邻参照之二）。
                const ks::window::MenuProbeMeasurement after = ks::window::MeasureMenuOpenLatency(
                    probeContext, explorerPid,
                    ks::window::MenuProbeOptions{ kItemBracketSamples, 8000, kProbeGapMs });

                if (!before.attempted || before.samples.empty() ||
                    !after.attempted || after.samples.empty())
                {
                    continue;
                }

                // 参照取紧邻的前后两次基准里更快的一次。
                const double itemReferenceMs = std::min(before.minMs, after.minMs);

                // 稳定性判据：前后两次基准自己就对不上，说明这几秒内外部状态变了
                // （这台机器有"阵发性卡顿"，会自己来自己走）。此时这条的差值不可信 ——
                // 宁可标成「不稳定」也不能写一个数字，否则会把"卡顿离开"记到这一条头上
                // （实测出现过普通动词被报成 1212 ms，正好等于另一个慢扩展的延迟）。
                if (std::abs(before.minMs - after.minMs) > thresholdMs)
                {
                    contributions[index] = -1.0;
                    publishResult(item.entryIndex, -1.0);
                    ++unstableCount;
                    continue;
                }

                const double rawContribution = itemReferenceMs - mutedMs;
                contributions[index] = rawContribution > thresholdMs ? rawContribution : 0.0;
                // 测完一条立刻填一条，不等整轮结束。
                publishResult(item.entryIndex, contributions[index]);
            }

            // 汇总：只统计超过门限的条目。
            for (const double value : contributions)
            {
                if (value > 0.0)
                {
                    ++significantCount;
                    attributableMs += value;
                }
            }
            const double residualMs = std::max(0.0, baselineMs - attributableMs);
            const int notPlannedCount = total - plannedItems;

            // 报告只留结论与关键数字；逐条明细在表格「耗时」列里（很短 = 无可测贡献）。
            report.push_back(QStringLiteral("逐条：共测 %1 项，其中 %2 项有显著贡献，%3 项因状态不稳定跳过，合计 %4")
                .arg(plannedItems).arg(significantCount).arg(unstableCount)
                .arg(formatMilliseconds(attributableMs)));
            report.push_back(QStringLiteral("残差：%1（基准里无法归因到单条扩展的部分）")
                .arg(formatMilliseconds(residualMs)));
            report.push_back(QString());
            report.push_back(QStringLiteral("结论：%1").arg(
                residualMs > attributableMs
                    ? QStringLiteral("主要不是某一条菜单扩展的问题，优先按上面的判定方向排查；表格里显示「很短」的条目可以直接排除。")
                    : QStringLiteral("耗时主要落在标红的条目上，可优先禁用它们后再测一次。")));
            if (notPlannedCount > 0)
            {
                report.push_back(QStringLiteral("未测：%1 项（超出本次时间预算）").arg(notPlannedCount));
            }
            if (aliasGroupCount > 0)
            {
                report.push_back(QStringLiteral("已按 CLSID 归组：%1 条与其它位置共用同一扩展，禁用时一并处理。")
                    .arg(aliasGroupCount));
            }
            if (truncatedCount > 0)
            {
                report.push_back(QStringLiteral("未测：另有 %1 项（超出单次测量上限）").arg(truncatedCount));
            }
            if (!unreverted.isEmpty())
            {
                report.push_back(QStringLiteral("警告：%1 项未能还原，请用「恢复备份」兜底")
                    .arg(unreverted.size()));
            }
            report.push_back(QString());
            report.push_back(QStringLiteral("明细见表格「耗时」列。"));

            // ---- 回主线程应用结果 ----
            const QString reportText = report.join(QLatin1Char('\n'));
            if (!guardThis.isNull())
            {
                QMetaObject::invokeMethod(guardThis, [guardThis, area, baselineMs,
                    contributions, reportText]()
                    {
                        if (!guardThis.isNull())
                        {
                            guardThis->applyLatencyResults(area, baselineMs, contributions, reportText);
                        }
                    }, Qt::QueuedConnection);
            }
        });
}

void ContextMenuCleanerTab::cancelLatencyMeasurement()
{
    if (m_latencyRunning.load())
    {
        m_latencyCancelRequested.store(true);
        if (m_latencyStatusLabel != nullptr)
        {
            m_latencyStatusLabel->setText(QStringLiteral("正在停止测量（等待当前一项测完）…"));
        }
    }
}

void ContextMenuCleanerTab::applyLatencyResults(
    const MenuArea area,
    const double baselineMs,
    const QVector<double>& perEntryMs,
    const QString& report)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets != nullptr && areaWidgets->table != nullptr)
    {
        // 把逐条贡献写进耗时列：超过阈值的用警示色标红，便于一眼看出该从哪里下手。
        for (int row = 0; row < areaWidgets->table->rowCount(); ++row)
        {
            QTableWidgetItem* anchorItem = areaWidgets->table->item(row, kColumnName);
            if (anchorItem == nullptr)
            {
                continue;
            }
            const int entryIndex = anchorItem->data(Qt::UserRole).toInt();
            if (entryIndex < 0 || entryIndex >= perEntryMs.size())
            {
                continue;
            }
            const double value = perEntryMs.at(entryIndex);
            if (value < 0.0)
            {
                continue; // 未测（本轮时间预算没轮到它）。
            }
            writeLatencyCell(areaWidgets, row, value);
        }
    }

    // 报告写进详情编辑器：复用上一轮接好的详情布局系统（四种布局都生效）。
    if (areaWidgets != nullptr && areaWidgets->detailEditor != nullptr)
    {
        areaWidgets->detailEditor->setText(report);
    }
    if (m_latencyStatusLabel != nullptr)
    {
        m_latencyStatusLabel->setText(QStringLiteral("测量完成：基准 %1，明细见下方详情区")
            .arg(formatMilliseconds(baselineMs)));
    }

    if (m_latencyProgressPid > 0)
    {
        kPro.set(m_latencyProgressPid, "测量完成", 0, 1.0f);
        m_latencyProgressPid = 0;
    }

    m_latencyRunning.store(false);
    m_latencyCancelRequested.store(false);
    setLatencyUiRunning(false);
}

void ContextMenuCleanerTab::writeLatencyCell(
    AreaWidgets* widgets, const int row, const double valueMs) const
{
    if (widgets == nullptr || widgets->table == nullptr || row < 0 ||
        row >= widgets->table->rowCount())
    {
        return;
    }

    QTableWidgetItem* latencyItem = widgets->table->item(row, kColumnLatency);
    if (latencyItem == nullptr)
    {
        latencyItem = new QTableWidgetItem();
        widgets->table->setItem(row, kColumnLatency, latencyItem);
    }

    // 低于门限的贡献一律显示「很短」：不给用户一串分不出真假的毫秒数。
    // 负值表示"未测"（时间预算没轮到，或前后基准对不上判定为不稳定）。
    const bool measured = valueMs >= 0.0;
    const bool significant = valueMs > 0.0;
    if (!measured)
    {
        latencyItem->setText(QStringLiteral("不稳定"));
        latencyItem->setToolTip(QStringLiteral(
            "这一条测量期间前后基准对不上（外部状态在变），差值不可信，故不给出数值"));
    }
    else
    {
        latencyItem->setText(significant ? formatMilliseconds(valueMs) : QStringLiteral("很短"));
        latencyItem->setToolTip(significant
            ? QStringLiteral("禁用这一条后整个菜单变快了这么多（超过本次噪声门限，可作参考）")
            : QStringLiteral("贡献低于本次测量的门限（噪声底噪或 50 ms），视为没有可测影响"));
    }

    QFont font = latencyItem->font();
    if (significant)
    {
        // 值得看的条目标红加粗：用主题的语义错误色，浅色/深色主题下都可读。
        latencyItem->setForeground(QBrush(QColor(KswordTheme::ErrorHex())));
        font.setBold(true);
    }
    else
    {
        // 未超门限的用次要文字色。必须用 *ColorHex() 这种"具体 #RRGGBB"访问器：
        // TextSecondaryHex() 返回的是 palette(...) 动态令牌，只适合塞进样式表，
        // 用 QColor 解析会得到无效颜色（工程的主题令牌审计会直接拦下）。
        latencyItem->setForeground(QBrush(QColor(KswordTheme::TextSecondaryColorHex())));
        font.setBold(false);
    }
    latencyItem->setFont(font);
}

void ContextMenuCleanerTab::applySingleLatencyResult(
    const MenuArea area, const int entryIndex, const double valueMs)
{
    // "测完一条填一条"：只按 entries 下标定位那一行，不动其它行、不重建表格。
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr || entryIndex < 0)
    {
        return;
    }
    const int rowCount = areaWidgets->table->rowCount();
    for (int row = 0; row < rowCount; ++row)
    {
        const QTableWidgetItem* anchorItem = areaWidgets->table->item(row, kColumnName);
        if (anchorItem == nullptr ||
            anchorItem->data(Qt::UserRole).toInt() != entryIndex)
        {
            continue;
        }
        writeLatencyCell(areaWidgets, row, valueMs);
        return;
    }
    // 该条目当前被筛选/未显示在表格里：结果留在最终的统一写入里体现，不算错误。
}

void ContextMenuCleanerTab::clearLatencyColumn(const MenuArea area)
{
    AreaWidgets* areaWidgets = widgetsForArea(area);
    if (areaWidgets == nullptr || areaWidgets->table == nullptr)
    {
        return;
    }
    const int rowCount = areaWidgets->table->rowCount();
    for (int row = 0; row < rowCount; ++row)
    {
        if (QTableWidgetItem* latencyItem = areaWidgets->table->item(row, kColumnLatency);
            latencyItem != nullptr)
        {
            latencyItem->setText(QString());
            latencyItem->setToolTip(QString());
        }
    }
}

void ContextMenuCleanerTab::setLatencyUiRunning(const bool running)
{
    if (m_latencyButton != nullptr)
    {
        m_latencyButton->setEnabled(!running);
    }
    if (m_latencyStopButton != nullptr)
    {
        m_latencyStopButton->setEnabled(running);
    }

    // 测量期间禁用各分类的刷新/删除/筛选/复制：避免表格被重建，把逐条结果冲掉。
    const std::array<MenuArea, 7> allAreas{
        MenuArea::InternetExplorer, MenuArea::Desktop, MenuArea::File, MenuArea::UrlBinding,
        MenuArea::OpenWith, MenuArea::FormatMenu, MenuArea::ExplorerHome };
    for (const MenuArea area : allAreas)
    {
        AreaWidgets* widgets = widgetsForArea(area);
        if (widgets == nullptr)
        {
            continue;
        }
        if (widgets->refreshButton != nullptr)
        {
            widgets->refreshButton->setEnabled(!running);
        }
        if (widgets->deleteButton != nullptr)
        {
            widgets->deleteButton->setEnabled(!running);
        }
        if (widgets->copyButton != nullptr)
        {
            widgets->copyButton->setEnabled(!running);
        }
        if (widgets->filterEdit != nullptr)
        {
            widgets->filterEdit->setEnabled(!running);
        }
        if (widgets->restoreButton != nullptr)
        {
            widgets->restoreButton->setEnabled(!running);
        }
    }
}

}  // namespace ks::misc
