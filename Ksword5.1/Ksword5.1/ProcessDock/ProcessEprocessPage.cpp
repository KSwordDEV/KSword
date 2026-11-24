#include "ProcessEprocessPage.h"
#include "KernelStructureTree.h"
#include "KernelStructureLiveSample.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ToolbarMetrics.h"

#include <QCoreApplication>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QSortFilterProxyModel>
#include <QStandardItemModel>
#include <QTabWidget>
#include <QThreadPool>
#include <QTreeView>
#include <QVBoxLayout>
#include <cstring>
#include <limits>

namespace
{
    namespace structure = ks::ui::kernelstructure; // 共享精确布局、现场投影与五列树入口。

    struct Snapshot
    {
        structure::Layout layout; // 磁盘布局独立于现场进程读取是否成功。
        structure::Samples live; // 只收录驱动明确报告来源和有效性的字段。
        structure::LiveSample body; // 优先采用的新正文采样；失败原因在固定回退成功时仍保留。
        std::uint64_t base = 0; // 已复核对象的 EPROCESS 基址。
    };

    // 将固定回执中的地址和值格式化；不解引用指针。
    QString Hex(const std::uint64_t value, const int width = 0)
    {
        return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), width, 16, QLatin1Char('0'));
    }

    // 工作线程输入入口冻结的目标；优先返回同次正文投影，仅正文不可用时读取固定详情。
    Snapshot ReadSnapshot(const structure::LiveTarget& target)
    {
        Snapshot result; // R0 不可用时仍返回完整磁盘符号布局。
        result.layout = structure::LoadLayout(ks::threadlayout::Kind::Process);
        result.body = structure::ReadLiveSample(target, result.layout);
        if (result.body.body.identityVerified)
        {
            result.base = result.body.body.response.objectAddress;
            result.live = structure::ProjectedSamples(result.layout.profile, result.body.body.projection);
            return result;
        }

        // 旧固定协议没有创建时间回显，必须持有原句柄夹住请求；不混入正文的任何值。
        const auto pid = target.request.processId; // 只使用入口冻结的 PID，不读取变化中的列表选择。
        if (!target.process.isValid() || !structure::LiveTargetRunning(target))
        {
            return result;
        }
        const auto reply = ksword::ark::DriverClient().queryProcessRuntimeDetail(pid); // 仅使用固定只读协议。
        const auto& data = reply.response; // 因 PID 回收导致的旧回执不入表。
        if (!reply.io.ok || data.version != KSWORD_ARK_RUNTIME_DETAIL_PROTOCOL_VERSION || data.processId != pid ||
            !structure::LiveTargetRunning(target))
        {
            return result;
        }
        if (data.fieldFlags & KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_ADDRESS)
        {
            result.base = data.processObjectAddress;
        }
        const auto& at = data.offsets; // 每个固定字段单独验证偏移来源。
        const auto& from = data.sources; // 各字段的独立来源，不能用字段值非零代替有效性。
        // 输入固定协议字段与显示文本；仅将有效且有来源的字段加入本轮回退表，不返回值。
        const auto add = [&](const unsigned long flag, const unsigned long offset, const unsigned long source,
            const QString& name, const QString& type, const QString& value)
        {
            if ((data.fieldFlags & flag) && source != KSW_DYN_FIELD_SOURCE_UNAVAILABLE &&
                offset != KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE)
            {
                result.live.insert(name, {static_cast<std::uint32_t>(offset), value, type});
            }
        };
        // 输入两个链表指针数值，返回可复制文本；不读取任何相邻节点。
        const auto links = [](const std::uint64_t first, const std::uint64_t second)
        {
            return QStringLiteral("Flink %1 / Blink %2").arg(Hex(first), Hex(second));
        };
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_UNIQUE_PROCESS_ID, at.epUniqueProcessId, from.epUniqueProcessId,
            QStringLiteral("UniqueProcessId"), QStringLiteral("HANDLE"), QString::number(data.uniqueProcessIdValue));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_ACTIVE_PROCESS_LINKS, at.epActiveProcessLinks, from.epActiveProcessLinks,
            QStringLiteral("ActiveProcessLinks"), QStringLiteral("_LIST_ENTRY"), links(data.activeProcessLinksFlink, data.activeProcessLinksBlink));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_THREAD_LIST_HEAD, at.epThreadListHead, from.epThreadListHead,
            QStringLiteral("ThreadListHead"), QStringLiteral("_LIST_ENTRY"), links(data.threadListHeadFlink, data.threadListHeadBlink));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_IMAGE_FILE_NAME, at.epImageFileName, from.epImageFileName,
            QStringLiteral("ImageFileName"), QStringLiteral("char[]"), QString::fromLatin1(data.imageName,
                static_cast<qsizetype>(strnlen_s(data.imageName, sizeof(data.imageName)))));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_TOKEN_FASTREF, at.epToken, from.epToken,
            QStringLiteral("Token"), QStringLiteral("_EX_FAST_REF"), Hex(data.tokenFastRef));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_OBJECT_TABLE, at.epObjectTable, from.epObjectTable,
            QStringLiteral("ObjectTable"), QStringLiteral("_HANDLE_TABLE*"), Hex(data.objectTableAddress));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_OBJECT, at.epSectionObject, from.epSectionObject,
            QStringLiteral("SectionObject"), QStringLiteral("void*"), Hex(data.sectionObjectAddress));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_PROTECTION, at.epProtection, from.epProtection,
            QStringLiteral("Protection"), QStringLiteral("_PS_PROTECTION"), Hex(data.protection, 2));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_SIGNATURE_LEVEL, at.epSignatureLevel, from.epSignatureLevel,
            QStringLiteral("SignatureLevel"), QStringLiteral("UChar"), Hex(data.signatureLevel, 2));
        add(KSWORD_ARK_PROCESS_DETAIL_FIELD_SECTION_SIGNATURE, at.epSectionSignatureLevel, from.epSectionSignatureLevel,
            QStringLiteral("SectionSignatureLevel"), QStringLiteral("UChar"), Hex(data.sectionSignatureLevel, 2));
        return result;
    }

    // 把一个完整的采样批次投影到五列；未命中布局不影响已有固定回执。
    void Publish(QStandardItemModel& model, QTreeView& tree, QSortFilterProxyModel& filter, QLabel& state,
        const std::uint32_t pid, const Snapshot& result)
    {
        const auto empty = QStringLiteral("—"); // 不存在字段地址时保持空证据。
        const auto note = structure::LayoutStatus(result.layout); // 区分磁盘和运行内核符号。
        const bool hasBody = result.body.body.identityVerified; // 正文成功时不再掺入固定回执。
        const auto liveState = ks::i18n::displayText(result.live.isEmpty()
            ? QStringLiteral("现场字段不可用") : QStringLiteral("字段读取成功")); // 固定回退自身的可用状态。
        QString description; // 按用户要求，成功后不再显示覆盖率、符号键和采样时间长横幅。
        if (!hasBody)
        {
            description = structure::DescribeLiveSample(result.body) + QStringLiteral(" · ") +
                ks::i18n::displayText(result.live.isEmpty()
                ? QStringLiteral("仅布局；本次没有可用现场值")
                : QStringLiteral("固定字段回退（独立采样，不与对象体快照合并）"));
        }
        else if (result.body.body.projection.unreadRows)
        {
            description = ks::i18n::displayText(QStringLiteral("部分字段未完整读取：%1"))
                .arg(static_cast<qulonglong>(result.body.body.projection.unreadRows));
        }
        state.setText(description.isEmpty() ? QString() : QStringLiteral("PID %1 · %2").arg(pid).arg(description));
        state.setVisible(!description.isEmpty());
        ks::ui::ApplyStatusRole(&state, hasBody && result.body.body.projection.unreadRows == 0
            ? ks::ui::StatusRole::Info : ks::ui::StatusRole::Warning);
        model.removeRows(0, model.rowCount());
        auto* root = structure::Append(*model.invisibleRootItem(), {empty,
            result.base ? Hex(result.base) : empty, QStringLiteral("EPROCESS"), QStringLiteral("_EPROCESS"), note}); // 本轮对象根。
        if (!result.layout.profile.fields.empty())
        {
            structure::AppendLayout(*root, result.layout, result.base,
                result.layout.runningMatch ? result.live : structure::Samples{});
        }
        structure::AppendCandidates(*root, result.layout.candidates, !result.layout.bracketed);
        if (!hasBody && !result.live.isEmpty())
        {
            auto* fixed = structure::Append(*root, {empty, empty, QStringLiteral("R0"), {}, liveState}); // 独立固定回执分组。
            auto names = result.live.keys(); // 固定回执保证稳定可搜索的顺序。
            names.sort();
            for (const auto& name : names)
            {
                const auto& field = result.live[name]; // 固定驱动提供的偏移和值不借用磁盘布局。
                const auto address = result.base && result.base <= (std::numeric_limits<std::uint64_t>::max)() - field.offset
                    ? Hex(result.base + field.offset) : empty; // 只在加法不溢出时展示字段存储地址。
                structure::Append(*fixed, {Hex(field.offset, 4), address, name, field.type, field.value});
            }
            tree.expand(filter.mapFromSource(fixed->index()));
        }
        if (result.layout.profile.fields.empty() && !result.layout.bracketed)
        {
            structure::ColorUnbracketedTree(*root); // 仅未命中精确布局且缺少双侧参考时，连根项和固定回退一起标黄。
        }
        if (filter.filterRegularExpression().pattern().isEmpty())
        {
            tree.expand(filter.mapFromSource(root->index()));
        }
        else
        {
            tree.expandAll();
        }
    }
}

// 输入承载 Tab 和冻结进程身份；注册惰性 EPROCESS 详情页，控件所有权交给 parent，无返回值。
void AddProcessEprocessPage(QTabWidget& parent, const std::uint32_t pid, const std::uint64_t creationTime)
{
    // 导航：进程详情 → EPROCESS；沿用专业结构树和共享 TablePresentation，不改变外壳。
    const auto target = structure::CaptureLiveTarget(pid, creationTime); // 缺少创建时间只在入口从持有句柄补齐。
    auto* page = new QWidget(&parent); // 父 Tab 管理生命周期及统一的六像素边距。
    page->setObjectName(QStringLiteral("ksword_eprocess_page"));
    page->setProperty("ksword_detail_keep_layout", true);
    auto* layout = new QVBoxLayout(page); // 固定工具带、状态，剩余高度交给树。
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(8);
    auto* toolbar = new QHBoxLayout(); // 与线程结构页一致的刷新和搜索。
    auto* refresh = new QPushButton(QIcon(QStringLiteral(":/Icon/process_refresh.svg")), QStringLiteral("R0 刷新"), page); // 图标与来源标签共同标识只读 R0 刷新。
    refresh->setToolTip(QStringLiteral("重新读取当前进程的只读字段"));
    auto* search = new QLineEdit(page); // 只查询当前结果模型。
    toolbar->addWidget(refresh);
    toolbar->addStretch();
    toolbar->addWidget(search, 1);
    ks::ui::NormalizeToolbarRow(toolbar);
    layout->addLayout(toolbar);
    auto* state = new QLabel(page); // 显示身份、符号来源和现场值可用性。
    state->setTextFormat(Qt::PlainText);
    state->setWordWrap(true);
    state->setTextInteractionFlags(Qt::TextSelectableByMouse);
    layout->addWidget(state);
    auto* tree = new QTreeView(page); // 唯一滚动容器。
    auto* model = new QStandardItemModel(tree); // 规范数据及复制来源。
    auto* filter = new QSortFilterProxyModel(tree); // 搜索保持父项路径。
    structure::Configure(*tree, *model, *filter, *search);
    layout->addWidget(tree, 1);
    parent.addTab(page, QStringLiteral("EPROCESS"));

    // 单个在途后台任务，关窗后不再访问 Qt 控件。
    const auto request = [refresh, state, tree, model, filter, pid, target]() // GUI 发起单次读取，返回值为空。
    {
        if (!refresh->isEnabled())
        {
            return;
        }
        refresh->setEnabled(false);
        state->show();
        state->setText(QStringLiteral("正在读取进程结构…"));
        ks::ui::ApplyStatusRole(state, ks::ui::StatusRole::Info);
        auto* app = QCoreApplication::instance(); // 使用 GUI 线程稳定接收入口。
        const QPointer<QPushButton> button(refresh); // 完成后恢复原刷新入口。
        const QPointer<QLabel> label(state); // 显示当前请求的诊断和采样范围。
        const QPointer<QTreeView> view(tree); // 页面关闭时丢弃在途展示。
        const QPointer<QStandardItemModel> source(model); // 保留原规范模型及其上下文菜单来源。
        const QPointer<QSortFilterProxyModel> proxy(filter); // 保留用户当前筛选条件。
        QThreadPool::globalInstance()->start([app, button, label, view, source, proxy, pid, target]()
        {
            auto snapshot = ReadSnapshot(*target); // 工作线程不创建视图对象，句柄与请求身份一致。
            QMetaObject::invokeMethod(app, [button, label, view, source, proxy, pid, snapshot = std::move(snapshot)]()
            {
                if (button && label && view && source && proxy)
                {
                    Publish(*source, *view, *proxy, *label, pid, snapshot);
                    button->setEnabled(true);
                }
            }, Qt::QueuedConnection);
        });
    };
    QObject::connect(refresh, &QPushButton::clicked, page, request);
    QObject::connect(&parent, &QTabWidget::currentChanged, page, [&parent, page, request, started = false](int index) mutable
    {
        if (!started && parent.widget(index) == page)
        {
            started = true; // 其他三个子页不触发读取。
            request();
        }
    });
}
