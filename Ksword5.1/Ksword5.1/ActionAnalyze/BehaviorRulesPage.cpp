#include "BehaviorRulesPage.h"
#include "../Framework.h"
#include "BehaviorRuleDraft.h"
#include "OfflineSegmentReader.h"
#include "../../../KswordCLI/ActionAnalyze/Rules/BehaviorPresets.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/AsyncOperation.h"
#include "../UI/CodeEditorWidget.h"
#include "../UI/CodeTextEdit.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ThemeStatusRole.h"
#include "../UI/ThemedMessageBox.h"
#include "../UI/ToolbarMetrics.h"
#include "../theme.h"

#include <QDateTime>
#include <QEvent>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QHBoxLayout>
#include <QLabel>
#include <QPointer>
#include <QPushButton>
#include <QSaveFile>
#include <QStringDecoder>
#include <QTextDocument>
#include <QVBoxLayout>

#include <algorithm>
#include <array>

namespace ks::action_analyze
{
namespace
{
    using ks::i18n::sourceText;
    namespace rule = Ksword::ActionAnalyze::Rules;

    enum class Operation { Idle, Open, Save, Validate, Replay, ArchivePresets }; // 单一在途操作的类型。
    enum class FileError { None, FileAccess, Size, Utf8 }; // 可独立本地化的文件错误。

    struct Request
    {
        Operation operation = Operation::Idle; // 用户选择的明确操作。
        QString path; // 打开、保存或检查时冻结的文件身份。
        QString text; // 本次保存或检查用的草稿快照。
        quint64 revision = 0; // 提交时的编辑代次。
    };

    struct FileResult
    {
        FileError error = FileError::None; // 严格区分读写、过大和编码错误。
        QString detail; // Qt 文件系统诊断原文。
        QString text; // 成功打开的原始规则内容。
    };

    struct ArchivePresetCheck
    {
        QString error; // 失败原因的稳定诊断码。
        QString projectId; // Stored 段头内的项目标识。
        QString sampleId; // Stored 段头内的采样标识。
        rule::ApiPresetReport report; // 已分析的单段最近窗口与线索证据。
    };

    struct ArchivePresetCategory
    {
        std::string_view ruleId; // 规则引擎回执中的细分预置 ID。
        bool memoryOperation; // 两组汇总的归属：内存操作或线程控制。
    };

    constexpr std::array kArchivePresetCategories{ // 顺序与下方五类计数文案一致。
        ArchivePresetCategory{"ksword.api.memory-write-observed.v1", true},
        ArchivePresetCategory{"ksword.api.section-map-observed.v1", true},
        ArchivePresetCategory{"ksword.api.thread-create-observed.v1", false},
        ArchivePresetCategory{"ksword.api.thread-context-observed.v1", false},
        ArchivePresetCategory{"ksword.api.apc-queue-observed.v1", false},
    };

    // 从已命中的细分规则定位报告槽位。目录外的 ID 不能归入现有两组。
    std::size_t ArchivePresetCategoryIndex(std::string_view ruleId)
    {
        const auto category = std::find_if(kArchivePresetCategories.begin(), kArchivePresetCategories.end(),
            [ruleId](const ArchivePresetCategory& entry) { return entry.ruleId == ruleId; }); // 末尾表示未登记。
        return static_cast<std::size_t>(category - kArchivePresetCategories.begin());
    }

    // 将严格解析器或规则引擎返回的原始 UTF-8 数据转换为纯文本。
    QString DisplayUtf8(std::string_view bytes)
    {
        return QString::fromUtf8(bytes.data(), static_cast<qsizetype>(bytes.size()));
    }

    // 工作线程从选中的段读取已验证 API Monitor 观测，一次运行得到细分结果。
    ArchivePresetCheck CheckArchivePresets(const Request& request, const ks::ui::AsyncOperationToken& token)
    {
        const auto segment = ReadOfflineSegment(request.path, [&token] { return token.isCanceled(); }); // 本次冻结输入。
        ArchivePresetCheck result; // 输出只保留验证后的证据坐标。
        switch (segment.end)
        {
        case SegmentEnd::Complete: break;
        case SegmentEnd::Unavailable: result.error = QStringLiteral("archive-unavailable"); break;
        case SegmentEnd::Truncated: result.error = QStringLiteral("archive-truncated"); break;
        case SegmentEnd::Invalid: result.error = QStringLiteral("archive-invalid"); break;
        case SegmentEnd::Unsupported: result.error = QStringLiteral("archive-unsupported"); break;
        case SegmentEnd::PreviewLimit: result.error = QStringLiteral("archive-preview-limit"); break;
        case SegmentEnd::Canceled: result.error = QStringLiteral("archive-canceled"); break;
        default: result.error = QStringLiteral("archive-incomplete"); break;
        }
        if (!result.error.isEmpty())
        {
            return result;
        }
        if (!segment.hasArchivedApi || segment.ordinal != 1 || segment.projectId.isEmpty() || segment.sampleId.isEmpty())
        {
            result.error = QStringLiteral("archive-not-api-monitor-import");
            return result;
        }
        result.projectId = segment.projectId;
        result.sampleId = segment.sampleId;

        // 转换后的字符串拥有稳定存储，供同步执行的规则解释器借用。
        std::vector<std::pair<QByteArray, QByteArray>> text; // 逐行持有导出名和已核验分类。
        std::vector<rule::ArchivedApiObservation> observations; // 只读借用视图。
        text.reserve(static_cast<std::size_t>(segment.rows.size()));
        observations.reserve(text.capacity());
        for (const auto& row : segment.rows)
        {
            if (!row.archivedApi || token.isCanceled())
            {
                result.error = token.isCanceled() ? QStringLiteral("archive-canceled") : QStringLiteral("archive-missing-api-row");
                return result;
            }
            const auto& clue = *row.archivedApi; // 归档读侧已根据原包字段核对。
            const auto& [api, family] = text.emplace_back(clue.api.toUtf8(), clue.family.toUtf8());
            observations.push_back({row.sequence, clue.sourceSequence,
                {api.constData(), static_cast<std::size_t>(api.size())},
                {family.constData(), static_cast<std::size_t>(family.size())}});
        }
        const auto database = rule::LoadApiPresetDatabase(); // 本次单段回放使用冻结的规则。
        result.report = rule::AnalyzeArchivedApiPresets(database, observations, segment.verifiedRows, rule::ApiPresetProfile::ByCategory);
        if (result.report.error != rule::ApiPresetError::None)
        {
            result.error = result.report.error == rule::ApiPresetError::InvalidPreset
                ? QStringLiteral("archive-preset-invalid") : QStringLiteral("archive-projection-invalid");
        }
        else if (std::any_of(result.report.matches.begin(), result.report.matches.end(), [](const rule::ApiPresetMatch& hit)
        {
            return ArchivePresetCategoryIndex(hit.ruleId) == kArchivePresetCategories.size();
        }))
        {
            result.error = QStringLiteral("archive-preset-invalid"); // 保留上次成功报告，避免把未知类别计入汇总。
        }
        return result;
    }

    // 结果身份和实际扫描范围随代码编辑器回执保留，方便复制并返回原归档核对。
    QString FormatArchivePresets(const ArchivePresetCheck& result)
    {
        std::array<qulonglong, kArchivePresetCategories.size()> categoryCounts{}; // 同次回放的五类条数。
        qulonglong memoryCount = 0; // 内存操作大类的合计，其余有效分类归入线程控制。
        QStringList evidenceLines; // 按原始顺序保留一份证据行。
        for (const auto& hit : result.report.matches)
        {
            const auto index = ArchivePresetCategoryIndex(hit.ruleId); // 后台发布前已验证类别。
            const bool memory = kArchivePresetCategories[index].memoryOperation; // 此条证据的汇总归属。
            ++categoryCounts[index];
            if (memory)
            {
                ++memoryCount;
            }

            const std::string_view groupId = memory // 保留旧汇总预置 ID，便于搜索历史回执。
                ? "ksword.api.memory-operation-observed.v1" : "ksword.api.thread-control-observed.v1";
            const auto ruleIds = DisplayUtf8(groupId) + QStringLiteral(" · ") + DisplayUtf8(hit.ruleId); // 同一观测的两层分类。
            evidenceLines << sourceText(QStringLiteral("段内序号 %1 · 源行 %2 · %3 · %4"))
                .arg(qulonglong(hit.rawSequence)).arg(qulonglong(hit.sourceSequence))
                .arg(DisplayUtf8(hit.api), ruleIds);
        }

        QStringList lines; // 完整回执文本。
        lines << sourceText(QStringLiteral("项目 %1 · 采样 %2")).arg(result.projectId, result.sampleId);
        lines << sourceText(QStringLiteral("已分析最近 %1 条，共验证 %2 条归档线索。命中 %3 条。"))
            .arg(qulonglong(result.report.analyzedRows)).arg(qulonglong(result.report.importedRows))
            .arg(qulonglong(result.report.matches.size()));
        lines << sourceText(QStringLiteral("汇总：内存操作 %1 条 · 线程控制 %2 条"))
            .arg(memoryCount).arg(qulonglong(result.report.matches.size()) - memoryCount);
        const auto& [writes, maps, creates, contexts, apcs] = categoryCounts; // 按摘要顺序展开五个计数槽位。
        lines << sourceText(QStringLiteral("细分：内存写入 %1 条 · 节映射 %2 条 · 线程创建 %3 条 · 线程上下文修改 %4 条 · APC 入队 %5 条"))
            .arg(writes).arg(maps).arg(creates).arg(contexts).arg(apcs);
        lines << sourceText(QStringLiteral("以下为 API 观测。目标身份、调用效果和采集覆盖未知。"));
        lines.append(evidenceLines);
        return lines.join(QLatin1Char('\n'));
    }

    // 在线程池读取用户选定的文件。失败时返回值诊断，原草稿由 UI 保留。
    FileResult ReadDraft(const Request& request)
    {
        QFile file(request.path); // 这次显式选择的文件读取句柄。
        if (!file.open(QIODevice::ReadOnly))
        {
            return {FileError::FileAccess, file.errorString(), {}};
        }
        const auto bytes = file.read(static_cast<qint64>(BehaviorRuleMaxBytes) + 1); // 有界 UTF-8 读取。
        if (file.error() != QFileDevice::NoError)
        {
            return {FileError::FileAccess, file.errorString(), {}};
        }
        if (bytes.size() > static_cast<qsizetype>(BehaviorRuleMaxBytes))
        {
            return {FileError::Size, {}, {}};
        }
        QStringDecoder decoder(QStringDecoder::Utf8, QStringConverter::Flag::Stateless); // 一次解码并检查尾字节。
        const QString text = decoder.decode(bytes);
        if (decoder.hasError())
        {
            return {FileError::Utf8, {}, {}};
        }
        return {FileError::None, {}, text};
    }

    // 在线程池原子写入冻结快照。文件错误时保持原有目标内容。
    FileResult SaveDraft(const Request& request)
    {
        const auto bytes = request.text.toUtf8(); // 本次明确提交的 UTF-8 字节。
        if (bytes.size() > static_cast<qsizetype>(BehaviorRuleMaxBytes))
        {
            return {FileError::Size, {}, {}};
        }
        QSaveFile file(request.path); // 原子写入事务，提交前保留原文件。
        if (!file.open(QIODevice::WriteOnly) || file.write(bytes) != bytes.size() || !file.commit())
        {
            return {FileError::FileAccess, file.errorString(), {}};
        }
        return {};
    }

    // 建立可正常换行的纯文本提示。文件路径和诊断原文始终作为纯文本显示。
    QLabel* WrappedLabel(QWidget* parent)
    {
        auto* label = new QLabel(parent); // 页面拥有的说明或状态标签。
        label->setTextFormat(Qt::PlainText);
        label->setWordWrap(true);
        label->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        label->setTextInteractionFlags(Qt::TextSelectableByMouse | Qt::TextSelectableByKeyboard);
        return label;
    }

    // 将规则回放的三值结果映射为可直接阅读的判定。
    QString TruthText(rule::Truth truth)
    {
        switch (truth)
        {
        case rule::Truth::True: return sourceText(QStringLiteral("命中"));
        case rule::Truth::False: return sourceText(QStringLiteral("未命中"));
        default: return sourceText(QStringLiteral("未知"));
        }
    }

    // 独立呈现引擎原因。代码可用于搜索、复制或和规则引擎回执对照。
    QString IssueCodes(rule::ReplayIssue flags)
    {
        constexpr std::pair<rule::ReplayIssue, const char*> entries[] = { // 原因到稳定码的对应表。
            {rule::ReplayIssue::Coverage, "coverage"}, {rule::ReplayIssue::ActorThread, "actor-thread"},
            {rule::ReplayIssue::Clock, "clock"}, {rule::ReplayIssue::Order, "order"},
            {rule::ReplayIssue::PredicateUnknown, "predicate-unknown"},
            {rule::ReplayIssue::PredicateInvalid, "predicate-invalid"},
            {rule::ReplayIssue::Budget, "budget"}, {rule::ReplayIssue::WindowLimit, "window-limit"}
        };
        QStringList codes; // 当前窗口或整次回放中实际出现的原因。
        for (const auto& [issue, code] : entries) // 逐一检查引擎位字段。
        {
            if (rule::HasIssue(flags, issue))
            {
                codes.append(QString::fromLatin1(code));
            }
        }
        return codes.join(QStringLiteral(", "));
    }

    // 生成可复制和导出的完整文本回执，包括每个窗口和证据序号。
    QString FormatCheck(const BehaviorRuleCheck& result)
    {
        QStringList lines; // 回执的可读行，按引擎输出顺序排列。
        if (!result.ruleId.empty())
        {
            lines << sourceText(QStringLiteral("规则 ID：%1")).arg(DisplayUtf8(result.ruleId));
        }
        if (!result.error.empty())
        {
            lines << sourceText(QStringLiteral("规则检查失败：%1")).arg(DisplayUtf8(result.error));
            if (result.offset)
            {
                lines << sourceText(QStringLiteral("UTF-8 字节偏移：%1")).arg(qulonglong(*result.offset));
            }
            if (!result.pointer.empty())
            {
                lines << sourceText(QStringLiteral("JSON 路径：%1")).arg(DisplayUtf8(result.pointer));
            }
            if (result.expressionLocation)
            {
                const auto& point = *result.expressionLocation; // 解码后谓词自身的位置。
                lines << sourceText(QStringLiteral("谓词位置：第 %1 行，第 %2 字节列（偏移 %3，长度 %4）"))
                    .arg(qulonglong(point.line)).arg(qulonglong(point.byteColumn))
                    .arg(qulonglong(point.offset)).arg(qulonglong(point.length));
            }
            return lines.join(QLatin1Char('\n'));
        }
        lines << sourceText(QStringLiteral("规则校验通过。"));
        lines << sourceText(QStringLiteral("合成事件：%1 条")).arg(qulonglong(result.eventCount));
        if (!result.replay)
        {
            return lines.join(QLatin1Char('\n'));
        }

        // 无锚点、含未知判定、成功命中显示为不同的回执。
        const auto& replay = *result.replay; // 当前实际执行结果。
        if (replay.windows.empty())
        {
            lines << sourceText(QStringLiteral("回放未产生锚点窗口。"));
        }
        else
        {
            lines << sourceText(QStringLiteral("锚点窗口：%1 个")).arg(qulonglong(replay.windows.size()));
        }
        if (replay.duplicateEvents)
        {
            lines << sourceText(QStringLiteral("合并重复事件：%1 条")).arg(qulonglong(replay.duplicateEvents));
        }
        const auto runIssues = IssueCodes(replay.issues); // 整次运行中出现的原因。
        if (!runIssues.isEmpty())
        {
            lines << sourceText(QStringLiteral("回放诊断：%1")).arg(runIssues);
        }

        // 每个锚点显示可比较区间、三值结果和确证的步骤证据。
        for (const auto& window : replay.windows) // 引擎的一个锚点窗口结果。
        {
            lines << QString();
            lines << sourceText(QStringLiteral("锚点 %1：%2"))
                .arg(qulonglong(window.anchorOrdinal)).arg(TruthText(window.truth));
            if (window.range)
            {
                lines << sourceText(QStringLiteral("时间范围（100 ns）：[%1, %2]"))
                    .arg(qulonglong(window.range->start100ns)).arg(qulonglong(window.range->end100ns));
            }
            const auto issues = IssueCodes(window.issues); // 当前锚点中的诊断码。
            if (!issues.isEmpty())
            {
                lines << sourceText(QStringLiteral("窗口诊断：%1")).arg(issues);
            }
            if (!window.stepOrdinals.empty())
            {
                QStringList steps; // 确认匹配的证据序号。
                for (const auto ordinal : window.stepOrdinals) // 当前窗口中的一条实际证据。
                {
                    steps << QString::number(qulonglong(ordinal));
                }
                lines << sourceText(QStringLiteral("步骤证据：%1")).arg(steps.join(QStringLiteral(", ")));
            }
        }
        return lines.join(QLatin1Char('\n'));
    }

    class BehaviorRulesPage final : public QWidget
    {
    public:
        // 接入共享参数/动作/结果框架，初始草稿为实际可执行的合成例子。
        explicit BehaviorRulesPage(QWidget* parent);
        ~BehaviorRulesPage() override;

    protected:
        // 语言热切换时重投影自己的文案，保留规则原文和检查快照。
        void changeEvent(QEvent* event) override;

    private:
        // 更新控件文字和冻结回执，供首次构造及语言切换调用。
        void retranslate();
        // 依据真实操作状态和未保存标记，更新按钮与身份标签。
        void refreshState();
        // 操作回执独立显示，输入改动只更新最新结果是否仍对应当前草稿。
        void refreshReportIdentity();
        // 用户明确选择打开外部规则文件，失败时保留原草稿。
        void open();
        // 保存当前冻结草稿，首次保存让用户选择明确路径。
        void save();
        // 将当前草稿提交到实际规则准备器，可选运行合成回放。
        void check(Operation operation);
        // 选择一个已导入的 API Monitor 数据段并运行只读预置。
        void archivePresets();
        // 发布一次文件级回执。request 含提交时的操作和草稿版本。
        void applyFile(const Request& request, const FileResult& result);
        // 返回本次请求的正文。未编辑时沿用原始换行，编辑后保留普通空格和不换行空格的区别。
        QString currentDraftText() const;
        // 根据文件操作和文件错误类型提供本地化状态。
        QString fileStatus() const;

        ks::ui::AsyncOperation* m_worker = nullptr; // 唯一在途处理器，析构时关闭。
        CodeTextEdit* m_draft = nullptr; // 共享代码编辑核心，文件动作归本页所有。
        CodeEditorWidget* m_report = nullptr; // 支持查找、复制和导出的只读回执。
        QLabel* m_title = nullptr; // 当前规则草稿的段落名称。
        QLabel* m_help = nullptr; // 草稿约束与回放范围说明。
        QLabel* m_draftIdentity = nullptr; // 当前文件路径、未保存状态。
        QLabel* m_progress = nullptr; // 当前操作或文件回执状态。
        QLabel* m_reportIdentity = nullptr; // 最近一次检查/回放的提交来源和时间。
        QPushButton* m_open = nullptr; // 打开源文件，切换前确认未保存改动。
        QPushButton* m_save = nullptr; // 原子保存当前草稿。
        QPushButton* m_validate = nullptr; // 类型化校验动作。
        QPushButton* m_replay = nullptr; // 校验并运行合成回放。
        QPushButton* m_archivePresets = nullptr; // 归档输入和预置回放入口。
        Operation m_operation = Operation::Idle; // 当前完成前保持的工作类型。
        Operation m_lastFileOperation = Operation::Idle; // 最近完成的打开或保存动作。
        Operation m_reportOperation = Operation::Idle; // 最近回执所属的校验/回放类型。
        bool m_workerFailed = false; // 后台异常与正常业务诊断分开显示。
        FileResult m_fileResult; // 最近完成的文件状态及系统错误。
        QString m_path; // 当前草稿绑定的显式路径。
        QString m_unmodifiedText; // 模板或最近一次成功打开或保存的原始文本。
        QString m_requestPath; // 最近一次打开或保存的实际目标路径。
        QString m_reportPath; // 结果产生时冻结的来源路径。
        QDateTime m_reportAt; // 最近一次校验回执的本地时间。
        quint64 m_revision = 0; // 由草稿实际编辑递增的代次。
        quint64 m_reportRevision = 0; // 最近回执对应的草稿代次。
        std::optional<BehaviorRuleCheck> m_result; // 不可变的最近回执，用于语言重投影。
        std::optional<ArchivePresetCheck> m_archiveResult; // 独立归档回执，不随草稿编辑改变。
        QString m_archiveError; // 最近一次回放失败的稳定代码。
        QString m_archiveErrorPath; // 与失败编码对应的实际文件。
    };

    // 页壳内由共享框架拥有宽窄分栏和固定动作。父工作台负责页签外边距。
    BehaviorRulesPage::BehaviorRulesPage(QWidget* parent)
        : QWidget(parent)
    {
        auto* root = new QVBoxLayout(this); // 当前页签的无重复留白容器。
        root->setContentsMargins(0, 0, 0, 0);
        auto* workspace = new ks::ui::ParameterWorkspace(this); // 共享参数、动作和回执布局。
        workspace->useWideParameterLayout(55);
        root->addWidget(workspace);

        // 专业编辑视口承担自己的滚动。文件操作集中在本页以保证编码和保存状态一致。
        auto* header = workspace->parameterHeader(); // 参数正文上方的固定身份区。
        auto* headerOwner = header->parentWidget(); // 当前标题和说明的直接宿主。
        m_title = WrappedLabel(headerOwner);
        auto titleFont = m_title->font(); // 跟随共享正文字号，只加重标题。
        titleFont.setBold(true);
        m_title->setFont(titleFont);
        m_help = WrappedLabel(headerOwner);
        m_draftIdentity = WrappedLabel(headerOwner);
        header->addWidget(m_title);
        header->addWidget(m_help);
        header->addWidget(m_draftIdentity);
        auto* viewport = new QWidget(workspace); // 主编辑器独立视口的共享布局宿主。
        auto* editorLayout = new QVBoxLayout(viewport); // 单一专业编辑器，无外层滚动。
        editorLayout->setContentsMargins(0, 0, 0, 0);
        m_draft = new CodeTextEdit(viewport);
        m_draft->setObjectName(QStringLiteral("ks_behavior_rule_editor"));
        m_draft->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Json);
        m_draft->setLineWrapMode(QPlainTextEdit::WidgetWidth);
        m_draft->setTabChangesFocus(true);
        m_draft->setMinimumSize(0, 0);
        m_unmodifiedText = DisplayUtf8(BehaviorRuleExample());
        m_draft->setPlainText(m_unmodifiedText);
        editorLayout->addWidget(m_draft);
        workspace->setParameterViewport(viewport);

        // 文件操作用共享方形图标，复杂操作保留文字，分别保留键盘和悬停释义。
        auto* actions = workspace->actions(); // 位于共享固定底栏的动作行。
        auto* actionOwner = actions->parentWidget(); // 四个按钮的直接宿主。
        m_open = new QPushButton(actionOwner);
        m_save = new QPushButton(actionOwner);
        m_validate = new QPushButton(actionOwner);
        m_replay = new QPushButton(actionOwner);
        KswordTheme::ApplyStandardIconButtonMetrics(m_open);
        KswordTheme::ApplyStandardIconButtonMetrics(m_save);
        ks::ui::SetThemeButtonIcon(m_open, QIcon(QStringLiteral(":/Icon/process_open_folder.svg")));
        ks::ui::SetThemeButtonIcon(m_save, QIcon(QStringLiteral(":/Icon/disk_save.svg")));
        ks::ui::ApplyFlatButtonTheme(m_replay, ks::ui::FlatButtonTone::Accent, ks::ui::FlatButtonAppearance::Solid);
        for (auto* button : {m_open, m_save, m_validate, m_replay}) // 按文件、验证、执行的顺序。
        {
            actions->addWidget(button);
        }
        actions->addStretch(1);
        ks::ui::NormalizeToolbarRow(actions);

        // 结果面板保留上次回执。无结果时显示具体的编辑与试跑说明。
        auto* results = workspace->results(); // 共享结果面板。
        auto* resultOwner = results->parentWidget(); // 只读回执及状态的实际宿主。
        m_progress = WrappedLabel(resultOwner);
        m_reportIdentity = WrappedLabel(resultOwner);
        m_archivePresets = new QPushButton(resultOwner);
        m_archivePresets->setObjectName(QStringLiteral("ks_archive_behavior_presets"));
        m_report = new CodeEditorWidget(resultOwner);
        m_report->setObjectName(QStringLiteral("ks_behavior_rule_receipt"));
        m_report->setReadOnly(true);
        m_report->setReadOnlyExportEnabled(true);
        m_report->setWordWrapEnabled(true);
        m_report->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Ignored);
        results->addWidget(m_reportIdentity);
        results->addWidget(m_archivePresets, 0, Qt::AlignLeft);
        results->addWidget(m_report, 1);
        results->addWidget(m_progress);
        workspace->finish();

        // 修改代次和文件未保存标记各自更新，结果不跟随草稿内容重算。
        m_worker = new ks::ui::AsyncOperation(this);
        m_worker->setStateChangedCallback([this]() { refreshState(); });
        connect(m_draft, &QPlainTextEdit::textChanged, this, [this]()
        {
            ++m_revision;
            refreshReportIdentity();
        });
        connect(m_draft->document(), &QTextDocument::modificationChanged, this, [this]() { refreshState(); });
        connect(m_open, &QPushButton::clicked, this, [this]() { open(); });
        connect(m_save, &QPushButton::clicked, this, [this]() { save(); });
        connect(m_validate, &QPushButton::clicked, this, [this]() { check(Operation::Validate); });
        connect(m_replay, &QPushButton::clicked, this, [this]() { check(Operation::Replay); });
        connect(m_archivePresets, &QPushButton::clicked, this, [this]() { archivePresets(); });
        retranslate();
    }

    // 先关闭结果投递门禁，再由 Qt 清理控件和后台控制器。
    BehaviorRulesPage::~BehaviorRulesPage()
    {
        m_worker->close();
    }

    // 共享组件处理主题，本页只重投影用户可见的操作文字与最近回执。
    void BehaviorRulesPage::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event->type() == QEvent::LanguageChange && m_worker)
        {
            retranslate();
        }
    }

    // 重投影当前语言下的静态入口和最近回执。草稿文字、撤销历史及路径不变。
    void BehaviorRulesPage::retranslate()
    {
        m_title->setText(sourceText(QStringLiteral("行为规则草稿")));
        m_help->setText(sourceText(QStringLiteral("编辑 UTF-8 规则草稿。回放只读取草稿内的合成事件。")));
        m_draft->setAccessibleName(m_title->text());
        m_validate->setText(sourceText(QStringLiteral("校验规则")));
        m_replay->setText(sourceText(QStringLiteral("回放合成事件")));
        m_archivePresets->setText(sourceText(QStringLiteral("运行归档预置")));
        m_report->setAccessibleName(sourceText(QStringLiteral("规则检查回执")));

        // 提交新回执后，格式提示仍可从草稿说明和编辑器的辅助信息读取。
        const QStringList guideLines{ // 分行翻译格式提示，保持 JSON 关键字原样。
            sourceText(QStringLiteral("校验当前示例以检查选择器和字段类型，或回放以查看锚点及证据。")),
            sourceText(QStringLiteral("mode 支持 countAtLeast、countEqual、sequence。window100ns 和计数阈值使用十进制字符串。")),
            sourceText(QStringLiteral("predicate 接受布尔常量或字段测试。运算符包括 eq、ne、lt、le、gt、ge、contains、startsWith、endsWith、isNull 和 isComplete。")),
            sourceText(QStringLiteral("predicate 也可使用 C# 风格表达式字符串，例如 source.headerPid == 42u64 && !isNull(source.headerPid)。支持括号、布尔组合、字段比较和白名单函数。")),
            sourceText(QStringLiteral("字段支持 event.projectId、event.sampleId、event.eventOrdinal、source.sequence、source.headerPid、source.headerTid 和 time.receivedQpc。")),
            sourceText(QStringLiteral("序列使用显式 sourceSequence。合成事件无法证明真实来源覆盖，缺证据的窗口可判为未知。"))
        };
        const QString guideText = guideLines.join(QLatin1Char('\n')); // 可滚动阅读的完整格式说明。
        m_help->setToolTip(guideText);
        m_draft->setAccessibleDescription(guideText);
        if (m_archiveResult)
        {
            m_report->setRawText(FormatArchivePresets(*m_archiveResult));
        }
        else if (m_result)
        {
            m_report->setRawText(FormatCheck(*m_result));
        }
        else
        {
            m_report->setRawText(guideText);
        }
        refreshState();
        refreshReportIdentity();
    }

    // 操作启动与结束统一走这里。后台打开期间锁住草稿，校验和保存允许继续编辑。
    void BehaviorRulesPage::refreshState()
    {
        const bool busy = m_worker->isBusy(); // 是否有实际排队或在途的任务。
        const bool dirty = m_draft->document()->isModified(); // 是否修改了当前加载或保存的草稿。
        m_draft->setReadOnly(busy && m_operation == Operation::Open);
        m_draftIdentity->setText(m_path.isEmpty()
            ? sourceText(QStringLiteral("未保存的规则草稿"))
            : dirty ? sourceText(QStringLiteral("%1（有未保存的修改）")).arg(m_path) : m_path);
        m_open->setAccessibleName(sourceText(QStringLiteral("打开规则草稿")));
        m_save->setAccessibleName(sourceText(QStringLiteral("保存规则草稿")));
        for (auto* button : {m_open, m_save, m_validate, m_replay, m_archivePresets}) // 单一在途门禁。
        {
            button->setEnabled(!busy);
            button->setToolTip(busy ? sourceText(QStringLiteral("请等待当前规则操作完成。"))
                : button->text().isEmpty() ? button->accessibleName() : button->text());
        }
        if (!busy)
        {
            m_archivePresets->setToolTip(sourceText(QStringLiteral("选择已导入的 API Monitor 数据段，查看两组汇总、五类观测及其源行。")));
        }
        const auto busyText = m_operation == Operation::ArchivePresets ? sourceText(QStringLiteral("正在分析归档预置…"))
            : sourceText(QStringLiteral("正在处理规则草稿…")); // 明确草稿与归档各自的在途状态。
        const auto failure = !m_archiveError.isEmpty() ? sourceText(QStringLiteral("归档预置失败：%1\n%2"))
            .arg(m_archiveErrorPath, m_archiveError) : fileStatus(); // 失败保留请求路径和原结果。
        const auto status = busy ? busyText
            : m_workerFailed ? sourceText(QStringLiteral("规则操作失败，请重试。")) : failure;
        m_progress->setVisible(!status.isEmpty());
        m_progress->setText(status);
        ks::ui::ApplyStatusRole(m_progress, busy ? ks::ui::StatusRole::Info
            : m_workerFailed || !m_archiveError.isEmpty() || m_fileResult.error != FileError::None ? ks::ui::StatusRole::Error
            : ks::ui::StatusRole::Success);
    }

    // 摘要只根据冻结请求身份判断新旧，不重建回执正文。
    void BehaviorRulesPage::refreshReportIdentity()
    {
        if (!m_result && !m_archiveResult)
        {
            m_reportIdentity->setText(sourceText(QStringLiteral("尚未校验或回放")));
            return;
        }
        const auto action = m_archiveResult ? m_archivePresets->text()
            : m_reportOperation == Operation::Replay ? m_replay->text() : m_validate->text(); // 回执类型。
        const auto origin = m_reportPath.isEmpty() ? sourceText(QStringLiteral("未绑定文件")) : m_reportPath; // 提交路径。
        const auto time = m_reportAt.toString(Qt::ISODateWithMs); // 用户可核对的回执时间。
        auto text = sourceText(QStringLiteral("%1 · %2\n%3")).arg(action, time, origin); // 固定来源及结果标识。
        if (!m_archiveResult && (m_reportRevision != m_revision || m_reportPath != m_path))
        {
            text += QLatin1Char('\n') + sourceText(QStringLiteral("当前草稿已变化，以下为上次检查的结果。"));
        }
        if (m_reportIdentity->text() != text)
        {
            m_reportIdentity->setText(text);
        }
    }

    // 文件选择是显式动作。原始草稿只有在确认替换且读取成功时才更新。
    void BehaviorRulesPage::open()
    {
        if (m_worker->isBusy())
        {
            return;
        }
        const QPointer<BehaviorRulesPage> alive(this); // 原生选择器进入嵌套事件循环时的页面保护。
        const auto path = QFileDialog::getOpenFileName(this, m_open->accessibleName(), m_path,
            sourceText(QStringLiteral("行为规则草稿 (*.aarules.json *.json);;所有文件 (*)"))); // 用户实际选择的路径。
        if (!alive || path.isEmpty())
        {
            return;
        }
        if (m_draft->document()->isModified())
        {
            // 共享应用主题负责确认框。取消或文件无法打开时不丢弃原稿。
            const auto answer = QMessageBox::question(this, m_open->accessibleName(),
                sourceText(QStringLiteral("当前草稿有未保存的修改。打开所选文件会替换当前草稿，是否继续？")),
                QMessageBox::Yes | QMessageBox::Cancel, QMessageBox::Cancel); // 用户是否明确同意替换。
            if (!alive || answer != QMessageBox::Yes)
            {
                return;
            }
        }

        const Request request{Operation::Open, QFileInfo(path).absoluteFilePath(), {}, m_revision}; // 冻结读取身份。
        m_operation = request.operation;
        m_workerFailed = false;
        m_archiveError.clear();
        m_worker->submit<Request, FileResult>(request,
            [](const Request& input, const ks::ui::AsyncOperationToken&) // 工作线程只读文件。
            {
                return ReadDraft(input);
            },
            [this, request](const FileResult& result, std::uint64_t) // 共享控制器门禁内发布。
            {
                applyFile(request, result);
                return true;
            },
            [this](std::exception_ptr) { m_workerFailed = true; });
    }

    // 将提交时的草稿原子写入指定路径。工作线程继续编辑时保留未保存标记。
    void BehaviorRulesPage::save()
    {
        if (m_worker->isBusy())
        {
            return;
        }
        auto path = m_path; // 已打开或保存的路径，首次需用户明确选择。
        const QPointer<BehaviorRulesPage> alive(this); // 原生选择器可能关闭当前控件。
        if (path.isEmpty())
        {
            path = QFileDialog::getSaveFileName(this, m_save->accessibleName(), QStringLiteral("rule.aarules.json"),
                sourceText(QStringLiteral("行为规则草稿 (*.aarules.json *.json);;所有文件 (*)")));
        }
        if (!alive || path.isEmpty())
        {
            return;
        }

        const Request request{Operation::Save, QFileInfo(path).absoluteFilePath(),
            currentDraftText(), m_revision}; // 本次写入完全冻结。
        m_operation = request.operation;
        m_workerFailed = false;
        m_archiveError.clear();
        m_worker->submitTransaction<Request, FileResult>(request, SaveDraft,
            [this, request](const FileResult& result, std::uint64_t) // 结果仅返回当前存活页面。
            {
                applyFile(request, result);
                return true;
            },
            [this](std::exception_ptr) { m_workerFailed = true; });
    }

    // 提交校验或回放动作。发布时只绑定当前请求的冻结输入和回执时间。
    void BehaviorRulesPage::check(Operation operation)
    {
        if (m_worker->isBusy())
        {
            return;
        }
        const Request request{operation, m_path, currentDraftText(), m_revision}; // 只复制用户当前草稿。
        m_operation = operation;
        m_lastFileOperation = Operation::Idle;
        m_fileResult = {};
        m_workerFailed = false;
        m_archiveError.clear();
        m_worker->submit<Request, BehaviorRuleCheck>(request,
            [](const Request& input, const ks::ui::AsyncOperationToken&) // 实际校验/回放后台执行。
            {
                const auto bytes = input.text.toUtf8(); // 规则解析器要求 UTF-8 字节范围。
                return CheckBehaviorRuleDraft({bytes.constData(), static_cast<std::size_t>(bytes.size())},
                    input.operation == Operation::Replay);
            },
            [this, request](const BehaviorRuleCheck& result, std::uint64_t) // 稳定的值回执投影。
            {
                m_archiveResult.reset();
                m_result = result;
                m_reportRevision = request.revision;
                m_reportOperation = request.operation;
                m_reportPath = request.path;
                m_reportAt = QDateTime::currentDateTime();
                m_report->setRawText(FormatCheck(result));
                refreshReportIdentity();
                return true;
            },
            [this](std::exception_ptr) { m_workerFailed = true; });
    }

    // 冻结显式选择的文件。失败回执使用状态行，最近成功结果照常可查看。
    void BehaviorRulesPage::archivePresets()
    {
        if (m_worker->isBusy())
        {
            return;
        }
        const QPointer<BehaviorRulesPage> alive(this); // 原生选择器的嵌套事件循环可关闭页面。
        const auto path = QFileDialog::getOpenFileName(this, m_archivePresets->text(), {},
            sourceText(QStringLiteral("采样数据段 (*.ksaseg)"))); // 用户确认的单段文件。
        if (!alive || path.isEmpty() || m_worker->isBusy())
        {
            return;
        }
        const Request request{Operation::ArchivePresets, QFileInfo(path).absoluteFilePath(), {}, 0}; // 独立于草稿。
        m_operation = request.operation;
        m_lastFileOperation = Operation::Idle;
        m_fileResult = {};
        m_workerFailed = false;
        m_archiveError.clear();
        m_worker->submit<Request, ArchivePresetCheck>(request, CheckArchivePresets,
            [this, request](const ArchivePresetCheck& result, std::uint64_t)
            {
                if (!result.error.isEmpty())
                {
                    m_archiveError = result.error;
                    m_archiveErrorPath = request.path;
                    return true;
                }
                // 当前保留一份结果，回执以本次归档请求的来源和时间为准。
                m_result.reset();
                m_archiveResult = result;
                m_reportOperation = request.operation;
                m_reportPath = request.path;
                m_reportAt = QDateTime::currentDateTime();
                m_report->setRawText(FormatArchivePresets(result));
                refreshReportIdentity();
                return true;
            },
            [this](std::exception_ptr) { m_workerFailed = true; });
    }

    // 更新当前文件会话。读取和写入失败都原位保留草稿、路径和最近回放结果。
    void BehaviorRulesPage::applyFile(const Request& request, const FileResult& result)
    {
        m_lastFileOperation = request.operation;
        m_requestPath = request.path;
        m_fileResult = {result.error, result.detail, {}};
        if (result.error == FileError::None)
        {
            m_path = request.path;
            if (request.operation == Operation::Open)
            {
                m_unmodifiedText = result.text;
                m_draft->setPlainText(result.text);
                m_draft->document()->setModified(false);
            }
            else
            {
                m_unmodifiedText = request.text;
                if (m_revision == request.revision)
                {
                    m_draft->document()->setModified(false);
                }
                else
                {
                    // 保存期间可能撤销到了旧的干净标记。该版本并非刚写入的文件内容。
                    m_draft->document()->setModified(true);
                }
            }
            refreshReportIdentity();
        }
    }

    // 编辑器快照用于保存和检查，Qt 的普通文本转换会把 NBSP 改为空格。
    QString BehaviorRulesPage::currentDraftText() const
    {
        const auto* document = m_draft->document(); // 当前草稿文档。
        if (!document->isModified())
        {
            return m_unmodifiedText;
        }
        auto text = document->toRawText(); // 避免隐式改变谓词字面量。
        text.replace(QChar::ParagraphSeparator, QLatin1Char('\n'));
        return text;
    }

    // 为最近的显式文件操作生成单独回执，并保留冻结目标和错误原因。
    QString BehaviorRulesPage::fileStatus() const
    {
        if (m_lastFileOperation == Operation::Idle)
        {
            return {};
        }
        if (m_fileResult.error == FileError::None)
        {
            return (m_lastFileOperation == Operation::Open ? sourceText(QStringLiteral("已打开草稿：%1"))
                : sourceText(QStringLiteral("已保存草稿：%1"))).arg(m_requestPath);
        }

        QString reason; // 尺寸、编码或实际文件错误原因。
        switch (m_fileResult.error)
        {
        case FileError::Size: reason = sourceText(QStringLiteral("草稿超过 256 KiB。")); break;
        case FileError::Utf8: reason = sourceText(QStringLiteral("草稿不是有效的 UTF-8 文件。")); break;
        case FileError::FileAccess: reason = m_fileResult.detail; break;
        default: break;
        }
        return (m_lastFileOperation == Operation::Open ? sourceText(QStringLiteral("无法打开草稿：%1\n%2"))
            : sourceText(QStringLiteral("无法保存草稿：%1\n%2"))).arg(m_requestPath, reason);
    }
}

// 返回工作台可以直接挂载的真实页签控件。
QWidget* CreateBehaviorRulesPage(QWidget* parent)
{
    return new BehaviorRulesPage(parent);
}
}
