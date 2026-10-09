#include "WorkbenchPseudocodeView.h"
#include "../CodeEditorWidget.h"
#include "../CodeTextEdit.h"
#include "../FlowLayout.h"
#include "../../PluginHost.h"
#include "../../Internationalization/LanguageManager.h"
#include "../../theme.h"
#include <QCheckBox>
#include <QCoreApplication>
#include <QEvent>
#include <QFileDialog>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QPushButton>
#include <QProgressBar>
#include <QSettings>
#include <QSignalBlocker>
#include <QToolButton>
#include <QVBoxLayout>
#include <QTimer>
#include <algorithm>
#include <limits>
#include <memory>
#include <vector>

namespace
{
    // ProgressVisibilityEvents：仅延后当前控件的可见性事件，避免观察者在 Qt setter 内销毁宿主。
    class ProgressVisibilityEvents final : public QObject
    {
    public:
        explicit ProgressVisibilityEvents(QWidget* widget) : widget_(widget)
        {
            application_ = QCoreApplication::instance();
            if (application_) application_->installEventFilter(this);
        }
        ~ProgressVisibilityEvents() override
        {
            if (application_) application_->removeEventFilter(this);
        }
        // take：先解除短期过滤，再交回实际事件；重放时所有正常观察者仍能收到通知。
        std::vector<std::unique_ptr<QEvent>> take()
        {
            if (application_) application_->removeEventFilter(this);
            return std::move(events_);
        }
    protected:
        bool eventFilter(QObject* watched, QEvent* event) override
        {
            if (watched != widget_) return false;
            switch (event->type())
            {
            case QEvent::Show:
            case QEvent::Hide:
            case QEvent::ShowToParent:
            case QEvent::HideToParent:
                events_.emplace_back(event->clone());
                return true;
            default:
                return false;
            }
        }
    private:
        QPointer<QWidget> widget_; // 本次 setter 操作的唯一控件，不改变其他窗口事件。
        QPointer<QCoreApplication> application_;
        std::vector<std::unique_ptr<QEvent>> events_; // 仅保存 Qt 实际产生的可见性事件。
    };
}

namespace ks::ui
{
    // buildUi：搭建所有宿主共用的配置、动作和项目代码编辑器，不读取目标。
    void WorkbenchPseudocodeView::buildUi()
    {
        setObjectName(QStringLiteral("memory_pseudocode_page"));
        setMinimumSize(0, 0);
        auto* layout = new QVBoxLayout(this); // 页面主布局，不把工具栏最小宽度回灌宿主。
        layout->setContentsMargins(0, 0, 0, 0);
        layout->setSizeConstraint(QLayout::SetNoConstraint);
        runtimeStatus_ = new QLabel(this);
        runtimeStatus_->setObjectName(QStringLiteral("memory_decompiler_runtime_status"));
        runtimeStatus_->setTextFormat(Qt::PlainText);
        runtimeStatus_->setWordWrap(true);
        layout->addWidget(runtimeStatus_);

        // 工具行采用自适应换行，窄窗口仍能看到安装和刷新入口。
        auto* configuration = new FlowLayout(nullptr, 0, 4, 4);
        install_ = new QPushButton(ks::i18n::sourceText(QStringLiteral("安装 / 管理 Ghidra 插件")), this);
        install_->setObjectName(QStringLiteral("memory_install_ghidra_plugin"));
        install_->setToolTip(install_->text());
        refresh_ = new QPushButton(ks::i18n::sourceText(QStringLiteral("刷新后端")), this);
        refresh_->setToolTip(refresh_->text());
        auto* advanced = new QCheckBox(ks::i18n::sourceText(QStringLiteral("高级路径")), this);
        advanced->setToolTip(advanced->text());
        configuration->addWidget(install_);
        configuration->addWidget(refresh_);
        configuration->addWidget(advanced);
        layout->addLayout(configuration);

        auto* advancedPage = new QWidget(this); // 仅在用户选择自定义配置时显示。
        auto* paths = new QHBoxLayout(advancedPage);
        paths->setContentsMargins(0, 0, 0, 0);
        paths->addWidget(new QLabel(ks::i18n::sourceText(QStringLiteral("Ghidra 目录")), advancedPage));
        directory_ = new QLineEdit(advancedPage);
        directory_->setObjectName(QStringLiteral("memory_decompiler_directory"));
        const auto directory = QSettings().value(QStringLiteral("analysis/ghidra_directory")).toString();
        directory_->setText(directory);
        directory_->setPlaceholderText(ks::i18n::sourceText(QStringLiteral("选择解压后的 Ghidra 安装目录")));
        paths->addWidget(directory_, 1);
        auto* browse = new QPushButton(ks::i18n::sourceText(QStringLiteral("浏览…")), advancedPage);
        browse->setToolTip(browse->text());
        paths->addWidget(browse);
        layout->addWidget(advancedPage);
        advanced->setChecked(!directory.isEmpty());
        advancedPage->setVisible(advanced->isChecked());
        connect(advanced, &QCheckBox::toggled, advancedPage, &QWidget::setVisible);
        decompiler_->setGhidraDirectory(directory);

        // 官方后端管理使用现有插件管理器；浏览对话框返回后先探活。
        connect(install_, &QPushButton::clicked, this, [this]() {
            ks::plugin_host::showPluginManager(this, QStringLiteral("ghidra"));
        });
        connect(refresh_, &QPushButton::clicked, this, &WorkbenchPseudocodeView::refreshDecompilerRuntime);
        connect(browse, &QPushButton::clicked, this, [this]() {
            const QPointer<WorkbenchPseudocodeView> self(this);
            const auto chosen = QFileDialog::getExistingDirectory(this,
                ks::i18n::sourceText(QStringLiteral("选择 Ghidra 安装目录")), directory_->text());
            if (!self || chosen.isEmpty()) return;
            directory_->setText(chosen);
            QSettings().setValue(QStringLiteral("analysis/ghidra_directory"), chosen);
            refreshDecompilerRuntime();
        });
        connect(directory_, &QLineEdit::editingFinished, this, [this]() {
            QSettings().setValue(QStringLiteral("analysis/ghidra_directory"), directory_->text().trimmed());
            refreshDecompilerRuntime();
        });

        auto* tools = new FlowLayout(nullptr, 0, 4, 4); // 导航动作随宽度换行。
        decompile_ = new QPushButton(ks::i18n::sourceText(QStringLiteral("反编译当前函数")), this);
        decompile_->setObjectName(QStringLiteral("memory_decompile_function"));
        cancel_ = new QPushButton(ks::i18n::sourceText(QStringLiteral("取消")), this);
        cancel_->setObjectName(QStringLiteral("memory_decompile_cancel"));
        locateHex_ = new QPushButton(ks::i18n::sourceText(QStringLiteral("定位十六进制")), this);
        locateHex_->setObjectName(QStringLiteral("memory_pseudocode_locate_hex"));
        locateDisasm_ = new QPushButton(ks::i18n::sourceText(QStringLiteral("定位反汇编")), this);
        locateDisasm_->setObjectName(QStringLiteral("memory_pseudocode_locate_disassembly"));
        for (auto* button : {decompile_, cancel_, locateHex_, locateDisasm_})
        {
            button->setToolTip(button->text());
            tools->addWidget(button);
        }
        layout->addLayout(tools);
        status_ = new QLabel(this);
        status_->setObjectName(QStringLiteral("memory_pseudocode_status"));
        status_->setTextFormat(Qt::PlainText);
        status_->setWordWrap(true);
        status_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        status_->setTextInteractionFlags(Qt::TextSelectableByMouse);
        layout->addWidget(status_);
        setStatus(QStringLiteral("选择代码地址后反编译；伪代码基于当前快照，类型和函数边界由后端推断。"));

        // 无法量化的阶段显示活动条和单调耗时；只有后端真实单位才使用有界范围。
        progressLabel_ = new QLabel(this);
        progressLabel_->setObjectName(QStringLiteral("memory_pseudocode_progress_label"));
        progressLabel_->setTextFormat(Qt::PlainText);
        progressLabel_->setWordWrap(true);
        progressLabel_->setSizePolicy(QSizePolicy::Ignored, QSizePolicy::Preferred);
        layout->addWidget(progressLabel_);
        progress_ = new QProgressBar(this);
        progress_->setObjectName(QStringLiteral("memory_pseudocode_progress"));
        progress_->setTextVisible(false);
        layout->addWidget(progress_);
        progressLabel_->hide();
        progress_->hide();
        progressTimer_ = new QTimer(this);
        progressTimer_->setInterval(250);
        connect(progressTimer_, &QTimer::timeout, this, &WorkbenchPseudocodeView::refreshProgress);

        // C 源码按原文显示，统一编辑器提供查找；报告结构化解释不适用于函数代码。
        code_ = new CodeEditorWidget(this);
        code_->setReadOnly(true);
        code_->setStructuredReportViewEnabled(false);
        text_ = dynamic_cast<CodeTextEdit*>(code_->findChild<QPlainTextEdit*>(QStringLiteral("code_editor_text")));
        if (text_)
        {
            text_->setObjectName(QStringLiteral("memory_pseudocode_view"));
            text_->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::Cpp);
            text_->setLineWrapMode(QPlainTextEdit::NoWrap);
            connect(text_, &QPlainTextEdit::cursorPositionChanged, this, &WorkbenchPseudocodeView::updateState);
        }
        layout->addWidget(code_, 1);
        connect(decompile_, &QPushButton::clicked, this, &WorkbenchPseudocodeView::startDecompilation);
        connect(cancel_, &QPushButton::clicked, this, [this]() {
            const QPointer<WorkbenchPseudocodeView> self(this);
            const auto epoch = epoch_; // 可见性回调换源后不能取消新请求或覆盖其状态。
            waitingForBytes_ = false;
            stopProgress();
            if (!self || epoch_ != epoch) return;
            if (decompiler_->isRunning())
            {
                setStatus(QStringLiteral("正在取消反编译…"));
                decompiler_->cancel();
            }
            else
            {
                setStatus(QStringLiteral("反编译已取消。"));
            }
            if (self && epoch_ == epoch) updateState();
        });
        connect(locateHex_, &QPushButton::clicked, this, [this]() { locateLine(false); });
        connect(locateDisasm_, &QPushButton::clicked, this, [this]() { locateLine(true); });
        connect(decompiler_, &GhidraDecompiler::runningChanged, this, [this](bool) { updateState(); });
        connect(decompiler_, &GhidraDecompiler::finished, this, &WorkbenchPseudocodeView::finishDecompilation);
        connect(decompiler_, &GhidraDecompiler::progressChanged, this, &WorkbenchPseudocodeView::handleProgress);
    }

    // beginProgress：当前分析开始或继续等待读取；只建立显示状态，不触发分析或目标 I/O。
    void WorkbenchPseudocodeView::beginProgress(const QElapsedTimer* continued)
    {
        progressEpoch_ = epoch_;
        progressActive_ = true;
        progressState_ = {};
        if (continued && continued->isValid()) progressElapsed_ = *continued;
        else progressElapsed_.start();
        progressTimer_->start();
        const auto epoch = epoch_; // show 事件可重入换源，需要同时保生命周期与票据。
        const QPointer<WorkbenchPseudocodeView> self(this);
        if (!setProgressVisible(progressLabel_, true)) return;
        if (!self || epoch_ != epoch || !progressActive_) return;
        if (!setProgressVisible(progress_, true)) return;
        if (self && epoch_ == epoch && progressActive_) refreshProgress();
    }

    // stopProgress：先撤销票据，再停止定时器与显示；迟到阶段不得重开活动条。
    void WorkbenchPseudocodeView::stopProgress()
    {
        progressActive_ = false;
        progressTimer_->stop();
        progressElapsed_.invalidate();
        const auto epoch = epoch_; // hide 事件若启动新请求，后续不可再隐藏新标签。
        const QPointer<WorkbenchPseudocodeView> self(this);
        if (!setProgressVisible(progress_, false)) return;
        if (self && epoch_ == epoch && !progressActive_) setProgressVisible(progressLabel_, false);
    }

    // setProgressVisible：Qt 完成可见性修改后才派发通知，关闭或换源会终止剩余旧事件。
    bool WorkbenchPseudocodeView::setProgressVisible(QWidget* widget, bool visible)
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const QPointer<QWidget> target(widget);
        const auto epoch = epoch_;
        ProgressVisibilityEvents deferred(widget);
        widget->setVisible(visible);
        auto events = deferred.take();
        for (const auto& event : events)
        {
            if (!self || !target || epoch_ != epoch) return false;
            QCoreApplication::sendEvent(target.data(), event.get());
        }
        return self && target && epoch_ == epoch;
    }

    // handleProgress：单位和阶段必须有效；重复活动通知允许计时，倒退阶段一律忽略。
    void WorkbenchPseudocodeView::handleProgress(const DecompilerProgress& progress)
    {
        if (!progressActive_ || progressEpoch_ != epoch_ || !hasRequest_
            || static_cast<int>(progress.stage) < static_cast<int>(progressState_.stage)
            || static_cast<int>(progress.stage) > static_cast<int>(DecompilerStage::Rendering)) return;
        if ((progress.totalUnits >= 0 || progress.completedUnits >= 0)
            && (progress.totalUnits < 0 || progress.completedUnits < 0
                || progress.completedUnits > progress.totalUnits)) return;
        // 已知单位不能在同一阶段倒退或突然变成另一总量；换阶段才重设工作量。
        if (progress.stage == progressState_.stage && progressState_.totalUnits >= 0
            && (progress.totalUnits != progressState_.totalUnits
                || progress.completedUnits < progressState_.completedUnits)) return;
        progressState_ = progress;
        refreshProgress();
    }

    // refreshProgress：阶段由真实流程提供，耗时每250ms刷新；未知总量不生成虚假百分比。
    void WorkbenchPseudocodeView::refreshProgress()
    {
        if (!progressActive_ || progressEpoch_ != epoch_) return;
        const auto epoch = epoch_; // valueChanged/布局回调发生换源时停止本次刷新。
        const DecompilerProgress state = progressState_; // 仅使用本轮冻结的阶段单位。
        const QPointer<WorkbenchPseudocodeView> self(this);
        QString stage; // 当前阶段的本地化说明，语言切换只重译显示。
        switch (state.stage)
        {
        case DecompilerStage::PreparingSnapshot:
            stage = ks::i18n::sourceText(QStringLiteral("读取和准备快照"));
            break;
        case DecompilerStage::StartingRuntime:
            stage = ks::i18n::sourceText(QStringLiteral("启动分析引擎"));
            break;
        case DecompilerStage::Importing:
            stage = ks::i18n::sourceText(QStringLiteral("导入捕获字节"));
            break;
        case DecompilerStage::Analyzing:
            stage = ks::i18n::sourceText(QStringLiteral("分析控制流"));
            break;
        case DecompilerStage::LocatingFunction:
            stage = ks::i18n::sourceText(QStringLiteral("定位函数边界"));
            break;
        case DecompilerStage::Decompiling:
            stage = ks::i18n::sourceText(QStringLiteral("生成 C 伪代码"));
            break;
        case DecompilerStage::Rendering:
            stage = ks::i18n::sourceText(QStringLiteral("整理分析结果"));
            break;
        default:
            return;
        }
        const auto elapsed = std::max<qint64>(0, progressElapsed_.elapsed()) / 1000; // 本次实际秒数。
        const bool bounded = state.totalUnits > 0 && state.completedUnits >= 0;
        progressLabel_->setText(bounded
            ? ks::i18n::sourceText(QStringLiteral("%1（%2/%3）· 已用 %4 秒"))
                .arg(stage).arg(state.completedUnits).arg(state.totalUnits).arg(elapsed)
            : ks::i18n::sourceText(QStringLiteral("%1 · 已用 %2 秒")).arg(stage).arg(elapsed));
        if (!self || epoch_ != epoch || !progressActive_) return;
        // 原生 setter 返回后再派发 valueChanged，观察者直接关闭宿主不会破坏 Qt 调用栈。
        const auto maximum = bounded
            ? std::min<qint64>(state.totalUnits, std::numeric_limits<int>::max()) : 0;
        const QPointer<QProgressBar> progress(progress_);
        const int previous = progress->value();
        {
            const QSignalBlocker blocked(progress.data());
            progress->setRange(0, static_cast<int>(maximum));
            if (bounded)
            {
                const int completed = static_cast<int>((static_cast<long double>(state.completedUnits)
                    / state.totalUnits) * maximum); // 仅按实际完成量缩放到控件整数范围。
                progress->setValue(completed);
            }
        }
        if (!self || !progress || epoch_ != epoch || !progressActive_) return;
        if (previous != progress->value()) emit progress->valueChanged(progress->value());
    }

    // setCode：文档更新完成后再派发观察信号，防止宿主在 Qt 原生调用栈内销毁页面。
    bool WorkbenchPseudocodeView::setCode(const QString& value)
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const QPointer<CodeTextEdit> view(text_);
        if (!view) return false;
        const auto epoch = epoch_; // 防止 textChanged 观察者重入建立新上下文。
        const auto changed = view->toPlainText() != value;
        const auto blocks = view->blockCount(); // 行数变更后让统一行号栏重新测量。
        const auto cursor = view->textCursor().position();
        {
            const QSignalBlocker blocked(view.data());
            code_->setRawText(value);
        }
        if (!self || !view || epoch != epoch_) return false;
        if (blocks != view->blockCount()) emit view->blockCountChanged(view->blockCount());
        if (!self || !view || epoch != epoch_) return false;
        if (changed) emit view->textChanged();
        if (!self || !view || epoch != epoch_) return false;
        if (cursor != view->textCursor().position()) emit view->cursorPositionChanged();
        if (!self || !view || epoch != epoch_) return false;
        emit view->updateRequest(view->viewport()->rect(), 0);
        return self && view && epoch == epoch_;
    }

    // setStatus：保存规范源文，语言切换时能重新翻译提示而不改变原始 C 内容。
    void WorkbenchPseudocodeView::setStatus(const QString& source)
    {
        statusSource_ = source;
        status_->setText(ks::i18n::sourceText(source));
    }

    // refreshDecompilerRuntime：只检查配置，不启动后端或访问被分析程序。
    void WorkbenchPseudocodeView::refreshDecompilerRuntime()
    {
        if (!decompiler_ || decompiler_->isRunning()) return;
        decompiler_->setGhidraDirectory(directory_->text().trimmed());
        const bool managed = directory_->text().trimmed().isEmpty()
            && qEnvironmentVariable("KSWORD_GHIDRA_DIR").trimmed().isEmpty()
            && !GhidraDecompiler::installedPluginDirectory().isEmpty();
        runtimeStatus_->setText(ks::i18n::sourceText(managed
            ? QStringLiteral("已就绪：Ghidra 插件")
            : !decompiler_->ghidraDirectory().isEmpty()
                ? QStringLiteral("已就绪：自定义 Ghidra 后端")
                : QStringLiteral("未安装 Ghidra 插件")));
    }

    // updateState：加载中/运行中只允许取消；有效结果的地址必须能反向映射才允许定位。
    void WorkbenchPseudocodeView::updateState()
    {
        if (!text_) return;
        const bool busy = progressActive_ || waitingForBytes_ || decompiler_->isRunning();
        decompile_->setEnabled(!busy && provider_ && context_.length != 0);
        cancel_->setEnabled(busy);
        directory_->setEnabled(!busy);
        install_->setEnabled(!busy);
        refresh_->setEnabled(!busy);
        const int line = text_->textCursor().blockNumber();
        bool mapped = hasRequest_ && line >= 0 && line < lineAddresses_.size()
            && line < lineValid_.size() && lineValid_.at(line);
        if (mapped && request_.inputKind == DecompilerInputKind::PortableExecutable)
            mapped = virtualAddressToFileOffset(lineAddresses_.at(line)).has_value();
        locateHex_->setEnabled(!busy && mapped);
        locateDisasm_->setEnabled(!busy && mapped);
    }

    // openFindPanel：复用统一编辑器已注册的查找动作，不重复实现第二套查找状态。
    void WorkbenchPseudocodeView::openFindPanel()
    {
        if (auto* find = code_->findChild<QToolButton*>(QStringLiteral("code_editor_find"))) find->click();
    }
    CodeTextEdit* WorkbenchPseudocodeView::editor() const noexcept { return text_; }
    GhidraDecompiler* WorkbenchPseudocodeView::decompiler() const noexcept { return decompiler_; }

    // changeEvent：实时主题由统一编辑器处理，本页仅重译生成提示与后端状态。
    void WorkbenchPseudocodeView::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event->type() == QEvent::LanguageChange)
        {
            setStatus(statusSource_);
            refreshDecompilerRuntime();
            refreshProgress();
        }
    }
}
