#include "WindowInputControl.h"
#include "DwmZOrderControl.h"
#include "../ArkDriverClient/ArkDriverClient.h"
#include "../Internationalization/LanguageManager.h"
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QEvent>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QScrollArea>
#include <QThread>
#include <QVBoxLayout>
#include <memory>

namespace ks::window_input
{
    namespace
    {
        QString Text(const char* source)
        { return ks::i18n::sourceText(QString::fromUtf8(source)); }

        void Bind(QObject* object, const char* source)
        {
            const auto value = QString::fromUtf8(source);
            ks::i18n::LanguageManager::instance().bindText(object, value, value);
        }

        std::wstring AgentPath()
        {
            return QDir::toNativeSeparators(QCoreApplication::applicationDirPath()
                + QStringLiteral("/KswordDwmZOrder.dll")).toStdWString();
        }

        QLabel* Label(QWidget* parent, const char* source, QVBoxLayout* layout, bool bind = true)
        {
            auto* label = new QLabel(parent);
            label->setWordWrap(true);
            label->setTextFormat(Qt::PlainText);
            label->setTextInteractionFlags(Qt::TextSelectableByMouse);
            if (bind) Bind(label, source);
            else label->setText(Text(source));
            layout->addWidget(label);
            return label;
        }

        QString Failure(const Result& result)
        {
            QString message;
            switch (result.status)
            {
            case Status::InvalidWindow: message = Text("目标窗口已关闭或身份发生变化，请重新选择。"); break;
            case Status::SelfWindow: message = Text("不能对 KSword 自身设置输入限制，请选择其他程序的窗口。"); break;
            case Status::UnsupportedWindow: message = Text("该窗口不支持所选模式。穿透不能用于自有 DC 类；遮挡点击要求可见、已启用、未最小化且无所有者的顶层窗口。"); break;
            case Status::OrderInUse: message = Text("已有窗口正在保持 DWM 顺序。请先恢复该窗口，再启用遮挡点击。"); break;
            case Status::OrderChanged: message = Text("原生置顶或 DWM 保持已改变，请恢复后重新应用。"); break;
            case Status::LimitReached: message = Text("已达到 128 个受控窗口，请先恢复部分窗口。"); break;
            case Status::RestoreFailed: message = Text("未能完整恢复，仍保留恢复记录。请检查权限后重试。"); break;
            case Status::DwmFailure: message = Text("DWM 操作未完成，未确认遮挡点击模式已启用。"); break;
            default: message = Text("Windows 未确认输入设置生效，请检查权限和窗口状态。"); break;
            }
            if (result.dwmAttempted && (result.status == Status::DwmFailure || result.status == Status::RestoreFailed))
            {
                if (result.dwm.response.status == dwm_order::Status::NotRunning)
                    message += QLatin1Char('\n') + Text("请先在“杂项 → DWM / Win32k 注入”中加载 DWM 代理。");
                else if (result.dwm.response.status != dwm_order::Status::Ok)
                    message += QLatin1Char('\n') + dwm_order::ErrorDescription(result.dwm);
            }
            if (result.error) message += QLatin1Char('\n') + Text("Windows 错误码：%1。").arg(result.error);
            return message;
        }

        class Control final : public QWidget
        {
        public:
            Control(const dwm_order::WindowIdentity& identity, QWidget* parent)
                : QWidget(parent), identity_(identity)
            {
                auto* root = new QVBoxLayout(this);
                auto* scroll = new QScrollArea(this);
                scroll->setWidgetResizable(true);
                root->addWidget(scroll);
                auto* content = new QWidget(scroll);
                auto* layout = new QVBoxLayout(content);
                auto* group = new QGroupBox(content);
                Bind(group, "鼠标与键盘输入");
                auto* input = new QVBoxLayout(group);
                Label(group, "选择输入模式并应用。恢复只撤销本次 KSword 保存的修改，不会重置目标窗口的其他样式。", input);
                modes_ = new QComboBox(group);
                const char* names[] = {"不可点击（同时禁用键盘输入）", "鼠标穿透（点击落到下层窗口）", "被盖住仍可点击（原 Band 内）"};
                for (int i = 0; i < 3; ++i)
                {
                    modes_->addItem(Text(names[i]), i + 1);
                    ks::i18n::LanguageManager::instance().bindComboBoxItem(modes_, i,
                        QString::fromUtf8(names[i]), QString::fromUtf8(names[i]));
                }
                input->addWidget(modes_);
                Label(group, "遮挡点击会将真实窗口设为置顶，并持续把画面移到 DWM 最后。鼠标仍按原生窗口顺序分发；更高 Band（包括 UIAccess）仍会挡住点击。", input);
                Label(group, "设置在关闭本页后继续保留。退出 KSword 前请恢复；也可在杂项页恢复全部输入设置。", input);
                auto* actions = new QHBoxLayout;
                apply_ = new QPushButton(group);
                restore_ = new QPushButton(group);
                query_ = new QPushButton(group);
                Bind(apply_, "应用输入设置");
                Bind(restore_, "恢复本次修改");
                Bind(query_, "读取当前输入状态");
                actions->addWidget(apply_);
                actions->addWidget(restore_);
                actions->addWidget(query_);
                input->addLayout(actions);
                status_ = Label(group, "尚未读取输入状态。", input, false);
                layout->addWidget(group);
                layout->addWidget(dwm_order::CreateControl(identity, content));
                layout->addStretch();
                scroll->setWidget(content);
                connect(apply_, &QPushButton::clicked, this, [this] { Start(1); });
                connect(restore_, &QPushButton::clicked, this, [this] { Start(2); });
                connect(query_, &QPushButton::clicked, this, [this] { Start(0); });
                Start(0);
            }

        protected:
            void changeEvent(QEvent* event) override
            {
                QWidget::changeEvent(event);
                if (event->type() == QEvent::LanguageChange && status_) Render();
            }

        private:
            void Start(int operation)
            {
                if (busy_) return;
                busy_ = true;
                operation_ = operation;
                for (auto* button : {apply_, restore_, query_}) button->setEnabled(false);
                modes_->setEnabled(false);
                Render();
                const auto identity = identity_;
                const auto mode = static_cast<Mode>(modes_->currentData().toInt());
                const auto path = AgentPath();
                auto result = std::make_shared<Result>();
                auto* worker = QThread::create([identity, mode, path, operation, result]
                {
                    try
                    {
                        *result = operation == 1 ? Apply(identity, mode, path)
                            : operation == 2 ? Restore(identity, path) : Query(identity, path);
                    }
                    catch (...) { result->status = Status::NativeFailure; }
                });
                connect(worker, &QThread::finished, this, [this, result]
                {
                    result_ = *result;
                    busy_ = false;
                    for (auto* button : {apply_, restore_, query_}) button->setEnabled(true);
                    modes_->setEnabled(true);
                    Render();
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                worker->start();
            }

            void Render()
            {
                if (busy_) { status_->setText(Text("正在读取或修改窗口输入状态…")); return; }
                if (result_.status != Status::Ok) { status_->setText(Failure(result_)); return; }
                QString text = operation_ == 1 ? Text("输入设置已回读确认。")
                    : operation_ == 2 ? Text("本次输入修改已恢复。") : Text("已读取目标窗口的当前输入状态。");
                if (operation_ == 2 && !result_.restored)
                    text = Text("没有本次修改的恢复记录，当前设置保持不变。");
                text += QLatin1Char('\n') + Text("窗口：0x%1；输入：%2；鼠标穿透：%3；原生置顶：%4。")
                    .arg(identity_.hwnd, 0, 16)
                    .arg(result_.enabled ? Text("已启用") : Text("已禁用"))
                    .arg(result_.clickThrough ? Text("开启") : Text("关闭"))
                    .arg(result_.topmost ? Text("开启") : Text("关闭"));
                if (result_.managed && result_.mode == Mode::Covered)
                    text += QLatin1Char('\n') + Text("正在保持视觉置底；输入优先级仍受原 Band 限制。");
                status_->setText(text);
            }

            dwm_order::WindowIdentity identity_;
            Result result_;
            bool busy_ = false;
            int operation_ = 0;
            QComboBox* modes_ = nullptr;
            QPushButton* apply_ = nullptr;
            QPushButton* restore_ = nullptr;
            QPushButton* query_ = nullptr;
            QLabel* status_ = nullptr;
        };

        class InjectionPage final : public QWidget
        {
        public:
            explicit InjectionPage(QWidget* parent) : QWidget(parent)
            {
                auto* layout = new QVBoxLayout(this);
                auto* dwm = new QGroupBox(this);
                Bind(dwm, "DWM 排序代理");
                auto* dwmLayout = new QVBoxLayout(dwm);
                Label(dwm, "在这里加载当前会话的 DWM 代理，然后到“窗口 → 窗口输入与顺序”设置目标窗口。加载代理本身不会改变任何窗口顺序。", dwmLayout);
                auto* actions = new QHBoxLayout;
                load_ = new QPushButton(dwm);
                check_ = new QPushButton(dwm);
                stop_ = new QPushButton(dwm);
                Bind(load_, "加载 DWM 代理");
                Bind(check_, "检查 DWM 状态");
                Bind(stop_, "停止保持并恢复全部输入设置");
                for (auto* button : {load_, check_, stop_}) actions->addWidget(button);
                dwmLayout->addLayout(actions);
                dwmStatus_ = Label(dwm, "尚未检查 DWM 状态。", dwmLayout, false);
                layout->addWidget(dwm);
                auto* win32k = new QGroupBox(this);
                Bind(win32k, "Win32k 输入控制");
                auto* win32kLayout = new QVBoxLayout(win32k);
                Label(win32k, "Win32k 是内核模块，通过 KSword 驱动访问。当前仅支持查询，暂不支持跨 Band 输入重排。", win32kLayout);
                kernel_ = new QPushButton(win32k);
                Bind(kernel_, "读取 Win32k 状态");
                win32kLayout->addWidget(kernel_);
                kernelStatus_ = Label(win32k, "尚未检查 Win32k 状态。", win32kLayout, false);
                layout->addWidget(win32k);
                layout->addStretch();
                connect(load_, &QPushButton::clicked, this, [this] { Start(1); });
                connect(check_, &QPushButton::clicked, this, [this] { Start(0); });
                connect(stop_, &QPushButton::clicked, this, [this] { Start(2); });
                connect(kernel_, &QPushButton::clicked, this, [this] { Start(3); });
            }

        protected:
            void changeEvent(QEvent* event) override
            {
                QWidget::changeEvent(event);
                if (event->type() == QEvent::LanguageChange && dwmStatus_) Render();
            }

        private:
            void Start(int operation)
            {
                if (busy_) return;
                busy_ = true;
                operation_ = operation;
                for (auto* button : {load_, check_, stop_, kernel_}) button->setEnabled(false);
                Render();
                auto result = std::make_shared<Result>();
                auto kernelResult = std::make_shared<ksword::ark::Win32kProfileStatusResult>();
                const auto path = AgentPath();
                auto* worker = QThread::create([operation, path, result, kernelResult]
                {
                    try
                    {
                        if (operation == 3)
                        { *kernelResult = ksword::ark::DriverClient().queryWin32kProfileStatus(); return; }
                        const std::lock_guard<std::recursive_mutex> lock(dwm_order::OperationMutex());
                        if (operation == 2)
                        {
                            *result = RestoreAll(path);
                            if (result->status != Status::Ok) return;
                        }
                        dwm_order::Request request;
                        request.action = operation == 2 ? dwm_order::Action::Stop : dwm_order::Action::Connect;
                        result->dwm = dwm_order::ExecuteRequest(request, path, operation == 1);
                    }
                    catch (...)
                    {
                        result->status = Status::NativeFailure;
                        kernelResult->io.ok = false;
                        kernelResult->io.win32Error = ERROR_UNHANDLED_EXCEPTION;
                    }
                });
                connect(worker, &QThread::finished, this, [this, result, kernelResult]
                {
                    busy_ = false;
                    for (auto* button : {load_, check_, stop_, kernel_}) button->setEnabled(true);
                    if (operation_ == 3) { kernelResult_ = *kernelResult; hasKernel_ = true; }
                    else { result_ = *result; hasDwm_ = true; lastDwmOperation_ = operation_; }
                    Render();
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                worker->start();
            }

            void Render()
            {
                if (!hasDwm_) dwmStatus_->setText(Text("尚未检查 DWM 状态。"));
                if (!hasKernel_) kernelStatus_->setText(Text("尚未检查 Win32k 状态。"));
                if (hasDwm_)
                {
                    const auto& reply = result_.dwm;
                    QString text;
                    if (result_.status != Status::Ok) text = Failure(result_);
                    else if (reply.response.status == dwm_order::Status::NotRunning)
                        text = lastDwmOperation_ == 2 ? Text("输入设置已恢复；当前没有运行 DWM 排序代理。") : Text("当前尚未加载 DWM 排序代理。");
                    else if (reply.response.status == dwm_order::Status::Ok && (reply.response.flags & dwm_order::Verified))
                    {
                        text = lastDwmOperation_ == 2 ? Text("已恢复输入设置并停止全部 DWM 保持。代理 DLL 仍保留在 DWM 中。")
                            : Text("DWM 排序代理已就绪。进程 ID：%1。").arg(reply.response.dwmProcessId);
                        if (reply.response.flags & dwm_order::Maintaining)
                            text += QLatin1Char('\n') + Text("正在保持窗口 0x%1 的画面顺序。").arg(reply.response.maintainedWindow, 0, 16);
                    }
                    else if (reply.response.status == dwm_order::Status::UnsupportedRuntime)
                        text = Text("代理已连接，但当前系统未通过 DWM 排序兼容性校验，不能调整画面顺序。");
                    else if (reply.response.status == dwm_order::Status::AgentMismatch)
                        text = Text("DWM 中仍是旧版代理。请注销登录后使用同一套新版 EXE 和 DLL。");
                    else text = dwm_order::ErrorDescription(reply);
                    dwmStatus_->setText(text);
                }
                if (hasKernel_)
                {
                    QString text;
                    if (!kernelResult_.io.ok)
                        text = Text("无法读取 Win32k 状态，请检查 R0 驱动是否可用。Windows 错误码：%1。").arg(kernelResult_.io.win32Error);
                    else if (kernelResult_.status == KSWORD_ARK_WIN32K_STATUS_OK)
                        text = Text("Win32k 查询已完成。当前驱动仍不支持跨 Band 输入重排。");
                    else
                        text = Text("Win32k 查询返回了不完整或不支持的状态，不能据此启用输入控制。");
                    kernelStatus_->setText(text);
                }
                if (busy_)
                    (operation_ == 3 ? kernelStatus_ : dwmStatus_)->setText(Text("正在处理，请稍候…"));
            }

            Result result_;
            ksword::ark::Win32kProfileStatusResult kernelResult_;
            bool busy_ = false, hasDwm_ = false, hasKernel_ = false;
            int operation_ = 0, lastDwmOperation_ = 0;
            QPushButton *load_ = nullptr, *check_ = nullptr, *stop_ = nullptr, *kernel_ = nullptr;
            QLabel *dwmStatus_ = nullptr, *kernelStatus_ = nullptr;
        };
    }

    QWidget* CreateControl(const dwm_order::WindowIdentity& identity, QWidget* parent)
    { return new Control(identity, parent); }

    QWidget* CreateInjectionPage(QWidget* parent)
    { return new InjectionPage(parent); }
}
