#include "DwmZOrderControl.h"
#include "DwmZOrderClient.h"
#include "../Internationalization/LanguageManager.h"
#include <QCheckBox>
#include <QComboBox>
#include <QCoreApplication>
#include <QDir>
#include <QGridLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QPushButton>
#include <QThread>
#include <QVBoxLayout>
#include <memory>

namespace ks::dwm_order
{
    namespace
    {
        QString Text(const char* key, const char* source)
        { return ks::i18n::text(QString::fromLatin1(key), QString::fromUtf8(source)); }

        void Bind(QObject* object, const char* key, const char* source)
        { ks::i18n::LanguageManager::instance().bindText(object, QString::fromLatin1(key), QString::fromUtf8(source)); }

        QString ErrorText(Status status)
        {
            switch (status)
            {
            case Status::Ok: return Text("window.dwm_order.ok", "DWM 顺序已回读确认。");
            case Status::InvalidWindow: return Text("window.dwm_order.invalid_window", "窗口已失效或身份发生变化，请重新选择窗口。");
            case Status::DifferentDesktop: return Text("window.dwm_order.desktop", "目标与参照窗口必须位于当前会话的同一桌面。");
            case Status::UnsupportedRuntime: return Text("window.dwm_order.unsupported", "当前 DWM 未通过排序特征模型的完整校验，已拒绝修改；此版本暂不支持该系统构建。");
            case Status::HookConflict: return Text("window.dwm_order.conflict", "DWM 排序入口已有其他修改，未覆盖该入口。");
            case Status::WindowNotComposed: return Text("window.dwm_order.not_composed", "目标尚未进入 DWM 合成列表，或没有可排序的窗口节点。");
            case Status::NativeFailure: return Text("window.dwm_order.native_failure", "DWM 内部调用失败；修改可能部分生效，请读取当前顺序或恢复。");
            case Status::VerificationFailed: return Text("window.dwm_order.verify_failed", "未通过 DWM 链表或执行回执验证，请读取当前顺序。");
            case Status::NotRunning: return Text("window.dwm_order.not_running", "当前 DWM 中没有运行此排序代理。");
            case Status::AgentMismatch: return Text("window.dwm_order.agent_mismatch", "DWM 中的代理与当前 DLL 不一致；停止旧功能并注销登录后再试。");
            case Status::Timeout: return Text("window.dwm_order.timeout", "等待 DWM 超时，未取得完成回执；操作可能仍在进行，请稍后读取状态。");
            case Status::TransportFailure: return Text("window.dwm_order.transport", "无法连接 DWM。请检查管理员权限和代理 DLL。");
            case Status::InternalException: return Text("window.dwm_order.exception", "排序代理发生异常，未确认操作成功。");
            default: return Text("window.dwm_order.invalid_request", "排序请求或协议无效。");
            }
        }

        QString StageText(Stage stage)
        {
            switch (stage)
            {
            case Stage::Window: return Text("window.dwm_order.stage.window", "校验窗口身份");
            case Stage::AgentFile: return Text("window.dwm_order.stage.file", "读取排序代理");
            case Stage::DwmProcess: return Text("window.dwm_order.stage.process", "打开当前会话的 DWM");
            case Stage::PrepareAgent: return Text("window.dwm_order.stage.prepare", "准备 DWM 可读取的代理副本");
            case Stage::LoadAgent: return Text("window.dwm_order.stage.load", "加载 DWM 排序代理");
            case Stage::Request: return Text("window.dwm_order.stage.request", "执行排序请求");
            default: return Text("window.dwm_order.stage.receipt", "核对 DWM 回执");
            }
        }

        class Control final : public QGroupBox
        {
        public:
            Control(std::uint64_t hwnd, QWidget* parent) : QGroupBox(parent)
            {
                Bind(this, "window.dwm_order.title", "注入 DWM 调整窗口序列");
                auto* layout = new QVBoxLayout(this);
                auto* hint = new QLabel(this);
                hint->setWordWrap(true);
                Bind(hint, "window.dwm_order.hint", "可跨 Band 调整合成遮挡顺序；鼠标命中、焦点和原始 Band 不变。持续保持一次作用于一个窗口，切换目标时恢复上一个窗口。");
                layout->addWidget(hint);
                auto* support = new QLabel(this);
                support->setWordWrap(true);
                Bind(support, "window.dwm_order.support", "适配范围：Windows 11 24H2 x64；Windows 10 的 19041 系列 DWM x64（实验性，待实机验证）。具体组件版本须通过完整特征校验。");
                layout->addWidget(support);
                auto* form = new QGridLayout;
                auto* orderLabel = new QLabel(this);
                Bind(orderLabel, "window.dwm_order.position", "合成位置");
                order_ = new QComboBox(this);
                const char* keys[] = {"window.dwm_order.front", "window.dwm_order.back", "window.dwm_order.before", "window.dwm_order.after"};
                const char* names[] = {"移到合成最前", "移到合成最后", "紧邻参照窗口之前", "紧邻参照窗口之后"};
                for (int i = 0; i < 4; ++i)
                {
                    order_->addItem(Text(keys[i], names[i]), i);
                    ks::i18n::LanguageManager::instance().bindComboBoxItem(order_, i,
                        QString::fromLatin1(keys[i]), QString::fromUtf8(names[i]));
                }
                form->addWidget(orderLabel, 0, 0);
                form->addWidget(order_, 0, 1);
                auto* referenceLabel = new QLabel(this);
                Bind(referenceLabel, "window.dwm_order.reference", "参照窗口 HWND");
                reference_ = new QLineEdit(this);
                ks::i18n::LanguageManager::instance().bindPlaceholder(reference_,
                    QStringLiteral("window.dwm_order.reference_hint"), QStringLiteral("十六进制 0x1234 或十进制句柄"));
                reference_->setEnabled(false);
                form->addWidget(referenceLabel, 1, 0);
                form->addWidget(reference_, 1, 1);
                layout->addLayout(form);
                maintain_ = new QCheckBox(this);
                Bind(maintain_, "window.dwm_order.maintain", "持续保持，直到恢复或目标窗口关闭");
                maintain_->setChecked(true);
                layout->addWidget(maintain_);
                auto* actions = new QGridLayout;
                apply_ = MakeButton("window.dwm_order.apply", "应用 DWM 顺序");
                query_ = MakeButton("window.dwm_order.query", "连接并读取顺序");
                restore_ = MakeButton("window.dwm_order.restore", "恢复系统顺序");
                stop_ = MakeButton("window.dwm_order.stop", "停止全部保持并恢复");
                actions->addWidget(apply_, 0, 0);
                actions->addWidget(query_, 0, 1);
                actions->addWidget(restore_, 1, 0);
                actions->addWidget(stop_, 1, 1);
                layout->addLayout(actions);
                status_ = new QLabel(this);
                status_->setWordWrap(true);
                status_->setTextFormat(Qt::PlainText);
                status_->setTextInteractionFlags(Qt::TextSelectableByMouse);
                status_->setText(Text("window.dwm_order.disconnected", "尚未连接 DWM；操作时将加载排序代理。"));
                layout->addWidget(status_);
                identityOk_ = CaptureWindow(hwnd, identity_, identityError_);
                connect(order_, &QComboBox::currentIndexChanged, this, [this] { reference_->setEnabled(!busy_ && order_->currentIndex() >= 2); });
                connect(apply_, &QPushButton::clicked, this, [this] { Start(Action::Apply); });
                connect(query_, &QPushButton::clicked, this, [this] { Start(Action::Query); });
                connect(restore_, &QPushButton::clicked, this, [this] { Start(Action::Restore); });
                connect(stop_, &QPushButton::clicked, this, [this] { Start(Action::Stop); });
            }

        private:
            QPushButton* MakeButton(const char* key, const char* source)
            {
                auto* button = new QPushButton(this);
                Bind(button, key, source);
                return button;
            }

            void Busy(bool busy)
            {
                busy_ = busy;
                for (auto* button : {apply_, query_, restore_, stop_}) button->setEnabled(!busy);
                order_->setEnabled(!busy);
                maintain_->setEnabled(!busy);
                reference_->setEnabled(!busy && order_->currentIndex() >= 2);
            }

            void Start(Action action)
            {
                if (busy_) return;
                if (!identityOk_ && action != Action::Stop)
                {
                    status_->setText(ErrorText(Status::InvalidWindow) + QStringLiteral(" (%1)").arg(identityError_));
                    return;
                }
                Request request;
                request.action = action;
                request.target = identity_;
                request.position = static_cast<Position>(order_->currentData().toUInt());
                request.maintain = maintain_->isChecked() ? 1u : 0u;
                if (action == Action::Apply && (request.position == Position::Before || request.position == Position::After))
                {
                    const QString input = reference_->text().trimmed();
                    bool parsed = false;
                    const auto hwnd = input.toULongLong(&parsed, input.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
                    std::uint32_t error = 0;
                    if (!parsed || !hwnd || hwnd == identity_.hwnd || !CaptureWindow(hwnd, request.reference, error))
                    {
                        status_->setText(Text("window.dwm_order.bad_reference", "请输入同一桌面上另一个有效顶层窗口的 HWND。"));
                        return;
                    }
                }
                const auto dll = QDir::toNativeSeparators(QCoreApplication::applicationDirPath()
                    + QStringLiteral("/KswordDwmZOrder.dll")).toStdWString();
                auto result = std::make_shared<Reply>();
                auto* worker = QThread::create([request, dll, result]
                {
                    try { *result = ExecuteRequest(request, dll); }
                    catch (...) { result->response.status = Status::InternalException; }
                });
                connect(worker, &QThread::finished, this, [this, result]
                {
                    Busy(false);
                    QString text = ErrorText(result->response.status);
                    if (result->response.status == Status::TransportFailure && result->stage == Stage::PrepareAgent)
                        text = Text("window.dwm_order.prepare_failure", "DWM 已打开，但未能准备代理副本或授予读取权限。");
                    if (result->response.status == Status::TransportFailure && result->stage == Stage::LoadAgent)
                        text = result->loaderCompleted
                            ? Text("window.dwm_order.loader_failure", "DWM 已打开，但 Windows 加载器未能加载代理 DLL。")
                            : Text("window.dwm_order.loader_transport", "DWM 已打开，但代理加载未能完成，请查看详细错误。");
                    if (result->response.status == Status::Ok)
                    {
                        if (result->response.flags & Restored)
                            text = Text("window.dwm_order.restored", "已恢复 Windows 当前顺序，并停止对应的持续保持。");
                        if (result->response.windowCount)
                            text += QStringLiteral("\n") + Text("window.dwm_order.state", "DWM 合成位置：%1 / %2（1 为最前）；Band：%3；上方窗口：0x%4；下方窗口：0x%5。")
                                .arg(result->response.index + 1).arg(result->response.windowCount).arg(result->response.band)
                                .arg(result->response.previous, 0, 16).arg(result->response.next, 0, 16);
                    }
                    else
                    {
                        if (result->error)
                            text += QStringLiteral("\n") + Text("window.dwm_order.error_detail", "%1；Win32 %2。")
                                .arg(StageText(result->stage)).arg(result->error);
                        if (result->response.nativeResult)
                            text += QStringLiteral("\n") + Text("window.dwm_order.error_hresult", "DWM 调用 HRESULT：0x%1。")
                                .arg(static_cast<std::uint32_t>(result->response.nativeResult), 8, 16, QLatin1Char('0'));
                        if (result->loaderThreadExitCode)
                            text += QStringLiteral("\n") + Text("window.dwm_order.loader_thread", "加载线程退出码：0x%1。")
                                .arg(result->loaderThreadExitCode, 8, 16, QLatin1Char('0'));
                        if (result->requestThreadExitCode)
                            text += QStringLiteral("\n") + Text("window.dwm_order.request_thread", "排序线程退出码：0x%1。")
                                .arg(result->requestThreadExitCode, 8, 16, QLatin1Char('0'));
                    }
                    if (result->response.flags & Maintaining)
                        text += QStringLiteral("\n") + Text("window.dwm_order.active", "正在持续保持窗口 0x%1。").arg(result->response.maintainedWindow, 0, 16);
                    if (result->response.maintenanceStatus != Status::Ok)
                        text += QStringLiteral("\n") + ErrorText(result->response.maintenanceStatus);
                    status_->setText(text);
                });
                connect(worker, &QThread::finished, worker, &QObject::deleteLater);
                Busy(true);
                status_->setText(Text("window.dwm_order.pending", "正在连接 DWM 并等待执行回执…"));
                worker->start();
            }

            WindowIdentity identity_;
            std::uint32_t identityError_ = 0;
            bool identityOk_ = false;
            bool busy_ = false;
            QComboBox* order_ = nullptr;
            QLineEdit* reference_ = nullptr;
            QCheckBox* maintain_ = nullptr;
            QPushButton* apply_ = nullptr;
            QPushButton* query_ = nullptr;
            QPushButton* restore_ = nullptr;
            QPushButton* stop_ = nullptr;
            QLabel* status_ = nullptr;
        };
    }

    QWidget* CreateControl(std::uint64_t hwnd, QWidget* parent) { return new Control(hwnd, parent); }
}
