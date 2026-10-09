#include "HvmWatchEventDialog.h"
#include "./DetailDialogChrome.h"

#include "StructuredFieldView.h"
#include "HvmControl.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"

#include <QClipboard>
#include <QDialog>
#include <QDialogButtonBox>
#include <QGuiApplication>
#include <QPushButton>
#include <QStringList>
#include <QVBoxLayout>

namespace
{
    // text：统一走语言包，保持与其余 HVM 界面一致。
    QString text(const QString& source)
    {
        return ks::i18n::sourceText(source);
    }

    // hex64：十六进制显示统一格式，16 位补零并大写。
    QString hex64(const unsigned long long value)
    {
        return QStringLiteral("0x%1")
            .arg(value, 16, 16, QLatin1Char('0')).toUpper();
    }

    /*
     * describeEptQualification：解码 EPT violation 的退出限定符。
     *
     * 只在退出原因确实是 EPT violation（48）时解码：同一个字段在别的退出原因下
     * 是完全不同的位布局，照着 EPT 的表去读会得到一串**读起来很像回事**的假话。
     *
     * 解码的是 Intel SDM 给 EPT violation 定义的低位：
     *   bit 0 本次访问是数据读      bit 3 该客户物理地址当时可读
     *   bit 1 本次访问是数据写      bit 4 该客户物理地址当时可写
     *   bit 2 本次访问是取指        bit 5 该客户物理地址当时可执行
     *   bit 7 客户线性地址有效      bit 8 有效时区分访问翻译结果还是访问页表本身
     *
     * 入参 qualification：事件行里的原始值。
     * 入参 exitReason：事件行里的退出原因，不是 48 就不解码。
     * 返回：逐行的解码说明；不解码时只说明为什么。
     */
    void appendEptQualification(
        ks::ui::FieldDocument& document,
        const unsigned long long qualification,
        const unsigned long exitReason)
    {
        if (exitReason != KSWORD_ARK_HVM_EXIT_REASON_EPT_VIOLATION)
        {
            document.field(QStringLiteral("限定符"), QStringLiteral("%1（退出原因是 %2，不是 EPT violation，所以这个字段不按 EPT 的位布局解读）")
                .arg(hex64(qualification))
                .arg(exitReason));
            return;
        }
        document.field(QStringLiteral("限定符"), QStringLiteral("%1")
            .arg(hex64(qualification)));
        // 本次访问的类型。三位可以同时为零（某些页表遍历产生的访问）。
        QStringList access;
        if ((qualification & 0x1ULL) != 0ULL)
        {
            access << text(QStringLiteral("数据读"));
        }
        if ((qualification & 0x2ULL) != 0ULL)
        {
            access << text(QStringLiteral("数据写"));
        }
        if ((qualification & 0x4ULL) != 0ULL)
        {
            access << text(QStringLiteral("取指"));
        }
        document.field(QStringLiteral("本次访问"), QStringLiteral("%1")
            .arg(access.isEmpty()
                ? text(QStringLiteral("处理器未标出读/写/取指中的任何一项"))
                : access.join(text(QStringLiteral(" + ")))));
        // 违规当时这一页在 EPT 上还剩哪些权限。它直接印证监视装上去的掩码。
        QStringList present;
        if ((qualification & 0x8ULL) != 0ULL)
        {
            present << text(QStringLiteral("可读"));
        }
        if ((qualification & 0x10ULL) != 0ULL)
        {
            present << text(QStringLiteral("可写"));
        }
        if ((qualification & 0x20ULL) != 0ULL)
        {
            present << text(QStringLiteral("可执行"));
        }
        document.field(QStringLiteral("页当时权限"), QStringLiteral("%1")
            .arg(present.isEmpty()
                ? text(QStringLiteral("读/写/执行全部被拿掉"))
                : present.join(text(QStringLiteral(" + ")))));
        // 线性地址是否有效，以及有效时它描述的是哪一层访问。
        const bool linearValid = (qualification & 0x80ULL) != 0ULL;
        document.field(QStringLiteral("线性地址"), QStringLiteral("%1")
            .arg(linearValid
                ? text(QStringLiteral("有效"))
                : text(QStringLiteral("处理器未报告（这与“地址不在范围内”是两件事）"))));
        if (linearValid)
        {
            document.field(QStringLiteral("访问对象"), QStringLiteral("%1")
                .arg((qualification & 0x100ULL) != 0ULL
                    ? text(QStringLiteral("线性地址翻译出来的那一页"))
                    : text(QStringLiteral("页表结构本身（不是目标数据页）"))));
        }

    }
}

namespace ks::ui
{
    FieldDocument buildWatchHitDocument(
        const ksword::hvm::HvmWatchEntry& entry,
        const ksword::hvm::HvmWatchHitEvent& hit,
        const QString& label)
    {
        ks::ui::FieldDocument document;
        document.section(QStringLiteral("监视目标"));
        // 标签是 R3 这一侧存的，协议里没有；没存过就明说，不留一行空白。
        document.field(QStringLiteral("标签"), QStringLiteral("%1")
            .arg(label.isEmpty()
                ? text(QStringLiteral("（未命名，在这一页直接添加的监视没有标签）"))
                : label));
        document.field(QStringLiteral("编号"), QStringLiteral("%1")
            .arg(entry.watchId));
        document.field(QStringLiteral("请求地址"), QStringLiteral("%1")
            .arg(hex64(entry.requestedAddress)));
        document.field(QStringLiteral("请求长度"), QStringLiteral("%1 字节")
            .arg(entry.requestedLength));
        document.field(QStringLiteral("实际监视页"), QStringLiteral("%1，4096 字节")
            .arg(hex64(entry.physicalPage)));
        /*
         * 页内偏移单独列出来。
         *
         * 它是"请求地址落在被监视那一页的第几个字节"，也就是页粒度与用户真正
         * 关心的那几个字节之间的距离。不列出来，两个地址摆在一起看着像是同一
         * 回事；列出来，用户一眼能看出监视范围比自己选的宽了多少。
         */
        document.field(QStringLiteral("页内偏移"), QStringLiteral("+0x%1")
            .arg(entry.requestedAddress & 0xFFFULL, 0, 16));
        document.field(QStringLiteral("请求访问"), QStringLiteral("%1")
            .arg(ksword::hvm::describeWatchAccess(entry.requestedAccess)));
        document.field(QStringLiteral("实际访问"), QStringLiteral("%1")
            .arg(ksword::hvm::describeWatchAccess(entry.effectiveAccess)));


        document.section(QStringLiteral("监视自己保留的现场"));
        // 这一段来自 watch 记录本身，事件环丢了也还在。
        document.field(QStringLiteral("命中时间"), QStringLiteral("%1")
            .arg(ksword::hvm::describeWatchHitTime(entry.lastHitTimestamp)));
        document.field(QStringLiteral("累计命中"), QStringLiteral("%1 次")
            .arg(entry.hitCount));
        document.field(QStringLiteral("处理器"), QStringLiteral("%1:%2")
            .arg(entry.lastHitProcessorGroup)
            .arg(entry.lastHitProcessorNumber));
        document.field(QStringLiteral("RIP"), QStringLiteral("%1")
            .arg(hex64(entry.lastHitRip)));
        document.field(QStringLiteral("RSP"), QStringLiteral("%1")
            .arg(hex64(entry.lastHitRsp)));
        document.field(QStringLiteral("CR3"), QStringLiteral("%1")
            .arg(entry.lastHitCr3 != 0ULL
                ? hex64(entry.lastHitCr3)
                : text(QStringLiteral("未采集"))));


        document.section(QStringLiteral("事件环"));
        document.field(QStringLiteral("查询结果"), QStringLiteral("%1").arg(hit.message));
        switch (hit.kind)
        {
        case ksword::hvm::HvmWatchHitEventKind::Found:
        {
            // 只有这一态能拿到 qualification，而它正是这个窗口存在的理由。
            document.field(QStringLiteral("事件序号"), QStringLiteral("%1")
                .arg(hit.event.sequence));
            document.field(QStringLiteral("退出原因"), QStringLiteral("%1")
                .arg(hit.event.exitReason));
            document.field(QStringLiteral("客户物理地址"), QStringLiteral("%1")
                .arg(hex64(hit.event.guestPhysicalAddress)));
            document.field(QStringLiteral("客户线性地址"), QStringLiteral("%1")
                .arg((hit.event.eventFlags &
                        KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID) != 0UL
                    ? hex64(hit.event.guestLinearAddress)
                    : text(QStringLiteral("处理器未报告"))));
            // 两种"答不了"与面板详情同一套判据：处理器没给线性地址，
            // 或者这条监视按物理地址建立（那时比较的两个值不在同一个地址空间）。
            document.field(QStringLiteral("落在请求范围内"), QStringLiteral("%1")
                .arg((hit.event.eventFlags &
                        KSWORD_ARK_HVM_EVENT_FLAG_GLA_VALID) == 0UL
                    ? text(QStringLiteral("无法判断（没有有效的客户线性地址）"))
                    : entry.addressKind !=
                        KSWORD_ARK_HVM_WATCH_ADDRESS_VIRTUAL
                        ? text(QStringLiteral("无法判断（这条监视按物理地址建立，而处理器报告的是线性地址，两者不在同一个地址空间）"))
                        : (hit.event.eventFlags &
                            KSWORD_ARK_HVM_EVENT_FLAG_RANGE_MATCH) != 0UL
                            ? text(QStringLiteral("是"))
                            : text(QStringLiteral("否，落在同一页的其它偏移上"))));
            document.field(QStringLiteral("命中后状态"), QStringLiteral("%1")
                .arg(ksword::hvm::describeWatchState(hit.event.watchState)));
            appendEptQualification(document, hit.event.qualification, hit.event.exitReason);
            break;
        }
        case ksword::hvm::HvmWatchHitEventKind::Evicted:
            /*
             * 证据丢了。这一段必须说出"目标确实被访问过"。
             *
             * 少了这句，界面上"取不回事件"与"从未命中"长得一模一样，而它们的
             * 结论正好相反——这是这个功能最不能给错的那一条。
             */
            document.field(QStringLiteral("已经确定的事"), QStringLiteral("目标被访问过。上面那份现场是监视在命中那一刻自己留的，与事件环是否接住无关。"));
            document.field(QStringLiteral("取不回来的是"), QStringLiteral("处理器给出的退出限定符（qualification）——它只写进事件环，监视记录里没有这个字段。"));
            break;
        case ksword::hvm::HvmWatchHitEventKind::Unavailable:
            document.field(QStringLiteral("注意"), QStringLiteral("这一条说的是“这次查询没跑起来”，不是“目标没被访问”。上面那份现场如果非零，就说明确实命中过。"));
            break;
        case ksword::hvm::HvmWatchHitEventKind::NeverHit:
        default:
            break;
        }
        if (hit.droppedRows != 0UL)
        {
            document.field(QStringLiteral("本次快照丢行"), QStringLiteral("%1（消费跟不上产生速度，环在回绕）")
                .arg(hit.droppedRows));
        }


        document.section(QStringLiteral("HVM"));
        document.field(QStringLiteral("监视状态"), QStringLiteral("%1")
            .arg(ksword::hvm::describeWatchState(entry.state)));
        document.field(QStringLiteral("武装代次"), QStringLiteral("%1")
            .arg(entry.armedGeneration));
        /*
         * 命中前后的常驻处理器数不在这里显示。
         *
         * issue 的详情规格里列了 Resident before / Resident after，但协议没有在
         * watch 记录或事件行里存过这两个数——驱动在命中路径上不统计它们。能查到
         * 的只有"现在有几个处理器在常驻"，而那是查看的这一刻的值，不是命中那一
         * 刻的值。把当前值标成 before/after 就是在报一个没有观测过的数字，所以
         * 这里明说它从哪来，判据留给 hvm_ctl 的自检——那条路径是在命中前后各读
         * 一次，真的量到了差值。
         */
        document.field(QStringLiteral("常驻处理器数"), QStringLiteral("命中前后的数值未被记录；命中不结束常驻这一条的判据在 hvm_ctl 的 watch-selftest 里（它在命中前后各读一次并比对）。"));
        return document;
    }

    void showWatchHitEvent(
        QWidget* const parent,
        const ksword::hvm::HvmWatchEntry& entry,
        const ksword::hvm::HvmWatchHitEvent& hit,
        const QString& label)
    {
        QDialog dialog(parent);
        dialog.setObjectName(QStringLiteral("hvmWatchHitEventDialog"));
        dialog.setWindowTitle(
            text(QStringLiteral("内存监视 #%1 的命中现场")).arg(entry.watchId));
        dialog.resize(900, 640);
        // 详情弹窗必须显式设置不透明背景，否则浅色主题下可能出现黑底黑字。
        dialog.setStyleSheet(
            KswordTheme::OpaqueDialogStyle(dialog.objectName()));

        auto* const layout = new QVBoxLayout(&dialog);
        layout->setContentsMargins(10, 10, 10, 10);
        layout->setSpacing(8);

        // 文本详情统一用项目内置编辑器，而不是裸 QTextEdit。
        auto* const editor = new StructuredFieldView(&dialog);
        editor->setDocument(buildWatchHitDocument(entry, hit, label));
        layout->addWidget(editor, 1);

        auto* const buttonBox =
            new QDialogButtonBox(QDialogButtonBox::Close, &dialog);
        QPushButton* const copyButton = buttonBox->addButton(
            text(QStringLiteral("复制现场")),
            QDialogButtonBox::ActionRole);
        copyButton->setToolTip(
            text(QStringLiteral("把这一页完整的命中现场复制到剪贴板，可直接贴进报告。")));
        QObject::connect(copyButton, &QPushButton::clicked, &dialog,
            [editor]() {
                if (editor != nullptr &&
                    QGuiApplication::clipboard() != nullptr)
                {
                    QGuiApplication::clipboard()->setText(editor->plainText());
                }
            });
        QObject::connect(buttonBox, &QDialogButtonBox::rejected,
            &dialog, &QDialog::reject);
        layout->addWidget(buttonBox);
        ApplyDetailDialogChrome(&dialog);
        dialog.exec();
    }
}
