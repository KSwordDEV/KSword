#pragma once

// ============================================================
// WorkbenchStatusBar.h
// 作用：
// - 工作台的单一状态条（ux.md 第 5 节）：一行可省略/可复制的摘要 + 保护属性
//   徽章 + ▾诊断抽屉（只读、自动换行可选、错误时自动展开、带"复制诊断"钮）。
// - 两个 chip 的持久化规则不同，必须分别实现：
//     暂存扇区脏（scratchAreaDirty）—— 一旦任意一次写入报告过为真，chip 就
//     常驻显示，哪怕后面成功也不消失，**只能点 × 显式确认**才消（不变式 14）；
//     读-改-写窗口（readModifyWriteWindow）—— 只反映"最近这一次"的状态，不常驻。
// - 诊断抽屉经 IWorkbenchDiagnosticsHost 注入：结构报告走正式字段模型接口；
//   通道失败信息和原始日志走文本接口。复制仅在触发时从当前数据源生成。
// ============================================================

#include <QString>
#include <QWidget>

#include "../ThemeStatusRole.h"

#include <memory>

class QCheckBox;
class QLabel;
class QToolButton;
class QWidget;

namespace ks::ui
{
    struct FieldDocument;
    // IWorkbenchDiagnosticsHost：诊断抽屉的最小接口，把"只读、可选换行、可复制"的
    // 字段模型或原始文本与具体控件实现解耦。
    class IWorkbenchDiagnosticsHost
    {
    public:
        virtual ~IWorkbenchDiagnosticsHost() = default;

        // HostWidget：嵌入抽屉布局的控件；状态条通过接口持有宿主对象的所有权。
        virtual QWidget* HostWidget() = 0;

        // SetDiagnosticsText：设置一条原始失败信息或真实日志。
        virtual void SetDiagnosticsText(const QString& text) = 0;
        // 结构报告必须由实现直接显示模型，不允许导出全文后回落到文本控件。
        virtual void SetDiagnosticsDocument(const FieldDocument& document) = 0;
        // 文本为原文；结构模式按需导出当前模型，供复制动作使用。
        virtual QString DiagnosticsText() const = 0;

        // SetWrapEnabled：切换自动换行（ux.md 要求"自动换行可选"）。
        virtual void SetWrapEnabled(bool wrap) = 0;
    };

    // WorkbenchStatusBar：单一状态条控件。
    class WorkbenchStatusBar final : public QWidget
    {
        Q_OBJECT

    public:
        // 构造：diagnosticsHost 必须非空；生产双模式控件或测试替身均实现正式接口。
        // 本控件取得宿主对象的所有权（存进 unique_ptr）。
        explicit WorkbenchStatusBar(std::unique_ptr<IWorkbenchDiagnosticsHost> diagnosticsHost, QWidget* parent = nullptr);
        ~WorkbenchStatusBar() override;

        // setChannelScopeText：①通道·范围段。文字已在上层翻译好，本控件只负责展示。
        void setChannelScopeText(const QString& text);

        // setReadResultText：②读取结果段（"已读 M/N 字节"一类），warning 为真时加⚠标记。
        void setReadResultText(const QString& text, bool warning);

        // setProtection：③保护属性徽章，text 是展示文字（例如 "RWX"），role 决定配色。
        void setProtection(const QString& text, ks::ui::StatusRole role);

        // setWindowRangeText：④窗口范围段。
        void setWindowRangeText(const QString& text);

        // setWriteResultText：⑤写入结果段的主句（通常来自
        // WorkbenchMessages::CommitReportSummary，本控件不关心它怎么拼出来的）。
        void setWriteResultText(const QString& text);

        // reportScratchAreaDirty：喂入"这一次访问是否报告了暂存区变脏"。为真会让红
        // chip 常驻显示（即使后面传入 false 也不会自动隐藏，必须用户点 ×）；默认
        // 不显示，首次为真才出现。
        void reportScratchAreaDirty(bool dirtyThisReport);

        // isScratchAreaDirtyChipVisible / acknowledgeScratchAreaDirty：供测试读取与
        // 模拟用户点 × 确认；确认后 chip 隐藏，scratchDirtyAcknowledged 信号发出。
        bool isScratchAreaDirtyChipVisible() const;
        void acknowledgeScratchAreaDirty();

        // setReadModifyWriteWindow：橙色瞬时 chip，直接反映最近一次调用的布尔值。
        void setReadModifyWriteWindow(bool active);
        bool isReadModifyWriteWindowChipVisible() const;

        // setNeedsReread：显示/隐藏"建议重新读取"提示；点击它会发出 rereadRequested。
        void setNeedsReread(bool needsReread);

        // setDiagnosticsText：写入诊断抽屉的完整文本；autoExpand 为真时强制展开抽屉
        //（ux.md："错误时自动展开"）。
        void setDiagnosticsText(const QString& text, bool autoExpand);
        void setDiagnosticsDocument(const FieldDocument& document, bool autoExpand);
        QString diagnosticsText() const;

        // setDrawerExpanded / isDrawerExpanded：展开/收起诊断抽屉。
        void setDrawerExpanded(bool expanded);
        bool isDrawerExpanded() const;

        // summaryText：当前拼好的一行摘要（省略前的完整文本，供测试核对）。
        QString summaryText() const;

    protected:
        // resizeEvent：窗口变宽/变窄时重新计算摘要的省略显示。
        void resizeEvent(QResizeEvent* event) override;

        // eventFilter：只用来捕获"建议重新读取"提示标签上的鼠标点击，转成 rereadRequested。
        bool eventFilter(QObject* watched, QEvent* event) override;

    signals:
        // scratchDirtyAcknowledged：用户点了暂存区脏 chip 的 ×。
        void scratchDirtyAcknowledged();
        // rereadRequested：用户点了"建议重新读取"提示。
        void rereadRequested();

    private:
        // rebuildSummary：按四个段落字段（保护属性徽章单独展示，不进摘要文本，理由
        // 见 .cpp）刷新四个独立 QLabel 与分隔符的文字/显隐，并重新拼出
        // m_summaryFullText（供 summaryText()/tooltip 使用），再调用 applyElidedSummary。
        // S1：四段故意分成四个独立 QLabel 而不是拼成一条字符串——运行期整句翻译
        // （LanguageManager）按控件逐一扫描 QLabel::text() 做匹配，拼接出的新字符串
        // 不会出现在任何词条表里，英文界面下这一整行会原样显示中文。拆成独立
        // QLabel 后，每一段仍是调用方给出的那个原始字符串，才能被正确匹配到。
        void rebuildSummary();

        // applyElidedSummary：对"写入结果"这一段做 setText 级省略（它是唯一可能携带任意长度
        // 失败详情的段落），省略宽度按容器宽度减去其余可见控件估算。其余三段不走这里：
        // 通道·范围段文字短且有界，始终完整显示；读取结果/窗口范围两段是绘制级省略的标签
        // （text() 仍是完整原文，窄时画成"…"，见 .cpp 的 ElidedSegmentLabel）。
        void applyElidedSummary();

        // m_summaryFullText：五段拼接后的完整摘要（未省略），resizeEvent 时据此重新省略。
        QString m_summaryFullText;

        // m_channelScopeText..m_writeResultText：五个段落的当前文字。
        QString m_channelScopeText;
        QString m_readResultText;
        QString m_protectionText;
        QString m_windowRangeText;
        QString m_writeResultText;

        // m_scratchDirtyLatched：暂存区脏 chip 是否仍处于"需要用户确认"状态。
        bool m_scratchDirtyLatched = false;

        std::unique_ptr<IWorkbenchDiagnosticsHost> m_diagnosticsHost;

        QLabel* m_protectionBadge = nullptr;
        // m_channelScopeLabel..m_writeResultLabel：四段摘要各自的 QLabel（S1）；
        // m_separators[0..2] 是它们之间的竖线分隔符，只有"前面已经有可见段、且本段
        // 本身也可见"时才显示，避免连续出现"| |"（逐一对应原来拼接字符串时跳过
        // 空段的规则）。
        QLabel* m_channelScopeLabel = nullptr;
        QLabel* m_readResultLabel = nullptr;
        QLabel* m_windowRangeLabel = nullptr;
        QLabel* m_writeResultLabel = nullptr;
        QLabel* m_separators[3] = { nullptr, nullptr, nullptr };
        QToolButton* m_expandButton = nullptr;
        QWidget* m_drawerContainer = nullptr;
        QToolButton* m_copyDiagnosticsButton = nullptr;
        // m_wrapCheckBox：诊断抽屉的"自动换行"勾选框（B12——SetWrapEnabled 原来是
        // 一个没有任何调用方的死接口，现在真正接上）。
        QCheckBox* m_wrapCheckBox = nullptr;
        QWidget* m_scratchDirtyChip = nullptr;
        QToolButton* m_scratchDirtyAckButton = nullptr;
        QWidget* m_rmwChip = nullptr;
        QLabel* m_needsRereadLabel = nullptr;
    };
}
