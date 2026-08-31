#pragma once

// ============================================================
// ReportStructuredView.h
// 作用：
// - 把本程序各审计页生成的“只读详情报告纯文本”解析成结构化视图；
// - 解析结果按内容形态分块呈现，而不是一律塞进同一棵属性树：
//     · 分组字段 → 可折叠分组 + 两列属性表；
//     · 无分组字段 → 平铺两列属性表（不显示树形箭头）；
//     · 同构多列行（竖线/多空格对齐） → 真正的表格控件；
//     · hex dump / 反汇编 / 连续缩进块 → 等宽只读代码块；
//     · 整句说明 → 跨列说明行或独立段落；
// - 只做展示层解析，绝不改写报告原文，也不参与取证逻辑。
//
// 使用方式：
// - CodeEditorWidget 在只读报告模式下内置本视图并提供切换入口；
// - 其它需要“同一份报告换个结构化视图”的场景可直接复用。
// ============================================================

#include <QFont>
#include <QString>
#include <QWidget>

class QVBoxLayout;
class QScrollArea;

namespace ks::ui
{
    // ScaledReportFont 作用：
    // - 输入 baseFont：界面默认字体；
    // - 处理：按结构化报告统一的放大倍数放大，优先用 pointSizeF，磅值不可用时退回像素值；
    // - 返回：报告结构化呈现应当使用的字体。
    // 用途：详情报告要逐条读地址、哈希和路径，界面默认那一档字号看着吃力。
    //       页面自建的属性树（例如文件常规页那棵从 R0 结构体搭出来的树）也必须调用它，
    //       否则同一个窗口里两种结构化视图会出现两种字号。
    QFont ScaledReportFont(const QFont& baseFont);

    // ReportStructuredView：报告结构化视图控件。
    // 生命周期由 Qt 父子机制管理；控件不持有任何业务数据副本以外的资源。
    class ReportStructuredView final : public QWidget
    {
    public:
        // 构造函数：建立滚动容器与纵向块布局，不做任何解析。
        // 入参 parent：Qt 父控件，可为空。
        explicit ReportStructuredView(QWidget* parent = nullptr);
        ~ReportStructuredView() override;

        // setReportText：
        // - 入参 localizedReportText：已完成本地化的报告纯文本（调用方负责翻译）；
        // - 处理：解析成块模型并缓存；控件不可见时只缓存不建控件，等到显示时再构建；
        // - 返回：true 表示解析出可展示结构，调用方应允许切到本视图；
        //         false 表示该文本没有结构（纯说明、日志、原始数据），应继续用纯文本。
        bool setReportText(const QString& localizedReportText);

        // canStructure：
        // - 入参 localizedReportText：待判定的报告纯文本；
        // - 处理：只做解析判定，不建任何控件；
        // - 返回：true 表示值得提供结构视图。
        static bool canStructure(const QString& localizedReportText);

        // hasStructure：返回最近一次 setReportText 的判定结果。
        bool hasStructure() const;

        // verticalScrollBarWidth：
        // - 返回当前可见的垂直滚动条宽度，没有滚动条时为 0；
        // - 用途：宿主把悬浮控件贴到右上角时需要避开滚动条，否则拖动条容易误点。
        int verticalScrollBarWidth() const;

    protected:
        // changeEvent：主题调色板变化时按新前景色重建块，保证状态色跟随主题。
        void changeEvent(QEvent* event) override;

        // showEvent：首次显示或缓存失效时才真正构建子控件，避免频繁选行造成无谓开销。
        void showEvent(QShowEvent* event) override;

    private:
        // rebuildBlocks：按当前缓存的块模型重建全部子控件。
        void rebuildBlocks();

        // clearBlocks：删除已构建的块控件并清空布局。
        void clearBlocks();

        QScrollArea* m_scrollArea = nullptr;   // m_scrollArea：块容器的滚动宿主。
        QWidget* m_blockHost = nullptr;        // m_blockHost：承载全部块控件的内容面板。
        QVBoxLayout* m_blockLayout = nullptr;  // m_blockLayout：块纵向布局。
        QString m_reportText;                  // m_reportText：最近一次解析的报告原文（已本地化）。
        bool m_hasStructure = false;           // m_hasStructure：最近一次解析是否命中结构。
        bool m_blocksDirty = true;             // m_blocksDirty：块控件是否需要重建。
    };
}
