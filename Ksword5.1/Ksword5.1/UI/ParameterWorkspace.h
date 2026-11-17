#pragma once
#include <QWidget>
#include <QList>

class QVBoxLayout;
class QHBoxLayout;
class QSplitter;
class QScrollArea;
class QGroupBox;

namespace ks::ui
{
    // 参数操作页的两栏骨架；参数独立滚动，执行区固定，结果保留全部可用高度。
    class ParameterWorkspace final : public QWidget
    {
    public:
        explicit ParameterWorkspace(QWidget* parent, int parameterWidth = 480);
        QVBoxLayout* parameters() const { return m_parameters; }
        QVBoxLayout* results() const { return m_results; }
        QHBoxLayout* actions() const { return m_actions; }
        // 多组参数共用的标题/管理动作固定在滚动正文上方；按需创建。
        QVBoxLayout* parameterHeader();
        // 目录选择器等已有内部滚动的正文使用独立视口，避免外层表单滚动再次包树。
        // 构造期间、添加 parameters() 内容之前调用一次；动作栏与自适应分栏继续由框架拥有。
        void setParameterViewport(QWidget* viewport);
        // 明确需要并排比较的参数列保留最小宽度，由同一正文视口承担横纵滚动。
        void enableHorizontalParameterScroll();
        void revealParameter(QWidget* target);
        // 仅参数密集页显式调用；宽屏按百分比分配初始宽度，之后保留用户拖动的分栏比例。
        void useWideParameterLayout(int parameterPercent = 60);
        // 查询面板嵌入并列工作流时，参数在上、动作固定居中、结果占下方空间。
        // 页面构造完成、finish() 前调用；其它页面保持原自适应两栏行为。
        void useStackedLayout();
        // 页面完成构造后调用，只为该参数区内的独立输入控件补齐表面和行高。
        void finish();
    protected:
        void resizeEvent(QResizeEvent* event) override;
    private:
        QSplitter* m_splitter = nullptr; // 宽窗口左右排列，窄窗口上下排列。
        QScrollArea* m_scroll = nullptr; // 只有参数正文参与滚动，底部动作不滚走。
        QWidget* m_parameterPanel = nullptr;
        QWidget* m_parameterViewport = nullptr;
        QWidget* m_resultPanel = nullptr;
        QVBoxLayout* m_parameters = nullptr;
        QVBoxLayout* m_parameterHeader = nullptr;
        QVBoxLayout* m_results = nullptr;
        QHBoxLayout* m_actions = nullptr;
        int m_parameterWidth = 480;
        int m_parameterPercent = 0; // 零表示原固定宽参数栏，非零表示页面选择的宽屏比例。
        QList<int> m_horizontalSizes; // 宽窄切换前记住用户的横向分栏比例。
        QList<int> m_verticalSizes; // 独立保留上下排列时的用户高度分配。
        bool m_positioned = false; // 初次分配后保留用户拖动分隔条的位置。
        bool m_stackedLayout = false; // 显式选择上下参数/结果，不按窄面板再套左右栏。
    };

    // 仅由逐页布局明确登记；保留内容、验证器、业务信号与启用状态。
    void StyleParameterFields(QWidget* container);
    // 同步明确登记编辑区的 QSS 与真实 palette；只读日志跟随面板底色，输入单独铺底。
    void StyleWorkspaceTextViews(QWidget* container);
    void StyleParameterSection(QGroupBox* group);
    // 独立条件卡片使用有底色的标题/正文结构，适用于一列内多个列表型参数。
    void StyleParameterCard(QGroupBox* group);
    // 嵌入参数面板的普通页壳与滚动画布复用同一内容底色，不新增页根层。
    void StyleParameterCanvas(QWidget* canvas);
    // 页面完成分区后显式调用：两列分别自然排列；不够两列时按原 layout 顺序回到单列。
    // 不替换任何字段或连接；minimumColumnWidth 是每列正文可用宽度下限，单位为逻辑像素。
    void ArrangeParameterColumns(QVBoxLayout* layout, const QList<QWidget*>& primary,
        const QList<QWidget*>& secondary, int minimumColumnWidth = 300);
    // 将低频参数放入可展开分区，默认折叠，不改变子控件自身 enabled 状态。
    QWidget* FoldParameterSection(QGroupBox* group, bool expanded = false);
}
