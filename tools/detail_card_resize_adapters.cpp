// 普通详情卡片夹具只隔离未使用的复杂报告分支；误入该分支立即失败，不模拟任何字段几何。
#include "UI/ComplexReportView.h"
#include "UI/CodeEditorWidget.h"
#include "UI/CodeTextEdit.h"
#include <cstdlib>

// 本夹具不构造编辑器；只满足共享分栏文件中未调用的类型识别依赖。
const QMetaObject CodeEditorWidget::staticMetaObject = QWidget::staticMetaObject;
void CodeTextEdit::refreshThemeColors()
{
    std::abort();
}

namespace ks::ui
{
    // 输入父窗口；普通令牌文档不应构造复杂报告，调用即中止夹具。
    ComplexReportView::ComplexReportView(QWidget* parent) : QWidget(parent)
    {
        std::abort();
    }

    // 无输入输出；只补齐未使用分支的虚表，生产卡片不经过此析构。
    ComplexReportView::~ComplexReportView() = default;

    // 输入规范文档；该夹具禁止复杂报告业务路径，调用即失败。
    void ComplexReportView::setDocument(const FieldDocument&)
    {
        std::abort();
    }

    // 输入搜索词；普通字段搜索必须由真实DetailFieldProjection处理。
    void ComplexReportView::setSearchText(const QString&)
    {
        std::abort();
    }

    // 输入搜索框；普通字段页不允许走复杂报告的搜索绑定。
    void ComplexReportView::bindSearchField(QLineEdit*)
    {
        std::abort();
    }

    // 无输入输出；禁止把复杂报告主题路径当成普通卡片测试。
    void ComplexReportView::refreshTheme()
    {
        std::abort();
    }

    // 输入Qt事件；未使用的复杂报告对象不应收到窗口事件。
    void ComplexReportView::changeEvent(QEvent*)
    {
        std::abort();
    }

    // 输入显示事件；普通卡片夹具误入复杂报告时立刻报告失败。
    void ComplexReportView::showEvent(QShowEvent*)
    {
        std::abort();
    }

    // 无输入；夹具关闭无关Tab动画，不影响普通卡片布局和字段搜索。
    bool AreUiAnimationsEnabled()
    {
        return false;
    }
}
