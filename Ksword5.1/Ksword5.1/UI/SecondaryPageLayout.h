#pragma once

class QWidget;
class QTabWidget;
class QGroupBox;
class QFormLayout;
class QDialogButtonBox;
class QLayout;

namespace ks::ui
{
    // 只为逐页确认的配置、编辑或工具窗口启用平面主题；属性和详情窗口不调用。
    // window 保留原来的布局、业务信号和关闭语义，主题更新仅替换本模块拥有的样式。
    void StyleSecondaryWindow(QWidget* window);

    // tabs 保留页序、惰性构建和键盘路由，仅改为顶部文字导航与细选中线。
    void StyleSecondaryTabs(QTabWidget* tabs);

    // section 保留标题、勾选状态及内容，使用标题下的细线分区，减少嵌套卡片。
    void StyleSecondarySection(QGroupBox* section);

    // form 将标签左对齐，labelWidth 是同列标签的建议最小宽度；窄窗允许换行。
    void StyleSecondaryForm(QFormLayout* form, int labelWidth = 160);

    // footer 是已置于滚动内容之外的操作区；函数不会搬动或重复创建业务按钮。
    void StyleSecondaryFooter(QWidget* footer);
    void StyleSecondaryButtonBox(QDialogButtonBox* buttons);

    // 只调整调用方明确传入的内容布局，不递归改变内部表格、编辑器或工具条。
    void StyleSecondaryContentLayout(QLayout* layout);

    // primary、secondary 为已创建的两块内容；宽窗按比例并列，窄窗按原顺序纵排。
    // parent 管理返回容器生命周期，breakpoint 使用逻辑像素并跟随字号缩放。
    QWidget* CreateSecondaryColumns(QWidget* primary, QWidget* secondary,
        QWidget* parent = nullptr, int breakpoint = 900,
        int primaryStretch = 3, int secondaryStretch = 2);
}
