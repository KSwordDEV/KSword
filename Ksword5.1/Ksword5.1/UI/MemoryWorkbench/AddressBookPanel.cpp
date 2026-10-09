// AddressBookPanel.cpp
#include "../FlatButtonTheme.h"
// 作用：AddressBookPanel.h 声明的实现——UI 装配、列组切换、kind 分段、键盘/双击行为、
// previewCopyText/selectedIds 等查询方法，以及两个内部辅助类
// （detail::AddressBookTableView、detail::ValueColumnDelegate）的实现。
// 右键菜单单独放在 AddressBookPanel.Menu.cpp（见该文件）。

#include "AddressBookPanel.h"

#include "../FlowLayout.h"
#include "../../theme.h"
#include "../../Internationalization/LanguageManager.h"
#include "HexViewWidgets.h"

#include <QApplication>
#include <QEvent>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QKeyEvent>
#include <QKeySequence>
#include <QLineEdit>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSortFilterProxyModel>
#include <QVBoxLayout>

namespace ks::ui
{
    namespace
    {
        // kValueEditorInitializedProperty / kValueEditorInitialTextProperty：挂在"值"列
        // 编辑器（QLineEdit）上的动态属性名。
        // - Initialized：编辑器第一次被 ValueColumnDelegate::setEditorData 填充后置真；
        //   修复 C1——Qt 对"正在编辑的索引"收到 dataChanged 会再调一次 setEditorData，
        //   若每次都重新 setText+selectAll，常驻监视按 1Hz 喂入哪怕值没变也会反复调用
        //   setValueText（Model 侧已经按"值没变就不发 dataChanged"挡掉一部分，这里再挡
        //   "值确实变了"的那部分），把用户刚敲的字抹成旧值、还全选。只在第一次（刚
        //   createEditor 之后）真正填充，后续调用一律忽略。
        // - InitialText：编辑器打开时的初始文本快照；修复 C2——提交（Tab/Enter/失焦）时
        //   与它比较，文本完全没动就不发 valueEditRequested，避免把 Stale/占位文本当新值
        //   写回目标。
        constexpr const char* kValueEditorInitializedProperty = "ksAddressBookValueEditorInitialized";
        constexpr const char* kValueEditorInitialTextProperty = "ksAddressBookValueEditorInitialText";

        // BuildColumnButtonStyle：A/B 列组按钮的样式，照抄仓库既有范式
        // （MiscDock/ClipboardGuard/ClipboardGuardPage::buildPresetButtonStyle）：未选中态用
        // 主题表面色，选中态（:checked）用强调色；两个按钮都未选中时自然呈现"未着色"的外观，
        // 这正是"自定义列显隐后 A/B 钮都不着色"的实现方式——不需要额外的"不着色"样式分支。
        // 传入：leftButton 决定圆角画在哪一侧（A 在左、B 在右，紧贴摆放）。
        // 修复 C10：未选中态的三个颜色改用 *Hex()（返回 "palette(...)" 这类 Qt 样式表动态
        // 占位符，由 Qt 的样式引擎在每次绘制时现查当前 QPalette），不再用 *ColorHex()
        // （在调用的那一刻把颜色定格成字面 "#RRGGBB"）——样式表字符串本身只在构造时生成
        // 一次，若颜色是字面值，深浅主题切换后 QApplication::setPalette 不会让这段已经生成
        // 好的 QSS 文本重新生成，按钮就停留在旧主题的颜色上；palette(...) 占位符不受这个
        // 限制，与参照实现（ClipboardGuardPage::buildPresetButtonStyle）基本一致。
        // 修复 D11（C10 只修了一半）：选中态底色/边框原来用 AccentHex(Blue)——这个函数
        // 尽管名字里也带 Hex，返回的仍是调用瞬间现查现算后定格的字面 "#RRGGBB"（不是
        // palette(...) 占位符），参照实现 ClipboardGuardPage 其实有同样的问题，只是它靠
        // 每次切换列预设都重新 setStyleSheet 这件事"附带"刷新了颜色，本面板构造时只设一次
        // 样式表，没有这个附带效果。这里换成 KswordTheme::PrimaryBlueHex——它是
        // "palette(highlight)" 的动态占位符（theme.h 里专门为兼容旧调用点保留的
        // const QString，不是函数），选中态底色与边框因此也能随 Qt 样式引擎重新求值。
        // 悬停底色（%5）theme.h 里没有现成的动态"淡强调色"角色（Qt 的 palette(...) 语法
        // 本身没有这个标准角色可用），这一色仍是调用瞬间算好的字面值，靠下面新增的
        // changeEvent（监听 ApplicationPaletteChange）在主题真的切换时重新调用本函数、
        // 整段样式表一起换新来兜底——不依赖主程序的全局 ThemeColorRemap。
        QString BuildColumnButtonStyle(const bool leftButton)
        {
            const QString outerRadius = leftButton
                ? QStringLiteral("border-top-left-radius:3px;border-bottom-left-radius:3px;")
                : QStringLiteral("border-top-right-radius:3px;border-bottom-right-radius:3px;border-left:0px;");
            // 紧贴 A/B 保留固定点击区与外侧圆角，checked 状态由实心主题规则绘制。
            return ks::ui::BuildFlatButtonStyle(ks::ui::FlatButtonTone::Neutral)
                + QStringLiteral("QPushButton{min-width:27px;max-width:27px;min-height:26px;max-height:26px;"
                    "padding:0px;font-weight:700;border-radius:0px;%1}").arg(outerRadius);
        }
    }

    // ========================= detail::AddressBookTableView =========================

    detail::AddressBookTableView::AddressBookTableView(AddressBookPanel* owner, QWidget* parent)
        : QTableView(parent)
        , m_owner(owner)
    {
    }

    void detail::AddressBookTableView::keyPressEvent(QKeyEvent* event)
    {
        // 这个函数只会在"表格本身持有焦点"时被调用：某个单元格处于编辑态时，焦点落在
        // 编辑器控件（例如 QLineEdit）上，按键事件会先交给编辑器，不会到这里——所以下面
        // 四个分支天然不会打断正在进行中的编辑。
        if (event->key() == Qt::Key_Delete)
        {
            m_owner->handleDeleteKey();
            event->accept();
            return;
        }
        if (event->key() == Qt::Key_F2)
        {
            m_owner->handleF2Key();
            event->accept();
            return;
        }
        if (event->key() == Qt::Key_Return || event->key() == Qt::Key_Enter)
        {
            m_owner->handleEnterKey();
            event->accept();
            return;
        }
        if (event->matches(QKeySequence::Copy))
        {
            m_owner->handleCopyShortcut();
            event->accept();
            return;
        }
        QTableView::keyPressEvent(event);
    }

    // ========================= detail::ValueColumnDelegate =========================

    detail::ValueColumnDelegate::ValueColumnDelegate(AddressBookPanel* owner, QObject* parent)
        : QStyledItemDelegate(parent)
        , m_owner(owner)
    {
    }

    QWidget* detail::ValueColumnDelegate::createEditor(
        QWidget* parent,
        const QStyleOptionViewItem& option,
        const QModelIndex& index) const
    {
        Q_UNUSED(option);
        const AddressBookModel* const model = m_owner->model();
        if (model != nullptr && model->isPointerChain(model->idAt(m_owner->sourceIndexForProxy(index))))
        {
            return nullptr;
        }
        // 单行文本框即可：ValueType 决定的只是"这串文本按什么类型编码"，编码本身发生在
        // 上层收到 valueEditRequested 之后，编辑器不需要按类型切换成不同的输入控件。
        QLineEdit* const editor = new QLineEdit(parent);
        editor->setFrame(false);
        return editor;
    }

    void detail::ValueColumnDelegate::setEditorData(QWidget* editor, const QModelIndex& index) const
    {
        QLineEdit* const lineEdit = qobject_cast<QLineEdit*>(editor);
        if (lineEdit == nullptr)
        {
            return;
        }
        // 修复 C1：只在"刚 createEditor 出来、还没填过一次"时才真正填充。这个函数在编辑
        // 期间还会被 Qt 再次调用——QAbstractItemView::dataChanged 对"正在编辑的索引"会
        // 重新调用委托的 setEditorData 来刷新编辑器，哪怕用户已经敲了一半的字——第二次及
        // 以后的调用一律忽略，不然用户刚输入的内容会被原样喂回来的旧文本覆盖、还被全选。
        if (lineEdit->property(kValueEditorInitializedProperty).toBool())
        {
            return;
        }
        // index 是视图侧的索引（经由 QSortFilterProxyModel），先换成源模型索引再向宿主要
        // 初始文本——宿主只认 id，不认代理行号。
        const QModelIndex sourceIndex = m_owner->sourceIndexForProxy(index);
        const QString initialText = m_owner->editorInitialText(sourceIndex);
        lineEdit->setProperty(kValueEditorInitializedProperty, true);
        // 记下这次编辑的初始文本快照：供 setModelData 判断"用户到底有没有真的改过"（C2）。
        lineEdit->setProperty(kValueEditorInitialTextProperty, initialText);
        lineEdit->setText(initialText);
        lineEdit->selectAll();
    }

    void detail::ValueColumnDelegate::setModelData(
        QWidget* editor,
        QAbstractItemModel* model,
        const QModelIndex& index) const
    {
        // 故意不碰 model：本委托绝不直接写模型，"值"列的真正提交永远是
        // AddressBookPanel::valueEditRequested 信号，由上层经写事务完成。
        Q_UNUSED(model);
        QLineEdit* const lineEdit = qobject_cast<QLineEdit*>(editor);
        if (lineEdit == nullptr)
        {
            return;
        }
        // 修复 C2：提交的文本与打开编辑器时的初始文本完全相同就不发信号——典型场景是
        // 一次误双击，或者值处于 Stale（过期）状态时什么都没改就按了 Tab/Enter/点了别处，
        // 这种"未改动"的提交若照常发出去，会把过期/占位文本当成用户想写的新值，交给上层
        // 的写事务真的写进目标。
        const QString initialText = lineEdit->property(kValueEditorInitialTextProperty).toString();
        if (lineEdit->text() == initialText)
        {
            return;
        }
        const QModelIndex sourceIndex = m_owner->sourceIndexForProxy(index);
        m_owner->commitValueEdit(sourceIndex, lineEdit->text());
    }

    // ========================= AddressBookPanel =========================

    AddressBookPanel::AddressBookPanel(AddressBookModel* model, QWidget* parent)
        : QWidget(parent)
        , m_model(model)
    {
        buildUi();
        connectSignals();
        // 分段控件要带计数，构造时才第一次真正创建它（见 refreshKindSegmentLabelsAndCounts）。
        refreshKindSegmentLabelsAndCounts();
        applyColumnGroup(ColumnGroup::PresetA);
    }

    AddressBookModel* AddressBookPanel::model() const
    {
        return m_model;
    }

    void AddressBookPanel::buildUi()
    {
        QVBoxLayout* const rootLayout = new QVBoxLayout(this);
        rootLayout->setContentsMargins(4, 4, 4, 4);
        rootLayout->setSpacing(4);
        buildToolbar(rootLayout);
        buildTable(rootLayout);
    }

    void AddressBookPanel::buildToolbar(QVBoxLayout* rootLayout)
    {
        // 工具栏放进一个独立的宿主控件，专门交给 FlowLayout 管理：窄侧栏放不下一整排时
        // 自动换到下一行，而不是把分段按钮的文字压没（见本文件头与 UI/FlowLayout.h 的说明）。
        QWidget* const toolbarHost = new QWidget(this);
        m_toolbarFlow = new FlowLayout(toolbarHost, 4, 6, 4);

        // A/B 列组按钮先建好；分段控件（带计数）在 refreshKindSegmentLabelsAndCounts 里
        // 第一次创建，并会把这个宿主重新插入一遍以保证"分段在前、A/B 在后"的顺序。
        m_columnAButton = new QPushButton(QStringLiteral("A"), toolbarHost);
        m_columnBButton = new QPushButton(QStringLiteral("B"), toolbarHost);
        m_columnAButton->setCheckable(true);
        m_columnBButton->setCheckable(true);
        m_columnAButton->setToolTip(ks::i18n::sourceText(QStringLiteral("列预设 A：类型图标·地址·值·备注（日常浏览）。")));
        m_columnBButton->setToolTip(ks::i18n::sourceText(QStringLiteral("列预设 B：地址·值类型·模块+RVA·目标（诊断来源）。")));
        m_columnAButton->setStyleSheet(BuildColumnButtonStyle(true));
        m_columnBButton->setStyleSheet(BuildColumnButtonStyle(false));

        // 修复 C11：A、B 两个按钮必须始终紧贴在同一行，不能被 FlowLayout 拆到两行去——
        // FlowLayout 是按"条目"换行的，之前把 A、B 当成两个独立条目加进去，窄窗口下只要
        // A 恰好排在一行的最后，B 就会被单独挤到下一行开头，变成"A 在第一行右端、B 在第二
        // 行最左"，完全不是设计要求的"左右紧贴"。这里把 A、B 装进一个内部间距为 0 的
        // QHBoxLayout 小控件，作为 FlowLayout 的同一个条目——换行只能整体换，不能把这一对
        // 拆开。
        m_columnButtonsHost = new QWidget(toolbarHost);
        QHBoxLayout* const columnButtonsLayout = new QHBoxLayout(m_columnButtonsHost);
        columnButtonsLayout->setContentsMargins(0, 0, 0, 0);
        columnButtonsLayout->setSpacing(0);
        columnButtonsLayout->addWidget(m_columnAButton);
        columnButtonsLayout->addWidget(m_columnBButton);
        m_toolbarFlow->addWidget(m_columnButtonsHost);

        m_pointerChainAddButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("添加指针链")), toolbarHost);
        m_toolbarFlow->addWidget(m_pointerChainAddButton);
        m_pointerChainCancelButton = new QPushButton(
            ks::i18n::sourceText(QStringLiteral("取消解析")), toolbarHost);
        m_toolbarFlow->addWidget(m_pointerChainCancelButton);

        rootLayout->addWidget(toolbarHost);

        // 载入失败横幅：默认隐藏，由外层在 AddressBookStore::load() 失败后调用
        // showLoadFailure 显示（见 .h 顶部注释）。颜色现取主题色，深浅主题切换自动跟随，
        // 与 HexViewWidgets 一族"全部自绘、不缓存"的做法一致。
        m_loadFailureLabel = new HexViewMessageLabel(this);
        m_loadFailureLabel->hide();
        rootLayout->addWidget(m_loadFailureLabel);
    }

    void AddressBookPanel::buildTable(QVBoxLayout* rootLayout)
    {
        m_proxy = new QSortFilterProxyModel(this);
        m_proxy->setSourceModel(m_model);
        m_proxy->setDynamicSortFilter(true);

        m_view = new detail::AddressBookTableView(this, this);
        m_view->setModel(m_proxy);
        m_view->setSelectionBehavior(QAbstractItemView::SelectRows);
        m_view->setSelectionMode(QAbstractItemView::ExtendedSelection);
        // 只在双击或显式按下编辑键（F2/Enter 由本类自己接管，这里留的是 Qt 内建的
        // EditKeyPressed 触发路径，供"值"列以外的可编辑列走标准流程）时进入编辑态。
        m_view->setEditTriggers(QAbstractItemView::DoubleClicked | QAbstractItemView::EditKeyPressed);
        m_view->setSortingEnabled(true);
        // 修复 C15 的一半：排序改按 AddressBookModel::SortRole 比较，而不是默认的
        // Qt::DisplayRole——"地址"列的 DisplayRole 是格式化好的十六进制文本，按字符串排序
        // 会把 0x10000 排到 0x2000 前面（字典序），SortRole 对这一列给的是数值可比较的键。
        m_proxy->setSortRole(AddressBookModel::SortRole);
        // 修复 C15 的另一半：setSortingEnabled(true) 会让视图立刻按第 0 列（类型图标，没有
        // DisplayRole/SortRole 以外的可比较内容）升序排一次，表头却仍会显示排序箭头，
        // 看着"排了"实际什么都没变——用 sortByColumn(-1, …) 清掉这个误导性的初始排序箭头，
        // 保持 Store 的插入顺序，直到用户自己点某一列表头。
        m_view->sortByColumn(-1, Qt::AscendingOrder);
        m_view->verticalHeader()->setVisible(false);
        m_view->horizontalHeader()->setSectionsClickable(true);
        m_view->setContextMenuPolicy(Qt::CustomContextMenu);
        m_view->horizontalHeader()->setContextMenuPolicy(Qt::CustomContextMenu);
        m_view->setWordWrap(false);

        // 修复 C17：窄侧栏（ux 默认 300px）下若不给列宽合理默认值，备注列会被挤到屏外、
        // 地址被截断、类型图标列却占了过宽的默认宽度。图标列给个刚好够放 16px 图标的定宽，
        // 其余列给一个常见内容下够用的交互式默认宽度，最后一个"当前可见"的列由
        // setStretchLastSection 吃掉剩余空间（A 组下是备注、B 组下是目标——QHeaderView 的
        // "最后一节"按可见顺序算，隐藏列不参与）。
        m_view->setColumnWidth(AddressBookModel::ColumnKindIcon, 28);
        m_view->setColumnWidth(AddressBookModel::ColumnAddress, 112);
        m_view->setColumnWidth(AddressBookModel::ColumnValue, 90);
        m_view->setColumnWidth(AddressBookModel::ColumnValueType, 96);
        m_view->setColumnWidth(AddressBookModel::ColumnModuleOffset, 132);
        m_view->setColumnWidth(AddressBookModel::ColumnTarget, 112);
        m_view->horizontalHeader()->setStretchLastSection(true);

        // "值"列专用编辑委托：双击/F2/Enter 打开编辑器，提交时发信号而不是直接写模型。
        m_valueDelegate = new detail::ValueColumnDelegate(this, this);
        m_view->setItemDelegateForColumn(AddressBookModel::ColumnValue, m_valueDelegate);

        rootLayout->addWidget(m_view, 1);
    }

    void AddressBookPanel::connectSignals()
    {
        connect(m_columnAButton, &QPushButton::clicked, this, [this]() { applyColumnGroup(ColumnGroup::PresetA); });
        connect(m_columnBButton, &QPushButton::clicked, this, [this]() { applyColumnGroup(ColumnGroup::PresetB); });
        connect(m_pointerChainAddButton, &QPushButton::clicked,
            this, &AddressBookPanel::pointerChainCreateRequested);
        connect(m_pointerChainCancelButton, &QPushButton::clicked,
            this, &AddressBookPanel::pointerChainCancelRequested);
        connect(m_view, &QWidget::customContextMenuRequested, this, &AddressBookPanel::showRowContextMenu);
        connect(
            m_view->horizontalHeader(), &QWidget::customContextMenuRequested,
            this, &AddressBookPanel::showHeaderContextMenu);
        connect(m_model, &AddressBookModel::kindCountsChanged, this, &AddressBookPanel::refreshKindSegmentLabelsAndCounts);
        // 修复 D6（第二部分）：批量变更（load/removeMany/addMany/clearSearchResults，以及
        // D9 里 Store 销毁触发的整表重建）都走 beginResetModel/endResetModel，Qt 的选择
        // 模型对此的默认行为就是清空选区与当前格——这里在真正 reset 之前按 id 记一下，
        // reset 完成后原样尝试恢复，让"新一轮搜索灌入结果"这类操作不再把用户在书签/监视
        // 分段里的选区冲掉。
        connect(m_model, &QAbstractItemModel::modelAboutToBeReset, this, &AddressBookPanel::captureSelectionForResetRestore);
        connect(m_model, &QAbstractItemModel::modelReset, this, &AddressBookPanel::restoreSelectionAfterReset);

        // 双击"地址/模块+RVA/目标"这几个只读列等同于跳转；双击"类型图标"列同样跳转
        // （该列本身不可编辑，双击没有别的意义）。"值/值类型/备注"三列双击是进入编辑，
        // 由 setEditTriggers 与各自的 flags() 接管，不在这里处理。
        connect(m_view, &QTableView::doubleClicked, this, [this](const QModelIndex& proxyIndex) {
            switch (proxyIndex.column())
            {
            case AddressBookModel::ColumnKindIcon:
            case AddressBookModel::ColumnAddress:
            case AddressBookModel::ColumnModuleOffset:
            case AddressBookModel::ColumnTarget:
                jumpCurrentRow();
                break;
            default:
                break;
            }
        });
    }

    void AddressBookPanel::applyColumnGroup(const ColumnGroup group)
    {
        if (group == ColumnGroup::Custom)
        {
            m_columnGroup = group;
            updateColumnGroupButtons();
            return;
        }
        // 两个预设列组要隐藏的物理列下标集合（显示的是其余列），与 ux.md §4.3 的定义一致：
        // A＝类型图标·地址·值·备注；B＝地址·值类型·模块+RVA·目标。
        static const QList<int> kPresetAHidden{
            AddressBookModel::ColumnValueType, AddressBookModel::ColumnModuleOffset,
            AddressBookModel::ColumnTarget
        };
        static const QList<int> kPresetBHidden{
            AddressBookModel::ColumnKindIcon, AddressBookModel::ColumnValue,
            AddressBookModel::ColumnNote
        };
        applyColumnVisibility(group == ColumnGroup::PresetA ? kPresetAHidden : kPresetBHidden);
        m_columnGroup = group;
        updateColumnGroupButtons();
    }

    AddressBookPanel::ColumnGroup AddressBookPanel::columnGroup() const
    {
        return m_columnGroup;
    }

    QList<int> AddressBookPanel::hiddenColumns() const
    {
        QList<int> hidden;
        for (int column = 0; column < static_cast<int>(AddressBookModel::ColumnCount); ++column)
        {
            if (m_view->isColumnHidden(column))
            {
                hidden.push_back(column);
            }
        }
        return hidden;
    }

    void AddressBookPanel::setHiddenColumns(const QList<int>& hiddenColumnsIn)
    {
        applyColumnVisibility(hiddenColumnsIn);
        // 外层恢复的列显隐不一定正好等于某个预设：一律当作"自定义"，与表头右键改列
        // 显隐时的规则一致，不去猜它是不是碰巧等于 A 或 B。
        m_columnGroup = ColumnGroup::Custom;
        updateColumnGroupButtons();
    }

    void AddressBookPanel::applyColumnVisibility(const QList<int>& hiddenColumnsIn)
    {
        // m_applyingColumnGroup：本函数正在批量改列显隐期间置真，供表头右键菜单
        // （AddressBookPanel.Menu.cpp）据此跳过"用户手动改列显隐就退化为 Custom"的判断——
        // 这几行 setColumnHidden 都是程序自己触发的，不是用户点了表头菜单的勾选框。
        m_applyingColumnGroup = true;
        for (int column = 0; column < static_cast<int>(AddressBookModel::ColumnCount); ++column)
        {
            m_view->setColumnHidden(column, hiddenColumnsIn.contains(column));
        }
        m_applyingColumnGroup = false;
    }

    void AddressBookPanel::updateColumnGroupButtons()
    {
        const QSignalBlocker blockA(m_columnAButton);
        const QSignalBlocker blockB(m_columnBButton);
        m_columnAButton->setChecked(m_columnGroup == ColumnGroup::PresetA);
        m_columnBButton->setChecked(m_columnGroup == ColumnGroup::PresetB);
    }

    void AddressBookPanel::changeEvent(QEvent* event)
    {
        QWidget::changeEvent(event);
        if (event == nullptr)
        {
            return;
        }
        if ((event->type() == QEvent::ApplicationPaletteChange || event->type() == QEvent::PaletteChange)
            && m_columnAButton != nullptr && m_columnBButton != nullptr)
        {
            // 修复 D11：主题（调色板）切换时让 A/B 按钮真的跟上——不依赖主程序的全局
            // ThemeColorRemap 兜底。之前这两个按钮的样式表只在构造时 setStyleSheet 过一次，
            // 之后再也没有任何代码路径会重新设置它；本函数在真正的调色板切换事件里重新调用
            // BuildColumnButtonStyle 并 setStyleSheet 一遍，让 Qt 的样式引擎用当前调色板
            // 重新解析样式表里的 palette(...) 占位符。
            // 排雷记录（留着避免后人重踩同一处）：中途怀疑过"文本逐字节不变会被 Qt 判定
            // 没变而跳过重新解析"，加过 style()->unpolish/polish 绕开这个猜测中的捷径；也
            // 怀疑过"子控件调色板相对于 ApplicationPaletteChange 事件派发存在滞后"（探针
            // 打印确认过这个现象本身是真的），加过 button->setPalette(QApplication::
            // palette())。但把测试里的 QApplication::processEvents() 补上之后逐个去掉复测，
            // 两者都是多余的——只要 setStyleSheet 被重新调用过，接下来一次真实重绘
            // （update() 排的那次，或 grab() 强制的那次）就会用当前调色板正确求值，不需要
            // 这两步"补丁"。按"没有读数要求的改动不做"，已经都删掉，不要再加回来。
            for (QPushButton* const button : { m_columnAButton, m_columnBButton })
            {
                button->setStyleSheet(BuildColumnButtonStyle(button == m_columnAButton));
                // update() 只是排一次重绘，不是立即同步刷新；正常窗口下一轮事件循环就会
                // 把新颜色画出来，不需要调用方额外处理——夹具里用 grab() 截图验证时必须
                // 先 QApplication::processEvents() 一轮，这不是本函数的缺陷，是"截图校验
                // 必须等一轮重绘"这件事本身的要求（与真实窗口的使用体验无关）。
                button->update();
            }
        }
        if (event->type() == QEvent::LanguageChange)
        {
            // 修复 D4：HexViewSegmented 是自绘控件（不是 QLabel/QAbstractButton），
            // LanguageManager 的运行期遍历够不到它，分段文字构造期定型后就再也不会跟着
            // 切语言刷新。强制重算一次——refreshKindSegmentLabelsAndCounts 内部仍会按
            // "新文字是否真的不同"判断要不要真的重建控件，这里不需要绕过那个短路：切换
            // 语言后模板翻译结果本就会变，天然会被判定为"不同"而触发重建。
            refreshKindSegmentLabelsAndCounts();
            if (m_pointerChainAddButton != nullptr)
            {
                m_pointerChainAddButton->setText(ks::i18n::sourceText(QStringLiteral("添加指针链")));
            }
            if (m_pointerChainCancelButton != nullptr)
            {
                m_pointerChainCancelButton->setText(ks::i18n::sourceText(QStringLiteral("取消解析")));
            }
        }
    }

    void AddressBookPanel::setKindFilterIndex(const int index)
    {
        if (m_model.isNull() || m_kindSegment == nullptr)
        {
            return;
        }
        // index 是外部持久化编码：-1=全部，0=搜索，1=书签，2=监视（见 ux.md §9）；
        // 分段控件内部下标则是 0=全部，1=搜索，2=书签，3=监视，这里做一次换算。
        int segment = 0;
        if (index == 0) segment = 1;
        else if (index == 1) segment = 2;
        else if (index == 2) segment = 3;
        m_kindSegment->setCurrentIndex(segment);
        // setCurrentIndex 只在值真的变化时才发信号；显式再调一次，保证模型过滤一定同步
        // （segment 恰好与分段控件当前值相同时不会有任何副作用，setKindFilter 本身是幂等的）。
        onKindSegmentChanged(segment);
    }

    int AddressBookPanel::kindFilterIndex() const
    {
        if (m_kindSegment == nullptr)
        {
            return -1;
        }
        switch (m_kindSegment->currentIndex())
        {
        case 1: return 0;
        case 2: return 1;
        case 3: return 2;
        default: return -1;
        }
    }

    void AddressBookPanel::onKindSegmentChanged(const int index)
    {
        if (m_model.isNull())
        {
            return;
        }
        switch (index)
        {
        case 1: m_model->setKindFilter(ksword::memwb::EntryKind::Search); break;
        case 2: m_model->setKindFilter(ksword::memwb::EntryKind::Bookmark); break;
        case 3: m_model->setKindFilter(ksword::memwb::EntryKind::Watch); break;
        default: m_model->setKindFilter(std::nullopt); break;
        }
    }

    void AddressBookPanel::refreshKindSegmentLabelsAndCounts()
    {
        if (m_model.isNull())
        {
            return;
        }
        const AddressBookModel::KindCounts counts = m_model->kindCounts();
        // 四段文字经语言包翻译（C12）：先翻译带 %1 占位符的模板，拿到当前语言下的格式串，
        // 再 .arg() 填计数——与仓库既有调用惯例一致（例如 MainWindow.Hvm.cpp 的同类用法）。
        QStringList labels;
        labels << ks::i18n::sourceText(QStringLiteral("全部(%1)")).arg(counts.all)
               << ks::i18n::sourceText(QStringLiteral("搜索(%1)")).arg(counts.search)
               << ks::i18n::sourceText(QStringLiteral("书签(%1)")).arg(counts.bookmark)
               << ks::i18n::sourceText(QStringLiteral("监视(%1)")).arg(counts.watch);

        // 修复可疑点 #9 / C9 的再一道防线：本函数现在只会在 kindCountsChanged 真的带着
        // "计数变了"的含义时被调用（见 AddressBookModel 那一侧的 before==after 判断），
        // 但这里仍再比一次文字——如果恰好与当前分段控件已经显示的完全相同（理论上不会
        // 发生，纯防御），就不必销毁重建，省一次控件重建与潜在的焦点丢失。
        if (m_kindSegment != nullptr && m_kindSegment->count() == labels.size())
        {
            bool identical = true;
            for (int i = 0; i < labels.size(); ++i)
            {
                if (m_kindSegment->labelAt(i) != labels.at(i))
                {
                    identical = false;
                    break;
                }
            }
            if (identical)
            {
                return;
            }
        }

        // HexViewSegmented 的段文字在构造期固定，没有"改文字"的 API（见 HexViewWidgets.h
        // 的冻结接口摘要，本阶段不允许改它），计数真的变了时只能整个重建这一个小控件；
        // 重建前记下当前段下标与是否持有键盘焦点，重建后原样恢复——修复 C9 的"键盘导航
        // 失效"那一半：方向键挪到分段控件上之后，一次真实的计数变化不该让焦点和当前段
        // 一起飞走。顺带把 A/B 按钮的共同宿主也挪出来再按"分段在前、A/B 在后"的顺序放
        // 回去——FlowLayout 不支持按下标插入，这是维持顺序最简单的办法。
        const int previousIndex = (m_kindSegment != nullptr) ? m_kindSegment->currentIndex() : 0;
        const bool hadFocus = (m_kindSegment != nullptr) && m_kindSegment->hasFocus();
        if (m_kindSegment != nullptr)
        {
            m_toolbarFlow->removeWidget(m_kindSegment);
            // 修复 C9 的另一半：改用 deleteLater 而不是立即 delete——触发这次重建的调用链
            // 有可能正是分段控件自己的事件处理函数（鼠标点击 -> setCurrentIndex -> emit
            // currentIndexChanged -> onKindSegmentChanged -> model->setKindFilter ->
            // ……一路传导到这里），在这条调用链还没退出之前 delete this 是 Qt 文档明确
            // 禁止的写法。配合 Model 侧"仅切换过滤不触发"的修复，正常情况下根本不会走到
            // 这里；这里的 deleteLater 是最后一道保险，不依赖那条修复也不会悬空。
            m_kindSegment->deleteLater();
            m_kindSegment = nullptr;
        }
        m_toolbarFlow->removeWidget(m_columnButtonsHost);
        m_toolbarFlow->removeWidget(m_pointerChainAddButton);
        m_toolbarFlow->removeWidget(m_pointerChainCancelButton);

        m_kindSegment = new HexViewSegmented(labels, this);
        // 修复 C13：HexViewSegmented::event 会接管 ToolTip 事件、只显示"逐段提示"，
        // 没有逐段提示的段会直接吞掉事件——这里之前设的整体 setToolTip 从来没有机会
        // 显示过。改成给每一段单独设提示。
        m_kindSegment->setSegmentToolTip(
            0, ks::i18n::sourceText(QStringLiteral("显示全部条目（搜索结果、书签与监视）")));
        m_kindSegment->setSegmentToolTip(
            1, ks::i18n::sourceText(QStringLiteral("仅显示搜索结果（临时条目，清空搜索会整体删除）")));
        m_kindSegment->setSegmentToolTip(2, ks::i18n::sourceText(QStringLiteral("仅显示书签")));
        m_kindSegment->setSegmentToolTip(3, ks::i18n::sourceText(QStringLiteral("仅显示监视中的条目")));
        connect(m_kindSegment, &HexViewSegmented::currentIndexChanged, this, &AddressBookPanel::onKindSegmentChanged);
        m_kindSegment->setCurrentIndex(previousIndex);
        if (hadFocus)
        {
            m_kindSegment->setFocus();
        }

        m_toolbarFlow->addWidget(m_kindSegment);
        m_toolbarFlow->addWidget(m_columnButtonsHost);
        m_toolbarFlow->addWidget(m_pointerChainAddButton);
        m_toolbarFlow->addWidget(m_pointerChainCancelButton);
    }

    QModelIndex AddressBookPanel::sourceIndexForCurrent() const
    {
        return sourceIndexForProxy(m_view->currentIndex());
    }

    QModelIndex AddressBookPanel::sourceIndexForProxy(const QModelIndex& proxyIndex) const
    {
        if (!proxyIndex.isValid() || m_proxy == nullptr)
        {
            return QModelIndex();
        }
        return m_proxy->mapToSource(proxyIndex);
    }

    // targetRowId/selectedIds/复制/跳转/反汇编/升级/删除/编辑备注/值类型批改/键盘快捷键
    // 转发/D6 的选区保存恢复/载入失败横幅拼装：全部拆到 AddressBookPanel.RowActions.cpp
    // （本文件修复波后超过单文件行数上限，按"构造/布局/主题/kind 分段"与"按行为的动作"
    // 两类职责拆开，定义见该文件，声明仍在 AddressBookPanel.h）。
}
