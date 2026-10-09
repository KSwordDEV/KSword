#include "DetailLayoutHost.h"
#include "CodeEditorWidget.h"

#include <QAbstractItemView>
#include <QBoxLayout>
#include <QSplitter>
#include <QWidget>

#include <algorithm>

// 兼容适配只服务没有显式布局声明的存量页面，新页面不通过祖先推断接管布局。
namespace
{
    // directChildUnder：返回 widget 在 ancestor 下的第一层子控件，用于识别分隔器面板。
    QWidget* directChildUnder(QWidget* widget, QWidget* ancestor)
    {
        QWidget* childWidget = widget;
        while (childWidget != nullptr && childWidget->parentWidget() != ancestor)
        {
            childWidget = childWidget->parentWidget();
        }
        return childWidget != nullptr && childWidget->parentWidget() == ancestor
            ? childWidget
            : nullptr;
    }

    // findSharedSplitter：从表格祖先向上查找同时包含详情编辑器的分隔器。
    QSplitter* findSharedSplitter(QAbstractItemView* tableView, QWidget* detailEditor)
    {
        QWidget* ancestorWidget = tableView;
        while (ancestorWidget != nullptr)
        {
            QSplitter* splitter = qobject_cast<QSplitter*>(ancestorWidget);
            if (splitter != nullptr && splitter->isAncestorOf(detailEditor))
            {
                // 只有表格和详情处于 splitter 的不同直接面板时才接管它。
                // 页面常见的外层 splitter 可能同时包住整个表格页，误认它会在折叠时
                // 把承载表格的整块面板一起隐藏，最终只剩一个箭头。
                QWidget* tablePane = directChildUnder(tableView, splitter);
                QWidget* detailPane = directChildUnder(detailEditor, splitter);
                if (tablePane != nullptr && detailPane != nullptr && tablePane != detailPane)
                {
                    return splitter;
                }
            }
            ancestorWidget = ancestorWidget->parentWidget();
        }
        return nullptr;
    }

    // findCommonParent：找到两个控件最近的共同 QWidget 祖先。
    QWidget* findCommonParent(QWidget* firstWidget, QWidget* secondWidget)
    {
        for (QWidget* firstParent = firstWidget; firstParent != nullptr;
            firstParent = firstParent->parentWidget())
        {
            for (QWidget* secondParent = secondWidget; secondParent != nullptr;
                secondParent = secondParent->parentWidget())
            {
                if (firstParent == secondParent)
                {
                    return firstParent;
                }
            }
        }
        return nullptr;
    }

}

void ks::ui::DetailLayoutHost::resolveCompatiblePanels()
{
    if (m_tableView.isNull() || (detailWidget() == nullptr))
    {
        return;
    }

    QSplitter* sharedSplitter = findSharedSplitter(m_tableView.data(), detailWidget());
    if (sharedSplitter != nullptr)
    {
        m_splitter = sharedSplitter;
        m_tablePane = directChildUnder(m_tableView.data(), sharedSplitter);
        m_detailPane = directChildUnder(detailWidget(), sharedSplitter);
        if (m_tablePane == nullptr || m_detailPane == nullptr || m_tablePane == m_detailPane)
        {
            m_splitter.clear();
            m_tablePane.clear();
            m_detailPane.clear();
            return;
        }
        detailWidget()->setMinimumHeight(0);
        detailWidget()->setMaximumHeight(QWIDGETSIZE_MAX);
        return;
    }

    // 直接布局页面没有既有 QSplitter：保留原控件对象，仅把两者包装进统一分隔器。
    QWidget* commonParent = findCommonParent(m_tableView.data(), detailWidget());
    QBoxLayout* commonLayout = commonParent != nullptr
        ? qobject_cast<QBoxLayout*>(commonParent->layout())
        : nullptr;
    if (commonParent == nullptr || commonLayout == nullptr)
    {
        return;
    }

    QWidget* tablePane = directChildUnder(m_tableView.data(), commonParent);
    QWidget* detailPane = directChildUnder(detailWidget(), commonParent);
    if (tablePane == nullptr || detailPane == nullptr || tablePane == detailPane)
    {
        return;
    }

    const int tableIndex = commonLayout->indexOf(tablePane);
    const int detailIndex = commonLayout->indexOf(detailPane);
    const int insertionIndex = std::max(0, std::min(tableIndex, detailIndex));
    commonLayout->removeWidget(tablePane);
    commonLayout->removeWidget(detailPane);

    QSplitter* splitter = new QSplitter(Qt::Vertical, commonParent);
    tablePane->setParent(splitter);
    detailPane->setParent(splitter);
    splitter->addWidget(tablePane);
    splitter->addWidget(detailPane);
    splitter->setStretchFactor(0, 3);
    splitter->setStretchFactor(1, 1);
    commonLayout->insertWidget(insertionIndex, splitter, 1);

    m_splitter = splitter;
    m_tablePane = tablePane;
    m_detailPane = detailPane;
    detailWidget()->setMinimumHeight(0);
    detailWidget()->setMaximumHeight(QWIDGETSIZE_MAX);
}
