#include "FieldTreePresenter.h"
#include "CodeTextEdit.h"
#include "../Internationalization/LanguageManager.h"
#include "../theme.h"
#include <QApplication>
#include <QEvent>
#include <QFontMetrics>
#include <QHeaderView>
#include <QPointer>
#include <QTimer>
#include <QTreeWidget>
#include <algorithm>
#include <functional>

namespace
{
    // 专用展示角色避免从可见文字猜测分组和说明；这些角色不包含业务证据。
    constexpr int groupRole = Qt::UserRole + 913;
    constexpr int noteRole = Qt::UserRole + 914;
    constexpr int decorateRole = Qt::UserRole + 915;

    // 单节点样式更新不扫描全树，避免逐个添加 JSON 节点导致平方复杂度。
    void refreshItem(QTreeWidget* tree, QTreeWidgetItem* item)
    {
        const QFont base = tree->font();
        const QFont fixed = ks::ui::ScaledReportFont(CodeTextEdit::editorFont());
        if (item->data(0, groupRole).toBool())
        {
            QFont group = base;
            group.setBold(true);
            item->setFont(0, group);
        }
        else if (item->data(0, noteRole).toBool())
        {
            item->setFont(0, base);
            item->setForeground(0, KswordTheme::TextSecondaryColor());
        }
        else if (item->data(0, decorateRole).toBool())
        {
            QColor color;
            item->setForeground(1, ks::ui::FieldValueStatusColor(item->text(1), &color)
                ? QBrush(color) : QBrush());
            item->setFont(1, ks::ui::FieldValueLooksMonospace(item->text(1)) ? fixed : base);
        }
    }

    // 字体和主题热更新才遍历完整字段，业务文本和选区均不改变。
    void refreshItems(QTreeWidget* tree)
    {
        std::function<void(QTreeWidgetItem*)> refresh = [&](QTreeWidgetItem* item)
        {
            refreshItem(tree, item);
            for (int index = 0; index < item->childCount(); ++index) refresh(item->child(index));
        };
        for (int index = 0; index < tree->topLevelItemCount(); ++index) refresh(tree->topLevelItem(index));
    }

    // 控制器从未放大的应用字体重算，防止 preserve_custom_font 把旧字体永久固定。
    // Qt 父子所有权在树销毁时自动移除应用过滤器，延迟刷新只持 QPointer。
    class FieldTreeController final : public QObject
    {
    public:
        explicit FieldTreeController(QTreeWidget* tree) : QObject(tree), m_tree(tree)
        {
            tree->installEventFilter(this);
            qApp->installEventFilter(this);
        }
        bool eventFilter(QObject* source, QEvent* event) override
        {
            const bool font = event->type() == QEvent::FontChange || event->type() == QEvent::ApplicationFontChange;
            const bool palette = event->type() == QEvent::PaletteChange || event->type() == QEvent::ApplicationPaletteChange;
            if (!m_refreshing && (source == m_tree || source == qApp) && (font || palette) && !m_pending)
            {
                m_pending = true;
                QTimer::singleShot(0, this, [this]()
                {
                    m_pending = false;
                    if (!m_tree) return;
                    m_refreshing = true;
                    ks::ui::RefreshFieldTree(m_tree);
                    m_refreshing = false;
                });
            }
            return QObject::eventFilter(source, event);
        }
    private:
        QPointer<QTreeWidget> m_tree; // 树生命周期探活。
        bool m_pending = false;      // 合并字体和主题事件。
        bool m_refreshing = false;   // 避免 setFont 递归刷新。
    };
}

namespace ks::ui
{
    QFont ScaledReportFont(const QFont& baseFont)
    {
        QFont scaled = baseFont;
        if (scaled.pointSizeF() > 0) scaled.setPointSizeF(scaled.pointSizeF() * 1.6);
        else if (scaled.pixelSize() > 0) scaled.setPixelSize(static_cast<int>(scaled.pixelSize() * 1.6));
        return scaled;
    }

    bool FieldValueLooksMonospace(const QString& value)
    {
        if (value.size() < 6) return false;
        if (value.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) return true;
        for (const QChar character : value)
        {
            const bool hex = (character >= QLatin1Char('0') && character <= QLatin1Char('9')) ||
                (character >= QLatin1Char('a') && character <= QLatin1Char('f')) ||
                (character >= QLatin1Char('A') && character <= QLatin1Char('F'));
            if (!hex && character != QLatin1Char(' ')) return false;
        }
        return true;
    }

    bool FieldValueStatusColor(const QString& value, QColor* colorOut)
    {
        if (colorOut == nullptr || value.isEmpty() || value.size() > 64) return false;
        // 保持旧报告的双语关键词及优先级；仅着色，绝不推断业务信任结果。
        const QStringList errors{QStringLiteral("失败"), QStringLiteral("无效"), QStringLiteral("异常"),
            QStringLiteral("篡改"), QStringLiteral("风险"), QStringLiteral("错误"), QStringLiteral("拒绝"),
            QStringLiteral("命中"), QStringLiteral("未签名"), QStringLiteral("failed"), QStringLiteral("invalid"),
            QStringLiteral("error"), QStringLiteral("denied"), QStringLiteral("tampered"), QStringLiteral("unsigned")};
        const QStringList warnings{QStringLiteral("未知"), QStringLiteral("不可用"), QStringLiteral("降级"),
            QStringLiteral("未验证"), QStringLiteral("警告"), QStringLiteral("跳过"), QStringLiteral("unknown"),
            QStringLiteral("unavailable"), QStringLiteral("degraded"), QStringLiteral("warning"), QStringLiteral("skipped"), QStringLiteral("false")};
        const QStringList successes{QStringLiteral("有效"), QStringLiteral("正常"), QStringLiteral("通过"),
            QStringLiteral("成功"), QStringLiteral("已验证"), QStringLiteral("已启用"), QStringLiteral("valid"),
            QStringLiteral("normal"), QStringLiteral("passed"), QStringLiteral("success"), QStringLiteral("verified"),
            QStringLiteral("enabled"), QStringLiteral("true")};
        for (const QString& keyword : errors)
            if (value.contains(keyword, Qt::CaseInsensitive)) { *colorOut = KswordTheme::ErrorColor(); return true; }
        for (const QString& keyword : warnings)
            if (value.contains(keyword, Qt::CaseInsensitive)) { *colorOut = KswordTheme::WarningColor(); return true; }
        for (const QString& keyword : successes)
            if (value.contains(keyword, Qt::CaseInsensitive)) { *colorOut = KswordTheme::SuccessColor(); return true; }
        return false;
    }

    void ConfigureFieldTree(QTreeWidget* tree, const bool showBranches)
    {
        if (tree == nullptr) return;
        tree->setProperty("ksword_preserve_custom_font", true);
        tree->setColumnCount(2);
        tree->setHeaderLabels({ks::i18n::displayText(QStringLiteral("属性")), ks::i18n::displayText(QStringLiteral("值"))});
        tree->setRootIsDecorated(showBranches);
        tree->setAlternatingRowColors(true);
        tree->setSelectionBehavior(QAbstractItemView::SelectRows);
        tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
        tree->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tree->setUniformRowHeights(true);
        tree->setSortingEnabled(false);
        tree->setFrameShape(QFrame::NoFrame);
        tree->header()->setStretchLastSection(true);
        // 自有样式覆盖 FileDetailDialog 等宿主的旧树边框规则，所有字段树共享几何。
        // 颜色使用 palette 动态角色，热主题无需固化或重映射旧十六进制颜色。
        tree->setStyleSheet(QStringLiteral(
            "QTreeWidget{background-color:palette(base);alternate-background-color:palette(alternate-base);"
            "color:palette(text);border:0;padding:0;}"
            "QTreeWidget::item{padding:3px 6px;}"
            "QTreeWidget::item:selected{background-color:palette(highlight);color:palette(highlighted-text);}"
            "QHeaderView::section{background-color:palette(base);color:palette(text);border:0;"
            "border-bottom:1px solid palette(mid);padding:4px;font-weight:600;}"));
        // 重复调用只更新配置，不重复连接复制槽或字体过滤器。
        if (!tree->property("ksword_field_tree_managed").toBool())
        {
            tree->setProperty("ksword_field_tree_managed", true);
            new FieldTreeController(tree);
            InstallStructuredCopyMenu(tree);
        }
        RefreshFieldTree(tree);
    }

    void RefreshFieldTree(QTreeWidget* tree)
    {
        if (tree == nullptr) return;
        tree->setFont(ScaledReportFont(QApplication::font(tree)));
        refreshItems(tree);
        const QFontMetrics metrics(tree->font());
        int widest = 0;
        std::function<void(const QTreeWidgetItem*, int)> measure = [&](const QTreeWidgetItem* item, const int depth)
        {
            if (!item->isFirstColumnSpanned())
                widest = std::max(widest, metrics.horizontalAdvance(item->text(0)) + depth * tree->indentation());
            for (int index = 0; index < item->childCount(); ++index) measure(item->child(index), depth + 1);
        };
        for (int index = 0; index < tree->topLevelItemCount(); ++index) measure(tree->topLevelItem(index), 0);
        tree->setColumnWidth(0, std::clamp(widest + tree->indentation() + 16, 140, 360));
    }

    void SetFieldItemPresentation(QTreeWidgetItem* item, const bool group, const bool note, const bool decorateValue)
    {
        if (item == nullptr) return;
        item->setData(0, groupRole, group);
        item->setData(0, noteRole, note);
        item->setData(0, decorateRole, decorateValue);
        item->setFirstColumnSpanned(note);
        item->setToolTip(0, item->text(0));
        item->setToolTip(1, item->text(1));
        if (group)
        {
            item->setFlags(item->flags() & ~Qt::ItemIsSelectable);
            item->setExpanded(true);
        }
        if (QTreeWidget* tree = item->treeWidget()) refreshItem(tree, item);
    }

    QTreeWidgetItem* AppendFieldGroup(QTreeWidget* tree, const QString& title)
    {
        if (tree == nullptr) return nullptr;
        auto* item = new QTreeWidgetItem(tree);
        item->setText(0, title);
        SetFieldItemPresentation(item, true, false, false);
        return item;
    }

    QTreeWidgetItem* AppendFieldRow(QTreeWidget* tree, QTreeWidgetItem* parent,
        const QString& name, const QString& value, const bool note, const bool decorateValue)
    {
        if (tree == nullptr || (parent != nullptr && parent->treeWidget() != tree)) return nullptr;
        auto* item = parent != nullptr ? new QTreeWidgetItem(parent) : new QTreeWidgetItem(tree);
        item->setText(0, name);
        item->setText(1, value);
        SetFieldItemPresentation(item, false, note, decorateValue);
        return item;
    }
}
