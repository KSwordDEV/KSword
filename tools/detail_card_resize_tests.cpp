// 详情卡片宽度/滚动回归：运行真实投影与分栏实现，检查静止收敛和字段裁切。
#include "UI/DetailPresentation.h"
#include "UI/StructuredFieldView.h"
#include "UI/ThemeBinding.h"
#include "UI/DetailFieldProjectionWidgets.h"
#include "theme.h"
#include <QApplication>
#include <QDir>
#include <QEventLoop>
#include <QFontDatabase>
#include <QLabel>
#include <QLayout>
#include <QLineEdit>
#include <QPaintEvent>
#include <QScrollArea>
#include <QScrollBar>
#include <QThreadPool>
#include <QTimer>
#include <QVBoxLayout>
#include <cstdio>

namespace
{
    int failures = 0; // 累计失败数量，交给进程退出码报告。
    int checks = 0; // 已执行断言数量。

    // 输入被测投影；记录其可见子树的空闲绘制和布局，区分几何稳定与后台仍在抖动。
    class IdleEvents final : public QObject
    {
    public:
        explicit IdleEvents(QWidget* projection) : m_projection(projection) {}
        int layouts = 0; // 当前采样期内已收到的布局请求。
        int paints = 0; // 当前采样期内已收到的绘制事件。
        QMap<QString, int> paintedWidgets; // 诊断重绘来源，区分输入光标与字段卡片。
    protected:
        // 输入Qt事件接收者与事件；只计数被测子树，返回false保持原生分发。
        bool eventFilter(QObject* target, QEvent* event) override
        {
            auto* widget = qobject_cast<QWidget*>(target); // 只观察当前投影中的真实窗口控件。
            if (widget && (widget == m_projection || m_projection->isAncestorOf(widget)))
            {
                layouts += event->type() == QEvent::LayoutRequest;
                paints += event->type() == QEvent::Paint;
                if (event->type() == QEvent::Paint)
                    ++paintedWidgets[QString::fromLatin1(widget->metaObject()->className())
                        + QLatin1Char(':') + widget->objectName()
                        + (qobject_cast<QLabel*>(widget) ? QLatin1Char(':') + qobject_cast<QLabel*>(widget)->text() : QString())];
            }
            return false;
        }
    private:
        QWidget* m_projection; // 生命周期由main中的窗口覆盖本观察器。
    };

    // 只在动态滚动采样时观察原生事件，不调用grab/render或主动请求重绘。
    class ScrollPaintEvents final : public QObject
    {
    public:
        explicit ScrollPaintEvents(QWidget* projection) : m_projection(projection) {}
        bool active = false; // 只在连续滚动区间启用，排除构造/缩放的正常绘制。
        int layouts = 0; // 滚动导致的布局请求总数。
        int cardResizes = 0, cardMoves = 0; // 卡片自身移动/缩放，不包括正文原生滚动。
        int cardPaints = 0, broadCardPaints = 0; // 卡片绘制数及覆盖视口80%以上的绘制数。
        int shows = 0, hides = 0, styles = 0; // 字段可见性和样式变化次数。
        // 无输入输出；开始同一宽度的新一组动态采样。
        void reset()
        {
            layouts = cardResizes = cardMoves = cardPaints = broadCardPaints = shows = hides = styles = 0;
        }
    protected:
        bool eventFilter(QObject* target, QEvent* event) override
        {
            auto* widget = qobject_cast<QWidget*>(target); // 事件实际接收者，不遍历控件树。
            if (!active || !widget || !m_projection->isAncestorOf(widget)) return false;
            layouts += event->type() == QEvent::LayoutRequest;
            shows += event->type() == QEvent::Show;
            hides += event->type() == QEvent::Hide;
            styles += event->type() == QEvent::StyleChange;
            if (widget->property("ksword_detail_card").toBool())
            {
                cardResizes += event->type() == QEvent::Resize;
                cardMoves += event->type() == QEvent::Move;
                if (event->type() == QEvent::Paint)
                {
                    ++cardPaints;
                    auto* viewport = m_projection->findChild<QScrollArea*>()->viewport(); // 统一绘制面积的参照系。
                    const QRegion region = static_cast<QPaintEvent*>(event)->region().translated(widget->mapTo(viewport, QPoint()))
                        .intersected(viewport->rect());
                    qint64 area = 0; // 裁到视口后的实际脏区面积，不使用巨大逻辑卡片的总面积。
                    for (const QRect& rect : region) area += qint64(rect.width()) * rect.height();
                    broadCardPaints += area * 10 >= qint64(viewport->width()) * viewport->height() * 8;
                }
            }
            return false;
        }
    private:
        QWidget* m_projection; // main持有的被测投影，寿命覆盖本观察器。
    };

    // 输入断言结果与描述；失败时输出说明，不中断其它宽度检查。
    void check(bool passed, const char* description)
    {
        ++checks;
        if (!passed)
        {
            ++failures;
            std::fprintf(stderr, "FAIL %s\n", description);
        }
    }

    // 输入需要运行的毫秒数；让原生布局、异步投影和分片任务自然运行。
    void settle(int milliseconds)
    {
        QEventLoop loop; // 只服务测试的有限事件循环。
        QTimer::singleShot(milliseconds, &loop, &QEventLoop::quit);
        loop.exec();
    }

    // 输入实际投影；返回所有可见字段几何，便于发现静止时重复重排。
    QString geometrySnapshot(QWidget* projection)
    {
        QString result; // 按字段身份记录矩形，而非依赖临时控件地址。
        for (QLabel* label : projection->findChildren<QLabel*>())
        {
            if (!label->isVisible())
            {
                continue;
            }
            const QRect bounds(label->mapTo(projection, QPoint()), label->size()); // 投影内统一坐标。
            result += label->text() + QStringLiteral("=%1,%2,%3,%4;")
                .arg(bounds.x()).arg(bounds.y()).arg(bounds.width()).arg(bounds.height());
        }
        return result;
    }

    // 输入投影；以字段身份记录视口中央实际可见值的正文坐标，便于比较连续滚动中的跳动。
    QMap<QString, QRect> visibleValueGeometry(QWidget* projection)
    {
        QMap<QString, QRect> result; // 字段身份到不受原生滚动平移影响的正文坐标。
        auto* scroll = projection->findChild<QScrollArea*>(); // 被测正文及唯一视口。
        const QRect interior = scroll->viewport()->rect().adjusted(0, 30, 0, -30); // 排除正常进入/离开视口的边缘文字。
        for (QLabel* label : projection->findChildren<QLabel*>())
        {
            if (!label->isVisible() || !label->property("ksword_detail_field_value").toBool())
            {
                continue;
            }
            const QRect visible(label->mapTo(scroll->viewport(), QPoint()), label->size()); // 当前视口中的真实字段矩形。
            if (!interior.contains(visible))
            {
                continue;
            }
            const QString identity = QStringLiteral("%1:%2")
                .arg(label->property("ksword_card_section").toInt())
                .arg(label->property("ksword_card_field").toInt()); // 不依赖回收后变化的控件地址。
            result.insert(identity, QRect(label->mapTo(scroll->widget(), QPoint()), label->size()));
            label->setObjectName(identity); // 失败诊断只按稳定字段身份查找当前真实控件。
        }
        return result;
    }

    // 输入字段和正文；返回本轮祖先几何及布局高度，供连续帧前后对照，不参与布局。
    QString hostSnapshot(QWidget* field, QWidget* body)
    {
        QString result; // 从字段到虚拟卡片的每层局部位置。
        for (QWidget* host = field; host && host != body; host = host->parentWidget())
        {
            const QRect rect = host->geometry(); // 当前宿主在其父级中的实际矩形。
            result += QStringLiteral(" [%1 %2,%3,%4,%5 hint=%6 hfw=%7]")
                .arg(QString::fromLatin1(host->metaObject()->className()))
                .arg(rect.x()).arg(rect.y()).arg(rect.width()).arg(rect.height())
                .arg(host->sizeHint().height()).arg(host->heightForWidth(host->width()));
            if (host->layout())
            {
                // 记录前几个布局项，区分前缀占位、原生行距与外卡片偏移。
                for (int itemIndex = 0; itemIndex < qMin(3, host->layout()->count()); ++itemIndex)
                {
                    const auto* item = host->layout()->itemAt(itemIndex); // 首个占位或文字行。
                    result += QStringLiteral(" item%1:y%2,h%3,hint%4")
                        .arg(itemIndex).arg(item->geometry().y()).arg(item->geometry().height()).arg(item->sizeHint().height());
                }
            }
        }
        return result;
    }

    // 输入投影；核对视口内的字段文字不被自身高度截断，也不与其它行重叠。
    void checkRows(QWidget* projection)
    {
        QVector<QRect> values; // 比较名称和值的矩形，正常同行的两块文字也不应重叠。
        QScrollArea* scroll = projection->findChild<QScrollArea*>(); // 实际正文滚动区。
        for (QLabel* label : projection->findChildren<QLabel*>())
        {
            if (!label->isVisible() || (!label->property("ksword_detail_field_value").toBool()
                && !label->property("ksword_detail_field_label").toBool()))
            {
                continue;
            }
            const QRect bounds(label->mapTo(scroll->viewport(), QPoint()), label->size()); // 视口内位置。
            if (!bounds.intersects(scroll->viewport()->rect()))
            {
                continue;
            }
            QLabel natural; // 独立原生测量器，不继承被测控件的固定高度，避免断言自证。
            natural.setFont(label->font());
            natural.setWordWrap(true);
            natural.setTextFormat(Qt::PlainText);
            natural.setTextInteractionFlags(label->textInteractionFlags());
            natural.setText(label->text());
            const int needed = label->property("ksword_detail_field_label").toBool()
                ? qMax(label->fontMetrics().height(), label->fontMetrics().boundingRect(
                    QRect(0, 0, label->width(), 1000000), Qt::TextWordWrap | Qt::TextWrapAnywhere, label->text()).height())
                : qMax(natural.fontMetrics().height(), natural.heightForWidth(label->width())); // 无旧约束的文字高度。
            if (label->height() < needed)
            {
                std::fprintf(stderr, "CLIPPED width=%d text=%s actual=%d needed=%d\n",
                    projection->width(), qPrintable(label->text()), label->height(), needed);
            }
            check(label->height() >= needed, "visible field text is clipped");
            // 自身高度足够仍可能被上层表单/虚拟卡片截断；视口裁剪则属于正常滚动。
            for (QWidget* ancestor = label->parentWidget(); ancestor && ancestor != scroll->widget();
                ancestor = ancestor->parentWidget())
            {
                const int top = label->mapTo(ancestor, QPoint()).y(); // 在当前祖先中的完整文字范围。
                check(top >= 0 && top + label->height() <= ancestor->height(), "field is clipped by its layout host");
            }
            for (const QRect& previous : values)
            {
                if (previous.intersects(bounds))
                    std::fprintf(stderr, "OVERLAP width=%d text=%s rect=%d,%d,%d,%d previous=%d,%d,%d,%d\n",
                        projection->width(), qPrintable(label->text()), bounds.x(), bounds.y(), bounds.width(), bounds.height(),
                        previous.x(), previous.y(), previous.width(), previous.height());
                check(!previous.intersects(bounds), "visible value rows overlap");
            }
            values.append(bounds);
        }
    }
}

// 无额外输入；构造与令牌快照同形的80字段，输出宽度/滚动收敛回归结果。
int main(int argc, char** argv)
{
    QApplication application(argc, argv); // 真实Qt布局和字体度量所需的应用。
    // 静止采样排除输入光标的周期闪动；仍完整统计搜索栏、背景和字段的真实绘制事件。
    application.setCursorFlashTime(0);
    const QString fontPath = qEnvironmentVariable("WINDIR", QStringLiteral("C:/Windows"))
        + QStringLiteral("/Fonts/msyh.ttc"); // offscreen不枚举Windows字体，显式装入生产中文字体。
    const int fontId = QFontDatabase::addApplicationFont(fontPath); // 当前进程注册的真实字体身份。
    check(fontId >= 0, "Windows UI font is available");
    application.setFont(QFont(QStringLiteral("Microsoft YaHei UI"), 10));
    const QDir evidence(argc > 1 ? QString::fromLocal8Bit(argv[1]) : QDir::tempPath()); // 可选首参数指定截图输出目录。
    QWidget window; // 模拟共享投影所在的正文区域。
    auto* layout = new QVBoxLayout(&window); // 正文零额外留白。
    layout->setContentsMargins(0, 0, 0, 0);
    auto* source = new ks::ui::StructuredFieldView(&window); // 唯一规范文档源。
    ks::ui::FieldDocument document; // 长字段名、原始字节、短失败信息混排。
    document.section(QStringLiteral("All TokenInformationClass Snapshot"));
    const QStringList names = {QStringLiteral("TokenUser"), QStringLiteral("TokenGroups"),
        QStringLiteral("TokenRestrictedDeviceClaimAttributes"), QStringLiteral("TokenAppContainerNumber"),
        QStringLiteral("TokenSecurityAttributes"), QStringLiteral("TokenIsLessPrivilegedAppContainer")}; // 长短名称混排触发实际标签列宽调整。
    for (int index = 1; index <= 80; ++index)
    {
        // 实际快照既有24字节预览，也有4字节值和查询失败；不能用同长度文本代替。
        const QString value = index > 51 ? QStringLiteral("queryFailed(87)")
            : index % 3 ? QStringLiteral("size=1640, raw=88 30 10 5F 6E 02 00 00 38 32 10 5F 6E 02 00 00 38 32 10 5F 6E 02 00 00 ...")
                        : QStringLiteral("size=4, raw=00 00 00 00"); // 当前字段的原始预览。
        document.field(QStringLiteral("[%1] %2").arg(index).arg(names.at((index - 1) % names.size())), value);
    }
    source->setDocument(document);
    QWidget* projection = ks::ui::CreateDetailFieldProjection(source, &window); // 被测真实共享实现。
    IdleEvents idleEvents(projection); // 只用于静止采样，不参与生产布局。
    application.installEventFilter(&idleEvents);
    layout->addWidget(projection);
    window.resize(916, 570);
    window.show();
    const bool scrollPaintOnly = application.arguments().contains(QStringLiteral("--scroll-paint-only")); // 快速对照仅跑动态区间。
    ScrollPaintEvents scrollPaint(projection); // 真实事件诊断，不调用grab强制绘制。
    application.installEventFilter(&scrollPaint);

    // 围绕单/双列临界点以及截图宽度往返，避免只验证初次布局。
    if (!scrollPaintOnly)
    for (int width : {916, 670, 666, 665, 664, 663, 662, 661, 660, 659, 658, 650, 648, 644, 800, 920, 1100, 480, 916})
    {
        window.resize(width, 570);
        settle(350);
        auto* scroll = projection->findChild<QScrollArea*>(); // 每轮重新取得当前正文宿主。
        for (int position : {0, scroll->verticalScrollBar()->maximum() / 3, scroll->verticalScrollBar()->maximum()})
        {
            scroll->verticalScrollBar()->setValue(position);
            settle(250);
            QString previous = geometrySnapshot(projection); // 静止后应保持稳定的首份几何。
            int changes = 0; // 观察窗口内几何变化次数。
            idleEvents.layouts = 0;
            idleEvents.paints = 0;
            idleEvents.paintedWidgets.clear();
            for (int sample = 0; sample < 5; ++sample)
            {
                settle(30);
                const QString current = geometrySnapshot(projection); // 当前事件轮结束后的字段几何。
                changes += current != previous;
                previous = current;
            }
            std::printf("WIDTH=%d SCROLL=%d CHANGES=%d\n", width, position, changes);
            if (idleEvents.paints)
                std::fprintf(stderr, "IDLE width=%d scroll=%d layouts=%d paints=%d widgets=%s\n", width, position,
                    idleEvents.layouts, idleEvents.paints, qPrintable(idleEvents.paintedWidgets.keys().join(QLatin1Char('|'))));
            check(changes == 0, "stationary card geometry does not converge");
            check(idleEvents.layouts == 0, "stationary projection keeps requesting layout");
            check(idleEvents.paints == 0, "stationary projection keeps repainting");
            checkRows(projection);
            if (position == 0)
            {
                projection->grab().save(evidence.filePath(QStringLiteral("width-%1.png").arg(width)));
            }
        }
    }
    // 连续小步滚动时，仍在视口中央的同一字段应只随原生滚动平移，不能改变列宽或正文位置。
    int scrollJumps = 0; // 滚动窗口变化引起的可见字段重新排版数量。
    for (int width : {916, 665, 650, 480})
    {
        window.resize(width, 570);
        auto* scroll = projection->findChild<QScrollArea*>(); // 本轮唯一正文滚动区。
        scroll->verticalScrollBar()->setValue(0);
        settle(400);
        std::printf("SCROLL_CANVAS width=%d opaque=%d autofill=%d styled=%d\n", width,
            scroll->widget()->testAttribute(Qt::WA_OpaquePaintEvent), scroll->widget()->autoFillBackground(),
            scroll->widget()->testAttribute(Qt::WA_StyledBackground));
        QMap<QString, QRect> previous = visibleValueGeometry(projection); // 上一帧仍在视口中央的字段。
        QMap<QString, QString> previousHosts; // 上一帧宿主链，定位正文坐标变化来自哪一层。
        const int jumpsBeforeWidth = scrollJumps; // 区分各个窗口宽度的失败范围。
        scrollPaint.reset();
        scrollPaint.active = true;
        for (int direction : {1, -1})
        {
            for (int frame = 0; frame < 80; ++frame)
            {
                scroll->verticalScrollBar()->setValue(scroll->verticalScrollBar()->value() + direction * 19);
                settle(16);
                const auto current = visibleValueGeometry(projection); // 本轮16毫秒事件分发后的几何。
                for (auto entry = current.cbegin(); entry != current.cend(); ++entry)
                {
                    const auto before = previous.constFind(entry.key()); // 同一字段在上一帧的正文位置。
                    if (before != previous.cend() && before.value() != entry.value())
                    {
                        if (scrollJumps - jumpsBeforeWidth < 2)
                        {
                            std::fprintf(stderr, "SCROLL_JUMP width=%d field=%s old=%d,%d,%d,%d new=%d,%d,%d,%d\n",
                                width, qPrintable(entry.key()), before->x(), before->y(), before->width(), before->height(),
                                entry->x(), entry->y(), entry->width(), entry->height());
                            auto* field = projection->findChild<QLabel*>(entry.key()); // 同一字段的当前原生表单。
                            std::fprintf(stderr, "  BEFORE%s\n  AFTER%s\n",
                                qPrintable(previousHosts.value(entry.key())),
                                qPrintable(hostSnapshot(field, scroll->widget())));
                        }
                        ++scrollJumps;
                    }
                }
                previous = current;
                previousHosts.clear();
                for (auto entry = current.cbegin(); entry != current.cend(); ++entry)
                {
                    previousHosts.insert(entry.key(), hostSnapshot(projection->findChild<QLabel*>(entry.key()), scroll->widget()));
                }
            }
        }
        std::printf("SCROLL_WIDTH=%d JUMPS=%d\n", width, scrollJumps - jumpsBeforeWidth);
        scrollPaint.active = false;
        std::printf("SCROLL_PAINT width=%d layouts=%d card_resizes=%d card_moves=%d card_paints=%d broad_card_paints=%d shows=%d hides=%d styles=%d\n",
            width, scrollPaint.layouts, scrollPaint.cardResizes, scrollPaint.cardMoves, scrollPaint.cardPaints,
            scrollPaint.broadCardPaints, scrollPaint.shows, scrollPaint.hides, scrollPaint.styles);
        check(scrollPaint.cardResizes == 0 && scrollPaint.cardMoves == 0, "scroll resizes or moves the virtual card frame");
        check(scrollPaint.broadCardPaints < 40, "scroll repeatedly invalidates most of the viewport");

        // 已物化窗口内的1px往返不应再清空表单或触发大面积绘制；排除窗口边缘补行。
        scroll->verticalScrollBar()->setValue(scroll->verticalScrollBar()->maximum() / 2);
        settle(180);
        scrollPaint.reset();
        scrollPaint.active = true;
        for (int frame = 0; frame < 20; ++frame)
        {
            scroll->verticalScrollBar()->setValue(scroll->verticalScrollBar()->value() + (frame % 2 ? -1 : 1));
            settle(16);
        }
        scrollPaint.active = false;
        std::printf("SCROLL_REUSE width=%d layouts=%d broad_card_paints=%d styles=%d\n", width,
            scrollPaint.layouts, scrollPaint.broadCardPaints, scrollPaint.styles);
        check(scrollPaint.layouts == 0 && scrollPaint.styles == 0, "cached scrolling rebuilds layout or styles");
        check(scrollPaint.broadCardPaints == 0, "cached scrolling clears most of the viewport");
    }
    std::printf("CONTINUOUS_SCROLL_JUMPS=%d\n", scrollJumps);
    check(scrollJumps == 0, "continuous scrolling changes visible field layout");
    if (scrollPaintOnly)
    {
        QThreadPool::globalInstance()->waitForDone();
        return failures ? 1 : 0;
    }

    // 搜索必须保留规范文档，同时能从孤立短结果恢复到完整长字段布局。
    auto* search = projection->findChild<QLineEdit*>(); // 复用生产搜索框，触发真实异步过滤。
    check(search != nullptr, "canonical search control is present");
    // 选区使字段越过物化窗口后仍保活；返回原位置和搜索恢复不能替换原控件。
    window.resize(665, 570);
    auto* selectionScroll = projection->findChild<QScrollArea*>(); // 使用同一个生产滚动区。
    selectionScroll->verticalScrollBar()->setValue(0);
    settle(400);
    QPointer<QLabel> selectedValue; // 弱指针检测误回收，不延长被测标签寿命。
    for (QLabel* label : projection->findChildren<QLabel*>())
        if (label->property("ksword_detail_field_value").toBool()
            && label->property("ksword_card_field").toInt() == 0) selectedValue = label;
    check(bool(selectedValue), "first field can be selected");
    if (selectedValue)
    {
        selectedValue->setSelection(0, 9);
        const QString selectedText = selectedValue->selectedText(); // 保留原始选区内容。
        const QPoint initialPosition = selectedValue->mapTo(selectionScroll->widget(), QPoint());
        selectionScroll->verticalScrollBar()->setValue(selectionScroll->verticalScrollBar()->maximum());
        settle(250);
        check(selectedValue && selectedValue->selectedText() == selectedText, "scrolling retires a selected value");
        search->setText(QStringLiteral("no-such-field"));
        settle(350);
        check(selectedValue && selectedValue->selectedText() == selectedText, "filtering destroys a selected value");
        search->clear();
        settle(350);
        selectionScroll->verticalScrollBar()->setValue(0);
        settle(250);
        check(selectedValue && selectedValue->selectedText() == selectedText, "returning replaces selected value");
        check(selectedValue && selectedValue->mapTo(selectionScroll->widget(), QPoint()) == initialPosition,
            "selected value does not return to its original position");
        if (selectedValue) selectedValue->setSelection(0, 0);
        checkRows(projection);
    }
    // 自绘画布只在实际alpha255时拥有opaque声明；热切换必须同步撤销和恢复。
    ks::ui::detail_cards::Canvas canvas(nullptr); // 检查生产类的实际属性，不模拟其判断。
    for (int alpha : {255, 192, 0, 255})
    {
        canvas.setCanvasColor(QColor(20, 30, 40, alpha));
        check(canvas.testAttribute(Qt::WA_OpaquePaintEvent) == (alpha == 255),
            "canvas opaque attribute does not match actual alpha");
    }
    for (int pointSize : {10, 14})
    {
        window.setFont(QFont(QStringLiteral("Microsoft YaHei UI"), pointSize));
        for (int width : {480, 665, 916})
        {
            window.resize(width, 570);
            for (const QString& query : {QStringLiteral("RestrictedDevice"), QStringLiteral("queryFailed"), QStringLiteral("no-such-field"), QString()})
            {
                search->setText(query);
                settle(400);
                const QString before = geometrySnapshot(projection); // 搜索和字体变化收敛后的几何。
                settle(150);
                check(before == geometrySnapshot(projection), "filtered card geometry does not converge");
                checkRows(projection);
                check(source->document().nodes.first().children.size() == 80, "search preserves canonical fields");
            }
        }
    }
    // 共享投影还用于短卡片、长附注及窄窗全宽字段；补充真实文档组合与深浅主题切换。
    ks::ui::FieldDocument mixed; // 多段文档仍由同一规范源搜索和导出。
    mixed.section(QStringLiteral("Object header / service dependency summary"));
    mixed.field(QStringLiteral("Address"), QStringLiteral("0xFFFF800012345678"));
    mixed.field(QStringLiteral("Type"), QStringLiteral("Token"));
    mixed.note(QStringLiteral("Evidence note: a complete full-width explanation with enough text to wrap over multiple lines. ").repeated(5));
    mixed.section(QStringLiteral("All TokenInformationClass Snapshot with a deliberately long heading to exercise title wrapping"));
    for (int index = 0; index < 24; ++index)
    {
        mixed.field(names.at(index % names.size()), QStringLiteral("size=4, raw=00 00 00 00"));
    }
    mixed.note(QStringLiteral("Full-width raw note: 00 01 02 03 04 05 06 07 08 09 0A 0B 0C 0D 0E 0F ").repeated(5));
    mixed.section(QStringLiteral("No fields"));
    mixed.note(QStringLiteral("Only a note is available."));
    source->setDocument(mixed);
    for (bool dark : {true, false})
    {
        KswordTheme::SetDarkModeEnabled(dark);
        QPalette palette = application.palette(); // 使用共享主题角色构造当前应用的真实调色板。
        palette.setColor(QPalette::Window, KswordTheme::WindowColor());
        palette.setColor(QPalette::Base, KswordTheme::SurfaceColor());
        palette.setColor(QPalette::Text, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::WindowText, KswordTheme::TextPrimaryColor());
        palette.setColor(QPalette::ButtonText, KswordTheme::TextPrimaryColor());
        // 名称QSS读取placeholder-text；漏设此角色会把Windows默认浅色前景带入深色夹具。
        palette.setColor(QPalette::PlaceholderText, KswordTheme::TextSecondaryColor());
        application.setPalette(palette);
        ks::ui::RefreshWidgetThemeBindings();
        for (int width : {480, 665, 916})
        {
            window.resize(width, 570);
            settle(400);
            auto* scroll = projection->findChild<QScrollArea*>(); // 此轮真实滚动容器。
            for (int position : {0, scroll->verticalScrollBar()->maximum() / 2, scroll->verticalScrollBar()->maximum()})
            {
                scroll->verticalScrollBar()->setValue(position);
                settle(180);
                checkRows(projection);
                for (QLabel* label : projection->findChildren<QLabel*>())
                {
                    if (label->isVisible() && label->property("ksword_detail_field_label").toBool())
                    {
                        // 校验最终QSS解析后的实际绘制前景，防止自绘名称绕过主题或夹具漏配角色。
                        check(KswordTheme::ContrastRatio(label->palette().color(label->foregroundRole()),
                            KswordTheme::SurfaceColor()) >= 4.5, "field name foreground contrast is insufficient");
                    }
                }
                const QString before = geometrySnapshot(projection); // 主题和跨卡片物化后的稳定正文。
                settle(80);
                check(before == geometrySnapshot(projection), "mixed document geometry is unstable");
            }
            projection->grab().save(evidence.filePath(QStringLiteral("mixed-%1-%2.png").arg(dark).arg(width)));
        }
    }
    window.hide();
    QThreadPool::globalInstance()->waitForDone();
    std::printf("DETAIL_CARD_RESIZE_CHECKS=%d FAILURES=%d\n", checks, failures);
    return failures ? 1 : 0;
}
