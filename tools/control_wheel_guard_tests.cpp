// 本夹具加载 MainWindow.cpp 的实际过滤器，并通过 QApplication 测试原生 Qt 滚轮分发。
#include <QAbstractItemView>
#include <QAbstractScrollArea>
#include <QAbstractSlider>
#include <QAbstractSpinBox>
#include <QApplication>
#include <QComboBox>
#include <QCompleter>
#include <QDateTimeEdit>
#include <QDialog>
#include <QDial>
#include <QDoubleSpinBox>
#include <QLineEdit>
#include <QListView>
#include <QPlainTextEdit>
#include <QPointer>
#include <QScrollArea>
#include <QScrollBar>
#include <QSlider>
#include <QSpinBox>
#include <QStyledItemDelegate>
#include <QTableWidget>
#include <QTest>
#include <QVariant>
#include <QWheelEvent>
#include <QtTest/qtestwheel.h>
#include <iostream>
#include "Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.h"
#include "control_wheel_guard_extracted.h"
// 直接包含真实平滑滚动实现，聚合到专用夹具对象，避免共享目录的通用 OBJ 被覆盖。
#include "Ksword5.1/Ksword5.1/UI/SmoothScrollSupport.cpp"

namespace
{
    // checks/failures 记录全部实际行为断言数量与失败数量，便于脚本判定红绿结果。
    int checks = 0;
    int failures = 0;

    // WheelProbe 接收 popup 内普通 QWidget 的滚轮，记录边界是否被错误吞掉。
    class WheelProbe final : public QWidget
    {
    public:
        // 构造函数传入 QObject 所有者及窗口标记，建立可独立显示的 popup。
        explicit WheelProbe(QWidget* parent, const Qt::WindowFlags flags)
            : QWidget(parent, flags)
        {
        }

        // wheelCount 表示实际进入本控件 wheelEvent 的次数，不统计过滤器旁观事件。
        int wheelCount = 0;

    protected:
        // wheelEvent 输入真实滚轮，计数并接受，无返回值。
        void wheelEvent(QWheelEvent* event) override
        {
            ++wheelCount;
            event->accept();
        }
    };

    // check 输入判断与用例标签，输出单条 PASS/FAIL 并更新总计，无返回值。
    void check(const bool condition, const QString& label)
    {
        ++checks;
        if (!condition)
        {
            ++failures;
        }
        std::cout << (condition ? "PASS " : "FAIL ")
            << label.toStdString() << std::endl;
    }

    // wheel 向目标控件发送真实 Qt 滚轮；angle/pixel 分别表示鼠标与触控板增量。
    void wheel(QWidget* target, const QPoint angle = QPoint(0, 120),
        const QPoint pixel = QPoint(), const Qt::KeyboardModifiers modifiers = Qt::NoModifier)
    {
        // local/global 对应目标控件中心坐标，event 保留真实 QWheelEvent 元信息。
        const QPoint local = target->rect().center();
        const QPoint global = target->mapToGlobal(local);
        QWheelEvent event(local, global, pixel, angle, Qt::NoButton, modifiers,
            Qt::NoScrollPhase, false);
        QApplication::sendEvent(target, &event);
        QTest::qWait(210);
    }

    // nativeWheel 通过窗口系统路径产生 spontaneous 滚轮，验证 Qt 原生父链传播。
    void nativeWheel(QWidget* target, const QPoint angle = QPoint(0, 120),
        const QPoint pixel = QPoint(), const Qt::KeyboardModifiers modifiers = Qt::NoModifier)
    {
        // top/position 把子控件中心换算到顶层窗口，不依赖真实桌面鼠标或用户窗口。
        QWidget* top = target->window();
        const QPoint position = target->mapTo(top, target->rect().center());
        QTest::wheelEvent(top->windowHandle(), position, angle, pixel, modifiers);
        QTest::qWait(210);
    }

    // Form 提供已有父滚动页；area/content 为真实 QScrollArea 与可超出视口的页面。
    struct Form
    {
        QScrollArea area;
        QWidget* content = new QWidget;

        // 构造函数不接收参数，创建固定尺寸页面与中间位置滚动条。
        Form()
        {
            area.resize(420, 260);
            content->resize(380, 1800);
            area.setWidget(content);
            area.show();
            QTest::qWait(20);
            area.verticalScrollBar()->setValue(450);
        }
    };

    // stableControl 传入控件及值读取函数；分别检查禁用/启用与焦点状态及父页面滚动。
    template<class ReadValue>
    void stableControl(QWidget* control, ReadValue readValue, const QString& name,
        const bool smooth)
    {
        // form 保存控件拥有者；label 标注当前平滑滚动组合，用例可精确定位失败。
        Form form;
        const QString label = name + (smooth ? "/smooth-on" : "/smooth-off");
        control->setParent(form.content);
        control->setGeometry(10, 500, 180, 40);
        control->show();
        form.area.activateWindow();
        control->setFocus(Qt::OtherFocusReason);
        QTest::qWait(20);
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        const auto before = readValue();
        const int scrollBefore = form.area.verticalScrollBar()->value();
        wheel(control);
        check(readValue() == before, label + "/blocked-focused");
        std::cout << "OBSERVED " << label.toStdString() << "/synthetic-parent-scroll="
            << (form.area.verticalScrollBar()->value() < scrollBefore) << std::endl;
        // 合成 sendEvent 不走 Qt 原生祖先传播，因此父页面契约使用 spontaneous 路径检查。
        form.area.verticalScrollBar()->setValue(450);
        const auto nativeBefore = readValue();
        nativeWheel(control);
        check(readValue() == nativeBefore, label + "/native-blocked-focused");
        check(form.area.verticalScrollBar()->value() < 450, label + "/native-parent-scroll");

        // 开关即时启用后使用相同控件，不重新安装过滤器，证明运行中设置切换生效。
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", true);
        const auto enabledBefore = readValue();
        wheel(control);
        check(readValue() != enabledBefore, label + "/enabled-synthetic-adjust");
        const auto enabledNativeBefore = readValue();
        nativeWheel(control);
        check(readValue() != enabledNativeBefore, label + "/enabled-native-adjust");
    }

    // spinChild 输入真实数值控件，检查 wheel 发送到内部 lineEdit 的祖先命中行为。
    template<class Spin, class ReadValue>
    void spinChild(Spin* spin, ReadValue readValue, const QString& name, const bool smooth)
    {
        Form form;
        spin->setParent(form.content);
        spin->setGeometry(10, 500, 180, 40);
        spin->show();
        // editor 是 Qt 自建 lineEdit，过滤器必须识别其数值控件祖先。
        QLineEdit* editor = spin->template findChild<QLineEdit*>();
        check(editor != nullptr, name + "/lineedit-exists");
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        const auto before = readValue();
        const int scrollBefore = form.area.verticalScrollBar()->value();
        wheel(editor);
        const QString label = name + (smooth ? "/smooth-on" : "/smooth-off");
        check(readValue() == before, label + "/child-blocked");
        std::cout << "OBSERVED " << label.toStdString() << "/synthetic-child-parent-scroll="
            << (form.area.verticalScrollBar()->value() < scrollBefore) << std::endl;
        form.area.verticalScrollBar()->setValue(450);
        const auto nativeBefore = readValue();
        nativeWheel(editor);
        check(readValue() == nativeBefore, label + "/native-child-blocked");
        check(form.area.verticalScrollBar()->value() < 450, label + "/native-child-parent-scroll");
    }

    // controlMatrix 对每一种真实调值控件执行相同策略；smooth 是平滑开关的输入。
    void controlMatrix(const bool smooth)
    {
        ks::ui::SetGlobalSmoothScrollingEnabled(smooth);
        // 各指针只由其测试页面拥有；初始值留出上滚与下滚空间，避免边界误判。
        auto* slider = new QSlider(Qt::Horizontal);
        slider->setRange(0, 100);
        slider->setValue(50);
        stableControl(slider, [slider] { return slider->value(); }, "slider", smooth);
        auto* dial = new QDial;
        dial->setRange(0, 100);
        dial->setValue(50);
        stableControl(dial, [dial] { return dial->value(); }, "dial", smooth);

        auto* combo = new QComboBox;
        combo->addItems({"zero", "one", "two", "three", "four"});
        combo->setCurrentIndex(2);
        stableControl(combo, [combo] { return combo->currentIndex(); }, "combo", smooth);
        auto* editableCombo = new QComboBox;
        editableCombo->setEditable(true);
        editableCombo->addItems({"zero", "one", "two", "three", "four"});
        editableCombo->setCurrentIndex(2);
        stableControl(editableCombo, [editableCombo] { return editableCombo->currentIndex(); },
            "editable-combo", smooth);

        auto* spin = new QSpinBox;
        spin->setRange(0, 100);
        spin->setValue(50);
        stableControl(spin, [spin] { return spin->value(); }, "spin", smooth);
        auto* doubleSpin = new QDoubleSpinBox;
        doubleSpin->setRange(0.0, 100.0);
        doubleSpin->setValue(50.0);
        stableControl(doubleSpin, [doubleSpin] { return doubleSpin->value(); }, "double-spin", smooth);
        auto* date = new QDateTimeEdit(QDateTime(QDate(2026, 10, 8), QTime(12, 0)));
        stableControl(date, [date] { return date->dateTime(); }, "date-time", smooth);

        auto* childSpin = new QSpinBox;
        childSpin->setValue(50);
        spinChild(childSpin, [childSpin] { return childSpin->value(); }, "spin", smooth);
        auto* childDouble = new QDoubleSpinBox;
        childDouble->setValue(50.0);
        spinChild(childDouble, [childDouble] { return childDouble->value(); }, "double-spin", smooth);
        auto* childDate = new QDateTimeEdit(QDateTime(QDate(2026, 10, 8), QTime(12, 0)));
        spinChild(childDate, [childDate] { return childDate->dateTime(); }, "date-time", smooth);

        // editableChild 专门向下拉框内部编辑器发送事件，覆盖非根控件接收路径。
        Form form;
        auto* editableChild = new QComboBox(form.content);
        editableChild->setEditable(true);
        editableChild->addItems({"zero", "one", "two", "three", "four"});
        editableChild->setCurrentIndex(2);
        editableChild->setGeometry(10, 500, 180, 40);
        editableChild->show();
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        const int childScrollBefore = form.area.verticalScrollBar()->value();
        wheel(editableChild->lineEdit());
        check(editableChild->currentIndex() == 2, "editable-combo/child-blocked");
        std::cout << "OBSERVED editable-combo/synthetic-child-parent-scroll="
            << (form.area.verticalScrollBar()->value() < childScrollBefore) << std::endl;
        form.area.verticalScrollBar()->setValue(450);
        const int nativeIndexBefore = editableChild->currentIndex();
        nativeWheel(editableChild->lineEdit());
        check(editableChild->currentIndex() == nativeIndexBefore,
            "editable-combo/native-child-blocked");
        check(form.area.verticalScrollBar()->value() < 450,
            "editable-combo/native-child-parent-scroll");
    }

    // nativeScrolling 检查保护开关不能破坏普通滚动条、表格、文本与 popup 列表。
    void nativeScrolling(const bool smooth)
    {
        ks::ui::SetGlobalSmoothScrollingEnabled(smooth);
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        const QString label = smooth ? "smooth-on" : "smooth-off";
        QScrollBar bar(Qt::Vertical);
        bar.setRange(0, 1000);
        bar.setValue(500);
        bar.show();
        wheel(&bar);
        check(bar.value() < 500, label + "/scrollbar-native");

        QTableWidget table(100, 2);
        table.resize(400, 200);
        table.show();
        QTest::qWait(20);
        table.verticalScrollBar()->setValue(table.verticalScrollBar()->maximum() / 2);
        const int tableBefore = table.verticalScrollBar()->value();
        wheel(table.viewport());
        check(table.verticalScrollBar()->value() < tableBefore, label + "/table-scroll");
        QPlainTextEdit text;
        for (int line = 0; line < 100; ++line)
        {
            text.appendPlainText(QString::number(line));
        }
        text.resize(400, 200);
        text.show();
        QTest::qWait(20);
        text.verticalScrollBar()->setValue(40);
        wheel(text.viewport());
        check(text.verticalScrollBar()->value() < 40, label + "/text-scroll");

        // popup 自己是可滚动列表；不能因 QObject 祖先带 QComboBox 被当作调值控件。
        QComboBox combo;
        combo.setMaxVisibleItems(8);
        for (int item = 0; item < 100; ++item)
        {
            combo.addItem(QString::number(item));
        }
        combo.resize(200, 30);
        combo.show();
        combo.showPopup();
        QTest::qWait(20);
        combo.view()->verticalScrollBar()->setValue(combo.view()->verticalScrollBar()->maximum() / 2);
        const int popupBefore = combo.view()->verticalScrollBar()->value();
        wheel(combo.view()->viewport());
        check(popupBefore > 0 && combo.view()->verticalScrollBar()->value() < popupBefore,
            label + "/popup-list-scroll");
        combo.hidePopup();
    }

    // standaloneAndDelegate 创建安装过滤器后的动态窗口与原生 delegate 编辑器。
    void standaloneAndDelegate()
    {
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        QDialog dialog;
        QComboBox combo(&dialog);
        combo.addItems({"zero", "one", "two", "three"});
        combo.setCurrentIndex(2);
        combo.setGeometry(10, 10, 180, 30);
        dialog.show();
        wheel(&combo);
        check(combo.currentIndex() == 2, "standalone-dialog/dynamic-combo-blocked");
        QSpinBox spin;
        spin.setValue(50);
        spin.show();
        wheel(&spin);
        check(spin.value() == 50, "standalone-control/no-parent-blocked");
        nativeWheel(&spin);
        check(spin.value() == 50, "standalone-control/native-no-parent-blocked");

        QTableWidget table(100, 1);
        table.setItem(0, 0, new QTableWidgetItem);
        table.item(0, 0)->setData(Qt::EditRole, 50);
        table.resize(400, 200);
        table.show();
        table.openPersistentEditor(table.item(0, 0));
        QTest::qWait(20);
        // editor 来自 Qt QStyledItemDelegate，祖先穿过 viewport，仍必须阻止调值。
        QSpinBox* editor = table.findChild<QSpinBox*>();
        check(editor != nullptr, "delegate/native-spin-editor-exists");
        if (editor != nullptr)
        {
            wheel(editor);
            check(editor->value() == 50, "delegate/editor-value-blocked");
            wheel(editor->findChild<QLineEdit*>());
            check(editor->value() == 50, "delegate/editor-lineedit-blocked");
            nativeWheel(editor);
            check(editor->value() == 50, "delegate/native-editor-value-blocked");
            nativeWheel(editor->findChild<QLineEdit*>());
            check(editor->value() == 50, "delegate/native-editor-lineedit-blocked");
        }

        // focusChild 是滑块中的动态子 QWidget，覆盖自绘复合滑块的事件接收路径。
        QSlider slider(Qt::Horizontal);
        slider.setValue(50);
        QWidget focusChild(&slider);
        focusChild.resize(30, 20);
        slider.show();
        focusChild.show();
        wheel(&focusChild);
        check(slider.value() == 50, "slider/dynamic-child-blocked");
        nativeWheel(&focusChild);
        check(slider.value() == 50, "slider/native-dynamic-child-blocked");
    }

    // nativeScrollContract 比较同一父页视口与值控件上的原生增量，排除重复滚动与单位变换。
    void nativeScrollContract(const bool smooth)
    {
        ks::ui::SetGlobalSmoothScrollingEnabled(smooth);
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        Form form;
        QSpinBox spin(form.content);
        spin.setValue(50);
        spin.setGeometry(10, 500, 180, 40);
        spin.show();
        // label 标注平滑设置，expectedWheel/expectedPixel/expectedShift 保存父页自身结果。
        const QString label = smooth ? "smooth-on" : "smooth-off";
        nativeWheel(form.area.viewport());
        const int expectedWheel = form.area.verticalScrollBar()->value();
        form.area.verticalScrollBar()->setValue(450);
        nativeWheel(&spin);
        check(form.area.verticalScrollBar()->value() == expectedWheel,
            label + "/native-parent-single-wheel-delivery");
        check(spin.value() == 50, label + "/native-single-delivery-value-stable");

        form.area.verticalScrollBar()->setValue(450);
        nativeWheel(form.area.viewport(), QPoint(), QPoint(0, 30));
        const int expectedPixel = form.area.verticalScrollBar()->value();
        form.area.verticalScrollBar()->setValue(450);
        nativeWheel(&spin, QPoint(), QPoint(0, 30));
        check(form.area.verticalScrollBar()->value() == expectedPixel,
            label + "/native-parent-pixel-wheel-preserved");
        check(spin.value() == 50, label + "/native-pixel-value-stable");

        form.content->resize(1600, 1800);
        form.area.horizontalScrollBar()->setValue(450);
        nativeWheel(form.area.viewport(), QPoint(0, 120), QPoint(), Qt::ShiftModifier);
        const int expectedShift = form.area.horizontalScrollBar()->value();
        form.area.horizontalScrollBar()->setValue(450);
        // 横向移动后的控件重新放在可见位置，避免原生事件命中空白内容。
        spin.move(500, 500);
        nativeWheel(&spin, QPoint(0, 120), QPoint(), Qt::ShiftModifier);
        check(form.area.horizontalScrollBar()->value() == expectedShift,
            label + "/native-parent-shift-wheel-preserved");
        check(spin.value() == 50, label + "/native-shift-value-stable");
    }

    // focusModifiersAndPopups 对焦点、修饰键与自动完成 popup 各跑少量代表用例。
    void focusModifiersAndPopups()
    {
        ks::ui::SetGlobalSmoothScrollingEnabled(true);
        qApp->setProperty("ksword_slider_wheel_adjust_enabled", false);
        Form form;
        QComboBox combo(form.content);
        combo.addItems({"zero", "one", "two", "three"});
        combo.setCurrentIndex(2);
        combo.setGeometry(10, 500, 180, 30);
        combo.show();
        QSpinBox spin(form.content);
        spin.setValue(50);
        spin.setGeometry(10, 550, 180, 30);
        spin.show();
        // focusSink 是同窗口普通输入；确保测试控件真正处于未聚焦状态。
        QLineEdit focusSink(form.content);
        focusSink.setGeometry(210, 500, 120, 30);
        focusSink.show();
        form.area.activateWindow();
        focusSink.setFocus();
        QTest::qWait(20);
        check(!combo.hasFocus() && !spin.hasFocus(), "unfocused/precondition");
        nativeWheel(&combo);
        nativeWheel(&spin);
        check(combo.currentIndex() == 2, "unfocused/native-combo-blocked");
        check(spin.value() == 50, "unfocused/native-spin-blocked");

        // modifiers 保留两种代表修饰键，过滤保护不能因业务滚动修饰键而绕过。
        for (const Qt::KeyboardModifiers modifiers :
            {Qt::KeyboardModifiers(Qt::ControlModifier), Qt::KeyboardModifiers(Qt::ShiftModifier)})
        {
            form.area.verticalScrollBar()->setValue(450);
            const QString label = modifiers.testFlag(Qt::ControlModifier) ? "ctrl" : "shift";
            nativeWheel(&combo, QPoint(0, 120), QPoint(), modifiers);
            check(combo.currentIndex() == 2, label + "/native-combo-blocked");
            form.area.verticalScrollBar()->setValue(450);
            nativeWheel(&spin, QPoint(0, 120), QPoint(), modifiers);
            check(spin.value() == 50, label + "/native-spin-blocked");
        }

        QComboBox owner;
        owner.setEditable(true);
        for (int item = 0; item < 100; ++item)
        {
            owner.addItem(QString("item-%1").arg(item));
        }
        owner.resize(240, 30);
        owner.show();
        // completer/popup 由真实可编辑 combo 创建，保留 QObject 祖先关系与原生窗口。
        QCompleter* completer = owner.completer();
        completer->setMaxVisibleItems(8);
        completer->setCompletionMode(QCompleter::PopupCompletion);
        completer->setCompletionPrefix("");
        completer->complete();
        QTest::qWait(20);
        QAbstractItemView* popup = completer->popup();
        QScrollBar* popupBar = popup->verticalScrollBar();
        popupBar->setValue(popupBar->maximum() / 2);
        const int popupBefore = popupBar->value();
        wheel(popup->viewport());
        check(popupBefore > 0 && popupBar->value() < popupBefore,
            "completer/synthetic-popup-viewport-scroll");
        popupBar->setValue(popupBefore);
        nativeWheel(popup->viewport());
        check(popupBar->value() < popupBefore, "completer/native-popup-viewport-scroll");
        popupBar->setValue(popupBefore);
        wheel(popupBar);
        check(popupBar->value() < popupBefore, "completer/popup-scrollbar-scroll");
        popup->hide();

        WheelProbe plainPopup(&owner, Qt::Popup);
        plainPopup.resize(200, 100);
        plainPopup.show();
        wheel(&plainPopup);
        check(plainPopup.wheelCount == 1, "popup-window/combo-ancestor-synthetic-passthrough");
        nativeWheel(&plainPopup);
        check(plainPopup.wheelCount == 2, "popup-window/combo-ancestor-native-passthrough");
    }
}

// main 接收标准 argc/argv，返回非零表示回归失败；仅运行独立离屏 Qt 夹具。
int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    app.setStyle("Fusion");
    ks::ui::InstallGlobalSmoothScrollSupport(&app);
    // guard 加载的是生产类本体，不能在测试中复制或重写保护判断策略。
    GlobalSliderWheelFilter guard;
    app.installEventFilter(&guard);
    controlMatrix(false);
    nativeScrolling(false);
    nativeScrollContract(false);
    controlMatrix(true);
    nativeScrolling(true);
    nativeScrollContract(true);
    standaloneAndDelegate();
    focusModifiersAndPopups();
    std::cout << "CONTROL_WHEEL_GUARD_CHECKS=" << checks << '\n'
        << "CONTROL_WHEEL_GUARD_FAILURES=" << failures << std::endl;
    return failures == 0 ? 0 : 1;
}
