// 原生 HexView 宿主契约：文件偏移、当前窗口查找、只读/设备置脏与关闭安全。
#include "memwb_ui_hexview.h"
#include <QApplication>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QVBoxLayout>

namespace memwb_test
{
    namespace
    {
        using ks::ui::HexView;
        using ks::ui::HexFindBar;

        // SearchText：只搜索宿主已加载的缓冲，等待原生查找条的完成信号。
        bool SearchText(HexView& view, const QString& text)
        {
            auto& bar = *view.findBar();
            bar.setMode(HexFindBar::Mode::TextUtf8);
            bar.setCaseSensitive(true);
            bar.setPatternText(text);
            QSignalSpy completed(&bar, &HexFindBar::searchCompleted);
            return bar.findNext() && PumpUntil([&]() { return !completed.isEmpty(); }, 8000)
                && completed.at(0).at(0).toBool();
        }

        // TestFileWindows：换文件页必须换偏移身份，旧搜索/编辑不能污染新窗口。
        void TestFileWindows()
        {
            QByteArray file = MakePattern(0x30123, 4); // 宿主拥有的原始文件证据。
            file.replace(0x1234, 9, QByteArrayLiteral("FILEMARK1"));
            file.replace(0x21000, 9, QByteArrayLiteral("OTHERWIN!"));
            auto page = std::make_unique<QWidget>();
            auto* layout = new QVBoxLayout(page.get());
            auto* view = new HexView(page.get());
            view->setEditable(false);
            view->setBytesPerRow(16);
            layout->addWidget(view, 1);
            page->resize(1000, 600);
            page->show();
            const QPointer<HexView> guard(view);
            const auto first = file.mid(0, 0x10000);
            view->setBuffer(0, first);
            Flush();
            CHECK(view->buffer() == first && view->bufferSize() == 0x10000 && view->baseAddress() == 0);
            CHECK(view->jumpToAddress(0x1234) && view->caretAddress() == 0x1234);
            CHECK(SearchText(*view, QStringLiteral("FILEMARK1")) && view->caretAddress() == 0x1234);
            CHECK(!SearchText(*view, QStringLiteral("OTHERWIN!")));
            QSignalSpy edited(view, &HexView::byteEdited);
            view->canvas()->setFocus();
            Click(*view->canvas(), 0x1300);
            Type(*view->canvas(), QStringLiteral("AB"));
            CHECK(edited.isEmpty() && view->buffer() == first);

            // 查找只属于当前捕获窗口，换页后不能沿用旧命中、高亮或基址。
            const auto second = file.mid(0x20000, 0x10000);
            view->setBuffer(0x20000, second);
            Flush();
            CHECK(view->baseAddress() == 0x20000 && view->buffer() == second);
            CHECK(!view->findBar()->highlightActive() && view->caretAddress() == 0x20000);
            CHECK(SearchText(*view, QStringLiteral("OTHERWIN!")) && view->caretAddress() == 0x21000);
            CHECK(!SearchText(*view, QStringLiteral("FILEMARK1")));
            CHECK(!view->jumpToAddress(0x1234) && !view->jumpToAddress(0x30000));
            view->setBuffer(0x30000, file.mid(0x30000));
            Flush();
            CHECK(view->bufferSize() == 0x123);
            CHECK(view->jumpToAddress(0x30122) && !view->jumpToAddress(0x30123));
            view->setBuffer(0, QByteArray());
            CHECK(view->buffer().isEmpty() && !view->jumpToAddress(0));
            view->setBuffer(0, first);
            auto* find = new QPushButton(page.get()); // 宿主自有按钮直接接原生查找槽。
            QObject::connect(find, &QPushButton::clicked, view, &HexView::openFind);
            view->closeFindBar();
            Flush();
            CHECK(!view->findBar()->isVisible());
            find->click();
            Flush();
            CHECK(view->findBar()->isVisible());
            page.reset();
            CHECK(guard.isNull());
        }

        // TestDeviceDirty：原生编辑信号提供绝对偏移与 before/after，宿主决定是否写盘。
        void TestDeviceDirty()
        {
            const auto original = MakePattern(4096, 7);
            constexpr std::uint64_t base = 0x200000;
            auto view = MakeHexView(base, original, false, QSize(1000, 520));
            bool dirty = false; // 宿主置脏标记，不承担实际设备写入。
            QSignalSpy edits(view.get(), &HexView::byteEdited);
            QObject::connect(view.get(), &HexView::byteEdited, view.get(),
                [&](std::uint64_t, std::uint8_t, std::uint8_t) { dirty = true; });
            Click(*view->canvas(), base + 0x10);
            Type(*view->canvas(), QStringLiteral("FF"));
            CHECK(!dirty && edits.isEmpty() && view->buffer() == original);
            view->setEditable(true);
            const auto oldByte = static_cast<std::uint8_t>(original.at(0x10));
            const auto newByte = static_cast<std::uint8_t>(oldByte ^ 0x55);
            Click(*view->canvas(), base + 0x10);
            Type(*view->canvas(), QStringLiteral("%1").arg(newByte, 2, 16, QLatin1Char('0')));
            CHECK(dirty && edits.size() == 1);
            if (edits.size() == 1)
            {
                CHECK(edits.at(0).at(0).toULongLong() == base + 0x10);
                CHECK(edits.at(0).at(1).toUInt() == oldByte && edits.at(0).at(2).toUInt() == newByte);
            }
            auto expected = original;
            expected[0x10] = static_cast<char>(newByte);
            CHECK(view->buffer() == expected && original == MakePattern(4096, 7));

            // 重读新设备窗口不发写入信号，之后只读状态继续禁止修改。
            const auto next = MakePattern(4096, 11);
            dirty = false;
            edits.clear();
            view->setBuffer(0x300000, next);
            Flush();
            CHECK(!dirty && edits.isEmpty() && view->buffer() == next && view->caretAddress() == 0x300000);
            CHECK(CellOf(*view, 0x300010).change == ks::ui::HexCanvas::ChangeKind::Unchanged);
            view->setEditable(false);
            Click(*view->canvas(), 0x300020);
            Type(*view->canvas(), QStringLiteral("12"));
            CHECK(edits.isEmpty() && view->buffer() == next);
            view->clearBuffer();
            CHECK(view->buffer().isEmpty() && view->bufferSize() == 0 && !view->isEditable());
        }

        // TestHostClosing：只验证仍适用的原生生命周期，不复刻被删除的类名吸附规则。
        void TestHostClosing()
        {
            auto view = MakeHexView(0x1000, MakePattern(1024), true, QSize(900, 400));
            auto* menu = view->canvas()->buildContextMenu(0x1010, true);
            const QPointer<QMenu> menuGuard(menu);
            view.reset();
            CHECK(menuGuard.isNull());
            QByteArray large(8 * 1024 * 1024, '\0');
            auto searching = MakeHexView(0, large, false, QSize(900, 400));
            searching->findBar()->setMode(HexFindBar::Mode::Hex);
            searching->findBar()->setPatternText(QStringLiteral("DE AD BE EF 01 02 03 04 05"));
            CHECK(searching->findBar()->findNext());
            const QPointer<HexView> searchGuard(searching.get());
            searching.reset();
            CHECK(searchGuard.isNull());
            PumpFor(100);

            // 宿主从编辑回调请求关闭；处理 DeferredDelete 后不留下页对象。
            auto editing = MakeHexView(0x1000, MakePattern(1024), true, QSize(900, 400));
            auto* raw = editing.release();
            const QPointer<HexView> editGuard(raw);
            QObject::connect(raw, &HexView::byteEdited, raw,
                [raw](std::uint64_t, std::uint8_t, std::uint8_t) { raw->deleteLater(); });
            const auto oldByte = static_cast<std::uint8_t>(raw->buffer().at(0x20));
            Click(*raw->canvas(), 0x1020);
            Type(*raw->canvas(), QStringLiteral("%1").arg(oldByte ^ 0x55, 2, 16, QLatin1Char('0')));
            QCoreApplication::sendPostedEvents(nullptr, QEvent::DeferredDelete);
            QApplication::processEvents();
            CHECK(editGuard.isNull());
        }
    }

    // RunHexViewHostTests：随 HexView 原生套件执行，复用其设置隔离与断言记录。
    void RunHexViewHostTests()
    {
        ApplyTheme(false);
        TestFileWindows();
        TestDeviceDirty();
        TestHostClosing();
    }
}
