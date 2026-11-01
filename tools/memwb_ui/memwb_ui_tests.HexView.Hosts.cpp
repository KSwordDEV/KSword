// 原生 HexView 宿主契约：文件偏移、当前窗口查找、只读/设备置脏与关闭安全。
#include "memwb_ui_hexview.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexCanvasOverviewBar.h"
#include "../../Ksword5.1/Ksword5.1/UI/FloatingScrollbars.h"
#include <QApplication>
#include <QCoreApplication>
#include <QFontMetrics>
#include <QMenu>
#include <QPointer>
#include <QPushButton>
#include <QScrollBar>
#include <QToolButton>
#include <QVBoxLayout>

namespace memwb_test
{
    namespace
    {
        using ks::ui::HexView;
        using ks::ui::HexFindBar;
        using Rail = ks::ui::HexCanvasOverviewBar;

        // Same public buffer host used directly by registry/network/disk pages
        // and inside the file-property SnapshotWorkbenchWidget. No target IO.
        void TestSharedPresentation()
        {
            auto view = std::make_unique<HexView>();
            view->setEditable(false);
            QByteArray data(8192, '\0');
            std::fill(data.begin()+4096,data.end(),'A');
            constexpr std::uint64_t base = 0x20000;
            view->setBuffer(base,data);
            auto* canvas=view->canvas();
            auto* const original=canvas->verticalScrollBar();
            ks::ui::InstallFloatingScrollbars(canvas);
            CHECK(canvas->overviewEnabled() && canvas->fixedAddressScale());
            CHECK(!canvas->findChild<QWidget*>(QStringLiteral("memwb_hex_overview")));
            auto* button=canvas->findChild<QToolButton*>(QStringLiteral("memwb_address_collapse"));
            CHECK(button && !canvas->addressColumnCollapsed());
            view->resize(900,500);view->show();Flush();
            auto* rail=static_cast<Rail*>(canvas->findChild<QWidget*>(QStringLiteral("memwb_hex_overview")));
            CHECK(rail && rail->isVisible() && rail->width()==25);
            if(!rail || !button) return;
            CHECK(button->isVisible() && button->size()==QSize(28,28));
            CHECK(!button->icon().pixmap(16,16).isNull());
            CHECK(original==canvas->verticalScrollBar());
            CHECK(ks::ui::HasFloatingScrollbars(canvas));
            CHECK(rail->geometry().left()==canvas->viewport()->geometry().right()+1);
            const auto imageOf=[&]() { rail->repaint();Flush();return rail->grab().toImage(); };
            const auto colorAt=[](const QImage& image,int x,int y) {
                return image.pixelColor(qRound(x*image.devicePixelRatio()),qRound(y*image.devicePixelRatio()));
            };
            for(const bool dark : {false,true}) {
                ApplyTheme(dark);Flush();const auto image=imageOf();
                const auto zero=colorAt(image,rail->width()/2,rail->height()/4);
                const auto text=colorAt(image,rail->width()/2,rail->height()*3/4);
                CHECK(zero!=Qt::white && text!=Qt::white);
                CHECK(ColorDistance(text,Qt::white)>ColorDistance(zero,Qt::white));
                view->grab().save(QCoreApplication::applicationDirPath()+(dark
                    ? QStringLiteral("/hex-shared-overview-dark.png") : QStringLiteral("/hex-shared-overview-light.png")));
            }
            const auto selected=canvas->selectedRange();
            const auto revision=canvas->sourceRevision();
            const auto oldCell=canvas->cellRect(base,ks::ui::HexCanvas::ActivePane::Hex);
            QTest::mouseClick(button,Qt::LeftButton);Flush();
            CHECK(canvas->addressColumnCollapsed() && !canvas->addressColumnPrefix().isEmpty());
            CHECK(canvas->cellRect(base,ks::ui::HexCanvas::ActivePane::Hex).left()<oldCell.left());
            CHECK(view->buffer()==data && !view->isEditable() && canvas->sourceRevision()==revision);
            CHECK(canvas->selectedRange()==selected && view->caretAddress()==base);
            const int charWidth=QFontMetrics(canvas->font()).horizontalAdvance(QLatin1Char('0'));
            CHECK(QFontMetrics(canvas->font()).horizontalAdvance(canvas->addressColumnPrefix())<=button->x()-charWidth-4);
            imageOf();const auto builds=rail->summaryBuildCount();
            const auto target=base+0x1800;
            const QPoint point(rail->width()/2,qRound(rail->rowPosition((target-base)/16)));
            QTest::mouseClick(rail,Qt::LeftButton,Qt::NoModifier,point);Flush();
            CHECK(!canvas->cellRect(target,ks::ui::HexCanvas::ActivePane::Hex).isNull());
            CHECK(view->caretAddress()==base && canvas->selectedRange()==selected);
            for(int row : {80,120,300,330}) { original->setValue(row);imageOf(); }
            CHECK(rail->summaryBuildCount()==builds);
            CHECK(view->buffer()==data && original==canvas->verticalScrollBar());
            view->setToolbarVisible(false);view->setStatusBarVisible(false);Flush();
            CHECK(!view->toolbar()->isVisible() && rail->isVisible() && button->isVisible());
            const auto nextBase=0x100020000ULL;
            view->setBuffer(nextBase,QByteArray(8192,'\0'));Flush();const auto replaced=imageOf();
            CHECK(view->baseAddress()==nextBase && view->caretAddress()==nextBase);
            CHECK(canvas->visibleAddressRange()->first>=nextBase && canvas->visibleAddressRange()->last<nextBase+8192);
            CHECK(canvas->addressColumnCollapsed() && !canvas->addressColumnPrefix().isEmpty());
            CHECK(ColorDistance(colorAt(replaced,rail->width()/2,rail->height()*3/4),Qt::white)<100);
            CHECK(!view->jumpToAddress(base));
            view->setBuffer(nextBase,QByteArray(2*1024*1024,'\0'));Flush();imageOf();
            const auto unseen=nextBase+2*1024*1024-1;
            CHECK(canvas->cellStateAt(unseen).byteState==ks::ui::HexCanvas::ByteState::NotLoaded);
            const auto idleBuilds=rail->summaryBuildCount();
            QImage idle;
            for(int paint=0;paint<5;++paint) idle=imageOf();
            CHECK(canvas->cellStateAt(unseen).byteState==ks::ui::HexCanvas::ByteState::NotLoaded);
            CHECK(colorAt(idle,rail->width()/2,rail->height()*3/4)==Qt::white);
            CHECK(rail->summaryBuildCount()==idleBuilds);
            view->clearBuffer();Flush();const auto cleared=imageOf();
            CHECK(!button->isVisible() && canvas->addressColumnPrefix().isEmpty());
            CHECK(colorAt(cleared,rail->width()/2,rail->height()/2)==Qt::white);
            CHECK(!view->isEditable());
        }

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
        TestSharedPresentation();
        TestFileWindows();
        TestDeviceDirty();
        TestHostClosing();
    }
}
