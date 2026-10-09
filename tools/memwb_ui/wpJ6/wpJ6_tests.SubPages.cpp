// ============================================================
// wpJ6_tests.SubPages.cpp
// 作用：反汇编 / 文本 / 对比三个子页"自动跳转（跟随十六进制）"的回归（真机反馈：三个子页不自动跳转）。
//   覆盖：切页签时跟随选区起点（而不是 caret）、同步令牌（用户手动导航后切回不覆盖、十六进制动过才覆盖）、
//   子页可见时十六进制插入点变化跟随（后退/前进/地址条）、没有选区时落到起始模块（含"模块目录
//   还在加载就挂起、到了再落"、进程名命中、没有 .exe 取最低基址、枚举失败退回插入点）、
//   重启后恢复在子页再附加进程、数据晚到的刷新、显式入口（Ctrl+D 不折叠选区、右键"从此处反汇编"
//   真的跳到反汇编页）、不重复压后退栈、内核/物理/DDMA 的兜底边界、未附加时不崩。
// 入口：RunSubPageTests（由 wpJ6_main.cpp 调用）。
// 夹具约定：假后备内存 base=0、0x20000 字节（ConfigureSharedOnce）；本文件每个用例开头把要用的字节写进
//   去，结束时一并清零，不污染后面的用例。反汇编用一个只认 90（nop）的假解码器。
// ============================================================
#include "wpJ6_common.h"

#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/MemoryRowCanvas.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexCanvas.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchCompareView.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchDisasmView.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchHexPane.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchTextView.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchPseudocodeView.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchNavigation.h"
#include "../../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchTarget.h"
#include "../wpI/memwb_wpI_common.h"

#include <QKeySequence>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QPlainTextEdit>
#include <QScrollBar>
#include <QShortcut>
#include <QTableView>

#include <algorithm>
#include <cstring>
#include <mutex>
#include <optional>
#include <vector>

namespace wpj6_test
{
    void RunPseudocodeNavigationTests();
    namespace
    {
        // 三个子页在 subTabStack_ 里的下标。
        constexpr int kDisasmTab = 1;
        constexpr int kTextTab = 2;
        constexpr int kCompareTab = 3;

        // PlantedBytes：往假后备内存里写字节，并在析构时清零这些位置，不污染后面的用例。
        class PlantedBytes
        {
        public:
            // 传入：地址（相对后备内存 base=0）、要写的字节。
            void Plant(const std::uint64_t address, const std::vector<std::uint8_t>& bytes)
            {
                auto& backend = ConfigureSharedOnce();
                std::lock_guard<std::mutex> lock(backend.backing->mutex);
                for (std::size_t i = 0; i < bytes.size(); ++i)
                {
                    backend.backing->bytes[static_cast<std::size_t>(address) + i] = bytes[i];
                }
                planted_.emplace_back(address, bytes.size());
            }

            ~PlantedBytes()
            {
                auto& backend = ConfigureSharedOnce();
                std::lock_guard<std::mutex> lock(backend.backing->mutex);
                for (const auto& [address, length] : planted_)
                {
                    std::fill_n(backend.backing->bytes.begin() + static_cast<std::ptrdiff_t>(address), length, std::uint8_t{0});
                }
            }

        private:
            std::vector<std::pair<std::uint64_t, std::size_t>> planted_;   // 已写过的 (地址, 长度)。
        };

        // InstallNopDecoder：给视图装一个只认 0x90 的假解码器（其余字节解不出来 = db 占位行）。
        void InstallNopDecoder(ks::ui::MemoryWorkbenchView& view)
        {
            view.setDisasmBackends(
                [](const std::uint8_t* bytes, const std::size_t available, const std::uint64_t address, const bool) {
                    std::optional<ks::ui::DecodedRow> row;
                    if (available >= 1U && bytes[0] == 0x90U)
                    {
                        ks::ui::DecodedRow decoded;
                        decoded.address = address;
                        decoded.bytes = QByteArray(1, static_cast<char>(0x90));
                        decoded.mnemonic = QStringLiteral("nop");
                        decoded.decoded = true;
                        row = decoded;
                    }
                    return row;
                },
                ks::ui::AssembleOneFn());
        }

        // 取三个子页的指针（按 subTabStack_ 的固定下标）。
        ks::ui::WorkbenchDisasmView* DisasmOf(ks::ui::MemoryWorkbenchView& view)
        {
            return qobject_cast<ks::ui::WorkbenchDisasmView*>(view.subTabStackForTest()->widget(kDisasmTab));
        }
        ks::ui::WorkbenchTextView* TextOf(ks::ui::MemoryWorkbenchView& view)
        {
            return qobject_cast<ks::ui::WorkbenchTextView*>(view.subTabStackForTest()->widget(kTextTab));
        }
        ks::ui::WorkbenchCompareView* CompareOf(ks::ui::MemoryWorkbenchView& view)
        {
            return qobject_cast<ks::ui::WorkbenchCompareView*>(view.subTabStackForTest()->widget(kCompareTab));
        }

        // OpenAt：十六进制跳到 address 并选中 length 字节，然后等基线窗口覆盖它（子页才读得到）。
        // focusView=false：不自动切回十六进制页，调用方自己决定当前页签。
        void OpenAt(ks::ui::MemoryWorkbenchView& view, const std::uint64_t address, const std::uint64_t length = 1)
        {
            ks::ui::NavRequest nav;
            nav.address = address;
            nav.selectLength = length;
            nav.focusView = false;
            (void)view.openAt(nav);
            (void)WaitForStageable(view.hexPaneForTest(), address);
            PumpFor(80);
        }

        // StatusOf：取某个子页状态行的文字。
        QString StatusOf(QWidget* page, const char* objectName)
        {
            auto* label = page->findChild<QLabel*>(QString::fromLatin1(objectName));
            return label != nullptr ? label->text() : QString();
        }

        // UpperHex16：与子页状态行一致的"0x + 16 位大写十六进制"。
        QString UpperHex16(const std::uint64_t value)
        {
            // 只把数字部分转大写，前缀 "0x" 保持小写（整串 toUpper 会得到 "0X"，与状态行不一致）。
            return QStringLiteral("0x") + QString::number(value, 16).rightJustified(16, QLatin1Char('0')).toUpper();
        }

        // 切到某个子页并等界面稳定。
        void GoTab(ks::ui::MemoryWorkbenchView& view, const int tab)
        {
            view.subTabStackForTest()->setCurrentIndex(tab);
            PumpFor(120);
        }

        // ---------------- T1~T3：切页签时三页都跟到选区起点 ----------------
        void TestFollowOnTabSwitch()
        {
            PlantedBytes planted;
            planted.Plant(0x2000, {0x90, 0x90, 0x90, 0x90});
            planted.Plant(0x2010, {'K', 'S', 'w', 'o', 'r', 'd', 'F', 'o', 'l', 'l', 'o', 'w'});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x2000, 4);

            // 反汇编：锚点就是选区起点，第 0 行是该地址，状态行不再是"尚未定位"。
            GoTab(*view, kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm != nullptr)
            {
                WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x2000ULL,
                    QStringLiteral("切到反汇编页应跟到选区起点 0x2000，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));
                const auto row = disasm->model()->rowAt(0);
                WPJ6_CHECK_NOTE(row.has_value() && row->address == 0x2000ULL,
                    QStringLiteral("反汇编第 0 行应是 0x2000"));
                WPJ6_CHECK_NOTE(!StatusOf(disasm, "ksMemwbDisasmStatus").contains(QStringLiteral("尚未定位")),
                    QStringLiteral("反汇编状态行不应还是'尚未定位'：%1").arg(StatusOf(disasm, "ksMemwbDisasmStatus")));
            }

            // 文本：窗口起点是 0x2000 所在行（行宽 16 对齐，恰为 0x2000），内容里能看到 0x2010 行的字符串。
            OpenAt(*view, 0x2010, 1);
            GoTab(*view, kTextTab);
            auto* text = TextOf(*view);
            WPJ6_CHECK(text != nullptr);
            if (text != nullptr)
            {
                const QString status = StatusOf(text, "ksMemwbTextStatus");
                WPJ6_CHECK_NOTE(status.contains(UpperHex16(0x2010)),
                    QStringLiteral("文本页状态行应含 0x2010 起的窗口，实际：%1").arg(status));
                WPJ6_CHECK_NOTE(!status.contains(QStringLiteral("超出已读取窗口")) && !status.contains(QStringLiteral("尚未定位")),
                    QStringLiteral("文本页不应显示占位/超出文案：%1").arg(status));
                WPJ6_CHECK_NOTE(text->renderedText().startsWith(QStringLiteral("KSwordFollow")),
                    QStringLiteral("文本页第一行应是 0x2010 处的字符串，实际 '%1'").arg(text->renderedText().left(24)));
            }

            // 对比：先切到"暂存后应用"模式（立即写入模式下 stageBytes 会直接写入，不留待写入修改），
            // 暂存一个补丁后切到对比页，表格里有命中行，并且选中/滚到了目标所在分组。
            GoTab(*view, 0);
            (void)view->writeControllerForTest()->requestModeSwitch(ksword::memwb::WriteMode::StagedThenApply);
            OpenAt(*view, 0x2004, 1);
            view->hexPaneForTest()->canvas()->stageBytes(0x2004, QByteArray(1, static_cast<char>(0x91)), nullptr);
            PumpFor(100);
            GoTab(*view, kCompareTab);
            auto* compare = CompareOf(*view);
            WPJ6_CHECK(compare != nullptr);
            if (compare != nullptr)
            {
                WPJ6_CHECK_NOTE(compare->model()->rowCount() >= 1,
                    QStringLiteral("对比页应有命中行，实际 %1").arg(compare->model()->rowCount()));
                WPJ6_CHECK_NOTE(compare->table()->currentIndex().isValid(),
                    QStringLiteral("对比页应选中目标所在分组"));
            }

            // 第二个补丁落在另一个 16 字节分组：目标恰好是某分组的起点（0x2020）时必须选中该分组本身，
            // 而不是它的下一个——只有一个分组的用例分不出"第一个 >= 目标"与"第一个 > 目标"。
            // 用三个分组（0x2000 / 0x2020 / 0x2040）：只有两个分组时，"第一个 > 目标"没有命中会落到"最后一行"，
            // 恰好也是第 1 行，分不出 >= 与 > 两种判据。
            GoTab(*view, 0);
            view->hexPaneForTest()->canvas()->stageBytes(0x2024, QByteArray(1, static_cast<char>(0x92)), nullptr);
            view->hexPaneForTest()->canvas()->stageBytes(0x2044, QByteArray(1, static_cast<char>(0x93)), nullptr);
            PumpFor(100);
            OpenAt(*view, 0x2020, 1);
            GoTab(*view, kCompareTab);
            if (compare != nullptr)
            {
                WPJ6_CHECK_NOTE(compare->model()->rowCount() == 3,
                    QStringLiteral("三个补丁在三个分组里，应有 3 行，实际 %1").arg(compare->model()->rowCount()));
                WPJ6_CHECK_NOTE(compare->table()->currentIndex().row() == 1,
                    QStringLiteral("目标 0x2020 恰是第二个分组的起点，应选中第 1 行（不是第 2 行），实际 %1")
                        .arg(compare->table()->currentIndex().row()));
            }
            view->hide();
        }

        // ---------------- 外部变化到达后子页自动刷新（订阅画布 contentChanged） ----------------
        // 窗口在切页时已经覆盖目标，所以"数据晚到"路径测不到订阅有没有接上；这里改假内存再重读，
        // 只有 contentChanged -> onSubPageDataChanged -> 刷新 这条链接着，反汇编才会跟着变。
        void TestRefreshOnExternalChange()
        {
            PlantedBytes planted;
            planted.Plant(0x8000, {0x90, 0x90});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x8000, 1);
            GoTab(*view, kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm == nullptr)
            {
                return;
            }
            const bool decoded = PumpUntil([disasm]() {
                const auto first = disasm->model()->rowAt(0);
                return first.has_value() && first->address == 0x8000ULL && first->decoded;
            }, 3000);
            WPJ6_CHECK_NOTE(decoded, QStringLiteral("前置：0x8000 处应先解码出 nop"));

            // 外部把 0x8000 改成 0x00（假解码器只认 0x90，于是变成 db 占位行），重读窗口。
            int contentChangedCount = 0;
            const QMetaObject::Connection counter = QObject::connect(
                view->hexPaneForTest()->canvas(), &ks::ui::HexCanvas::contentChanged, [&contentChangedCount]() { ++contentChangedCount; });
            {
                auto& backend = ConfigureSharedOnce();
                std::lock_guard<std::mutex> lock(backend.backing->mutex);
                backend.backing->bytes[0x8000] = 0x00;
            }
            // 用 requestReload（来源代次 +1 并原位重读）而不是裸 rereadWindow：基线喂入器只在来源代次变了
            // 才会原位重喂叠加层基线（RefreshSameSpan），裸 rereadWindow 只刷新画布页缓存，三个子页读的叠加层不会变。
            view->target().requestReload();
            const bool changed = PumpUntil([disasm]() {
                const auto first = disasm->model()->rowAt(0);
                return first.has_value() && first->address == 0x8000ULL && !first->decoded;
            }, 3000);
            QObject::disconnect(counter);
            const auto rowNow = disasm->model()->rowAt(0);
            WPJ6_CHECK_NOTE(changed,
                QStringLiteral("外部改了字节并重读后，反汇编应自动刷新成 db 行（没有订阅 contentChanged 就会停在旧内容）"
                               "[诊断：重读后 contentChanged %1 次；第 0 行 addr=0x%2 bytes=%3 mnemonic=%4 decoded=%5；当前页签 %6；基线 [0x%7,+%8)；"
                               "叠加层 0x8000 基线字节=%9 上次读取字节=%10 变化种类=%11]")
                    .arg(contentChangedCount)
                    .arg(rowNow.has_value() ? rowNow->address : 0ULL, 0, 16)
                    .arg(rowNow.has_value() ? QString::fromLatin1(rowNow->bytes.toHex()) : QString())
                    .arg(rowNow.has_value() ? rowNow->mnemonic : QString())
                    .arg(rowNow.has_value() && rowNow->decoded ? 1 : 0)
                    .arg(view->subTabStackForTest()->currentIndex())
                    .arg(view->hexPaneForTest()->overlay().BaseAddress(), 0, 16)
                    .arg(view->hexPaneForTest()->overlay().BaselineSize())
                    .arg(view->hexPaneForTest()->overlay().BaselineByte(0x8000).has_value()
                            ? QString::number(*view->hexPaneForTest()->overlay().BaselineByte(0x8000)) : QStringLiteral("无"))
                    .arg(view->hexPaneForTest()->overlay().PreviousByte(0x8000).has_value()
                            ? QString::number(*view->hexPaneForTest()->overlay().PreviousByte(0x8000)) : QStringLiteral("无"))
                    .arg(static_cast<int>(view->hexPaneForTest()->overlay().ChangeKind(0x8000))));
            view->hide();
        }

        // ---------------- 文本页：内容没变的刷新不重写编辑器（保留滚动位置） ----------------
        // CodeEditorWidget::setRawText 会把滚动位置重置回顶部；数据到达/实时刷新反复触发重建时，
        // 文本没变就不该打断用户的阅读位置（WorkbenchTextView::applyEditorText 的等值守卫）。
        void TestTextRefreshKeepsScrollPosition()
        {
            PlantedBytes planted;
            planted.Plant(0x9000, std::vector<std::uint8_t>(4000, static_cast<std::uint8_t>('x')));

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            view->resize(1000, 600);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x9000, 1);
            GoTab(*view, kTextTab);
            auto* text = TextOf(*view);
            WPJ6_CHECK(text != nullptr);
            if (text == nullptr)
            {
                return;
            }
            const bool loaded = PumpUntil([text]() { return text->renderedText().count(QLatin1Char('\n')) > 50; }, 3000);
            WPJ6_CHECK_NOTE(loaded, QStringLiteral("前置：文本页应载入 50 行以上"));
            auto* const canvas = text->canvas();
            WPJ6_CHECK_NOTE(canvas != nullptr, QStringLiteral("前置：应能找到共享文本行画布"));
            if (canvas == nullptr)
            {
                return;
            }
            QScrollBar* const bar = canvas->verticalScrollBar();
            WPJ6_CHECK_NOTE(bar->maximum() > 10, QStringLiteral("前置：编辑器应可滚动，maximum=%1").arg(bar->maximum()));
            bar->setValue(10);
            PumpFor(50);
            WPJ6_CHECK(bar->value() == 10);
            text->refreshView();
            PumpFor(100);
            WPJ6_CHECK_NOTE(bar->value() == 10,
                QStringLiteral("内容没变的刷新不应重置滚动位置，实际 %1").arg(bar->value()));
            view->hide();
        }

        // ---------------- 换目标（身份变化）清空子页 ----------------
        // 文本页/对比页换目标后必须回到"尚未定位"，不能继续显示上一个目标的窗口。
        void TestIdentityChangeResetsPages()
        {
            PlantedBytes planted;
            planted.Plant(0x2010, {'O', 'L', 'D', 'T', 'A', 'R', 'G', 'E', 'T'});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x2010, 1);
            GoTab(*view, kTextTab);
            auto* text = TextOf(*view);
            WPJ6_CHECK(text != nullptr);
            if (text == nullptr)
            {
                return;
            }
            WPJ6_CHECK_NOTE(text->renderedText().startsWith(QStringLiteral("OLDTARGET")),
                QStringLiteral("前置：文本页应显示旧目标的内容"));

            // 回到十六进制页再换一个进程（不同 pid、不同代次）：此刻当前页不是子页，不会立刻重新跟随，
            // 所以文本页必须已经被清成占位，而不是残留旧窗口。
            GoTab(*view, 0);
            harness.AttachProcess(4343, 2);
            PumpFor(250);
            auto* textAfter = TextOf(*view);
            WPJ6_CHECK(textAfter != nullptr);
            if (textAfter != nullptr)
            {
                WPJ6_CHECK_NOTE(StatusOf(textAfter, "ksMemwbTextStatus").contains(QStringLiteral("尚未定位")),
                    QStringLiteral("换目标后文本页应回到'尚未定位'，实际：%1").arg(StatusOf(textAfter, "ksMemwbTextStatus")));
                WPJ6_CHECK_NOTE(textAfter->renderedText().isEmpty(),
                    QStringLiteral("换目标后文本页不应残留旧内容：'%1'").arg(textAfter->renderedText().left(24)));
            }
            view->hide();
        }

        // ---------------- T4：选区起点而不是 caret ----------------
        void TestSelectionStartNotCaret()
        {
            PlantedBytes planted;
            planted.Plant(0x3000, {0x90, 0x90});
            planted.Plant(0x3010, {0x90, 0x90});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x3000, 1);
            // 向前拖选：锚点 0x3010 固定、插入点（caret）留在 0x3020，选区起点是 0x3010？不——
            // 这里用两步让 selection.first=0x3010、caret=0x3020：先落 0x3010，再扩选到 0x3020。
            auto* canvas = view->hexPaneForTest()->canvas();
            canvas->setCaretAddress(0x3010, false, false);
            canvas->setCaretAddress(0x3020, true, false);
            PumpFor(60);
            WPJ6_CHECK(canvas->caretAddress() == 0x3020ULL);
            WPJ6_CHECK(canvas->selectedRange().has_value() && canvas->selectedRange()->first == 0x3010ULL);

            GoTab(*view, kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm != nullptr)
            {
                WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x3010ULL,
                    QStringLiteral("应跟到选区起点 0x3010 而不是 caret 0x3020，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));
            }
            view->hide();
        }

        // ---------------- T5：手动导航保留与覆盖（同步令牌） ----------------
        void TestManualNavigationKeptUntilHexMoves()
        {
            PlantedBytes planted;
            planted.Plant(0x2000, {0x90, 0x90});
            planted.Plant(0x4000, {0x90, 0x90});
            planted.Plant(0x5000, {0x90, 0x90});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x2000, 1);
            GoTab(*view, kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm == nullptr)
            {
                return;
            }
            WPJ6_CHECK(disasm->anchorAddress() == 0x2000ULL);

            // 用户在反汇编里手动导航（例如追一个 call 目标）到 0x4000；十六进制没动。
            // 先保证基线窗口覆盖 0x4000：用十六进制画布滚过去不改选区。
            view->hexPaneForTest()->canvas()->scrollToAddress(0x4000);
            (void)WaitForStageable(view->hexPaneForTest(), 0x4000);
            PumpFor(100);
            WPJ6_CHECK(disasm->jumpTo(0x4000ULL));
            PumpFor(60);

            // 切走再切回：十六进制选区没动 -> 保留用户在反汇编里的位置 0x4000。
            GoTab(*view, 0);
            GoTab(*view, kDisasmTab);
            WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x4000ULL,
                QStringLiteral("十六进制没动过，切回来不应覆盖用户的手动位置，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));

            // 十六进制动过（选区起点变了）：切回来必须跟到新位置。
            GoTab(*view, 0);
            OpenAt(*view, 0x5000, 1);
            GoTab(*view, kDisasmTab);
            WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x5000ULL,
                QStringLiteral("十六进制动过之后切回来应跟到 0x5000，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));
            view->hide();
        }

        // ---------------- T6/T12：子页可见时跟随十六进制；后退不重复压栈 ----------------
        void TestFollowWhileVisibleAndNoDuplicateBackStack()
        {
            PlantedBytes planted;
            planted.Plant(0x2000, {0x90, 0x90});
            planted.Plant(0x3000, {0x90, 0x90});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x2000, 1);
            OpenAt(*view, 0x3000, 1);
            GoTab(*view, kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm == nullptr)
            {
                return;
            }
            WPJ6_CHECK(disasm->anchorAddress() == 0x3000ULL);

            // 子页可见时点"后退"：十六进制回到 0x2000，当前页签仍是反汇编，并且跟到 0x2000。
            view->backButtonForTest()->click();
            PumpFor(150);
            WPJ6_CHECK_NOTE(view->subTabStackForTest()->currentIndex() == kDisasmTab,
                QStringLiteral("后退不应切换页签"));
            WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x2000ULL,
                QStringLiteral("子页可见时十六进制后退应带动反汇编跟到 0x2000，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));

            // 重复跟随同一地址不应反复压后退栈：先记下栈深度，再触发几次不改变选区的"数据到达"。
            const int hexBackDepth = static_cast<int>(view->backStackForTest().size());
            view->hexPaneForTest()->rereadWindow();
            PumpFor(200);
            WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x2000ULL, QStringLiteral("数据到达后锚点不应变"));
            WPJ6_CHECK(static_cast<int>(view->backStackForTest().size()) == hexBackDepth);
            view->hide();
        }

        // ---------------- T7/T8：没有选区时落到起始模块 ----------------
        // 一组模块：a.dll@0x1000、main.exe@0x4000、b.dll@0x9000（基址升序）。
        ks::ui::ModuleEnumResult ModulesResult(const bool withExe)
        {
            ks::ui::ModuleEnumResult result;
            result.ok = true;
            ksword::memwb::ModuleRecord a;
            a.name = "a.dll";
            a.fullPath = "C:\\x\\a.dll";
            a.base = 0x1000;
            a.size = 0x1000;
            result.records.push_back(a);
            if (withExe)
            {
                ksword::memwb::ModuleRecord exe;
                exe.name = "main.exe";
                exe.fullPath = "C:\\x\\main.exe";
                exe.base = 0x4000;
                exe.size = 0x2000;
                result.records.push_back(exe);
            }
            ksword::memwb::ModuleRecord b;
            b.name = "b.dll";
            b.fullPath = "C:\\x\\b.dll";
            b.base = 0x9000;
            b.size = 0x1000;
            result.records.push_back(b);
            return result;
        }

        void TestModuleFallback()
        {
            PlantedBytes planted;
            planted.Plant(0x1000, {0x90, 0x90});
            planted.Plant(0x4000, {0x90, 0x90});

            // ---- 有 .exe：取 .exe 的基址 0x4000（不是最低基址 0x1000）；目录异步到达前先挂起 ----
            {
                Harness harness;
                auto* services = LastFakeServices();
                WPJ6_CHECK(services != nullptr);
                if (services == nullptr)
                {
                    return;
                }
                services->SetProcessModulesResult(4242, ModulesResult(true));
                // 延迟要远大于下面"附加 + 切页签"之间会泵掉的时间（约 200ms），否则目录在检查"挂起"之前就到了（时序抖动）。
                services->SetProcessEnumDelayMs(4242, 900);
                auto* view = harness.view.get();
                InstallNopDecoder(*view);
                view->resize(1000, 700);
                view->show();
                PumpFor(60);
                harness.AttachProcess();
                // 附加后十六进制不动（插入点停在地址空间起点 0），模块目录还在加载中。
                GoTab(*view, kDisasmTab);
                auto* disasm = DisasmOf(*view);
                WPJ6_CHECK(disasm != nullptr);
                if (disasm != nullptr)
                {
                    // 挂起：目录还没到，页面保持占位。
                    WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0ULL,
                        QStringLiteral("模块目录加载中应先挂起，不应抢先落到 0 或别的地址，实际 0x%1")
                            .arg(disasm->anchorAddress(), 0, 16));
                    // 目录到齐后自动落到 main.exe 基址，十六进制也落过去。
                    const bool landed = PumpUntil([disasm]() { return disasm->anchorAddress() == 0x4000ULL; }, 3000);
                    WPJ6_CHECK_NOTE(landed, QStringLiteral("模块目录就绪后应落到 .exe 基址 0x4000，实际 0x%1")
                        .arg(disasm->anchorAddress(), 0, 16));
                    WPJ6_CHECK_NOTE(view->hexPaneForTest()->insertionAddress() == 0x4000ULL,
                        QStringLiteral("十六进制也应落到 0x4000，实际 0x%1")
                            .arg(view->hexPaneForTest()->insertionAddress(), 0, 16));
                }
                view->hide();
            }

            // ---- 没有 .exe：取最低基址 0x1000 ----
            {
                Harness harness;
                auto* services = LastFakeServices();
                WPJ6_CHECK(services != nullptr);
                if (services == nullptr)
                {
                    return;
                }
                services->SetProcessModulesResult(4242, ModulesResult(false));
                auto* view = harness.view.get();
                InstallNopDecoder(*view);
                view->resize(1000, 700);
                view->show();
                PumpFor(60);
                harness.AttachProcess();
                PumpFor(200);
                GoTab(*view, kDisasmTab);
                auto* disasm = DisasmOf(*view);
                if (disasm != nullptr)
                {
                    const bool landed = PumpUntil([disasm]() { return disasm->anchorAddress() == 0x1000ULL; }, 3000);
                    WPJ6_CHECK_NOTE(landed, QStringLiteral("没有 .exe 时应取最低基址 0x1000，实际 0x%1")
                        .arg(disasm->anchorAddress(), 0, 16));
                }
                view->hide();
            }

            // ---- 进程名命中：提示名 b.dll -> 0x9000 ----
            {
                Harness harness;
                auto* services = LastFakeServices();
                WPJ6_CHECK(services != nullptr);
                if (services == nullptr)
                {
                    return;
                }
                services->SetProcessModulesResult(4242, ModulesResult(true));
                auto* view = harness.view.get();
                InstallNopDecoder(*view);
                view->setAttachedProcessInfoProvider([](const std::uint32_t) -> std::optional<ks::ui::AttachedProcessDisplayInfo> {
                    ks::ui::AttachedProcessDisplayInfo info;
                    info.processName = QStringLiteral("B.DLL");   // 故意大小写不同：按名字命中必须不区分大小写。
                    info.canReadWrite = true;
                    return info;
                });
                view->resize(1000, 700);
                view->show();
                PumpFor(60);
                harness.AttachProcess();
                PumpFor(200);
                GoTab(*view, kDisasmTab);
                auto* disasm = DisasmOf(*view);
                if (disasm != nullptr)
                {
                    const bool landed = PumpUntil([disasm]() { return disasm->anchorAddress() == 0x9000ULL; }, 3000);
                    WPJ6_CHECK_NOTE(landed, QStringLiteral("进程名命中应落到 0x9000，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));
                }
                view->hide();
            }

            // ---- T8：枚举失败 -> 退回当前插入点（0），不空等、不卡在占位文案 ----
            {
                Harness harness;
                auto* services = LastFakeServices();
                WPJ6_CHECK(services != nullptr);
                if (services == nullptr)
                {
                    return;
                }
                ks::ui::ModuleEnumResult failed;
                failed.ok = false;
                failed.failure = "fake enum failure";
                services->SetProcessModulesResult(4242, failed);
                auto* view = harness.view.get();
                InstallNopDecoder(*view);
                view->resize(1000, 700);
                view->show();
                PumpFor(60);
                harness.AttachProcess();
                PumpFor(300);
                GoTab(*view, kDisasmTab);
                PumpFor(200);
                auto* disasm = DisasmOf(*view);
                if (disasm != nullptr)
                {
                    WPJ6_CHECK_NOTE(!StatusOf(disasm, "ksMemwbDisasmStatus").contains(QStringLiteral("尚未定位")),
                        QStringLiteral("枚举失败后应退回当前插入点并定位，不应卡在'尚未定位'：%1")
                            .arg(StatusOf(disasm, "ksMemwbDisasmStatus")));
                }
                view->hide();
            }
        }

        // ---------------- T9：先在子页签、再附加进程（重启后恢复在子页的情形） ----------------
        void TestAttachWhileOnSubPage()
        {
            PlantedBytes planted;
            planted.Plant(0x0000, {'A', 'T', 'T', 'A', 'C', 'H'});

            Harness harness;
            auto* view = harness.view.get();
            view->resize(1000, 700);
            view->show();
            PumpFor(60);
            // 还没附加：切到文本页（相当于 loadSettings 恢复了上次的子页），页面是占位。
            GoTab(*view, kTextTab);
            auto* text = TextOf(*view);
            WPJ6_CHECK(text != nullptr);
            if (text == nullptr)
            {
                return;
            }
            WPJ6_CHECK(StatusOf(text, "ksMemwbTextStatus").contains(QStringLiteral("尚未定位")));
            // 附加进程：没有 currentChanged 事件，必须靠身份变化后的补跟随。
            harness.AttachProcess();
            const bool shown = PumpUntil([text]() {
                return !StatusOf(text, "ksMemwbTextStatus").contains(QStringLiteral("尚未定位"));
            }, 3000);
            WPJ6_CHECK_NOTE(shown, QStringLiteral("子页上附加进程后文本页应自动定位，状态行：%1").arg(StatusOf(text, "ksMemwbTextStatus")));
            view->hide();
        }

        // ---------------- T10：数据晚到的刷新 ----------------
        void TestLateDataRefresh()
        {
            PlantedBytes planted;
            planted.Plant(0x6000, {0x90, 0x90, 0x90});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            // 不等 WaitForStageable：跳转后立刻切到反汇编页，基线窗口此刻多半还没覆盖 0x6000。
            ks::ui::NavRequest nav;
            nav.address = 0x6000;
            nav.focusView = false;
            (void)view->openAt(nav);
            view->subTabStackForTest()->setCurrentIndex(kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm == nullptr)
            {
                return;
            }
            // 等第 0 行变成"真正解码出来的 0x6000 处的 nop"：数据到达前模型里可能先有占位行/窗口尾行，
            // 只看 rowCount>0 会过早通过。
            const bool rows = PumpUntil([disasm]() {
                const auto first = disasm->model()->rowAt(0);
                return first.has_value() && first->address == 0x6000ULL && first->decoded;
            }, 3000);
            WPJ6_CHECK_NOTE(rows, QStringLiteral("数据到达后反汇编第 0 行应是 0x6000 处解码出的指令（订阅 contentChanged 的刷新）"));
            view->hide();
        }

        // ---------------- T10b：数据刷新时保持用户在子页里的滚动位置 ----------------
        // 自动跟随引入了"数据到达就刷新"：反汇编/对比页的 model reset 会让表格回到顶部，
        // 用户在列表里往下看到一半就会被拽回去（实时刷新开着时每秒一次）。
        void TestRefreshKeepsScrollPosition()
        {
            PlantedBytes planted;
            // 0x7000 起 600 个 nop：解码出足够多的行，表格才有可滚动的范围。
            planted.Plant(0x7000, std::vector<std::uint8_t>(600, 0x90));

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 600);
            view->show();
            PumpFor(100);

            OpenAt(*view, 0x7000, 1);
            GoTab(*view, kDisasmTab);
            auto* disasm = DisasmOf(*view);
            WPJ6_CHECK(disasm != nullptr);
            if (disasm == nullptr)
            {
                return;
            }
            const bool rows = PumpUntil([disasm]() { return disasm->model()->rowCount() > 100; }, 3000);
            WPJ6_CHECK_NOTE(rows, QStringLiteral("前置：反汇编应解码出一百多行"));
            QScrollBar* const bar = disasm->canvas()->verticalScrollBar();
            WPJ6_CHECK_NOTE(bar->maximum() > 20, QStringLiteral("前置：表格应可滚动，maximum=%1").arg(bar->maximum()));
            bar->setValue(20);
            PumpFor(50);
            WPJ6_CHECK(bar->value() == 20);
            // 同锚点刷新（手动 refreshView 与"数据到达"走的是同一条路径）：滚动位置不得被拽回顶部。
            disasm->refreshView();
            PumpFor(100);
            WPJ6_CHECK_NOTE(bar->value() == 20,
                QStringLiteral("同锚点刷新后滚动位置应保持 20，实际 %1").arg(bar->value()));
            // 换锚点（真正的跳转）时则回到新位置的顶部，不继承旧滚动值。
            WPJ6_CHECK(disasm->jumpTo(0x7100ULL));
            PumpFor(100);
            WPJ6_CHECK_NOTE(bar->value() == 0, QStringLiteral("换锚点后应从顶部开始，实际 %1").arg(bar->value()));
            view->hide();
        }

        // ---------------- T11：显式入口 ----------------
        // FindShortcutByKey：按键序列找视图上的 QShortcut。
        QShortcut* FindShortcutByKey(ks::ui::MemoryWorkbenchView& view, const QKeySequence& key)
        {
            for (QShortcut* shortcut : view.findChildren<QShortcut*>())
            {
                if (shortcut->key() == key)
                {
                    return shortcut;
                }
            }
            return nullptr;
        }

        void TestExplicitEntries()
        {
            PlantedBytes planted;
            planted.Plant(0x2000, {0x90, 0x90, 0x90, 0x90});
            planted.Plant(0x2008, {0x90, 0x90});

            Harness harness;
            harness.AttachProcess();
            auto* view = harness.view.get();
            InstallNopDecoder(*view);
            view->resize(1000, 700);
            view->show();
            PumpFor(100);

            // ---- 右键"从此处反汇编"：必须真的切到反汇编页并锚到被点的地址（这条原来是个 bug：只在十六进制里重定位）----
            OpenAt(*view, 0x2000, 4);
            const auto selectionBefore = view->hexPaneForTest()->canvas()->selectedRange();
            WPJ6_CHECK(selectionBefore.has_value());
            auto* canvas = view->hexPaneForTest()->canvas();
            QMenu* menu = canvas->buildContextMenu(0x2008, true);
            WPJ6_CHECK(menu != nullptr);
            if (menu != nullptr)
            {
                QAction* openDisasm = nullptr;
                for (QAction* action : menu->actions())
                {
                    if (action->text().contains(QStringLiteral("从此处反汇编")))
                    {
                        openDisasm = action;
                    }
                }
                WPJ6_CHECK_NOTE(openDisasm != nullptr, QStringLiteral("右键菜单应有'从此处反汇编'"));
                if (openDisasm != nullptr)
                {
                    openDisasm->trigger();
                    PumpFor(120);
                    WPJ6_CHECK_NOTE(view->subTabStackForTest()->currentIndex() == kDisasmTab,
                        QStringLiteral("右键'从此处反汇编'应切到反汇编页，当前页签 %1").arg(view->subTabStackForTest()->currentIndex()));
                    auto* disasm = DisasmOf(*view);
                    if (disasm != nullptr)
                    {
                        WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x2008ULL,
                            QStringLiteral("应锚到被点击的地址 0x2008，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));
                    }
                    // 十六进制选区保持不变（旧路径会把选区折叠成 1 字节）。
                    WPJ6_CHECK_NOTE(canvas->selectedRange() == selectionBefore,
                        QStringLiteral("右键反汇编不应折叠十六进制选区"));
                }
                delete menu;
            }

            // ---- Ctrl+D：切到反汇编页、锚到选区起点、选区不折叠、只压一次后退栈 ----
            GoTab(*view, 0);
            OpenAt(*view, 0x2000, 4);
            const auto selection = canvas->selectedRange();
            if (QShortcut* ctrlD = FindShortcutByKey(*view, QKeySequence(Qt::CTRL | Qt::Key_D)))
            {
                emit ctrlD->activated();
                PumpFor(120);
                WPJ6_CHECK(view->subTabStackForTest()->currentIndex() == kDisasmTab);
                auto* disasm = DisasmOf(*view);
                if (disasm != nullptr)
                {
                    WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x2000ULL,
                        QStringLiteral("Ctrl+D 应锚到选区起点 0x2000，实际 0x%1").arg(disasm->anchorAddress(), 0, 16));
                }
                WPJ6_CHECK_NOTE(canvas->selectedRange() == selection, QStringLiteral("Ctrl+D 不应折叠十六进制选区"));
            }
            else
            {
                WPJ6_CHECK_NOTE(false, QStringLiteral("没找到 Ctrl+D 快捷键"));
            }

            // Ctrl+D 锚到"选区起点"而不是插入点：向前选 0x2000..0x2008，插入点在 0x2008，期望仍锚到 0x2000。
            GoTab(*view, 0);
            canvas->setCaretAddress(0x2000, false, false);
            canvas->setCaretAddress(0x2008, true, false);
            PumpFor(60);
            WPJ6_CHECK(canvas->caretAddress() == 0x2008ULL);
            WPJ6_CHECK(canvas->selectedRange().has_value() && canvas->selectedRange()->first == 0x2000ULL);
            if (QShortcut* ctrlD = FindShortcutByKey(*view, QKeySequence(Qt::CTRL | Qt::Key_D)))
            {
                emit ctrlD->activated();
                PumpFor(120);
                if (auto* disasm = DisasmOf(*view))
                {
                    WPJ6_CHECK_NOTE(disasm->anchorAddress() == 0x2000ULL,
                        QStringLiteral("向前选区下 Ctrl+D 应锚到选区起点 0x2000（而不是插入点 0x2008），实际 0x%1")
                            .arg(disasm->anchorAddress(), 0, 16));
                }
            }
            view->hide();
        }

        // ---------------- T13/T14：边界 ----------------
        void TestBoundaries()
        {
            // 未附加：切三个子页不崩，页面保持占位。
            {
                Harness harness;
                auto* view = harness.view.get();
                InstallNopDecoder(*view);
                view->resize(1000, 700);
                view->show();
                PumpFor(60);
                for (const int tab : {kDisasmTab, kTextTab, kCompareTab, 0})
                {
                    GoTab(*view, tab);
                }
                auto* disasm = DisasmOf(*view);
                WPJ6_CHECK(disasm != nullptr);
                if (disasm != nullptr)
                {
                    WPJ6_CHECK(disasm->anchorAddress() == 0ULL);
                    WPJ6_CHECK(StatusOf(disasm, "ksMemwbDisasmStatus").contains(QStringLiteral("尚未定位")));
                }
                view->hide();
            }
        }


    }

    void RunSubPageTests()
    {
        TestFollowOnTabSwitch();
        TestSelectionStartNotCaret();
        TestManualNavigationKeptUntilHexMoves();
        TestFollowWhileVisibleAndNoDuplicateBackStack();
        TestModuleFallback();
        TestAttachWhileOnSubPage();
        TestLateDataRefresh();
        TestRefreshKeepsScrollPosition();
        TestRefreshOnExternalChange();
        TestTextRefreshKeepsScrollPosition();
        TestIdentityChangeResetsPages();
        TestExplicitEntries();
        TestBoundaries();
        RunPseudocodeNavigationTests();
    }
}
