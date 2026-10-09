// wpH_tests.CompareRegression2.cpp
// 作用：第二轮独立审核（review2-wpH.md）针对 WorkbenchCompareView 的补测。
// 并入自审核者补测 extra2.cpp 的 T07/T08/T17/T25/T26，改写成本仓库的 WPH_CHECK 断言风格。
// - T07（杀 rC10）：外部变化分段不得把"上一次读取本来就没读到"的暂存字节误判成外部变化
//   ——previous/baseline 任一边不可用时，isExternalChangeByte 的 Pending 回补分支必须放弃。
// - T08（杀 rC11/rC12/rC22）：待写入分段的悬停明细必须恰好列出命中（已暂存）的字节，不得
//   把未暂存的字节也列进去；状态行"N 字节变化；共 M 行"的两个数字不能互换。
// - T17（杀 rC23）：整捕获范围必须分块覆盖 2 MiB 上限（Text 页已有 hM16 同款用例，对比页
//   之前没有）。
// - T25（N5 修复）：窗口贴着地址空间顶端（0xFFFFFFFFFFFFFFF0 起 15 字节）不得整数回绕死循环
//   ——带 8 秒看门狗线程，卡死就主动打印 FAIL 并退出，不让 CI 无限挂住。
// - T26（N6 修复）：en-US 下悬停明细里的"（另有待写入）"必须经运行期翻译，不能是硬编码中文。
// - M7（本轮自补新变异）：isExternalChangeByte 的 Pending 回补分支不能只检查 previous/
//   baseline 两边"是否有效"，还要真的比较它们的值——previous==baseline（两次读取其实没变，
//   只是恰好也被暂存覆盖了）不该被误判成"外部变化"，这是与 T07（检查有效性）互补的另一半。

#include "wpH_common.h"

#include "../../../Ksword5.1/Ksword5.1/Internationalization/LanguageManager.h"

#include <QLabel>
#include <QString>
#include <QtTest/QtTest>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <thread>

using ks::ui::WorkbenchCompareView;

namespace wpH_test
{
    namespace
    {
        std::vector<std::uint8_t> toVecCmp2(const QByteArray& bytes)
        {
            return std::vector<std::uint8_t>(
                reinterpret_cast<const std::uint8_t*>(bytes.constData()),
                reinterpret_cast<const std::uint8_t*>(bytes.constData()) + bytes.size());
        }

        bool hasHanCmp2(const QString& s)
        {
            for (const QChar ch : s)
            {
                if (ch.unicode() >= 0x3400 && ch.unicode() <= 0x9FFF)
                {
                    return true;
                }
            }
            return false;
        }

        // ---------------- T07（杀 rC10）：上一次读取没读到的字节不算外部变化 ----------------
        void runExternalWithInvalidPreviousTests()
        {
            FakeBytesProvider provider(64);
            const std::uint64_t base = 0x7000ULL;
            std::vector<std::uint8_t> bytes(32, 0x11);
            std::vector<std::uint8_t> mask(32, 1);
            mask[4] = 0; // 第一次读取时第 4 字节没读到（previous 无效）
            provider.overlay().LoadBaseline(QStringLiteral("t07").toStdString(), base, bytes, mask);
            provider.overlay().RefreshBaseline(QStringLiteral("t07").toStdString(), base, std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 1)); // 第二次读到了
            provider.overlay().Stage(base + 4, {0x99}); // 该字节只有暂存补丁，previous 仍然无效

            WorkbenchCompareView view;
            view.setBytesProvider(&provider);
            view.setMode(WorkbenchCompareView::Mode::ExternalChange);
            view.setWindow(base, 32);
            WPH_CHECK_NOTE(view.model()->rowCount() == 0,
                QStringLiteral("previous 无效时不能判定为外部变化，实得行数 %1").arg(view.model()->rowCount()));
        }

        // ---------------- T08（杀 rC11/rC12/rC22）：悬停明细与状态行的精确内容 ----------------
        void runTooltipAndStatusExactContentTests()
        {
            FakeBytesProvider provider(64);
            const std::uint64_t base = 0x8000ULL;
            provider.overlay().LoadBaseline(QStringLiteral("t08").toStdString(), base, std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 1));
            provider.overlay().Stage(base + 4, {0xAA});
            provider.overlay().Stage(base + 5, {0xAB}); // 只暂存了 2 个字节

            WorkbenchCompareView view;
            view.setBytesProvider(&provider);
            view.setMode(WorkbenchCompareView::Mode::Pending);
            view.setWindow(base, 32);
            WPH_CHECK(view.model()->rowCount() == 1);
            if (view.model()->rowCount() != 1)
            {
                return;
            }
            const QString tooltip = view.model()->index(0, 1).data(Qt::ToolTipRole).toString();
            // 悬停明细按"每个命中字节一行"格式化，恰好暂存了 2 个字节就应该恰好 2 行
            // （不多列未暂存的字节，不少列已暂存的字节）。
            WPH_CHECK_NOTE(tooltip.count(QLatin1Char('\n')) == 2,
                QStringLiteral("悬停明细应恰好列出 2 个命中字节，实得：%1").arg(QString(tooltip).replace(QLatin1Char('\n'), QStringLiteral("|"))));
            WPH_CHECK_NOTE(!tooltip.contains(QStringLiteral("另有待写入")),
                QStringLiteral("待写入分段自己的明细不应该标注'另有待写入'（那是两次读取之间分段才有的回补标注）"));
            const QString status = view.findChild<QLabel*>(QStringLiteral("ksMemwbCompareStatus"))->text();
            WPH_CHECK_NOTE(status.contains(QStringLiteral("2 字节变化；共 1 行")),
                QStringLiteral("状态行的'字节变化数'与'行数'不能互换，实得：%1").arg(status));
        }

        // ---------------- T17（杀 rC23）：整捕获范围必须分块覆盖 2 MiB ----------------
        void runCompareWindowCapTests()
        {
            constexpr qsizetype kSize = 2 * 1024 * 1024; // 请求 2 MiB
            FakeBytesProvider provider(64);
            const std::uint64_t base = 0x140000000ULL;
            provider.overlay().LoadBaseline(QStringLiteral("t17").toStdString(), base,
                std::vector<std::uint8_t>(kSize, 0), std::vector<std::uint8_t>(kSize, 1));
            provider.overlay().Stage(base, std::vector<std::uint8_t>(kSize, 0xAA)); // 全部暂存
            WorkbenchCompareView view;
            view.setBytesProvider(&provider);
            view.setMode(WorkbenchCompareView::Mode::Pending);
            view.setWindow(base, kSize);
            WPH_CHECK_NOTE(view.model()->rowCount() == 131072,
                QStringLiteral("2 MiB 请求必须完整比较（131072 个 16 字节分组），实得 %1").arg(view.model()->rowCount()));
        }

        // ---------------- T25（N5 修复）：窗口贴着地址空间顶端不得挂死 ----------------
        void runTopOfAddressSpaceDoesNotHangTests()
        {
            // 看门狗：8 秒内本用例的断言还没跑完，说明分组循环又回绕死循环了，主动打印
            // FAIL 并整进程退出（不让 CI 无限期挂住等不到结果）——与审核者补测 T25 同款做法。
            std::thread([]() {
                std::this_thread::sleep_for(std::chrono::seconds(8));
                std::cerr << "FAIL: setWindow(0xFFFFFFFFFFFFFFF0, 15) 超过 8 秒未返回（分组循环疑似回绕死循环）"
                          << "  (wpH_tests.CompareRegression2.cpp)" << std::endl;
                std::cerr << "[CompareRegression2] checks=1 failures=1" << std::endl;
                std::_Exit(3);
            }).detach();

            FakeBytesProvider provider(64);
            const std::uint64_t top = 0xFFFFFFFFFFFFFFF0ULL;
            provider.overlay().LoadBaseline(QStringLiteral("t25").toStdString(), top, std::vector<std::uint8_t>(15, 0x11), std::vector<std::uint8_t>(15, 1));
            provider.overlay().Stage(top + 2, {0xAA});
            WorkbenchCompareView view;
            view.setBytesProvider(&provider);
            view.setMode(WorkbenchCompareView::Mode::Pending);
            view.setWindow(top, 15); // 必须正常返回，不能卡死
            WPH_CHECK_NOTE(view.model()->rowCount() == 1, QString::number(view.model()->rowCount()));
        }

        // ---------------- T26（N6 修复）：悬停明细的"另有待写入"必须经运行期翻译 ----------------
        void runTooltipHintI18nTests()
        {
            QString err;
            WPH_CHECK_NOTE(ks::i18n::LanguageManager::instance().initialize(QStringLiteral("en-US"), &err), err);
            FakeBytesProvider provider(64);
            const std::uint64_t base = 0x6000ULL;
            provider.overlay().LoadBaseline(QStringLiteral("t26").toStdString(), base, std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 1));
            QByteArray second(32, '\x11');
            second[4] = '\x22'; // 外部把第 4 字节改了
            provider.overlay().RefreshBaseline(QStringLiteral("t26").toStdString(), base, toVecCmp2(second), std::vector<std::uint8_t>(32, 1));
            provider.overlay().Stage(base + 4, {0x99}); // 同一字节又挂了暂存补丁，触发"另有待写入"标注

            WorkbenchCompareView view;
            view.setBytesProvider(&provider);
            view.setMode(WorkbenchCompareView::Mode::ExternalChange);
            view.setWindow(base, 32);
            const QString tooltip = view.model()->index(0, 1).data(Qt::ToolTipRole).toString();
            WPH_CHECK_NOTE(!tooltip.isEmpty() && !hasHanCmp2(tooltip),
                QStringLiteral("en-US 下悬停明细不应包含汉字：%1").arg(tooltip));
            ks::i18n::LanguageManager::instance().initialize(QStringLiteral("zh-CN"));
            ks::i18n::LanguageManager::instance().retranslateAll();
        }

        // ---------------- M7：Pending 回补要求真的"变了"，不止是"两边都有效" ----------------
        // 与 T07（previous 无效）互补：这里 previous 与 baseline 都有效，但取值完全相同
        // （两次读取之间这个字节本来就没有发生外部变化），即使它同时又被我们自己暂存了
        // （Pending），也不该被"两次读取之间"视图误判成外部变化——isExternalChangeByte 的
        // Pending 回补分支必须真的比较 previousBytes 与 baselineBytes 的取值，不能只检查
        // 两个 validMask。
        void runPendingRebackRequiresRealChangeTests()
        {
            FakeBytesProvider provider(64);
            const std::uint64_t base = 0x9000ULL;
            provider.overlay().LoadBaseline(QStringLiteral("m7").toStdString(), base, std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 1));
            // 再读一次，取值完全没变（previous == baseline，真的没有外部变化）。
            provider.overlay().RefreshBaseline(QStringLiteral("m7").toStdString(), base, std::vector<std::uint8_t>(32, 0x11), std::vector<std::uint8_t>(32, 1));
            provider.overlay().Stage(base + 4, {0x99}); // 该字节又被我们自己暂存了，变成 Pending

            WorkbenchCompareView view;
            view.setBytesProvider(&provider);
            view.setMode(WorkbenchCompareView::Mode::ExternalChange);
            view.setWindow(base, 32);
            WPH_CHECK_NOTE(view.model()->rowCount() == 0,
                QStringLiteral("previous 与 baseline 取值相同（没有真外部变化）时，即使该字节同时是 Pending，"
                    "也不该出现在'两次读取之间'视图，实得行数 %1").arg(view.model()->rowCount()));
        }
    }

    void RunCompareRegressionTests2()
    {
        const int before = g_checks;
        const int beforeFail = g_failures;
        runExternalWithInvalidPreviousTests();
        runTooltipAndStatusExactContentTests();
        runCompareWindowCapTests();
        runTopOfAddressSpaceDoesNotHangTests();
        runTooltipHintI18nTests();
        runPendingRebackRequiresRealChangeTests();
        std::cerr << "[CompareRegression2] checks=" << (g_checks - before) << " failures=" << (g_failures - beforeFail) << std::endl;
    }
}
