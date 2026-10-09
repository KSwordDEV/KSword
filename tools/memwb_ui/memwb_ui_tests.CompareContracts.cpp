// 统一比较页回归：比较值与有效掩码，不依赖仅用于绘制的变化高亮开关。
#include "memwb_ui_common.h"
#include "../../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchCompareView.h"
#include <QTableView>

namespace memwb_test
{
    namespace
    {
        // CompareProvider：冻结的合成窗口，允许独立切换每套证据的有效掩码。
        class CompareProvider final : public ks::ui::IWorkbenchBytesProvider
        {
        public:
            ks::ui::WorkbenchByteWindow window; // 当前/基线/前次字节及逐字节有效性。
            CompareProvider()
            {
                window.ok = true;
                window.address = 0x1000;
                window.bytes.assign(16, 0);
                window.baselineBytes.assign(16, 0);
                window.previousBytes.assign(16, 0);
                window.validMask.assign(16, 1);
                window.baselineValidMask.assign(16, 1);
                window.previousValidMask.assign(16, 1);
                window.changeKinds.assign(16, ksword::memwb::ByteChangeKind::Unchanged);
            }
            ks::ui::WorkbenchByteWindow FetchWindow(std::uint64_t, std::uint64_t) const override { return window; }
            int AddressBits() const override { return 64; }
            bool HasPreviousRead() const override { return true; }
        };
    }

    // RunCompareContractTests：验证真实模型与真实子页，不访问真实目标。
    void RunCompareContractTests()
    {
        CompareProvider provider;
        ks::ui::WorkbenchCompareView view;
        view.setBytesProvider(&provider);
        provider.window.bytes[3] = 0xBB;
        view.setWindow(provider.window.address, provider.window.bytes.size());
        CHECK(view.model()->rowCount() == 1);
        CHECK(view.model()->data(view.model()->index(0, 5), Qt::DisplayRole).toInt() == 1);
        CHECK(view.model()->data(view.model()->index(0, 2), Qt::DisplayRole).toString().contains(QStringLiteral("BB")));

        // 高亮关闭时 changeKinds 全为 Unchanged，值差仍然是明确的待写入差异。
        provider.window.validMask[3] = 2;
        view.refreshView();
        CHECK(view.model()->rowCount() == 0);
        provider.window.validMask[3] = 1;
        provider.window.baselineValidMask[3] = 2;
        view.refreshView();
        CHECK(view.model()->rowCount() == 0);
        provider.window.baselineValidMask[3] = 1;
        view.refreshView();
        CHECK(view.model()->rowCount() == 1);

        // 外部变化只比较前次与基线；暂存值不同也不能取代任一读取证据。
        provider.window.baselineBytes[3] = 0x44;
        provider.window.previousBytes[3] = 0x22;
        provider.window.changeKinds[3] = ksword::memwb::ByteChangeKind::Pending;
        view.setMode(ks::ui::WorkbenchCompareView::Mode::ExternalChange);
        CHECK(view.model()->rowCount() == 1);
        CHECK(view.model()->data(view.model()->index(0, 1), Qt::DisplayRole).toString().contains(QStringLiteral("22")));
        CHECK(view.model()->data(view.model()->index(0, 2), Qt::DisplayRole).toString().contains(QStringLiteral("44")));
        // 直接 ExternalChange 标签同样不得跳过真实读取有效性检查。
        provider.window.changeKinds[3] = ksword::memwb::ByteChangeKind::ExternalChange;
        provider.window.previousValidMask[3] = 2;
        view.refreshView();
        CHECK(view.model()->rowCount() == 0);
        provider.window.previousValidMask[3] = 1;
        provider.window.baselineValidMask[3] = 2;
        view.refreshView();
        CHECK(view.model()->rowCount() == 0);
        provider.window.baselineValidMask[3] = 1;

        // 最后合法地址仍然有分组和真实定位值，循环和格式化都不能回绕到地址 0。
        provider.window.address = UINT64_MAX - 3;
        provider.window.bytes.resize(4);
        provider.window.baselineBytes.resize(4);
        provider.window.previousBytes.resize(4);
        provider.window.validMask.resize(4);
        provider.window.baselineValidMask.resize(4);
        provider.window.previousValidMask.resize(4);
        provider.window.changeKinds.resize(4);
        view.setWindow(provider.window.address, 4);
        CHECK(view.model()->rowCount() == 1);
        CHECK(view.model()->data(view.model()->index(0, 0), Qt::DisplayRole).toString()
            == QStringLiteral("0xFFFFFFFFFFFFFFF0"));
        CHECK(view.model()->data(view.model()->index(0, 0), Qt::UserRole).toULongLong() == UINT64_MAX - 3);
        const auto tooltip = view.model()->data(view.model()->index(0, 2), Qt::ToolTipRole).toString();
        CHECK(tooltip.contains(QStringLiteral("0xFFFFFFFFFFFFFFFF")));
        CHECK(!tooltip.contains(QStringLiteral("0x0000000000000000")));
        std::uint64_t located = 0; // 双击路由必须落在真实窗口内，而不是窗口前的虚拟对齐起点。
        QObject::connect(&view, &ks::ui::WorkbenchCompareView::requestHexLocate, &view,
            [&](quint64 address) { located = address; });
        emit view.table()->doubleClicked(view.model()->index(0, 0));
        CHECK(located == UINT64_MAX - 3);
    }
}
