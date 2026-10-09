#include "workbench_integration_regression_tests.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/SnapshotWorkbenchWidget.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/WorkbenchCompareView.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/AssemblyPreviewDialog.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryWorkbench/HexView.h"
#include "../Ksword5.1/Ksword5.1/UI/MemoryAssembly.h"
#include <QApplication>
#include <QLabel>
#include <QMenu>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QTabWidget>
#include <QTableView>
#include <QTest>
#include <QTimer>
#include <algorithm>

namespace
{
    // LimitedProvider：真实快照适配器外再限每次 997 字节，覆盖跨非对齐分块合并。
    class LimitedProvider final : public ks::ui::IWorkbenchBytesProvider
    {
    public:
        ks::ui::MemorySnapshotBytesProvider captured; // 冻结测试字节，绝不从进程读取。
        mutable std::uint64_t largestRequest = 0; // 最大请求长度，验证模型按小块工作。
        bool corruptTailMask = false; // 合成不可用尾部，不能报整范围无变化。
        ks::ui::WorkbenchByteWindow FetchWindow(std::uint64_t address, std::uint64_t length) const override
        {
            largestRequest = std::max(largestRequest, length);
            auto window = captured.FetchWindow(address, std::min<std::uint64_t>(997, length));
            if (corruptTailMask && address >= 0x1000 + 1024 * 1024 && !window.validMask.empty())
                window.validMask[0] = 2;
            return window;
        }
        int AddressBits() const override { return 64; }
        bool HasPreviousRead() const override { return captured.HasPreviousRead(); }
    };
}

// 整范围覆盖、尾部真实定位、每次读取预算和汇编完整指令边界都按实际生产入口断言。
void RunWorkbenchIntegrationRegressionTests(const std::function<void(bool, const char*)>& require)
{
    using namespace ks::ui;
    constexpr std::uint64_t base = 0x1000;
    constexpr qsizetype size = 2 * 1024 * 1024 + 3; // 最后块既超过 2 MiB 又不对齐 16 字节。
    const QByteArray initial(size, char{0});
    QByteArray changed = initial;
    changed[size - 1] = char{0x5A};
    changed[1024 * 1024 + 1] = char{0x43};
    SnapshotWorkbenchWidget host;
    host.setSnapshot(initial, base, DisassemblyArchitecture::X64, base, QStringLiteral("capture-full-range"));
    host.setSnapshot(changed, base, DisassemblyArchitecture::X64, base, QStringLiteral("capture-full-range"));
    auto* tabs = host.findChild<QTabWidget*>();
    auto* compare = host.findChild<WorkbenchCompareView*>();
    require(tabs && compare, "actual snapshot host exposes the native compare page");
    tabs->setCurrentIndex(3);
    compare->setMode(WorkbenchCompareView::Mode::ExternalChange);
    require(compare->rangeLength() == static_cast<std::uint64_t>(size)
        && compare->comparedBytes() == static_cast<std::uint64_t>(size)
        && compare->totalChangedBytes() == 2 && compare->model()->rowCount() == 2,
        "snapshot reread compares every captured byte including the second MiB and final partial block");
    const auto tail = compare->model()->index(1, 0);
    require(tail.data(Qt::UserRole).toULongLong() == base + static_cast<std::uint64_t>(size - 3),
        "last changed group retains its full captured address");
    require(compare->model()->index(1, 2).data().toString().contains(QStringLiteral("5A")),
        "virtual compare model formats the last partial row from the real provider");
    emit compare->table()->doubleClicked(tail);
    require(tabs->currentIndex() == 0 && host.hexEditor()->caretAddress() == tail.data(Qt::UserRole).toULongLong(),
        "double clicking the last compare row navigates through the actual snapshot host");

    // 暂存差异和前次读取差异走相同完整范围；关闭高亮不影响证据比较。
    host.setEditable(true);
    host.hexEditor()->setByteQuiet(base + static_cast<std::uint64_t>(size - 2), 0x6B);
    host.refreshFromHexEditor();
    tabs->setCurrentIndex(3);
    compare->setMode(WorkbenchCompareView::Mode::Pending);
    require(compare->comparedBytes() == static_cast<std::uint64_t>(size) && compare->totalChangedBytes() == 1,
        "pending edits in the final block are counted across the entire snapshot");
    require(compare->model()->index(0, 2).data().toString().contains(QStringLiteral("6B")),
        "virtual pending row shows the final block replacement bytes");

    LimitedProvider provider;
    provider.captured.setSnapshot(base, changed, initial, initial, 64, false);
    WorkbenchCompareView view;
    view.setBytesProvider(&provider);
    view.setWindow(base, static_cast<std::uint64_t>(size));
    require(view.comparedBytes() == static_cast<std::uint64_t>(size) && view.totalChangedBytes() == 2
        && view.model()->rowCount() == 2 && provider.largestRequest <= 65536,
        "sub-call provider limits never discard the remaining full capture");
    provider.corruptTailMask = true;
    view.refreshView();
    auto* status = view.findChild<QLabel*>(QStringLiteral("ksMemwbCompareStatus"));
    require(view.comparedBytes() < static_cast<std::uint64_t>(size) && status
        && status->text().contains(QStringLiteral("比较未完成")),
        "unavailable bytes report incomplete coverage rather than a complete zero-change result");
    view.setWindow(base, 64ULL * 1024ULL * 1024ULL + 1);
    require(view.model()->rowCount() == 0 && view.comparedBytes() == 0 && status
        && status->text().contains(QStringLiteral("未执行比较")),
        "oversized ranges are refused explicitly and never silently truncated");
    view.setWindow(UINT64_MAX - 3, 8);
    require(view.comparedBytes() == 0 && status->text().contains(QStringLiteral("未执行比较")),
        "wrapping ranges are refused before any scan or allocation");

    // 真模态菜单跨“切页 + 同数值范围换源”，旧行必须失效，不能路由到新来源。
    host.resize(1000, 600);
    host.show();
    tabs->setCurrentIndex(3);
    QTest::qWait(10);
    const QPersistentModelIndex oldRow(compare->model()->index(0, 0));
    require(oldRow.isValid(), "a changed row exists before the modal source switch");
    bool menuEntered = false;
    int staleNavigation = 0;
    QObject::connect(compare, &WorkbenchCompareView::requestHexLocate, &host,
        [&](quint64) { ++staleNavigation; });
    QTimer watchdog;
    watchdog.setSingleShot(true);
    QObject::connect(&watchdog, &QTimer::timeout, &watchdog, []() {
        if (auto* popup = QApplication::activePopupWidget()) popup->close();
    });
    watchdog.start(3000);
    QTimer::singleShot(0, &host, [&]() {
        const QPointer<QMenu> menu = qobject_cast<QMenu*>(QApplication::activePopupWidget());
        if (!menu) return;
        menuEntered = true;
        QAction* locate = nullptr;
        for (auto* action : menu->actions())
            if (action->text().contains(QStringLiteral("定位"))) locate = action;
        tabs->setCurrentIndex(0);
        host.setSnapshot(changed, base, DisassemblyArchitecture::X64, base, QStringLiteral("new-capture-same-address"));
        if (menu && locate)
        {
            menu->setActiveAction(locate);
            QTest::keyClick(menu, Qt::Key_Return);
        }
        else if (menu) menu->close();
    });
    const QPoint point = compare->table()->visualRect(oldRow).center();
    emit compare->table()->customContextMenuRequested(point);
    watchdog.stop();
    require(menuEntered && !oldRow.isValid() && staleNavigation == 0 && compare->model()->rowCount() == 0,
        "cross-page source switch invalidates modal compare indices before stale navigation can target a new source");
    host.hide();

    // 清空时比较页也可能隐藏；清空源不能保留任何上个捕获范围的模型行。
    host.setSnapshot(initial, base, DisassemblyArchitecture::X64, base, QStringLiteral("clear-range"));
    host.setSnapshot(changed, base, DisassemblyArchitecture::X64, base, QStringLiteral("clear-range"));
    tabs->setCurrentIndex(3);
    compare->setMode(WorkbenchCompareView::Mode::ExternalChange);
    const QPersistentModelIndex clearing(compare->model()->index(0, 0));
    tabs->setCurrentIndex(0);
    host.clear();
    require(!clearing.isValid() && compare->model()->rowCount() == 0,
        "clearing a hidden compare page invalidates its former source rows");

    // reset 通知既可能销毁宿主也可能递归载入更新来源；外层动作须让新一代获胜。
    for (const bool clearingHost : {false, true})
    {
        QPointer<SnapshotWorkbenchWidget> retiring = new SnapshotWorkbenchWidget;
        retiring->setSnapshot(initial.left(16), base);
        auto* retiringCompare = retiring->findChild<WorkbenchCompareView*>();
        bool destroyed = false;
        QObject::connect(retiringCompare->model(), &QAbstractItemModel::modelReset, qApp, [&]() {
            if (!destroyed)
            {
                destroyed = true;
                delete retiring.data();
            }
        });
        if (clearingHost) retiring->clear();
        else retiring->setSnapshot(changed.left(16), base);
        require(destroyed && retiring.isNull(), "source reset remains safe when its model observer destroys the host");
    }
    SnapshotWorkbenchWidget reentrant;
    reentrant.setSnapshot(initial.left(16), base);
    auto* reentrantCompare = reentrant.findChild<WorkbenchCompareView*>();
    bool replaced = false;
    QObject::connect(reentrantCompare->model(), &QAbstractItemModel::modelReset, &reentrant, [&]() {
        if (replaced) return;
        replaced = true;
        reentrant.setSnapshot(QByteArray(16, char{0x7C}), base, DisassemblyArchitecture::X64,
            base, QStringLiteral("newer-reentrant-source"));
    });
    reentrant.setSnapshot(QByteArray(16, char{0x3B}), base, DisassemblyArchitecture::X64,
        base, QStringLiteral("older-outer-source"));
    require(replaced && reentrant.data() == QByteArray(16, char{0x7C}),
        "reset reentrancy preserves the newer source and abandons the older outer snapshot action");

    // 公共汇编核心调用生产解码器；旧指令五字节长度不能被三字节覆盖截断。
    const DecodeOneFn decode = [](const std::uint8_t* bytes, std::size_t length,
        std::uint64_t address, bool x64) -> std::optional<DecodedRow> {
        const QByteArray input(reinterpret_cast<const char*>(bytes),
            static_cast<qsizetype>(std::min<std::size_t>(length, 15)));
        const auto result = InstructionDecoder::decode(input, address,
            x64 ? DisassemblyArchitecture::X64 : DisassemblyArchitecture::X86, 1);
        if (result.rows.isEmpty()) return std::nullopt;
        const auto& row = result.rows.first();
        return DecodedRow{row.address, row.bytes, row.mnemonic, row.operands, row.decoded};
    };
    AssemblyPreviewInput input;
    input.address = 0x140001000;
    input.snapshot = QByteArray::fromHex("b801000000c3");
    input.maximumSpan = 65536;
    const WorkbenchAssembleResult oneByte{true, QByteArray::fromHex("90"), {}, 0};
    const auto padded = BuildAssemblyPreview(input, 5, true, oneByte, decode);
    require(padded.error.isEmpty() && padded.payload == QByteArray::fromHex("9090909090"),
        "shared preview pads exactly one complete old instruction with NOP");
    require(!BuildAssemblyPreview(input, 3, true, oneByte, decode).error.isEmpty(),
        "shared boundary scan rejects truncating an old instruction");
    require(!BuildAssemblyPreview(input, 5, false, oneByte, decode).error.isEmpty(),
        "both hosts require exact machine-code length when NOP padding is disabled");
    require(!BuildAssemblyPreview(input, 7, true, oneByte, decode).error.isEmpty(),
        "shared preview never fabricates uncaptured bytes beyond the frozen range");
    input.maximumSpan = 4;
    require(!BuildAssemblyPreview(input, 5, true, oneByte, decode).error.isEmpty(),
        "host-specific maximum span remains a hard boundary of the shared component");
    input.maximumSpan = 65536;
    input.snapshot = QByteArray::fromHex("0f");
    require(!BuildAssemblyPreview(input, 1, true, oneByte, decode).error.isEmpty(),
        "undecodable original bytes cannot be approved as a complete instruction boundary");
    input.address = UINT64_MAX;
    input.snapshot = QByteArray::fromHex("9090");
    require(!BuildAssemblyPreview(input, 2, true, oneByte, decode).error.isEmpty(),
        "assembly preview rejects address wraparound before decoding");
    const WorkbenchAssembleResult error{false, {}, QStringLiteral("fixture error"), 0};
    require(BuildAssemblyPreview(input, 1, true, error, decode).error.contains(QStringLiteral("第 1 行")),
        "shared compiler error consistently normalizes unavailable line zero to line one");
}
