// HexCanvas.cpp
// 作用：HexCanvas 的构造、数据源与页回填、模式（只读/行宽/分组）、选区 API 与选区变更通知，
// 以及"数据变化"信号 contentChanged 的排队与合并（scheduleContentChanged）。
// 其余职责按文件拆分：
//   HexCanvas.Scroll.cpp  滚动模型与页请求规划
//   HexCanvas.Layout.cpp  度量/布局/单元格几何/高亮层/尺寸与字体事件
//   HexCanvas.Paint.cpp   绘制、单元格状态与悬停提示
//   HexCanvas.Input.cpp   鼠标、滚轮、键盘、输入法、视口坐标命中查询
//   HexCanvas.Edit.cpp    暂存入口 stageBytes、编辑手势、粘贴、填充
//   HexCanvas.Menu.cpp    复制与右键菜单

#include "HexCanvas.h"
#include "HexCanvasFormat.h"

#include <QApplication>
#include <QEvent>
#include <QFontDatabase>
#include <QFontMetrics>
#include <QPalette>
#include <QPointer>
#include <QResizeEvent>
#include <QScrollBar>
#include <QTextOption>
#include <QTransform>

#include <algorithm>
#include <cstring>
#include <limits>

namespace ks::ui
{
    namespace
    {
        // kPageBytes：页大小，与 HexViewport 保持一致。
        constexpr std::uint64_t kPageBytes = ksword::memwb::HexViewport::kPageBytes;

        // StaticDataProvider：setStaticData 装的内置页提供者。
        // 持有一份字节数组（QByteArray 隐式共享，不深拷贝），被请求哪一页才切哪一页回填，
        // 因此 2 MiB 数据不会一次性塞满页缓存。
        class StaticDataProvider final : public IHexPageProvider
        {
        public:
            // 构造：canvas 为回填目标；base 为数据起始地址；data 为字节。
            StaticDataProvider(HexCanvas* canvas, std::uint64_t base, QByteArray data)
                : m_canvas(canvas), m_base(base), m_data(std::move(data))
            {
            }

            // RequestPages：逐页切片并同步回填。
            // 传入：页范围列表与代次；传出：无。页与数据的交集之外的字节标记为无效。
            void RequestPages(
                const std::vector<HexFetchRange>& ranges,
                std::uint64_t sourceRevision) override
            {
                // dataSize：数据字节数；dataLast：数据最后一个字节的地址。
                const std::uint64_t dataSize = static_cast<std::uint64_t>(m_data.size());
                const std::uint64_t dataLast = m_base + (dataSize - 1ULL);

                for (const HexFetchRange& range : ranges)
                {
                    for (std::uint64_t index = 0; index < range.pageCount; ++index)
                    {
                        // pageStart/pageLast：该页的起止地址（页对齐，不会溢出）。
                        const std::uint64_t pageStart = range.firstPageStart + index * kPageBytes;
                        const std::uint64_t pageLast = pageStart + (kPageBytes - 1ULL);

                        // bytes/mask：回填的页数据与有效掩码，默认全部无效。
                        QByteArray bytes(static_cast<qsizetype>(kPageBytes), '\0');
                        QByteArray mask(static_cast<qsizetype>(kPageBytes), '\0');

                        // 页与数据的交集：[copyFirst, copyLast]。
                        const std::uint64_t copyFirst = std::max(pageStart, m_base);
                        const std::uint64_t copyLast = std::min(pageLast, dataLast);
                        if (dataSize != 0 && copyFirst <= copyLast)
                        {
                            const qsizetype count = static_cast<qsizetype>(copyLast - copyFirst + 1ULL);
                            const qsizetype inPage = static_cast<qsizetype>(copyFirst - pageStart);
                            const qsizetype inData = static_cast<qsizetype>(copyFirst - m_base);
                            std::memcpy(bytes.data() + inPage, m_data.constData() + inData, static_cast<size_t>(count));
                            std::memset(mask.data() + inPage, 1, static_cast<size_t>(count));
                        }
                        m_canvas->deliverPage(pageStart, bytes, mask, sourceRevision);
                    }
                }
            }

        private:
            HexCanvas* m_canvas;    // 回填目标画布（非拥有）
            std::uint64_t m_base;   // 数据起始地址
            QByteArray m_data;      // 数据字节（隐式共享）
        };
    }

    // 构造。
    // 用法：auto* canvas = new HexCanvas(parent); canvas->setStaticData(0x1000, bytes);
    // 传入：父控件；传出：对象本身（空地址空间、只读、每行 16 字节）。
    HexCanvas::HexCanvas(QWidget* parent)
        : QAbstractScrollArea(parent),
          m_viewport(
              0,
              0,
              ksword::memwb::HexViewport::kDefaultBytesPerRow,
              ksword::memwb::HexViewport::kMaxCachedPages)
    {
        // 基本外观：无边框；竖向滚动条常驻（避免它出现/消失造成视口宽度跳变），横向按需。
        setFrameShape(QFrame::NoFrame);
        setFocusPolicy(Qt::StrongFocus);
        setVerticalScrollBarPolicy(Qt::ScrollBarAlwaysOn);
        setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);

        // 视口整个由 paintEvent 不透明填充，告诉 Qt 不必再擦除背景。
        viewport()->setAttribute(Qt::WA_OpaquePaintEvent, true);

        // 退出主程序的全局平滑滚动过滤器（UI/SmoothScrollSupport.cpp）：它把竖向滚动条的单位当"像素"，
        // 一档滚轮请求 clamp(singleStep*3, 48, 120) 个单位、再被限幅到 pageStep-重叠；而本画布的竖向滚动条单位
        // 是"行"（singleStep=1、pageStep=可见行数），结果一档滚轮就滚约一整页（真机反馈"一滚动就是一整页"）。
        // 本画布自己的 wheelEvent 已经是"每档 3 行 + Ctrl+滚轮缩放 + Shift/横向滚轮横滚"，必须让它收到事件。
        // 过滤器沿父链读这个属性，设在画布上即覆盖视口与两个滚动条。
        setProperty("ksword_disable_smooth_scroll", true);

        // 输入法：保持启用，以便通过 inputMethodQuery 声明"仅拉丁、不预测"。
        setAttribute(Qt::WA_InputMethodEnabled, true);
        viewport()->setAttribute(Qt::WA_InputMethodEnabled, true);

        // 可访问性名称：读屏软件据此朗读控件用途。
        setAccessibleName(QStringLiteral("十六进制视图"));
        setAccessibleDescription(QStringLiteral("以十六进制和 ASCII 两种形式显示并编辑内存字节"));

        // 字体：先设置等宽字体，随后量出字符宽度与行高。
        // m_baseFont 记下这份基准字体：字号缩放（setZoomLevel）永远从它出发算，级别 0 就是它本身。
        m_baseFont = hexcanvas_format::BuildFixedFont();
        setFont(m_baseFont);
        rebuildMetrics();

        // 滚动条与定时器的信号连接。
        connect(verticalScrollBar(), &QScrollBar::valueChanged, this, &HexCanvas::onVerticalBarChanged);
        connect(horizontalScrollBar(), &QScrollBar::valueChanged, this, &HexCanvas::onHorizontalBarChanged);
        m_autoScrollTimer.setInterval(kAutoScrollIntervalMs);
        connect(&m_autoScrollTimer, &QTimer::timeout, this, &HexCanvas::autoScrollTick);
    }

    // 析构：内置提供者由 unique_ptr 释放，定时器是成员随之销毁。
    HexCanvas::~HexCanvas() = default;

    // ======================== 数据源 ========================

    // 设置地址空间。
    // 传入：闭区间两端；传出：false 表示 first > last，保持原状。
    bool HexCanvas::setAddressSpace(std::uint64_t firstAddress, std::uint64_t lastAddress)
    {
        if (firstAddress > lastAddress)
        {
            return false;
        }
        return installSpace(firstAddress, lastAddress);
    }

    // 安装新的地址空间（不检查区间、不动提供者）。
    // 作用：重建 HexViewport、换新来源代次、滚动回顶部、通知选区变化并请求可见页。
    bool HexCanvas::installSpace(std::uint64_t firstAddress, std::uint64_t lastAddress)
    {
        // before：旧选区，用来决定是否发选区信号。
        const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
        const std::uint32_t rowWidth = m_viewport.BytesPerRow();

        // 重建视图：行宽沿用当前值，缓存容量用默认值。
        m_viewport = ksword::memwb::HexViewport(
            firstAddress,
            lastAddress,
            rowWidth,
            ksword::memwb::HexViewport::kMaxCachedPages);
        m_hasSpace = true;

        // 新代次：旧空间里还在途的异步结果回来时会被拒收。
        m_viewport.InvalidateAll(++m_revisionCounter);
        // 安装空间会发多种同步通知，观察者可删除画布或安装另一个来源。
        // 同一新来源里的导航允许保留，不用旧安装栈强制恢复初始选区。
        const QPointer<HexCanvas> alive(this);
        const std::uint64_t installedRevision = sourceRevision();
        const auto current = [this, alive, installedRevision]() {
            return alive && sourceRevision() == installedRevision;
        };
        m_firstRow = 0;
        m_hOffset = 0;
        cancelNibble();

        // 地址位数可能变化（8 位 <-> 16 位，例如 32 位目标与 64 位目标互换），重算几何后同步滚动条。
        // 自适应模式下地址位数变了每行内容宽度也变了，要在请求页之前重选行宽
        // （此刻首行恒为 0、插入点恒在行 0，行宽改变不需要什么锚点）。
        recomputeLayout();
        applyAutoBytesPerRow();
        if (!current()) return false;
        syncScrollBars();
        if (!current()) return false;
        viewport()->update();
        requestVisiblePages();
        if (!current()) return false;
        notifyVisibleRange();
        if (!current()) return false;
        applySelectionChange(before);
        if (!current()) return false;

        // 空间换了，所有地址显示的值都可能不同；同步供页产生的多次回填会在这里合并成一个信号。
        scheduleContentChanged();
        return true;
    }

    // 排队一次 contentChanged。
    // 作用：同一轮事件循环内无论调用多少次，信号只发一次；信号发出之前先清标志，
    // 这样槽里再改内容会再排一次，不会被"已排队"吞掉也不会递归。
    // 调用方法：任何会让某地址显示值变化的路径在改动落地之后调用。传入传出：无。
    void HexCanvas::scheduleContentChanged()
    {
        if (m_contentChangedQueued)
        {
            return;
        }
        m_contentChangedQueued = true;

        // 以 this 为上下文的排队调用：画布先于事件循环销毁时调用自动作废，不会悬空。
        QMetaObject::invokeMethod(
            this,
            [this]() {
                m_contentChangedQueued = false;
                emit contentChanged();
            },
            Qt::QueuedConnection);
    }

    // 回到无数据状态。
    void HexCanvas::clearAddressSpace()
    {
        const bool hadSpace = m_hasSpace;

        // 占位视图：单字节空间，仅为保持成员有效；m_hasSpace 为假时不会被画出。
        m_viewport = ksword::memwb::HexViewport(
            0,
            0,
            m_viewport.BytesPerRow(),
            ksword::memwb::HexViewport::kMaxCachedPages);
        m_viewport.InvalidateAll(++m_revisionCounter);
        const QPointer<HexCanvas> alive(this);
        const std::uint64_t clearedRevision = sourceRevision();
        m_hasSpace = false;
        m_firstRow = 0;
        m_hOffset = 0;
        m_notifiedOnce = false;
        cancelNibble();

        // 内置静态提供者没有数据可供，一并释放。
        if (m_provider == m_staticProvider.get())
        {
            m_provider = nullptr;
        }
        m_staticProvider.reset();

        recomputeLayout();
        syncScrollBars();
        if (!alive || sourceRevision() != clearedRevision) return;
        viewport()->update();
        if (hadSpace)
        {
            emit selectionChanged(false, 0, 0);
            if (!alive || sourceRevision() != clearedRevision) return;

            // 原来有数据现在什么都不显示：订阅者需要知道；本来就没有数据则没有任何变化。
            scheduleContentChanged();
        }
    }

    // 设置外部提供者。
    // 传入：提供者指针（非拥有，可为空）。作用：换提供者等于换了来源，所以换新代次并重新请求。
    void HexCanvas::setPageProvider(IHexPageProvider* provider)
    {
        // 换成外部提供者时丢弃内置静态提供者。
        if (provider != m_staticProvider.get())
        {
            m_staticProvider.reset();
        }
        m_provider = provider;
        refresh();
    }

    // 便捷接口：用一块字节数组当数据源。
    // 传入：起始地址与字节。
    void HexCanvas::setStaticData(std::uint64_t base, const QByteArray& content)
    {
        if (content.isEmpty())
        {
            clearAddressSpace();
            return;
        }

        // 末地址：base + size - 1，溢出 64 位时截断到可容纳的部分。
        // size：数据字节数；room：从 base 起到 UINT64_MAX 还能放多少字节减一。
        const std::uint64_t size = static_cast<std::uint64_t>(content.size());
        const std::uint64_t room = std::numeric_limits<std::uint64_t>::max() - base;
        QByteArray usable = content;
        std::uint64_t last = base + (size - 1ULL);
        if (size - 1ULL > room)
        {
            last = std::numeric_limits<std::uint64_t>::max();
            usable = content.left(static_cast<qsizetype>(room + 1ULL));
        }

        // 先装提供者再装空间：installSpace 内部会立即请求可见页，那时提供者必须已就绪。
        m_staticProvider = std::make_unique<StaticDataProvider>(this, base, usable);
        m_provider = m_staticProvider.get();
        installSpace(base, last);
    }

    // 设置叠加层。
    // 换叠加层会改变 Pending/ExternalChange 着色与补丁值，也改变"能不能编辑"，所以要通知订阅者。
    void HexCanvas::setOverlay(ksword::memwb::MemoryDiffOverlay* overlay)
    {
        m_overlay = overlay;
        cancelNibble();
        viewport()->update();
        scheduleContentChanged();
    }

    // 宿主绕过画布直接改了叠加层之后调用：重绘并通知订阅者。
    // 不取消半字节：半字节只记着高位与目标地址，叠加层变化不会让它失效（宿主写回后用户可能正敲到一半）。
    void HexCanvas::notifyOverlayChanged()
    {
        viewport()->update();
        scheduleContentChanged();
    }

    // 叠加层指针。
    ksword::memwb::MemoryDiffOverlay* HexCanvas::overlay() const
    {
        return m_overlay;
    }

    // 回填一页。
    // 传入：页起点、数据、掩码、请求时的代次；传出：HexViewport 的接收结果。
    HexCanvas::PageResult HexCanvas::deliverPage(
        std::uint64_t pageStart,
        const QByteArray& bytes,
        const QByteArray& validMask,
        std::uint64_t sourceRevision)
    {
        if (!m_hasSpace)
        {
            return PageResult::RejectedOutsideSpace;
        }

        // QByteArray -> vector<uint8_t>：HexViewport 是 Qt-free 的，这里做类型适配。
        const std::vector<std::uint8_t> byteVector(
            reinterpret_cast<const std::uint8_t*>(bytes.constData()),
            reinterpret_cast<const std::uint8_t*>(bytes.constData()) + bytes.size());
        const std::vector<std::uint8_t> maskVector(
            reinterpret_cast<const std::uint8_t*>(validMask.constData()),
            reinterpret_cast<const std::uint8_t*>(validMask.constData()) + validMask.size());

        const PageResult result = m_viewport.InsertPage(pageStart, byteVector, maskVector, sourceRevision);
        if (result == PageResult::Accepted)
        {
            // 被接受的页：该页地址的值从"未加载"变成了真实字节（也可能淘汰了别的页），排队通知订阅者。
            viewport()->update();
            scheduleContentChanged();
        }
        return result;
    }

    // 声明某范围整页不可读。
    HexCanvas::PageResult HexCanvas::deliverUnreadable(const HexFetchRange& range, std::uint64_t sourceRevision)
    {
        if (!m_hasSpace)
        {
            return PageResult::RejectedOutsideSpace;
        }
        const PageResult result = m_viewport.MarkUnreadable(range, sourceRevision);
        if (result == PageResult::Accepted)
        {
            viewport()->update();
            scheduleContentChanged();
        }
        return result;
    }

    // 撤销在途登记。
    void HexCanvas::cancelPages(const HexFetchRange& range)
    {
        if (m_hasSpace)
        {
            m_viewport.CancelInFlight(range);
        }
    }

    // 当前来源代次。
    std::uint64_t HexCanvas::sourceRevision() const
    {
        return m_viewport.SourceRevision();
    }

    // 页缓存导出的共用实现：严格版与掩码版都走这里，只差 allowUnreadable。
    // 传入：闭区间两端；allowUnreadable 为真时"已读完但读不到"的字节记为 0 + 掩码 0，为假时遇到即失败；
    //       bytesOut 接收字节（必填）；maskOut 接收有效掩码（可为空指针，表示不需要）。
    // 传出：true 表示整段都取到了，输出参数已填好；false 表示整体失败，输出参数保持调用前的值。
    // 失败条件（都不补零、不返回一半）：没有地址空间、first > last、区间不整体在地址空间内、
    //       区间比缓存容量还长（必然有字节没缓存）、任一字节未加载/在途、或（严格版）不可读。
    bool HexCanvas::collectCachedRange(
        std::uint64_t firstAddress,
        std::uint64_t lastAddress,
        bool allowUnreadable,
        std::vector<std::uint8_t>* bytesOut,
        std::vector<std::uint8_t>* maskOut) const
    {
        // 先排除无意义的区间：没有数据、反向区间、越出地址空间（空间是一整段连续闭区间，两端都在即整体在内）。
        if (bytesOut == nullptr || !m_hasSpace || firstAddress > lastAddress)
        {
            return false;
        }
        if (!m_viewport.ContainsAddress(firstAddress) || !m_viewport.ContainsAddress(lastAddress))
        {
            return false;
        }

        // 长度上限：缓存装不下的区间必然有字节不在缓存里，直接拒绝，也避免为一个巨大区间预先分配内存。
        // 用 last - first 与容量比较而不是先加一，这样区间覆盖整个 2^64 时也不会溢出。
        const std::uint64_t capacityBytes =
            static_cast<std::uint64_t>(m_viewport.MaxCachedPages()) * ksword::memwb::HexViewport::kPageBytes;
        const std::uint64_t spanMinusOne = lastAddress - firstAddress;
        if (spanMinusOne >= capacityBytes)
        {
            return false;
        }
        const std::uint64_t length = spanMinusOne + 1;

        // 逐字节取：先装进局部容器，全部成功才交给调用方，失败时调用方的输出不会被改成半截内容。
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint8_t> mask;
        bytes.reserve(static_cast<std::size_t>(length));
        if (maskOut != nullptr)
        {
            mask.reserve(static_cast<std::size_t>(length));
        }
        for (std::uint64_t offset = 0; offset < length; ++offset)
        {
            // PeekByte 不刷新 LRU；firstAddress + offset 不超过 lastAddress，不会溢出。
            const ksword::memwb::HexViewport::ByteLookup lookup = m_viewport.PeekByte(firstAddress + offset);
            if (lookup.state == ByteState::Valid)
            {
                bytes.push_back(lookup.value);
                if (maskOut != nullptr)
                {
                    mask.push_back(1);
                }
            }
            else if (lookup.state == ByteState::Unreadable && allowUnreadable)
            {
                // 已读完但读不到：0 字节只是占位，真假以掩码为准。
                bytes.push_back(0);
                if (maskOut != nullptr)
                {
                    mask.push_back(0);
                }
            }
            else
            {
                // 未加载 / 在途（两个版本都失败），或严格版遇到不可读。
                return false;
            }
        }

        *bytesOut = std::move(bytes);
        if (maskOut != nullptr)
        {
            *maskOut = std::move(mask);
        }
        return true;
    }

    // 严格版：整段都必须"已缓存且读到了"。
    std::optional<std::vector<std::uint8_t>> HexCanvas::copyCachedRange(
        std::uint64_t firstAddress,
        std::uint64_t lastAddress) const
    {
        std::vector<std::uint8_t> bytes;
        if (!collectCachedRange(firstAddress, lastAddress, false, &bytes, nullptr))
        {
            return std::nullopt;
        }
        return bytes;
    }

    // 掩码版：已读完但读不到的字节以 0 + 掩码 0 返回，只有未落定的才整体失败。
    std::optional<HexCanvas::CachedRangeCopy> HexCanvas::copyCachedRangeWithMask(
        std::uint64_t firstAddress,
        std::uint64_t lastAddress) const
    {
        CachedRangeCopy copy;
        if (!collectCachedRange(firstAddress, lastAddress, true, &copy.bytes, &copy.validMask))
        {
            return std::nullopt;
        }
        return copy;
    }

    // 按页对齐枚举 [firstAddress, lastAddress] 覆盖的整页，只返回"已经落定"的页起始地址
    // （详见头文件"四之四"与本方法声明处注释）。
    // 传入：闭区间两端（不要求预先页对齐）；传出：命中页起始地址集合；非法/无数据返回空集。
    std::set<std::uint64_t> HexCanvas::settledPageStartsInRange(
        std::uint64_t firstAddress,
        std::uint64_t lastAddress) const
    {
        std::set<std::uint64_t> result;
        if (!m_hasSpace || firstAddress > lastAddress)
        {
            return result;
        }

        // 页对齐：把查询区间收缩到"页起始地址"坐标系，才能与已缓存页的起始地址比较。
        // PageStartOf 只是向下取整到 kPageBytes 的整数倍（纯减法），不会溢出。
        const std::uint64_t firstPageStart = ksword::memwb::HexViewport::PageStartOf(firstAddress);
        const std::uint64_t lastPageStart = ksword::memwb::HexViewport::PageStartOf(lastAddress);

        // 溢出防线：firstAddress <= lastAddress 时按理 firstPageStart <= lastPageStart
        // 恒成立（当前页大小是 2 的幂且整除 2^64），这里仍显式核对一次，避免未来页大小
        // 改成不整除 2^64 的值时，本函数在不知情的情况下把反序区间当正常输入枚举。
        if (firstPageStart > lastPageStart)
        {
            return result;
        }

        // 不是"从 firstPageStart 到 lastPageStart 逐页加 kPageBytes 枚举再与缓存比对"：
        // 那样当查询区间覆盖接近整个 64 位地址空间时（例如内核范围）会逐页遍历到千万级，
        // 末页再加一次 kPageBytes 还要额外处理回绕。改为遍历"已缓存页"的列表（数量恒不
        // 超过 m_viewport.MaxCachedPages()，默认 256），按起始地址是否落在
        // [firstPageStart, lastPageStart] 过滤——两种写法结果等价（已缓存页本来就是一个
        // 很小的子集），但这样无论查询区间多大，开销只随"已缓存页数"变化。
        // CachedPageStartsLeastRecentFirst 只读取每页记录的 lastUsedTick 排序输出，不写
        // 回任何字段，满足"不刷新 LRU、不改变任何状态"的要求。
        for (const std::uint64_t pageStart : m_viewport.CachedPageStartsLeastRecentFirst())
        {
            if (pageStart >= firstPageStart && pageStart <= lastPageStart)
            {
                result.insert(pageStart);
            }
        }
        return result;
    }

    // 换新代次、清缓存并重新请求可见页。
    void HexCanvas::refresh()
    {
        if (!m_hasSpace)
        {
            return;
        }
        m_viewport.InvalidateAll(++m_revisionCounter);
        viewport()->update();
        requestVisiblePages();

        // 缓存被清空：所有地址回到"在途/未加载"，随后的回填各自也会排队，这里的一次与它们合并。
        scheduleContentChanged();
    }

    // ======================== 模式与外观 ========================

    // 设置是否允许编辑。
    // 传入：新状态。值真的变了才发 editableChanged（重复设置同一个值什么信号都没有）。
    void HexCanvas::setEditable(bool editable)
    {
        const bool changed = (m_editable != editable);
        m_editable = editable;
        if (!editable)
        {
            cancelNibble();
        }
        viewport()->update();
        if (changed)
        {
            emit editableChanged(editable);
        }
    }

    // 当前是否允许编辑。
    bool HexCanvas::isEditable() const
    {
        return m_editable;
    }

    // 改每行字节数（公开入口，手动选择）。
    // 传入：8/16/32/48/64；传出：是否接受。合法值会关闭自适应行宽（手动选择优先）。
    // 锚点策略见 applyBytesPerRow；行宽或自适应标志变了才发 rowWidthModeChanged。
    bool HexCanvas::setBytesPerRow(int bytesPerRow)
    {
        // 非法值：直接拒绝，不改行宽也不碰自适应标志。
        if (bytesPerRow < 0 || !ksword::memwb::HexViewport::IsSupportedBytesPerRow(static_cast<std::uint32_t>(bytesPerRow)))
        {
            return false;
        }

        // 先清自适应标志再改行宽：改行宽的路径里不允许再被自适应抢回去。
        // "与当前相同"的早返回必须放在清标志之后——用户在自适应模式下手选了恰好等于当前档的值，
        // 也是一次明确的"改成手动"，之后窗口再变宽不应该再自动换档。
        const bool modeChanged = m_autoBytesPerRow;
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        m_autoBytesPerRow = false;
        const bool rowChanged = applyBytesPerRow(bytesPerRow);
        if (!alive || sourceRevision() != revision || this->bytesPerRow() != bytesPerRow || m_autoBytesPerRow)
            return false;
        if (rowChanged || modeChanged)
        {
            emit rowWidthModeChanged(this->bytesPerRow(), false);
        }
        return alive && sourceRevision() == revision && this->bytesPerRow() == bytesPerRow && !m_autoBytesPerRow;
    }

    // 改行宽并重排（手动与自动共用，不动自适应标志、不发信号）。
    // 传入：已校验合法的行宽。传出：true 表示行宽真的变了；false 表示与当前相同，什么都没做。
    // 锚点：插入点在屏幕上完整可见时以插入点为锚点——换行宽后它仍停在同一屏幕行
    // （64 -> 16 之类的大变化里，旧的"首行锚点"会让插入点与选区直接滚出屏幕）；否则以首行起始地址为锚点。
    // 不 refresh()、不换来源代次、不发 contentChanged：缓存按绝对地址存放，换行宽只是换了行列映射。
    bool HexCanvas::applyBytesPerRow(int bytesPerRow)
    {
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision(); // 重排通知不允许旧来源继续请求或发出几何事件。
        if (static_cast<std::uint32_t>(bytesPerRow) == m_viewport.BytesPerRow())
        {
            return false;
        }

        // anchor：改行宽前选定的锚点地址；relativeRow：锚点在屏幕上相对首行的行数（首行锚点时为 0）。
        std::optional<std::uint64_t> anchor;
        std::uint64_t relativeRow = 0;
        if (m_hasSpace)
        {
            // caretRow：插入点所在行（用旧行宽换算）；它落在 [首行, 首行 + 完整可见行数) 内才算"可见"。
            const std::optional<std::uint64_t> caretRow = m_viewport.RowOfAddress(m_viewport.GetSelection().caret);
            if (caretRow.has_value() && *caretRow >= m_firstRow && *caretRow - m_firstRow < fullVisibleRows())
            {
                anchor = m_viewport.GetSelection().caret;
                relativeRow = *caretRow - m_firstRow;
            }
            else
            {
                anchor = m_viewport.RowStartAddress(m_firstRow);
            }
        }
        m_viewport.SetBytesPerRow(static_cast<std::uint32_t>(bytesPerRow));

        if (anchor.has_value())
        {
            // 首行的补空位地址早于空间起点，要先夹取到起点再换算行号。
            const std::uint64_t clamped = std::max(*anchor, m_viewport.FirstAddress());
            const std::optional<std::uint64_t> row = m_viewport.RowOfAddress(clamped);
            const std::uint64_t anchorRow = row.has_value() ? *row : 0ULL;

            // 让锚点停在同一屏幕行：首行 = 锚点新行号 - 相对行数（不足时贴顶）。
            m_firstRow = anchorRow - std::min(anchorRow, relativeRow);
        }
        m_firstRow = std::min(m_firstRow, maxFirstRow());

        recomputeLayout();
        syncScrollBars();
        if (!alive || sourceRevision() != revision || this->bytesPerRow() != bytesPerRow) return false;
        viewport()->update();
        requestVisiblePages();
        if (!alive || sourceRevision() != revision || this->bytesPerRow() != bytesPerRow) return false;
        notifyVisibleRange();
        return alive && sourceRevision() == revision && this->bytesPerRow() == bytesPerRow;
    }

    // 当前每行字节数。
    int HexCanvas::bytesPerRow() const
    {
        return static_cast<int>(m_viewport.BytesPerRow());
    }

    // 开关自适应行宽。
    // 传入：on 为真时立即按当前视口宽度重选一档，此后随宽度/分组/字体/地址位数自动重选；
    //       为假时停在当前档不再自动变。值真的变了发 rowWidthModeChanged。
    void HexCanvas::setAutoBytesPerRow(bool on)
    {
        if (m_autoBytesPerRow == on)
        {
            // 重复开启：再按当前宽度对一次，幂等且无信号（行宽没变就不发）。
            if (on)
            {
                applyAutoBytesPerRow();
            }
            return;
        }
        m_autoBytesPerRow = on;
        if (!on)
        {
            emit rowWidthModeChanged(bytesPerRow(), false);
            return;
        }

        // 打开：立即重选。重选换了档时 applyAutoBytesPerRow 已经发过信号；
        // 没换档（或还没有地址空间/视口尚未布局）时模式变了也要通知一次。
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        const bool changed = applyAutoBytesPerRow();
        if (!alive || sourceRevision() != revision || !m_autoBytesPerRow) return;
        if (!changed)
        {
            emit rowWidthModeChanged(bytesPerRow(), true);
        }
    }

    // 是否处于自适应行宽模式。
    bool HexCanvas::isAutoBytesPerRow() const
    {
        return m_autoBytesPerRow;
    }

    // 设置十六进制列分组。
    // 分组影响每行内容宽度，自适应模式下要在重算几何之后重选行宽。
    bool HexCanvas::setGroupSize(int groupSize)
    {
        if (groupSize != 1 && groupSize != 2 && groupSize != 4 && groupSize != 8)
        {
            return false;
        }
        m_groupSize = groupSize;
        const QPointer<HexCanvas> alive(this);
        const auto revision = sourceRevision();
        recomputeLayout();
        applyAutoBytesPerRow();
        if (!alive || sourceRevision() != revision || m_groupSize != groupSize) return false;
        syncScrollBars();
        if (!alive || sourceRevision() != revision || m_groupSize != groupSize) return false;
        viewport()->update();
        return true;
    }

    // 当前分组字节数。
    int HexCanvas::groupSize() const
    {
        return m_groupSize;
    }

    // ======================== 选区 ========================

    // 选区闭区间。
    std::optional<HexCanvas::AddressRange> HexCanvas::selectedRange() const
    {
        if (!m_hasSpace)
        {
            return std::nullopt;
        }
        return m_viewport.SelectedRange();
    }

    // 插入点地址。
    std::uint64_t HexCanvas::caretAddress() const
    {
        return m_viewport.GetSelection().caret;
    }

    // 活动面板。
    HexCanvas::ActivePane HexCanvas::activePane() const
    {
        return m_viewport.Pane();
    }

    // 切换活动面板。
    void HexCanvas::setActivePane(ActivePane pane)
    {
        if (m_viewport.Pane() == pane)
        {
            return;
        }
        cancelNibble();
        m_viewport.SetPane(pane);
        viewport()->update();
    }

    // 设置插入点。
    bool HexCanvas::setCaretAddress(std::uint64_t address, bool extend, bool ensureVisible)
    {
        if (!m_hasSpace)
        {
            return false;
        }
        const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
        const bool exact = m_viewport.SetCaret(address, extend);
        const auto expected = m_viewport.GetSelection();
        const std::uint64_t selectedRevision = sourceRevision();
        // 选区通知可同步销毁画布；原调用栈必须在滚动前停下，不能仅靠 pane 的外层守卫。
        const QPointer<HexCanvas> alive(this);
        applySelectionChange(before);
        if (!alive || sourceRevision() != selectedRevision || !selectionStillMatches(expected))
        {
            return false;
        }
        if (ensureVisible)
        {
            if (!revealCaret(ScrollAlign::Nearest)) return false;
        }
        return exact;
    }

    // 全选。
    void HexCanvas::selectAll()
    {
        if (!m_hasSpace)
        {
            return;
        }
        const ksword::memwb::HexViewport::Selection before = m_viewport.GetSelection();
        m_viewport.SelectAll();
        applySelectionChange(before);
    }

    bool HexCanvas::selectionStillMatches(const ksword::memwb::HexViewport::Selection& expected) const
    {
        if (!m_hasSpace) return false;
        const auto actual = m_viewport.GetSelection();
        return actual.anchor == expected.anchor && actual.caret == expected.caret && actual.pane == expected.pane;
    }

    // 选区变化后的统一收尾：取消半字节、刷新、发信号。
    // 传入：变化前的选区。所有改动选区的路径都必须经过这里。
    void HexCanvas::applySelectionChange(const ksword::memwb::HexViewport::Selection& before)
    {
        const ksword::memwb::HexViewport::Selection now = m_viewport.GetSelection();
        const bool anchorChanged = now.anchor != before.anchor;
        const bool caretChanged = now.caret != before.caret;
        const bool paneChanged = now.pane != before.pane;
        if (!anchorChanged && !caretChanged && !paneChanged)
        {
            return;
        }

        // 半字节只属于它输入时的那个字节与 Hex 面板，插入点或面板变了就作废。
        if (m_nibbleActive && (now.caret != m_nibbleAddress || now.pane != ActivePane::Hex))
        {
            cancelNibble();
        }
        viewport()->update();

        // 选区端点变化发 selectionChanged；插入点变化再发 caretMoved。
        // 两个信号之间没有异步边界，selectionChanged 的观察者允许直接删掉所属 pane。
        const QPointer<HexCanvas> alive(this);
        const std::uint64_t selectedRevision = sourceRevision();
        if (anchorChanged || caretChanged)
        {
            const std::optional<AddressRange> range = selectedRange();
            emit selectionChanged(
                range.has_value(),
                range.has_value() ? range->first : 0ULL,
                range.has_value() ? range->last : 0ULL);
            if (!alive || sourceRevision() != selectedRevision || !selectionStillMatches(now))
            {
                return;
            }
        }
        if (caretChanged)
        {
            emit caretMoved(now.caret);
        }
    }
}
