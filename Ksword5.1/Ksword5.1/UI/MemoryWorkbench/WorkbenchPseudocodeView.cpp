#include "WorkbenchPseudocodeView.h"
#include "../CodeTextEdit.h"
#include "../../Internationalization/LanguageManager.h"
#include <QLabel>
#include <QLineEdit>
#include <QPointer>
#include <QSignalBlocker>
#include <QTimer>
#include <algorithm>
#include <cstring>
#include <limits>

namespace ks::ui
{
    namespace
    {
        // ContextMatches：身份、代次、范围和架构必须全部对应，不接受跨目标迟到结果。
        bool ContextMatches(const WorkbenchPseudocodeContext& left, const WorkbenchPseudocodeContext& right)
        {
            return left.sourceIdentity == right.sourceIdentity && left.revision == right.revision
                && left.contentRevision == right.contentRevision
                && left.baseAddress == right.baseAddress && left.length == right.length
                && left.selectedAddress == right.selectedAddress && left.addressBits == right.addressBits
                && left.x86Compatible == right.x86Compatible && left.addressKind == right.addressKind
                && left.maximumWindowBytes == right.maximumWindowBytes
                && left.hasReadBounds == right.hasReadBounds && left.readFirst == right.readFirst
                && left.readLast == right.readLast && left.allowEvictedSnapshot == right.allowEvictedSnapshot;
        }

        // AddressText：原始地址显示，使用独立有效位，绝不把地址 0 当作空值。
        QString AddressText(const std::uint64_t address)
        {
            return QStringLiteral("0x%1").arg(address, 0, 16).toUpper();
        }

        // ErrorText：稳定后端错误码转成已有双语提示，不把日志内容当可执行指令。
        QString ErrorText(const QString& code)
        {
            QString source;
            if (code == QStringLiteral("ghidra_not_configured"))
                source = QStringLiteral("请通过插件管理安装 Ghidra 反编译后端。");
            else if (code == QStringLiteral("java_not_found"))
                source = QStringLiteral("未找到兼容的 JDK；请设置 JAVA_HOME 或 KSWORD_GHIDRA_JAVA。");
            else if (code == QStringLiteral("snapshot_too_large"))
                source = QStringLiteral("快照超过反编译后端的大小上限；请缩小分析范围。");
            else if (code == QStringLiteral("timeout"))
                source = QStringLiteral("反编译超时；可以缩小范围后重试。");
            else if (code == QStringLiteral("cancelled"))
                source = QStringLiteral("反编译已取消。");
            else if (code == QStringLiteral("no_function_at_address"))
                source = QStringLiteral("当前位置没有可恢复的函数；请在代码节选择函数起点后重试。");
            else if (code == QStringLiteral("unsupported_architecture"))
                source = QStringLiteral("当前伪代码后端仅支持 x86/x64 指令集。");
            else if (code == QStringLiteral("unmapped_pe_address"))
                source = QStringLiteral("当前位置没有有效的 PE 地址映射；请选择有文件内容的代码节。");
            else if (code == QStringLiteral("invalid_address"))
                source = QStringLiteral("分析位置超出可用地址范围；请重新选择地址或候选入口。");
            else if (code == QStringLiteral("process_isolation_failed"))
                source = QStringLiteral("无法创建隔离的反编译进程；请检查系统进程限制。");
            else if (code == QStringLiteral("bytes_loading"))
                source = QStringLiteral("正在读取反编译范围；字节就绪后继续分析。");
            else if (code == QStringLiteral("snapshot_unreadable"))
                source = QStringLiteral("所需代码或数据不可读，或超出已捕获范围；请重新读取或调整分析范围。");
            else if (code == QStringLiteral("non_code_address"))
                source = QStringLiteral("当前位置在 PE 头部，或映像将该范围声明为非执行区；请在代码节选择已知函数起点。");
            else if (code == QStringLiteral("invalid_instruction_data"))
                source = QStringLiteral("反编译遇到无效或不完整指令，未接受该伪代码结果；请核对地址、架构和完整函数范围。");
            else if (code == QStringLiteral("invalid_entry_address") || code == QStringLiteral("entry_unknown"))
                source = QStringLiteral("候选入口不是有效的十六进制地址，或超出当前可分析范围。");
            else if (code == QStringLiteral("selected_outside_function"))
                source = QStringLiteral("所选位置不在候选入口的可达代码中；请修正入口或重新选择分析位置。");
            else if (code == QStringLiteral("incomplete_control_flow"))
                source = QStringLiteral("控制流包含缺失代码或无法确定的间接跳转，未接受不完整伪代码。");
            else if (code == QStringLiteral("analysis_budget_exceeded"))
                source = QStringLiteral("分析已达到读取或指令数量上限，未接受截断结果；请缩小范围或选择更准确的入口。");
            else return ks::i18n::sourceText(QStringLiteral("反编译失败（%1）；请检查后端目录和运行日志。")).arg(code);
            return ks::i18n::sourceText(source);
        }
    }

    WorkbenchPseudocodeView::WorkbenchPseudocodeView(QWidget* parent) : QWidget(parent)
    {
        decompiler_ = new GhidraDecompiler(this);
        buildUi();
        updateState();
        refreshDecompilerRuntime();
    }

    // 析构先解除字节源和后端回调，再取消进程，避免非拥有数据源先被宿主释放。
    WorkbenchPseudocodeView::~WorkbenchPseudocodeView()
    {
        provider_ = nullptr;
        progressActive_ = false;
        if (progressTimer_) progressTimer_->stop(); // 析构不再触发子控件显示/进度信号。
        disconnect(decompiler_, nullptr, this, nullptr);
        decompiler_->cancel();
    }

    void WorkbenchPseudocodeView::setBytesProvider(IWorkbenchBytesProvider* provider)
    {
        if (provider_ == provider) return;
        provider_ = provider;
        invalidate();
    }

    // setContext：任何分析上下文变化都先取消旧票据，保留宿主明确传来的新范围。
    void WorkbenchPseudocodeView::setContext(const WorkbenchPseudocodeContext& context)
    {
        if (ContextMatches(context_, context)) return;
        if (entry_ && (context_.sourceIdentity != context.sourceIdentity || context_.addressKind != context.addressKind))
        {
            const QSignalBlocker blocked(entry_);
            entry_->clear();
        }
        context_ = context;
        invalidate();
    }

    void WorkbenchPseudocodeView::setSourceRevisions(const std::uint64_t source, const std::uint64_t content)
    {
        if (context_.revision == source && context_.contentRevision == content) return;
        context_.revision = source;
        context_.contentRevision = content;
        invalidate();
    }

    void WorkbenchPseudocodeView::setFileAnalysisContext(
        std::shared_ptr<const std::vector<std::uint8_t>> snapshot,
        const std::uint64_t imageBase, const QVector<FileAnalysisRegion>& regions,
        const bool x86Compatible)
    {
        // 同一冻结映像每次同步无需清空结果；重新提供映射则视为新分析语义。
        const bool same = fileSnapshot_ == snapshot && imageBase_ == imageBase
            && fileX86Compatible_ == x86Compatible && fileRegions_.size() == regions.size();
        bool sameRegions = same;
        for (qsizetype i = 0; sameRegions && i < regions.size(); ++i)
        {
            const auto& a = fileRegions_.at(i);
            const auto& b = regions.at(i);
            sameRegions = a.fileOffset == b.fileOffset && a.fileSize == b.fileSize
                && a.rva == b.rva && a.virtualSize == b.virtualSize;
        }
        if (sameRegions) return;
        fileSnapshot_ = std::move(snapshot);
        imageBase_ = imageBase;
        fileRegions_ = regions;
        fileX86Compatible_ = x86Compatible;
        invalidate();
    }

    // 偏移映射只接受唯一、非回绕且有真实文件内容的节区间。
    std::optional<std::uint64_t> WorkbenchPseudocodeView::fileOffsetToVirtualAddress(const std::uint64_t offset) const
    {
        if (!fileSnapshot_ || offset >= fileSnapshot_->size()) return std::nullopt;
        std::optional<std::uint64_t> candidate;
        for (const auto& region : fileRegions_)
        {
            if (offset < region.fileOffset) continue;
            const auto delta = offset - region.fileOffset;
            const auto mapped = std::min(region.fileSize, region.virtualSize ? region.virtualSize : region.fileSize);
            if (delta >= mapped) continue;
            if (candidate || region.rva > UINT32_MAX || delta > UINT32_MAX - region.rva
                || region.rva > UINT64_MAX - imageBase_ || delta > UINT64_MAX - imageBase_ - region.rva)
                return std::nullopt;
            candidate = imageBase_ + region.rva + delta;
        }
        return candidate;
    }

    // 后端返回 VA 后先映射回文件偏移，绝不把 VA 交给文件编辑器作为偏移。
    std::optional<std::uint64_t> WorkbenchPseudocodeView::virtualAddressToFileOffset(const std::uint64_t address) const
    {
        if (!fileSnapshot_ || address < imageBase_ || address - imageBase_ > UINT32_MAX) return std::nullopt;
        const auto rva = address - imageBase_;
        std::optional<std::uint64_t> candidate;
        for (const auto& region : fileRegions_)
        {
            if (rva < region.rva) continue;
            const auto delta = rva - region.rva;
            const auto mapped = std::min(region.fileSize, region.virtualSize ? region.virtualSize : region.fileSize);
            if (delta >= mapped) continue;
            if (candidate || delta > UINT64_MAX - region.fileOffset) return std::nullopt;
            const auto offset = region.fileOffset + delta;
            if (offset >= fileSnapshot_->size()) return std::nullopt;
            candidate = offset;
        }
        return candidate;
    }

    // buildRequest：同步拷贝共享来源的捕获字节，所有掩码必须明确为 1。
    bool WorkbenchPseudocodeView::buildRequest(DecompilerRequest& request, QString& reason) const
    {
        const QPointer<const WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        const auto* source = provider_;
        reason = QStringLiteral("invalid_address");
        const auto length = context_.length;
        if (!provider_ || !length || length - 1 > UINT64_MAX - context_.baseAddress
            || context_.selectedAddress < context_.baseAddress
            || context_.selectedAddress - context_.baseAddress >= length) return false;
        if (!context_.x86Compatible || (context_.addressBits != 32 && context_.addressBits != 64))
        {
            reason = QStringLiteral("unsupported_architecture");
            return false;
        }
        const bool pe = context_.addressKind == SnapshotAddressKind::FileOffset && fileSnapshot_;
        const auto maximum = pe ? GhidraDecompiler::MaximumPeBytes : GhidraDecompiler::MaximumRawBytes;
        if (length > static_cast<std::uint64_t>(maximum)
            || (context_.maximumWindowBytes && length > context_.maximumWindowBytes)
            || (pe && fileSnapshot_->size() > static_cast<std::size_t>(GhidraDecompiler::MaximumPeBytes)))
        {
            reason = QStringLiteral("snapshot_too_large");
            return false;
        }
        // 两种宿主的 FetchWindow 分别有 64 KiB/1 MiB 上限；逐块校验再组成完整证据。
        // 分块仅改变缓存拷贝粒度，既不缩小用户选区，也不越过上下文捕获边界。
        request.bytes.resize(static_cast<qsizetype>(length));
        bool loading = false;
        for (std::uint64_t offset = 0; offset < length;)
        {
            const auto count = std::min<std::uint64_t>(65536, length - offset);
            const auto address = context_.baseAddress + offset;
            const auto window = source->FetchWindow(address, count);
            if (!self || epoch_ != epoch || provider_ != source) return false;
            if (!window.ok)
            {
                loading = true;
                offset += count;
                continue;
            }
            if (window.address != address || window.bytes.size() != count || window.validMask.size() != count)
            {
                reason = QStringLiteral("snapshot_unreadable");
                return false;
            }
            for (const auto mask : window.validMask)
            {
                if (mask == 2) loading = true;
                else if (mask != 1)
                {
                    reason = QStringLiteral("snapshot_unreadable");
                    return false;
                }
            }
            std::memcpy(request.bytes.data() + static_cast<qsizetype>(offset), window.bytes.data(),
                static_cast<std::size_t>(count));
            offset += count;
        }
        if (loading)
        {
            reason = QStringLiteral("bytes_loading");
            return false;
        }
        request.baseAddress = context_.baseAddress;
        request.selectedAddress = context_.selectedAddress;
        request.x64 = context_.addressBits == 64;
        if (!pe) return true;

        // PE 请求以同一证据映像为基础，覆盖当前捕获范围内的已暂存编辑。
        const auto va = fileOffsetToVirtualAddress(context_.selectedAddress);
        if (!fileX86Compatible_ || !va)
        {
            reason = !fileX86Compatible_ ? QStringLiteral("unsupported_architecture") : QStringLiteral("unmapped_pe_address");
            return false;
        }
        if (context_.baseAddress > fileSnapshot_->size() || length > fileSnapshot_->size() - context_.baseAddress) return false;
        const QByteArray overlay = request.bytes;
        request.bytes = QByteArray(reinterpret_cast<const char*>(fileSnapshot_->data()), static_cast<qsizetype>(fileSnapshot_->size()));
        request.bytes.replace(static_cast<qsizetype>(context_.baseAddress), overlay.size(), overlay);
        request.baseAddress = imageBase_;
        request.selectedAddress = *va;
        request.inputKind = DecompilerInputKind::PortableExecutable;
        return true;
    }

    // invalidate：先令票据失效，再取消进程；取消的同步 finished 不能回写旧结果。
    void WorkbenchPseudocodeView::invalidate()
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto epoch = ++epoch_;
        hasRequest_ = false;
        requestContentStamp_.reset();
        requestSegmentStamps_.clear();
        rawPlanner_.reset();
        rawAdvanceQueued_ = false;
        rawRequestedWindow_.reset();
        rawEntry_.reset();
        waitingForBytes_ = false;
        stopProgress();
        if (!self || epoch != epoch_) return;
        lineAddresses_.clear();
        lineValid_.clear();
        if (decompiler_) decompiler_->cancel();
        if (!self || epoch != epoch_) return;
        if (code_ && !setCode(QString())) return;
        if (!self || epoch != epoch_) return;
        if (status_)
        {
            status_->setToolTip(QString());
            setStatus(QStringLiteral("快照或分析上下文已变化；请重新反编译当前函数。"));
        }
        if (decompile_) updateState();
    }

    bool WorkbenchPseudocodeView::requestStillCurrent() const
    {
        if (!hasRequest_ || !ContextMatches(context_, requestContext_)) return false;
        if (!request_.segments.isEmpty()) return sparseRequestStillCurrent();
        const QPointer<const WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        const auto* source = provider_;
        const auto stamp = provider_ ? provider_->ContentStamp(context_.baseAddress, context_.length) : std::nullopt;
        if (!self || epoch_ != epoch || provider_ != source) return false;
        if (stamp && requestContentStamp_ == stamp) return true;
        DecompilerRequest current;
        QString reason;
        const bool built = buildRequest(current, reason);
        if (!self || epoch_ != epoch || provider_ != source) return false;
        const bool unchanged = built && current.bytes == request_.bytes
            && current.baseAddress == request_.baseAddress && current.selectedAddress == request_.selectedAddress
            && current.inputKind == request_.inputKind && current.x64 == request_.x64;
        if (unchanged) requestContentStamp_ = stamp;
        return unchanged;
    }

    // refreshView：无关页回填不作废 C；输入窗口发生变化时取消旧请求并要求显式重分析。
    void WorkbenchPseudocodeView::refreshView()
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        if (rawPlanner_)
        {
            queueRawAnalysis();
            return;
        }
        if (hasRequest_ && !requestStillCurrent())
        {
            if (self && epoch_ == epoch) invalidate();
            return;
        }
        if (!self || epoch_ != epoch) return;
        if (waitingForBytes_)
        {
            DecompilerRequest current;
            QString reason;
            const bool ready = buildRequest(current, reason);
            if (!self || epoch_ != epoch) return;
            if (ready || reason != QStringLiteral("bytes_loading")) startDecompilation();
        }
        if (self) updateState();
    }

    // startDecompilation：用户显式动作建立冻结票据；没有后端时现有错误提示提供安装入口。
    void WorkbenchPseudocodeView::startDecompilation()
    {
        if (decompiler_->isRunning()) return;
        const QPointer<WorkbenchPseudocodeView> self(this);
        const bool continuedWaiting = waitingForBytes_ && progressElapsed_.isValid();
        const QElapsedTimer continuedClock = progressElapsed_; // 续读同一请求保持其真实等待耗时。
        const auto epoch = epoch_ + 1;
        invalidate();
        if (!self || epoch_ != epoch) return;
        if (context_.addressKind != SnapshotAddressKind::FileOffset || !fileSnapshot_)
        {
            startRawAnalysis();
            return;
        }
        QString reason;
        DecompilerRequest request;
        if (!buildRequest(request, reason))
        {
            if (!self || epoch_ != epoch) return;
            setStatus(ErrorText(reason));
            waitingForBytes_ = reason == QStringLiteral("bytes_loading");
            if (waitingForBytes_) beginProgress(continuedWaiting ? &continuedClock : nullptr);
            if (!self || epoch_ != epoch) return;
            updateState();
            if (waitingForBytes_) emit windowRequested(context_.baseAddress, context_.length);
            return;
        }
        if (continuedWaiting) beginProgress(&continuedClock);
        if (self && epoch_ == epoch) submitRequest(request);
    }

    void WorkbenchPseudocodeView::submitRequest(const DecompilerRequest& request)
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        const QElapsedTimer continuedClock = progressElapsed_;
        const bool continuedWaiting = progressActive_ && progressElapsed_.isValid();
        request_ = request;
        requestContext_ = context_;
        const auto stamp = request.segments.isEmpty() && provider_
            ? provider_->ContentStamp(context_.baseAddress, context_.length) : std::nullopt;
        if (!self || epoch_ != epoch) return;
        requestContentStamp_ = stamp;
        requestSegmentStamps_.clear();
        requestSegmentStamps_.resize(request.segments.size());
        hasRequest_ = true;
        if (!request.segments.isEmpty() && !sparseRequestStillCurrent())
        {
            if (self && epoch_ == epoch) invalidate();
            return;
        }
        if (!self || epoch_ != epoch) return;
        beginProgress(continuedWaiting ? &continuedClock : nullptr);
        if (!self || epoch_ != epoch) return;
        refreshDecompilerRuntime();
        setStatus(request.inputKind == DecompilerInputKind::PortableExecutable
            ? ks::i18n::sourceText(QStringLiteral("正在反编译 PE 函数：文件偏移 %1 → VA %2…"))
                .arg(AddressText(context_.selectedAddress), AddressText(request.selectedAddress))
            : ks::i18n::sourceText(QStringLiteral("正在按原始 x86/x64 快照反编译 %1；缺失范围不会补零。"))
                .arg(AddressText(context_.selectedAddress)));
        decompiler_->start(request);
        if (self) updateState();
    }

    void WorkbenchPseudocodeView::failRawAnalysis(const QString& error, const std::optional<quint64> address)
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        rawPlanner_.reset();
        rawRequestedWindow_.reset();
        rawAdvanceQueued_ = false;
        waitingForBytes_ = false;
        stopProgress();
        if (!self || epoch_ != epoch) return;
        const auto message = ErrorText(error);
        setStatus(address ? ks::i18n::sourceText(QStringLiteral("%1 | 地址 %2")).arg(message, AddressText(*address)) : message);
        if (self && epoch_ == epoch) updateState();
    }

    // finishDecompilation：接受结果前再验身份、代次和输入字节；导航仍使用同一请求映射。
    void WorkbenchPseudocodeView::finishDecompilation(const DecompilerResult& result)
    {
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        if (!hasRequest_) return;
        if (!requestStillCurrent())
        {
            if (self && epoch_ == epoch) invalidate();
            return;
        }
        if (!self || epoch_ != epoch) return;
        stopProgress();
        if (!self || epoch_ != epoch) return;
        lineAddresses_ = result.lineAddresses;
        lineValid_ = result.lineAddressValid;
        if (!setCode(result.success ? result.code : QString())) return;
        if (!self || epoch_ != epoch) return;
        if (result.success)
        {
            auto message = ks::i18n::sourceText(QStringLiteral("%1 | 函数地址 %2 | 分析位置 %3；伪代码由当前字节快照推断。"))
                .arg(result.functionName, AddressText(result.functionAddress), AddressText(requestContext_.selectedAddress));
            if (result.rawControlFlow)
                message += QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral("RAW 候选入口 %1；已捕获 %2 字节，分析 %3 条指令。"))
                    .arg(AddressText(result.functionAddress)).arg(result.capturedBytes).arg(result.decodedInstructions);
            else if (result.boundaryInferred)
                message += QLatin1Char('\n') + ks::i18n::sourceText(QStringLiteral("RAW 候选函数：函数起点和范围由分析推断；请优先从已知函数起点分析。"));
            setStatus(message);
        }
        else
        {
            lineAddresses_.clear();
            lineValid_.clear();
            setStatus(ErrorText(result.error));
        }
        if (!self || epoch_ != epoch) return;
        status_->setToolTip(result.diagnostics.toHtmlEscaped());
        updateState();
    }

    // locateLine：仅导航有有效映射的 C 行，范围外的文件偏移由宿主读取同一捕获证据。
    void WorkbenchPseudocodeView::locateLine(const bool disassembly)
    {
        if (!requestStillCurrent() || decompiler_->isRunning() || !text_) return;
        const auto line = text_->textCursor().blockNumber();
        if (line < 0 || line >= lineAddresses_.size() || line >= lineValid_.size() || !lineValid_.at(line)) return;
        const auto source = lineAddresses_.at(line);
        const auto address = request_.inputKind == DecompilerInputKind::PortableExecutable
            ? virtualAddressToFileOffset(source) : std::optional<std::uint64_t>(source);
        if (!address) return;
        if (disassembly) emit requestDisasmLocate(*address);
        else emit requestHexLocate(*address);
    }
}
