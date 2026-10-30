#include "WorkbenchPseudocodeView.h"
#include "../Decompiler/RawCodePlanner.h"
#include <QLineEdit>
#include <QPointer>
#include <QTimer>
#include <algorithm>
#include <limits>

namespace ks::ui
{
    void WorkbenchPseudocodeView::startRawAnalysis()
    {
        if (!provider_ || !context_.length || context_.length - 1 > UINT64_MAX - context_.baseAddress
            || context_.selectedAddress < context_.baseAddress
            || context_.selectedAddress - context_.baseAddress >= context_.length)
        {
            failRawAnalysis(QStringLiteral("invalid_address"));
            return;
        }
        if (!context_.x86Compatible || (context_.addressBits != 32 && context_.addressBits != 64))
        {
            failRawAnalysis(QStringLiteral("unsupported_architecture"));
            return;
        }
        detail::RawCodePlanner::Config config;
        config.selectedAddress = context_.selectedAddress;
        config.entryAddress = context_.selectedAddress;
        config.firstAddress = context_.hasReadBounds ? context_.readFirst : context_.baseAddress;
        config.lastAddress = context_.hasReadBounds ? context_.readLast : context_.baseAddress + context_.length - 1;
        config.x64 = context_.addressBits == 64;
        if (!config.x64) config.lastAddress = std::min<std::uint64_t>(config.lastAddress, UINT32_MAX);
        const auto text = entry_ ? entry_->text().trimmed() : QString();
        if (!text.isEmpty())
        {
            auto digits = text;
            if (digits.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive)) digits.remove(0, 2);
            bool valid = !digits.isEmpty() && digits.size() <= 16;
            for (const auto c : digits)
                valid = valid && ((c >= u'0' && c <= u'9') || (c >= u'a' && c <= u'f') || (c >= u'A' && c <= u'F'));
            bool parsed = false;
            config.entryAddress = digits.toULongLong(&parsed, 16);
            if (!valid || !parsed || config.entryAddress < config.firstAddress || config.entryAddress > config.lastAddress)
            {
                failRawAnalysis(QStringLiteral("invalid_entry_address"));
                return;
            }
        }
        rawEntry_ = config.entryAddress;
        rawPlanner_ = std::make_shared<detail::RawCodePlanner>(config);
        requestContext_ = context_;
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        beginProgress();
        if (!self || epoch_ != epoch || !rawPlanner_) return;
        updateState();
        if (!self || epoch_ != epoch || !rawPlanner_) return;
        // Failed/cancelled channels may leave pages pending. This deadline never
        // retries a failed read or keeps a hidden page waiting indefinitely.
        QTimer::singleShot(30000, this, [this, epoch] {
            if (epoch_ == epoch && rawPlanner_) failRawAnalysis(QStringLiteral("timeout"));
        });
        queueRawAnalysis();
    }

    void WorkbenchPseudocodeView::queueRawAnalysis()
    {
        if (!rawPlanner_ || rawAdvanceQueued_) return;
        rawAdvanceQueued_ = true;
        const auto epoch = epoch_;
        QTimer::singleShot(0, this, [this, epoch] {
            if (epoch_ != epoch) return;
            rawAdvanceQueued_ = false;
            continueRawAnalysis(epoch);
        });
    }

    void WorkbenchPseudocodeView::continueRawAnalysis(const quint64 epoch)
    {
        if (epoch_ != epoch || !rawPlanner_ || !provider_) return;
        // The local lease also survives a custom provider invalidating its host
        // synchronously; no planner owns or calls the provider after this turn.
        const auto planner = rawPlanner_;
        const auto* source = provider_;
        const auto readLimit = context_.maximumWindowBytes ? context_.maximumWindowBytes : 65536;
        const QPointer<WorkbenchPseudocodeView> self(this);
        const auto result = planner->advance([self, source, readLimit, epoch](const std::uint64_t address,
            const std::uint64_t length) {
            detail::RawCodePlanner::Page page;
            page.address = address;
            if (!self || self->epoch_ != epoch || self->provider_ != source) return page;
            page.ok = true;
            page.bytes.resize(static_cast<std::size_t>(length));
            page.validMask.resize(static_cast<std::size_t>(length), 2);
            for (std::uint64_t offset = 0; offset < length;)
            {
                if (!self || self->epoch_ != epoch || self->provider_ != source) return detail::RawCodePlanner::Page{};
                const auto count = std::min({length - offset, readLimit, std::uint64_t{65536}});
                const auto window = source->FetchWindow(address + offset, count);
                if (!self || self->epoch_ != epoch || self->provider_ != source) return detail::RawCodePlanner::Page{};
                if (window.ok)
                {
                    if (window.address != address + offset || window.bytes.size() != count || window.validMask.size() != count)
                    {
                        page.bytes.clear(); // A malformed provider is not a pending page.
                        return page;
                    }
                    std::copy(window.bytes.begin(), window.bytes.end(), page.bytes.begin() + static_cast<std::ptrdiff_t>(offset));
                    std::copy(window.validMask.begin(), window.validMask.end(), page.validMask.begin() + static_cast<std::ptrdiff_t>(offset));
                }
                offset += count;
            }
            return page;
        }, 128);
        if (!self || epoch_ != epoch || rawPlanner_ != planner) return;
        using Status = detail::RawCodePlanner::Status;
        if (result.status == Status::NeedData)
        {
            waitingForBytes_ = true;
            const std::pair<quint64, quint64> needed{result.address, result.length};
            if (rawRequestedWindow_ != needed)
            {
                rawRequestedWindow_ = needed;
                emit windowRequested(result.address, result.length);
            }
            return;
        }
        waitingForBytes_ = false;
        rawRequestedWindow_.reset();
        if (result.status == Status::Yield)
        {
            queueRawAnalysis();
            return;
        }
        if (result.status == Status::Error)
        {
            failRawAnalysis(QString::fromStdString(result.error), result.address);
            return;
        }
        DecompilerRequest request;
        request.x64 = context_.addressBits == 64;
        request.selectedAddress = context_.selectedAddress;
        request.entryAddress = rawEntry_;
        for (const auto& segment : planner->segments())
            request.segments.append({segment.address, QByteArray(reinterpret_cast<const char*>(segment.bytes.data()),
                static_cast<qsizetype>(segment.bytes.size()))});
        for (const auto& range : planner->bodyRanges()) request.bodyRanges.append({range.address, range.length});
        if (!request.segments.isEmpty()) request.baseAddress = request.segments.first().address;
        rawPlanner_.reset();
        submitRequest(request);
    }

    bool WorkbenchPseudocodeView::sparseRequestStillCurrent() const
    {
        if (!provider_) return false;
        const QPointer<const WorkbenchPseudocodeView> self(this);
        const auto epoch = epoch_;
        const auto* source = provider_;
        const auto segments = request_.segments;
        auto stamps = requestSegmentStamps_;
        stamps.resize(segments.size());
        const bool allowEvicted = context_.allowEvictedSnapshot;
        const auto readLimit = context_.maximumWindowBytes ? context_.maximumWindowBytes : 65536;
        for (qsizetype i = 0; i < segments.size(); ++i)
        {
            const auto& segment = segments.at(i);
            const auto size = static_cast<std::uint64_t>(segment.bytes.size());
            const auto stamp = source->ContentStamp(segment.address, size);
            if (!self || epoch_ != epoch || provider_ != source) return false;
            if (stamp && stamps.at(i) == stamp) continue;
            for (std::uint64_t offset = 0; offset < size;)
            {
                const auto count = std::min({size - offset, readLimit, std::uint64_t{65536}});
                const auto window = source->FetchWindow(segment.address + offset, count);
                if (!self || epoch_ != epoch || provider_ != source) return false;
                if (!window.ok)
                {
                    if (!allowEvicted) return false;
                }
                else
                {
                    if (window.address != segment.address + offset || window.bytes.size() != count || window.validMask.size() != count)
                        return false;
                    for (std::uint64_t n = 0; n < count; ++n)
                    {
                        if (window.validMask[n] == 2 && allowEvicted) continue;
                        if (window.validMask[n] != 1 || window.bytes[n] != static_cast<std::uint8_t>(segment.bytes.at(static_cast<qsizetype>(offset + n))))
                            return false;
                    }
                }
                offset += count;
            }
            stamps[i] = stamp;
        }
        requestSegmentStamps_ = std::move(stamps);
        return true;
    }
}
