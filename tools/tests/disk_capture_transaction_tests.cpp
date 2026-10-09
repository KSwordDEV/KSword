#include "../../Ksword5.1/Ksword5.1/MiscDock/DiskEditor/DiskCaptureTransaction.h"
#include <iostream>
#include <cstdlib>

namespace
{
    unsigned checks = 0; // checks：实际执行的断言数量。
    void require(const bool condition, const char* label)
    {
        ++checks;
        if (!condition)
        {
            std::cerr << "FAIL: " << label << '\n';
            std::exit(1);
        }
    }

    ks::misc::DiskCapturedRange capture()
    {
        ks::misc::DiskCapturedRange result; // result：只在内存构造的设备与扇区证据。
        result.source.diskIndex = 3;
        result.source.devicePath = QStringLiteral("fixture-disk-A");
        result.source.serial = QStringLiteral("serial-A");
        result.source.vendor = QStringLiteral("fixture-vendor");
        result.source.model = QStringLiteral("fixture-model");
        result.source.sizeBytes = 4096;
        result.source.bytesPerSector = 512;
        result.deviceIdentity = QStringLiteral("guid-A");
        result.backend = 1;
        result.generation = 7;
        result.offset = 512;
        result.original = QByteArray(512, 'A');
        return result;
    }

    struct MemoryDisk
    {
        QString identity = QStringLiteral("guid-A"); // identity：可模拟热替换的身份。
        QByteArray bytes = QByteArray(512, 'A');      // bytes：唯一目标，不访问系统磁盘。
        unsigned reads = 0, writes = 0, identities = 0;
        bool identityFails = false, readFails = false, writeFails = false;
        bool wrongReadback = false, swapBeforeWrite = false, swapAfterWrite = false;

        ks::misc::DiskWritePorts ports()
        {
            return {
                [this](QString& value, QString& error) {
                    ++identities;
                    if (identityFails) { error = QStringLiteral("identity failed"); return false; }
                    value = (swapBeforeWrite && identities >= 2) || (swapAfterWrite && writes)
                        ? QStringLiteral("guid-B") : identity;
                    return true;
                },
                [this](QByteArray& value, QString& error) {
                    ++reads;
                    if (readFails) { error = QStringLiteral("read failed"); return false; }
                    value = bytes;
                    if (wrongReadback && writes) value[0] = 'X';
                    return true;
                },
                [this](const QByteArray& value, QString& error) {
                    ++writes;
                    if (writeFails)
                    {
                        bytes[0] = 'Z'; // 模拟部分生效，回执必须标记写尝试而不是成功。
                        error = QStringLiteral("partial write failed");
                        return false;
                    }
                    bytes = value;
                    return true;
                }
            };
        }
    };
}

int main()
{
    using namespace ks::misc;
    const auto original = capture();
    const QByteArray replacement(512, 'B');
    require(CapturedDiskMatches(original, original.source, 1, 7), "matching captured source");
    auto selected = original.source;
    selected.diskIndex = 4;
    require(!CapturedDiskMatches(original, selected, 1, 7), "switch A to B invalidates source");
    selected = original.source;
    selected.serial = QStringLiteral("serial-B");
    require(!CapturedDiskMatches(original, selected, 1, 7), "same disk number different serial rejected");
    selected = original.source;
    selected.sizeBytes *= 2;
    require(!CapturedDiskMatches(original, selected, 1, 7), "capacity changed rejected");
    require(!CapturedDiskMatches(original, original.source, 2, 7), "backend switch invalidates source");
    require(!CapturedDiskMatches(original, original.source, 1, 8), "new enumeration/read invalidates generation");

    MemoryDisk normal;
    const auto committed = ApplyCapturedDiskWrite(original, replacement, normal.ports());
    require(committed.success && committed.writeAttempted, "successful write has verified receipt");
    require(committed.observed == replacement && normal.bytes == replacement, "baseline comes from actual readback");
    require(normal.identities == 3 && normal.reads == 2 && normal.writes == 1, "identity and original checks surround one write");

    MemoryDisk changedBytes;
    changedBytes.bytes[17] = 'C';
    const auto conflict = ApplyCapturedDiskWrite(original, replacement, changedBytes.ports());
    require(!conflict.success && !conflict.writeAttempted && changedBytes.writes == 0, "external byte change prevents writing");
    MemoryDisk changedIdentity;
    changedIdentity.identity = QStringLiteral("guid-B");
    const auto wrongTarget = ApplyCapturedDiskWrite(original, replacement, changedIdentity.ports());
    require(!wrongTarget.success && changedIdentity.reads == 0 && changedIdentity.writes == 0, "changed target rejected before read/write");
    MemoryDisk swap;
    swap.swapBeforeWrite = true;
    const auto swapped = ApplyCapturedDiskWrite(original, replacement, swap.ports());
    require(!swapped.success && swap.reads == 1 && swap.writes == 0, "identity rechecked after original read");
    MemoryDisk lateSwap;
    lateSwap.swapAfterWrite = true;
    const auto late = ApplyCapturedDiskWrite(original, replacement, lateSwap.ports());
    require(!late.success && late.writeAttempted, "post-write target replacement cannot report success");

    MemoryDisk unreadable;
    unreadable.readFails = true;
    require(!ApplyCapturedDiskWrite(original, replacement, unreadable.ports()).success && unreadable.writes == 0,
        "unreadable original cannot be written");
    MemoryDisk failedIdentity;
    failedIdentity.identityFails = true;
    require(!ApplyCapturedDiskWrite(original, replacement, failedIdentity.ports()).success && failedIdentity.writes == 0,
        "identity query failure cannot be written");
    MemoryDisk partial;
    partial.writeFails = true;
    const auto failedWrite = ApplyCapturedDiskWrite(original, replacement, partial.ports());
    require(!failedWrite.success && failedWrite.writeAttempted && partial.bytes != original.original,
        "failed partial write explicitly invalidates old baseline");
    MemoryDisk mismatched;
    mismatched.wrongReadback = true;
    const auto mismatch = ApplyCapturedDiskWrite(original, replacement, mismatched.ports());
    require(!mismatch.success && mismatch.writeAttempted && mismatch.observed != replacement,
        "readback mismatch cannot report success");

    for (int scenario = 0; scenario < 6; ++scenario)
    {
        auto invalid = original; // invalid：不合法捕获在端口调用之前拒绝。
        QByteArray candidate = replacement;
        if (scenario == 0) invalid.deviceIdentity.clear();
        if (scenario == 1) ++invalid.offset;
        if (scenario == 2) candidate.chop(1);
        if (scenario == 3) invalid.source.sizeBytes = invalid.offset;
        if (scenario == 4) invalid.source.bytesPerSector = 0;
        if (scenario == 5) invalid.offset = UINT64_MAX;
        MemoryDisk target;
        const auto refused = ApplyCapturedDiskWrite(invalid, candidate, target.ports());
        require(!refused.success && !refused.writeAttempted && target.identities == 0 && target.writes == 0,
            "invalid captured bounds/alignment/identity rejected without IO");
    }
    std::cout << "DISK_CAPTURE_TRANSACTION_CHECKS=" << checks << " FAILURES=0\n";
}
