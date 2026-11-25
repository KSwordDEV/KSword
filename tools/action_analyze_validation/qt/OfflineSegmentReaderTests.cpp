#include "../../../Ksword5.1/Ksword5.1/ActionAnalyze/OfflineSegmentReader.h"

#include <QString>
#include <cstdio>

namespace
{
    using ks::action_analyze::ReadOfflineSegment;
    using ks::action_analyze::SegmentEnd;

    // 检查一个读取断言；失败时输出夹具名和值的用途。
    bool Check(bool passed, const char* context)
    {
        if (!passed)
        {
            std::fprintf(stderr, "FAIL %s\n", context);
        }
        return passed;
    }
}

// 以固定夹具目录为输入，直接运行产品的 QtCore 读取路径。
int main(int argc, char** argv)
{
    if (argc != 2)
    {
        return 2;
    }
    const auto root = QString::fromLocal8Bit(argv[1]); // 存放可信格式向量的夹具目录。
    const auto read = [&root](const char* name) {
        return ReadOfflineSegment(root + u'/' + QString::fromLatin1(name) + QStringLiteral(".ksaseg"), [] { return false; });
    };
    const auto empty = read("valid-header-alone"); // 完整空文件仍含成对身份。
    bool passed = Check(empty.end == SegmentEnd::Complete && empty.rows.isEmpty() && empty.prefixBytes == 96,
        "valid empty segment");
    passed &= Check(empty.projectId == QStringLiteral("12345678-9abc-4def-8123-456789abcdef") &&
        empty.sampleId == QStringLiteral("fedcba98-7654-4321-a234-56789abcdef0"), "paired RFC UUIDs");

    const auto events = read("event-segment-with-known-zeroes"); // A0 向量的零值及固定字段。
    passed &= Check(events.end == SegmentEnd::Complete && events.rows.size() == 1 &&
        events.prefixBytes == events.fileBytes, "canonical segment");
    if (events.rows.size() == 1)
    {
        const auto& row = events.rows.front(); // 已验证的真实记录。
        passed &= Check(row.ordinal == 0 && row.receiveQpc == 2387509390608836392ull && row.decoded &&
            row.type == 4 && row.sequence == 29 && row.offset == 176,
            "known zero values, record type and offset");
        passed &= Check(row.category == 21862 && row.eventKind == 287454020 && row.sourceId == 72623859790382856ull &&
            !row.pid && !row.tid, "category and unresolved source, absent header IDs");
    }

    const auto partial = read("truncated-second-block-payload"); // 已通过校验的首块保留。
    passed &= Check(partial.end == SegmentEnd::Truncated && partial.rows.size() == 1 && partial.prefixBytes == 218 &&
        partial.prefixBytes < partial.fileBytes, "verified prefix after truncated block");
    const auto damaged = read("bad-second-stored-crc"); // 后续 CRC 失败不得提供行。
    passed &= Check(damaged.end == SegmentEnd::Invalid && damaged.rows.size() == 1 && damaged.prefixBytes == 218,
        "verified prefix after bad block CRC");
    const auto badBody = read("event-json-length-disagrees-with-payload"); // 封装可读不代表正文有效。
    passed &= Check(badBody.end == SegmentEnd::Invalid && badBody.rows.isEmpty() && badBody.prefixBytes == 96,
        "malformed canonical body");

    const auto optional = read("optional-unknown-record"); // 可选未知记录只保留封装字段。
    passed &= Check(optional.end == SegmentEnd::Complete && optional.rows.size() == 1 &&
        !optional.rows.front().decoded && !optional.rows.front().category, "opaque optional row");
    const auto required = read("required-unknown-record"); // 必需未知记录终止语义预览。
    passed &= Check(required.end == SegmentEnd::Unsupported && required.rows.isEmpty() && required.prefixBytes == 96,
        "unsupported required record");
    passed &= Check(read("unavailable-zstd").end == SegmentEnd::Unsupported, "unsupported codec");
    passed &= Check(read("missing").end == SegmentEnd::Unavailable, "missing file");

    // 在首条记录回调取消，确认已读取头部也不会产出正文行。
    int checks = 0; // 取消令牌读取次数，初次放行，下一次取消。
    const auto canceled = ReadOfflineSegment(events.path, [&checks]() { return ++checks > 1; });
    passed &= Check(canceled.end == SegmentEnd::Canceled && canceled.rows.isEmpty(), "canceled during preview");
    if (passed)
    {
        std::puts("PASS 13 QtCore Stored reader assertions");
    }
    return passed ? 0 : 1;
}
