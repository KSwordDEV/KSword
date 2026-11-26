#include "ProjectApiClueArchive.h"

#include <algorithm>

namespace Ksword::ActionAnalyze {
namespace {

namespace Archive = ks::cli::action_analyze::archive;
using V = Evidence::JsonValue;

constexpr std::size_t kBatchRows = 128; // 每个 Stored 块保留的线索上限。

} // namespace

ProjectResult WriteApiClueArchive(ProjectDocument& document, const SampleInfo& sample,
    std::span<const Evidence::ArchivedApiMonitorClue> rows, std::uint64_t sourceRows,
    Evidence::ApiMonitorArchiveSource source, Archive::RawEvidenceReceipt& receipt, bool mixedEtw)
{
    const auto* project = document.Info(); // 项目标识绑定当前持有的目录。
    if (!project) {
        return {ProjectError::NotOpen, 0, "writeClueArchive"};
    }
    // 将线索按原始顺序写入完整的块，不转码原包。
    const auto append = [&](Archive::RawEvidenceArchive& writer) -> ProjectResult {
        for (std::size_t first = 0; first < rows.size(); first += kBatchRows) {
            const auto count = (std::min)(kBatchRows, rows.size() - first); // 本批线索条数。
            std::vector<std::string> metadata; // 保证字段视图在整次 Append 内有效。
            std::vector<Archive::RawEvidenceInput> inputs; // 借用本批完整原包和元数据。
            metadata.reserve(count);
            inputs.reserve(count);
            for (const auto& row : rows.subspan(first, count)) {
                Evidence::JsonObject fields{{"kind", V::makeString(std::string(Evidence::kApiMonitorClueRecord))},
                    {"sourceSequence", V::makeString(std::to_string(row.sourceSequence))}}; // 来源序号不等于归档序号。
                if (row.readerCreation) {
                    fields.emplace_back("readerCreation100ns", V::makeString(std::to_string(row.readerCreation)));
                }
                metadata.push_back(Evidence::WriteJson(V::makeObject(std::move(fields))));
                inputs.push_back({metadata.back(), {reinterpret_cast<const char*>(&row.packet), sizeof(row.packet)}});
            }
            const auto written = writer.Append(inputs); // 块写入失败时不写可被误读为完整的尾记。
            if (written.result.status != Archive::SegmentWriteStatus::Ok) {
                return {ProjectError::IoError, written.result.error.win32Error, "writeClueBlock"};
            }
        }

        // 尾记只说明输入方式和本段计数，不认证历史生产者或覆盖。
        Evidence::JsonObject fields{
            {"kind", V::makeString(std::string(Evidence::kApiMonitorClueEnd))},
            {"archiveSource", V::makeString(std::string(Evidence::ApiMonitorArchiveSourceName(source)))},
            {"sourceRows", V::makeString(std::to_string(sourceRows))}, {"clueRows", V::makeString(std::to_string(rows.size()))}};
        if (mixedEtw) {
            fields.emplace_back("mixedEtw", V::makeBool(true)); // 专用 ETW 流独立发布自己的水位。
        }
        const auto metadata = Evidence::WriteJson(V::makeObject(std::move(fields))); // 已封装的终态声明。
        const Archive::RawEvidenceInput end{metadata, {}}; // 尾记不携带原包。
        const auto written = writer.Append(std::span(&end, 1)); // 单独封装尾记。
        if (written.result.status != Archive::SegmentWriteStatus::Ok) {
            return {ProjectError::IoError, written.result.error.win32Error, "writeClueEnd"};
        }
        return {};
    };
    return document.WriteRawEvidenceSegment({project->projectId, sample.sampleId, 1, {}, append}, receipt);
}

} // namespace Ksword::ActionAnalyze
