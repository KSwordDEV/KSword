#include "OfflineProjectReader.h"
#include "../../../shared/evidence/EvidenceJson.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QRegularExpression>
#include <QSet>
#include <QStringConverter>
#include <algorithm>
#include <cstdint>

namespace ks::action_analyze
{
namespace
{
    using Ksword::Evidence::JsonValue;
    using Ksword::Evidence::JsonType;

    // A1 离线元数据格式的读取配额，与已发布目录分页一致。
    constexpr auto kDocumentLimit = 4 * 1024 * 1024;
    constexpr quint64 kSamplesPerPage = 256;
    constexpr quint64 kSampleLimit = 4096;
    constexpr quint64 kGenerationLimit = 8192;

    // 从 JSON 读取严格字符串；缺失或类型不符返回空字符串。
    QString Text(const JsonValue& object, std::string_view key)
    {
        const auto* field = object.find(key); // 原始字段，不把数值隐式转为文本。
        std::string utf8; // 保留解析器解码后的原始 UTF-8。
        return field && field->tryGetString(utf8) ? QString::fromStdString(utf8) : QString();
    }

    // 将 A0 的十进制字符串读为 u64，不接受符号、前导零或溢出。
    bool Number(const JsonValue& object, std::string_view key, quint64& result)
    {
        static const QRegularExpression decimal(QStringLiteral("\\A(?:0|[1-9][0-9]*)\\z"));
        const QString text = Text(object, key); // 严格格式检查后才转换数值。
        if (!decimal.match(text).hasMatch())
        {
            return false;
        }
        bool valid = false; // Qt 转换返回的上界检查。
        result = text.toULongLong(&valid);
        return valid;
    }

    // 校验可用于目录名的标准 UUID，排除全零哨兵。
    bool IsId(const QString& id)
    {
        static const QRegularExpression uuid(QStringLiteral(
            "\\A[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}\\z"));
        return id != QLatin1String("00000000-0000-0000-0000-000000000000") && uuid.match(id).hasMatch();
    }

    // 校验原文 SHA-256 的规范小写形式。
    bool IsHash(const QString& hash)
    {
        static const QRegularExpression sha256(QStringLiteral("\\A[0-9a-f]{64}\\z"));
        return sha256.match(hash).hasMatch();
    }

    // 校验标题或说明原文长度与控制字符；说明允许换行和制表符。
    bool IsText(const QString& value, qsizetype maxBytes, bool multiline = false)
    {
        return !value.isNull() && (multiline || !value.isEmpty()) && value.toUtf8().size() <= maxBytes
            && std::none_of(value.cbegin(), value.cend(), [multiline](QChar character) {
                return character.unicode() < 32 && !(multiline && (character == u'\n' || character == u'\t'));
            });
    }

    // 比较明确的 JSON null；缺少字段不能被解释为未采集。
    bool IsNull(const JsonValue& object, std::string_view key)
    {
        const auto* field = object.find(key);
        return field && field->isNull();
    }

    // 校验每一级路径的可见身份，只接受所选本地项目下的普通文件。
    bool IsDirectPath(const QFileInfo& info, bool directory)
    {
        return !info.isSymLink() && !info.isJunction()
            && (directory ? info.isDir() : info.isFile())
            && QDir::cleanPath(info.canonicalFilePath()).compare(info.absoluteFilePath(), Qt::CaseInsensitive) == 0;
    }

    // 读取指定相对路径的 UTF-8 JSON，并在解析前复核原始字节散列。
    ReadProblem ReadDocument(const QDir& root, const QString& relativeFile, const QString& expectedHash,
        const CancelCheck& isCanceled, JsonValue& document)
    {
        if (isCanceled())
        {
            return { ReadStatus::Canceled, relativeFile };
        }
        QString path = root.absolutePath(); // 每次只拼接已冻结的规范分量。
        const auto parts = relativeFile.split(u'/');
        for (qsizetype index = 0; index < parts.size(); ++index)
        {
            path += QLatin1Char('/') + parts.at(index);
            if (!IsDirectPath(QFileInfo(path), index + 1 < parts.size()))
            {
                return { ReadStatus::Unavailable, relativeFile };
            }
        }

        // 用只读、带上界的读取应对在途修改和非法大文件。
        QFile file(path);
        if (!file.open(QIODevice::ReadOnly))
        {
            return { ReadStatus::Unavailable, relativeFile };
        }
        const QByteArray bytes = file.read(kDocumentLimit + 1); // 保留原文供散列和验证。
        if (file.error() != QFileDevice::NoError)
        {
            return { ReadStatus::Unavailable, relativeFile };
        }
        if (bytes.size() > kDocumentLimit || bytes.startsWith("\xef\xbb\xbf") || bytes.contains('\r')
            || (!expectedHash.isEmpty() && QCryptographicHash::hash(bytes, QCryptographicHash::Sha256).toHex()
                != expectedHash.toLatin1()))
        {
            return { ReadStatus::Invalid, relativeFile };
        }

        // 公共纯值解析器拒绝重复键、溢出和浮点；独立检查 UTF-8 编码。
        QStringDecoder decoder(QStringDecoder::Utf8, QStringConverter::Flag::Stateless);
        const QString decoded = decoder.decode(bytes);
        if (decoder.hasError() || decoded.isEmpty())
        {
            return { ReadStatus::Invalid, relativeFile };
        }
        Ksword::Evidence::JsonLimits limits;
        limits.maxDepth = 32;
        limits.maxStringBytes = 64 * 1024;
        limits.maxTotalBytes = kDocumentLimit;
        limits.maxContainerItems = kSamplesPerPage;
        limits.maxTotalNodes = 4096;
        auto parsed = Ksword::Evidence::ParseJson(std::string_view(bytes.constData(), bytes.size()), limits);
        if (!parsed.ok() || !parsed.value.asObject())
        {
            return { ReadStatus::Invalid, relativeFile };
        }
        document = std::move(parsed.value);
        return {};
    }

    // 读取项目清单、采样目录使用的根目录；不接受 UNC 或链接项目根。
    bool ResolveRoot(const QString& manifestPath, QDir& root)
    {
        const QFileInfo selection(manifestPath);
        root = selection.absoluteDir();
        const auto path = root.absolutePath();
        return selection.fileName().compare(QLatin1String("project.ksaproj"), Qt::CaseInsensitive) == 0
            && path.size() >= 3 && path.at(1) == u':' && path.at(2) == u'/'
            && IsDirectPath(QFileInfo(path), true);
    }

    // 提取目录记录与描述文件共用的五个原始字段。
    bool ReadSummary(const JsonValue& document, SampleSummary& result)
    {
        result.id = Text(document, "sampleId");
        result.title = Text(document, "title");
        result.revisionId = Text(document, "revisionId");
        result.snapshotId = Text(document, "snapshotId");
        return IsId(result.id) && IsId(result.revisionId) && IsId(result.snapshotId)
            && IsText(result.title, 1024) && Number(document, "createdUtc", result.createdUtc) && result.createdUtc;
    }

    // 校验目录页的项目、代次、页号及行数，然后往后台快照添加唯一采样。
    bool AppendPage(const JsonValue& document, const QString& projectId, quint64 generation,
        quint64 pageId, quint64 rowCount, QSet<QString>& ids, QList<SampleSummary>& rows)
    {
        quint64 actualGeneration = 0;
        quint64 actualPage = 0;
        const auto* field = document.find("samples");
        const auto* entries = field ? field->asArray() : nullptr;
        if (Text(document, "kind") != QLatin1String("sample-catalog-page") || Text(document, "projectId") != projectId
            || !Number(document, "generation", actualGeneration) || actualGeneration != generation
            || !Number(document, "pageId", actualPage) || actualPage != pageId
            || !entries || entries->size() != rowCount)
        {
            return false;
        }
        for (const auto& entry : *entries)
        {
            SampleSummary row; // 该页中的新采样身份与描述散列。
            row.descriptionHash = Text(entry, "descriptionHash");
            if (!ReadSummary(entry, row) || !IsHash(row.descriptionHash) || ids.contains(row.id))
            {
                return false;
            }
            ids.insert(row.id);
            rows.append(std::move(row));
        }
        return true;
    }
}

// 只读目录快照沿主清单的引用读取，不扫描样本目录或抢占写者。
ProjectSnapshot ReadProjectCatalog(const QString& manifestPath, const CancelCheck& isCanceled)
{
    const auto headFile = QStringLiteral("project.ksaproj"); // 生产写者的正式发布指针。
    ProjectSnapshot snapshot;
    snapshot.manifestPath = manifestPath;
    QDir root;
    if (!ResolveRoot(manifestPath, root))
    {
        snapshot.problem = { ReadStatus::Unavailable, headFile };
        return snapshot;
    }
    JsonValue head; // 整次读取只绑定第一次读取的清单代次。
    snapshot.problem = ReadDocument(root, headFile, {}, isCanceled, head);
    if (snapshot.problem.status != ReadStatus::Ready)
    {
        return snapshot;
    }
    if (Text(head, "kind") != QLatin1String("action-analyze-project"))
    {
        snapshot.problem = { ReadStatus::Invalid, headFile };
        return snapshot;
    }

    const auto* version = head.find("version");
    const auto* features = head.find("requiredFeatures");
    const auto* required = features ? features->asArray() : nullptr;
    std::uint64_t number = 0; // 公共 JSON 解析器要求的数值输出类型。
    std::string feature;
    if (!version || version->type() != JsonType::UInt || !version->tryGetU64(number) || number != 1
        || !required || required->size() != 1 || !required->front().tryGetString(feature)
        || feature != "cli-offline-project-v1" || Text(head, "producer") != QLatin1String("KswordCLI")
        || Text(head, "storagePolicy") != QLatin1String("local-ntfs-offline-metadata"))
    {
        snapshot.problem = { ReadStatus::Unsupported, headFile };
        return snapshot;
    }

    // 清单必须绑定合法项目身份、当前修订和不可变目录根。
    snapshot.id = Text(head, "projectId");
    snapshot.title = Text(head, "title");
    snapshot.revisionId = Text(head, "currentRevisionId");
    const auto* reference = head.find("catalogRoot");
    quint64 catalogGeneration = 0;
    const auto catalogHash = reference ? Text(*reference, "hash") : QString();
    if (!IsId(snapshot.id) || !IsId(snapshot.revisionId) || !IsText(snapshot.title, 1024)
        || !Number(head, "journalGeneration", snapshot.generation) || snapshot.generation > kGenerationLimit
        || !reference || !Number(*reference, "generation", catalogGeneration) || !catalogGeneration
        || catalogGeneration > snapshot.generation || !IsHash(catalogHash))
    {
        snapshot.problem = { ReadStatus::Invalid, headFile };
        return snapshot;
    }

    const auto catalogFolder = QStringLiteral("catalog/%1/").arg(catalogGeneration);
    const auto catalogFile = catalogFolder + QStringLiteral("manifest.json");
    JsonValue catalog; // 包含只读页的顺序和预期散列。
    snapshot.problem = ReadDocument(root, catalogFile, catalogHash, isCanceled, catalog);
    if (snapshot.problem.status != ReadStatus::Ready)
    {
        return snapshot;
    }
    quint64 sampleCount = 0;
    quint64 actualGeneration = 0;
    const auto* hashes = catalog.find("pageHashes");
    const auto* pages = hashes ? hashes->asArray() : nullptr;
    if (Text(catalog, "kind") != QLatin1String("sample-catalog") || Text(catalog, "projectId") != snapshot.id
        || !Number(catalog, "generation", actualGeneration) || actualGeneration != catalogGeneration
        || !Number(catalog, "sampleCount", sampleCount) || sampleCount > kSampleLimit
        || !pages || pages->size() != (sampleCount + kSamplesPerPage - 1) / kSamplesPerPage)
    {
        snapshot.problem = { ReadStatus::Invalid, catalogFile };
        return snapshot;
    }

    QSet<QString> sampleIds; // 整个目录中禁止重复或跨页冲突的采样 ID。
    snapshot.samples.reserve(static_cast<qsizetype>(sampleCount));
    for (std::size_t pageIndex = 0; pageIndex < pages->size(); ++pageIndex)
    {
        std::string hash;
        const auto pageId = static_cast<quint64>(pageIndex + 1);
        const auto pageFile = catalogFolder + QString::number(pageId) + QStringLiteral(".json");
        if (!(*pages)[pageIndex].tryGetString(hash) || !IsHash(QString::fromStdString(hash)))
        {
            snapshot.problem = { ReadStatus::Invalid, catalogFile };
            break;
        }
        JsonValue page;
        snapshot.problem = ReadDocument(root, pageFile, QString::fromStdString(hash), isCanceled, page);
        if (snapshot.problem.status != ReadStatus::Ready)
        {
            break;
        }
        const auto expectedRows = std::min(kSamplesPerPage, sampleCount - pageIndex * kSamplesPerPage);
        if (!AppendPage(page, snapshot.id, catalogGeneration, pageId, expectedRows, sampleIds, snapshot.samples))
        {
            snapshot.problem = { ReadStatus::Invalid, pageFile };
            break;
        }
    }
    if (snapshot.problem.status != ReadStatus::Ready)
    {
        snapshot.samples.clear(); // 不将残缺目录当作完整结果发布。
    }
    return snapshot;
}

// 目录行绑定描述文件，描述文件再绑定冻结的配置快照。
SampleDetails ReadSampleDetails(const SampleRequest& request, const CancelCheck& isCanceled)
{
    SampleDetails result;
    const auto& expected = request.sample;
    const auto folder = QStringLiteral("samples/%1/").arg(expected.id);
    const auto descriptionFile = folder + QStringLiteral("sample.json");
    QDir root;
    if (!ResolveRoot(request.manifestPath, root) || !IsId(expected.id) || !IsId(expected.snapshotId)
        || !IsHash(expected.descriptionHash))
    {
        result.problem = { ReadStatus::Unavailable, descriptionFile };
        return result;
    }

    JsonValue description;
    result.problem = ReadDocument(root, descriptionFile, expected.descriptionHash, isCanceled, description);
    if (result.problem.status != ReadStatus::Ready)
    {
        return result;
    }
    if (Text(description, "kind") != QLatin1String("offline-sample")
        || Text(description, "producer") != QLatin1String("KswordCLI")
        || Text(description, "status") != QLatin1String("not-collected"))
    {
        result.problem = { ReadStatus::Unsupported, descriptionFile };
        return result;
    }
    SampleSummary actual; // 核对目录摘要没有被不同采样的描述替换。
    const auto snapshotHash = Text(description, "snapshotHash");
    if (Text(description, "projectId") != request.projectId || !ReadSummary(description, actual)
        || actual.id != expected.id || actual.revisionId != expected.revisionId || actual.snapshotId != expected.snapshotId
        || actual.title != expected.title || actual.createdUtc != expected.createdUtc || !IsHash(snapshotHash)
        || !IsNull(description, "requestedBackend") || !IsNull(description, "actualBackend")
        || !IsNull(description, "initialTarget"))
    {
        result.problem = { ReadStatus::Invalid, descriptionFile };
        return result;
    }

    const auto snapshotFile = folder + QStringLiteral("snapshots/%1.json").arg(expected.snapshotId);
    JsonValue snapshot;
    result.problem = ReadDocument(root, snapshotFile, snapshotHash, isCanceled, snapshot);
    if (result.problem.status != ReadStatus::Ready)
    {
        return result;
    }
    const auto* config = snapshot.find("config");
    result.configurationTitle = config ? Text(*config, "title") : QString();
    result.configurationNotes = config ? Text(*config, "notes") : QString();
    result.configurationHash = Text(snapshot, "configSemanticHash");
    if (Text(snapshot, "kind") != QLatin1String("offline-config-snapshot")
        || Text(snapshot, "projectId") != request.projectId || Text(snapshot, "sampleId") != expected.id
        || Text(snapshot, "snapshotId") != expected.snapshotId || Text(snapshot, "revisionId") != expected.revisionId
        || !IsHash(Text(snapshot, "revisionHash")) || !IsHash(result.configurationHash)
        || !IsText(result.configurationTitle, 1024) || !IsText(result.configurationNotes, 64 * 1024, true))
    {
        result.problem = { ReadStatus::Invalid, snapshotFile };
    }
    return result;
}
}
