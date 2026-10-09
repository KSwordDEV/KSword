#include "ProcessDetailWindow.InternalCommon.h"

#include "../ksword/profile/ProfileJsonLoader.h"

// ============================================================
// ProcessDetailWindow.PdbCatalog.cpp
// 作用：
// - 只读解析 profiles\pdb_deep_offsets 中的 ntkrnlmp deep offset JSON；
// - 为进程详情/线程详情提供备用 PDB 偏移目录预览；
// - 不触发驱动调用，不修改任何 profile 文件。
// ============================================================

#include <QCoreApplication>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QIODevice>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QMutex>
#include <QMutexLocker>
#include <QStringList>

#include <algorithm>
#include <utility>

namespace process_detail_window_internal
{
    namespace
    {
        // findPdbDeepOffsetDirectory 作用：
        // - 输入无；
        // - 处理：按 Release 布局、开发工作目录布局逐个查找 profiles\pdb_deep_offsets；
        // - 返回：存在的目录；找不到时返回空字符串。
        QString findPdbDeepOffsetDirectory()
        {
            QStringList candidateDirectories;
            const QString applicationDirectory = QCoreApplication::applicationDirPath();
            const QString currentDirectory = QDir::currentPath();

            candidateDirectories.push_back(
                QDir(applicationDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
            candidateDirectories.push_back(
                QDir(applicationDirectory).filePath(QStringLiteral("../profiles/pdb_deep_offsets")));
            candidateDirectories.push_back(
                QDir(currentDirectory).filePath(QStringLiteral("profiles/pdb_deep_offsets")));
            candidateDirectories.push_back(
                QDir(currentDirectory).filePath(QStringLiteral("Ksword5.1/Ksword5.1/profiles/pdb_deep_offsets")));

            for (const QString& directoryText : candidateDirectories)
            {
                QDir candidateDirectory(directoryText);
                if (candidateDirectory.exists())
                {
                    return candidateDirectory.absolutePath();
                }
            }

            return QString();
        }

        // findNtosDeepOffsetJsonPath 作用：
        // - 输入无；
        // - 处理：在 deep offset 目录中定位 ntkrnlmp_*_deep_offsets.json；
        // - 返回：第一个匹配 JSON 文件路径，找不到时返回空字符串。
        QString findNtosDeepOffsetJsonPath()
        {
            const QString directoryText = findPdbDeepOffsetDirectory();
            if (directoryText.isEmpty())
            {
                return QString();
            }

            QDir directory(directoryText);
            QStringList fileNames = directory.entryList(
                QStringList{ QStringLiteral("ntkrnlmp_*_deep_offsets.json.qz") },
                QDir::Files,
                QDir::Name);
            if (fileNames.isEmpty())
            {
                fileNames = directory.entryList(
                    QStringList{ QStringLiteral("ntkrnlmp_*_deep_offsets.json") },
                    QDir::Files,
                    QDir::Name);
            }
            if (fileNames.isEmpty())
            {
                return QString();
            }

            return directory.absoluteFilePath(fileNames.first());
        }

        // findDynDataPackJsonPath 作用：
        // - 输入无；
        // - 处理：优先从 deep offset 目录的父级 profiles 定位 ark_dyndata_pack_v4.json；
        // - 返回：找到的 v4 pack 路径，找不到时返回空字符串。
        QString findDynDataPackJsonPath()
        {
            QStringList candidatePaths;
            const QString deepDirectoryText = findPdbDeepOffsetDirectory();
            if (!deepDirectoryText.isEmpty())
            {
                QDir profileDirectory(deepDirectoryText);
                profileDirectory.cdUp();
                candidatePaths.push_back(profileDirectory.filePath(QStringLiteral("ark_dyndata_pack_v4.json")));
            }

            const QString applicationDirectory = QCoreApplication::applicationDirPath();
            const QString currentDirectory = QDir::currentPath();
            candidatePaths.push_back(QDir(applicationDirectory).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
            candidatePaths.push_back(QDir(applicationDirectory).filePath(QStringLiteral("../profiles/ark_dyndata_pack_v4.json")));
            candidatePaths.push_back(QDir(currentDirectory).filePath(QStringLiteral("profiles/ark_dyndata_pack_v4.json")));
            candidatePaths.push_back(QDir(currentDirectory).filePath(QStringLiteral("Ksword5.1/Ksword5.1/profiles/ark_dyndata_pack_v4.json")));

            for (const QString& pathText : candidatePaths)
            {
                const QString resolvedPath = ks::profile::resolveProfileJsonPath(pathText);
                if (!resolvedPath.isEmpty())
                {
                    return QFileInfo(resolvedPath).absoluteFilePath();
                }
            }
            return QString();
        }

        // normalizeGuidText 作用：
        // - 输入 PDB GUID 文本，可能带大括号或连字符；
        // - 处理：去掉装饰字符并转小写，便于 deep JSON 与 pack JSON 比较；
        // - 返回：32 位十六进制 GUID 文本；无法规范化时返回原始小写文本。
        QString normalizeGuidText(const QString& guidText)
        {
            QString normalizedText = guidText.trimmed().toLower();
            normalizedText.remove(QChar('{'));
            normalizedText.remove(QChar('}'));
            normalizedText.remove(QChar('-'));
            normalizedText.remove(QChar(' '));
            return normalizedText;
        }

        // readJsonObjectFromFile 作用：
        // - 输入 pathText：JSON 文件路径；
        // - 处理：只读打开并解析对象根；
        // - 返回：解析成功时返回 object，否则返回空 object 并写 detailTextOut。
        QJsonObject readJsonObjectFromFile(const QString& pathText, QString* detailTextOut)
        {
            QJsonParseError parseError{};
            QString readErrorText;
            const QJsonDocument document = ks::profile::readProfileJsonDocument(pathText, &parseError, &readErrorText);
            if (parseError.error != QJsonParseError::NoError || !document.isObject())
            {
                if (detailTextOut != nullptr)
                {
                    *detailTextOut = QStringLiteral("JSON 解析失败：%1；文件=%2")
                        .arg(readErrorText.isEmpty() ? parseError.errorString() : readErrorText)
                        .arg(pathText);
                }
                return {};
            }

            return document.object();
        }

        // jsonString 作用：
        // - 输入 object/name/fallback；
        // - 处理：从 JSON object 中读取字符串字段；
        // - 返回：字段存在时返回字符串，否则返回 fallback。
        QString jsonString(const QJsonObject& object, const QString& name, const QString& fallback)
        {
            const QJsonValue value = object.value(name);
            return value.isString() ? value.toString() : fallback;
        }

        // jsonInt 作用：
        // - 输入 object/name/fallback；
        // - 处理：从 JSON object 中读取整数；
        // - 返回：字段存在时返回整数，否则返回 fallback。
        int jsonInt(const QJsonObject& object, const QString& name, const int fallback)
        {
            const QJsonValue value = object.value(name);
            return value.isDouble() ? value.toInt(fallback) : fallback;
        }

        // formatCatalogFieldLine 作用：
        // - 输入 fieldObject 为 deep catalog 的单个字段描述；
        // - 处理：提取 qualifiedName/offset/type/bitfield/alias；
        // - 返回：一行可读偏移目录文本。


        // formatCatalogDomain 作用：
        // - 输入 domainObject/maxTypes/maxFieldsPerType；
        // - 处理：把目标 domain 下的类型和字段裁剪成预览；
        // - 返回：适合 StructuredFieldView 展示的多行文本。
        // jsonHexUInt32 作用：
        // - 输入 object/name/fallback；
        // - 处理：优先解析 0x 前缀字符串，其次读取 JSON number；
        // - 返回：32 位无符号数，失败返回 fallback。
        std::uint32_t jsonHexUInt32(
            const QJsonObject& object,
            const QString& name,
            const std::uint32_t fallback)
        {
            const QJsonValue value = object.value(name);
            if (value.isString())
            {
                QString text = value.toString().trimmed();
                if (text.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive))
                {
                    text = text.mid(2);
                }
                bool ok = false;
                const quint64 parsedValue = text.toULongLong(&ok, 16);
                return ok ? static_cast<std::uint32_t>(parsedValue) : fallback;
            }
            if (value.isDouble())
            {
                return static_cast<std::uint32_t>(value.toDouble());
            }
            return fallback;
        }

        // inferRuntimeSampleSize 作用：
        // - 输入 PDB 字段类型文本和 bitfield 描述；
        // - 处理：只允许可安全小读的指针/整数/LIST_ENTRY/CLIENT_ID 等小结构；
        // - 返回：1/2/4/8/16 字节，无法判断时返回 0 表示跳过。
        std::uint32_t inferRuntimeSampleSize(const QString& fieldTypeText, const QJsonObject& bitFieldObject)
        {
            const QString lowerTypeText = fieldTypeText.toLower();
            if (!bitFieldObject.isEmpty() || lowerTypeText.contains(QStringLiteral("bitfield")))
            {
                return 4U;
            }
            if (lowerTypeText.contains(QStringLiteral("[15]")) &&
                (lowerTypeText.contains(QStringLiteral("char")) || lowerTypeText.contains(QStringLiteral("0x0020"))))
            {
                return 15U;
            }
            if (lowerTypeText.contains(QStringLiteral("_client_id")) ||
                lowerTypeText.contains(QStringLiteral("_unicode_string")))
            {
                return 16U;
            }
            if (lowerTypeText.contains(QStringLiteral("_ex_fast_ref")))
            {
                return 8U;
            }
            if (lowerTypeText.contains(QStringLiteral("_ps_protection")))
            {
                return 1U;
            }
            if (lowerTypeText.contains(QStringLiteral("_list_entry")))
            {
                return 16U;
            }
            if (lowerTypeText.contains(QStringLiteral("void*")) || lowerTypeText.contains(QChar('*')))
            {
                return 8U;
            }
            if (lowerTypeText.contains(QStringLiteral("__int64")) ||
                lowerTypeText.contains(QStringLiteral("large_integer")) ||
                lowerTypeText.contains(QStringLiteral("unsigned long long")))
            {
                return 8U;
            }
            if (lowerTypeText.contains(QStringLiteral("unsigned long")) ||
                lowerTypeText.contains(QStringLiteral(" long")) ||
                lowerTypeText.contains(QStringLiteral("enum")))
            {
                return 4U;
            }
            if (lowerTypeText.contains(QStringLiteral("short")))
            {
                return 2U;
            }
            if (lowerTypeText.contains(QStringLiteral("uchar")) ||
                lowerTypeText.contains(QStringLiteral("unsigned char")) ||
                lowerTypeText.contains(QStringLiteral("boolean")) ||
                lowerTypeText.contains(QStringLiteral("char")))
            {
                return 1U;
            }
            return 0U;
        }

        // typeAllowedForRuntimeSample 作用：
        // - 输入 domain/typeName；
        // - 处理：只采样与对象基址同源的顶层/首字段嵌入类型；
        // - 返回：true 表示 offset 可直接按 EPROCESS/ETHREAD 基址解释。
        bool typeAllowedForRuntimeSample(const QString& domainName, const QString& typeName)
        {
            if (domainName == QStringLiteral("process_detail"))
            {
                return typeName == QStringLiteral("_EPROCESS") || typeName == QStringLiteral("_KPROCESS");
            }
            if (domainName == QStringLiteral("thread_detail"))
            {
                return typeName == QStringLiteral("_ETHREAD") || typeName == QStringLiteral("_KTHREAD");
            }
            return false;
        }

        struct RuntimeSampleCandidate
        {
            ksword::ark::RuntimeFieldSampleRequestItem item; // item：最终发送给 ArkDriverClient 的采样请求项。
            int priority = 100000;                           // priority：越小越优先，保证关键字段先进列表。
            int sourceOrder = 0;                              // sourceOrder：同优先级下保持 JSON 原始顺序。
        };

        // prioritizedNameScore 作用：
        // - 输入 haystackText：qualifiedName/alias/type 拼成的小写文本；
        // - 输入 keywordText：要匹配的关键字段名；
        // - 输入 score：匹配后返回的优先级；
        // - 返回：匹配时返回 score，否则返回 fallback。
        int prioritizedNameScore(
            const QString& haystackText,
            const QString& keywordText,
            const int score,
            const int fallback)
        {
            return haystackText.contains(keywordText, Qt::CaseInsensitive)
                ? qMin(score, fallback)
                : fallback;
        }

        // runtimeSamplePriority 作用：
        // - 输入 domain/type/fieldObject：deep offset JSON 中的字段元数据；
        // - 处理：按“人读详情价值”排序，优先 PID/CID/链表/Token/栈/启动地址等字段；
        // - 返回：越小越优先，普通字段仍保留但排在关键字段之后。
        int runtimeSamplePriority(
            const QString& domainName,
            const QString& typeName,
            const QJsonObject& fieldObject)
        {
            const QString qualifiedName = jsonString(
                fieldObject,
                QStringLiteral("qualifiedName"),
                jsonString(fieldObject, QStringLiteral("fieldName"), QString()));
            const QString aliasName = jsonString(fieldObject, QStringLiteral("kswordItemName"), QString());
            const QString fieldTypeText = jsonString(fieldObject, QStringLiteral("fieldType"), QString());
            const QString haystackText =
                QStringLiteral("%1 %2 %3 %4")
                .arg(qualifiedName, aliasName, fieldTypeText, typeName)
                .toLower();

            int priority = 90000;
            if (domainName == QStringLiteral("process_detail"))
            {
                if (typeName == QStringLiteral("_EPROCESS"))
                {
                    priority = 10000;
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epuniqueprocessid"), 100, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("uniqueprocessid"), 110, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epactiveprocesslinks"), 120, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("activeprocesslinks"), 130, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epimagefilename"), 140, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("imagefilename"), 150, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("eptoken"), 160, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral(" token"), 170, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epobjecttable"), 180, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("objecttable"), 190, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epsectionobject"), 200, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("sectionobject"), 210, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epthreadlisthead"), 220, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("threadlisthead"), 230, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epprotection"), 240, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("protection"), 250, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("epsignaturelevel"), 260, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("signaturelevel"), 270, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("exitstatus"), 320, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("create_time"), 330, priority);
                }
                else if (typeName == QStringLiteral("_KPROCESS"))
                {
                    priority = 20000;
                    priority = prioritizedNameScore(haystackText, QStringLiteral("directorytablebase"), 300, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("threadlisthead"), 310, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("processlock"), 340, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("affinity"), 360, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("basepriority"), 380, priority);
                }
            }
            else if (domainName == QStringLiteral("thread_detail"))
            {
                if (typeName == QStringLiteral("_ETHREAD"))
                {
                    priority = 10000;
                    priority = prioritizedNameScore(haystackText, QStringLiteral("etcid"), 100, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral(" cid"), 110, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("etstartaddress"), 120, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("startaddress"), 130, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("etwin32startaddress"), 140, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("win32startaddress"), 150, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("etthreadlistentry"), 160, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("threadlistentry"), 170, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("createtime"), 180, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("exittime"), 190, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("crossthreadflags"), 260, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("sameprocesspassiveflags"), 270, priority);
                }
                else if (typeName == QStringLiteral("_KTHREAD"))
                {
                    priority = 20000;
                    priority = prioritizedNameScore(haystackText, QStringLiteral("ktinitialstack"), 200, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("initialstack"), 210, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("ktstacklimit"), 220, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("stacklimit"), 230, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("ktstackbase"), 240, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("stackbase"), 250, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("ktkernelstack"), 280, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("kernelstack"), 290, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("ktprocess"), 300, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral(" process"), 310, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("readoperationcount"), 400, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("writeoperationcount"), 410, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("otheroperationcount"), 420, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("readtransfercount"), 430, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("writetransfercount"), 440, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("othertransfercount"), 450, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("state"), 520, priority);
                    priority = prioritizedNameScore(haystackText, QStringLiteral("priority"), 530, priority);
                }
            }

            if (!aliasName.trimmed().isEmpty())
            {
                priority = qMin(priority, 1000);
            }
            return priority;
        }



        // formatCatalogGlobalSymbolLine 作用：
        // - 输入 symbolObject 为 deep catalog 的一个全局符号描述；
        // - 处理：提取符号名、RVA、section、runtime item id 和 DynData 别名；
        // - 返回：一行适合详情页展示的只读全局 RVA 目录文本。


        // formatCatalogGlobalDomain 作用：
        // - 输入 globalDomainObject/maxSymbols；
        // - 处理：把 kernel_global_detail 等全局 RVA domain 裁剪成可读预览；
        // - 返回：只读目录文本；没有副作用，也不触发 R0 查询。

    }

    ks::ui::FieldDocument buildPdbRuntimeCatalogPreview(
        const QString& domainName, const int maxTypes, const int maxFieldsPerType)
    {
        static QMutex cacheMutex;
        static QHash<QString, ks::ui::FieldDocument> previewCache;
        const QString cacheKey = QStringLiteral("%1|%2|%3").arg(domainName).arg(maxTypes).arg(maxFieldsPerType);
        { QMutexLocker lock(&cacheMutex); const auto found = previewCache.constFind(cacheKey);
          if (found != previewCache.constEnd()) return found.value(); }
        ks::ui::FieldDocument preview;
        preview.section(QStringLiteral("PDB Deep Runtime Catalog - %1").arg(domainName));
        const auto finish = [&]() { QMutexLocker lock(&cacheMutex); previewCache.insert(cacheKey, preview); return preview; };
        const QString jsonPath = findNtosDeepOffsetJsonPath();
        if (jsonPath.isEmpty())
        { preview.note(QStringLiteral("PDB deep offset JSON 未找到；请确认 profiles/pdb_deep_offsets 已随构建复制到程序目录。")); return finish(); }
        preview.field(QStringLiteral("Source"), jsonPath);
        QJsonParseError parseError{};
        QString readError;
        const QJsonDocument json = ks::profile::readProfileJsonDocument(jsonPath, &parseError, &readError);
        if (parseError.error != QJsonParseError::NoError || !json.isObject())
        { preview.note(QStringLiteral("PDB deep offset JSON 解析失败：%1；文件=%2").arg(readError.isEmpty() ? parseError.errorString() : readError).arg(jsonPath)); return finish(); }
        const QJsonObject catalog = json.object().value(QStringLiteral("runtimeDetailCatalog")).toObject();
        // The hierarchy is read directly from JSON objects. No generated lines
        // or indentation are retained or interpreted as fields.
        for (const QJsonValue& value : catalog.value(QStringLiteral("domains")).toArray())
        {
            const QJsonObject domain = value.toObject();
            if (jsonString(domain, QStringLiteral("domain"), QString()) != domainName) continue;
            preview.field(QStringLiteral("Types"), QString::number(jsonInt(domain, QStringLiteral("typeCount"), 0)));
            preview.field(QStringLiteral("Fields"), QString::number(jsonInt(domain, QStringLiteral("fieldCount"), 0)));
            preview.field(QStringLiteral("DynDataAliasFields"), QString::number(jsonInt(domain, QStringLiteral("kswordAliasFieldCount"), 0)));
            const QJsonArray types = domain.value(QStringLiteral("types")).toArray();
            int emittedTypes = 0;
            for (const QJsonValue& typeValue : types)
            {
                if (emittedTypes >= qMax(1, maxTypes)) break;
                const QJsonObject type = typeValue.toObject();
                if (type.isEmpty()) continue;
                ks::ui::FieldDocument typeDocument;
                typeDocument.section(jsonString(type, QStringLiteral("typeName"), QStringLiteral("<unknown type>")));
                typeDocument.nodes.last().initiallyExpanded = false;
                typeDocument.field(QStringLiteral("Size"), QString::number(jsonInt(type, QStringLiteral("typeSize"), -1)));
                typeDocument.field(QStringLiteral("Fields"), QString::number(jsonInt(type, QStringLiteral("fieldCount"), 0)));
                const QJsonArray fields = type.value(QStringLiteral("fields")).toArray();
                int emittedFields = 0;
                for (const QJsonValue& fieldValue : fields)
                {
                    if (emittedFields >= qMax(1, maxFieldsPerType)) break;
                    const QJsonObject field = fieldValue.toObject();
                    if (field.isEmpty()) continue;
                    ks::ui::FieldDocument fieldDocument;
                    fieldDocument.section(jsonString(field, QStringLiteral("qualifiedName"), jsonString(field, QStringLiteral("fieldName"), QStringLiteral("<unknown field>"))));
                    fieldDocument.field(QStringLiteral("Offset"), jsonString(field, QStringLiteral("offsetHex"), QStringLiteral("<no offset>")));
                    fieldDocument.field(QStringLiteral("Type"), jsonString(field, QStringLiteral("fieldType"), QStringLiteral("<unknown type>")));
                    const QJsonObject bits = field.value(QStringLiteral("bitField")).toObject();
                    if (!bits.isEmpty())
                    { fieldDocument.field(QStringLiteral("Bit offset"), QString::number(jsonInt(bits, QStringLiteral("bitOffset"), -1)));
                      fieldDocument.field(QStringLiteral("Bit size"), QString::number(jsonInt(bits, QStringLiteral("bitSize"), -1))); }
                    const QString alias = jsonString(field, QStringLiteral("kswordItemName"), QString());
                    if (!alias.trimmed().isEmpty()) fieldDocument.field(QStringLiteral("DynData"), alias);
                    typeDocument.nodes.last().children += fieldDocument.nodes;
                    ++emittedFields;
                }
                if (fields.size() > emittedFields) typeDocument.note(QStringLiteral("    ... 还有 %1 个字段在 deep offset JSON 中备用").arg(fields.size() - emittedFields));
                preview.nodes.first().children += typeDocument.nodes;
                ++emittedTypes;
            }
            if (types.size() > emittedTypes) preview.note(QStringLiteral("  ... 还有 %1 个类型在 deep offset JSON 中备用").arg(types.size() - emittedTypes));
            return finish();
        }
        for (const QJsonValue& value : catalog.value(QStringLiteral("globalDomains")).toArray())
        {
            const QJsonObject domain = value.toObject();
            if (jsonString(domain, QStringLiteral("domain"), QString()) != domainName) continue;
            preview.field(QStringLiteral("Kind"), jsonString(domain, QStringLiteral("kind"), QStringLiteral("global")), true);
            preview.field(QStringLiteral("Symbols"), QString::number(jsonInt(domain, QStringLiteral("symbolCount"), 0)));
            const QJsonArray symbols = domain.value(QStringLiteral("symbols")).toArray();
            int emitted = 0;
            for (const QJsonValue& symbolValue : symbols)
            {
                if (emitted >= qMax(1, maxFieldsPerType)) break;
                const QJsonObject symbol = symbolValue.toObject();
                if (symbol.isEmpty()) continue;
                ks::ui::FieldDocument node;
                node.section(jsonString(symbol, QStringLiteral("symbolName"), QStringLiteral("<unknown symbol>")));
                for (const auto& names : {qMakePair(QStringLiteral("RVA"), QStringLiteral("rvaHex")),
                     qMakePair(QStringLiteral("Kind"), QStringLiteral("kind")),
                     qMakePair(QStringLiteral("Section"), QStringLiteral("sectionName")),
                     qMakePair(QStringLiteral("Section offset"), QStringLiteral("sectionOffsetHex")),
                     qMakePair(QStringLiteral("Runtime item ID"), QStringLiteral("runtimeItemIdHex")),
                     qMakePair(QStringLiteral("DynData"), QStringLiteral("kswordItemName"))})
                    node.field(names.first, jsonString(symbol, names.second, QString()));
                preview.nodes.first().children += node.nodes;
                ++emitted;
            }
            if (symbols.size() > emitted) preview.note(QStringLiteral("    ... 还有 %1 个全局符号在 deep offset JSON 中备用").arg(symbols.size() - emitted));
            return finish();
        }
        preview.note(QStringLiteral("PDB deep offset JSON 中未找到 domain=%1；文件=%2").arg(domainName).arg(jsonPath));
        return finish();
    }

    bool pdbRuntimeCatalogMatchesKernelIdentity(
        const std::uint32_t timeDateStamp,
        const std::uint32_t sizeOfImage,
        ks::ui::FieldDocument* detailDocumentOut)
    {
        // 函数用途：
        // - 在 R3 侧给 deep PDB runtime sampler 加一层 identity 保险；
        // - deep JSON 本身只知道 PDB GUID/Age，v4 pack 知道同一 PDB 对应的 PE TimeDateStamp/SizeOfImage；
        // - 只有当前 R0 DynData 报告的 ntoskrnl identity 与 pack profile 完全一致时才允许采样。
        ks::ui::FieldDocument detailDocument;
        detailDocument.section(QStringLiteral("PDB Deep Runtime Identity Guard"));
        detailDocument.field(QStringLiteral("当前 ntoskrnl TimeDateStamp/SizeOfImage"), QStringLiteral("0x%1 / 0x%2")
            .arg(static_cast<qulonglong>(timeDateStamp), 8, 16, QChar('0')).toUpper()
            .arg(static_cast<qulonglong>(sizeOfImage), 8, 16, QChar('0')).toUpper());

        const auto finishWithDetail = [&detailDocument, detailDocumentOut](const bool matchValue, const QString& reasonText) -> bool
        {
            detailDocument.field(QStringLiteral("结论"), QStringLiteral("%1").arg(matchValue ? QStringLiteral("匹配，可执行只读采样") : QStringLiteral("不匹配，跳过只读采样")));
            detailDocument.field(QStringLiteral("原因"), QStringLiteral("%1").arg(reasonText));
            if (detailDocumentOut != nullptr)
            {
                *detailDocumentOut = detailDocument;
            }
            return matchValue;
        };

        if (timeDateStamp == 0U || sizeOfImage == 0U)
        {
            return finishWithDetail(false, QStringLiteral("R0 DynData 未提供有效 ntoskrnl 模块 identity。"));
        }

        const QString deepJsonPath = findNtosDeepOffsetJsonPath();
        if (deepJsonPath.isEmpty())
        {
            return finishWithDetail(false, QStringLiteral("未找到 profiles/pdb_deep_offsets 下的 ntkrnlmp deep offset JSON。"));
        }

        QString parseDetail;
        const QJsonObject deepRootObject = readJsonObjectFromFile(deepJsonPath, &parseDetail);
        if (deepRootObject.isEmpty())
        {
            return finishWithDetail(false, parseDetail);
        }

        const QJsonObject sourceObject = deepRootObject.value(QStringLiteral("source")).toObject();
        const QString deepGuidText = normalizeGuidText(jsonString(sourceObject, QStringLiteral("pdbGuid"), QString()));
        const std::uint32_t deepAge = jsonHexUInt32(sourceObject, QStringLiteral("pdbAge"), 0U);
        detailDocument.field(QStringLiteral("Deep JSON"), QStringLiteral("%1").arg(deepJsonPath));
        detailDocument.field(QStringLiteral("Deep PDB GUID/Age"), QStringLiteral("%1 / %2").arg(deepGuidText).arg(deepAge));
        if (deepGuidText.isEmpty() || deepAge == 0U)
        {
            return finishWithDetail(false, QStringLiteral("deep JSON source 中缺少 PDB GUID/Age。"));
        }

        const QString packJsonPath = findDynDataPackJsonPath();
        if (packJsonPath.isEmpty())
        {
            return finishWithDetail(false, QStringLiteral("未找到 profiles/ark_dyndata_pack_v4.json，无法把 PDB identity 映射到 PE identity。"));
        }

        const QJsonObject packRootObject = readJsonObjectFromFile(packJsonPath, &parseDetail);
        if (packRootObject.isEmpty())
        {
            return finishWithDetail(false, parseDetail);
        }

        detailDocument.field(QStringLiteral("Pack JSON"), QStringLiteral("%1").arg(packJsonPath));
        const QJsonArray profileArray = packRootObject.value(QStringLiteral("profiles")).toArray();
        ks::ui::FieldDocument candidateProfiles;
        for (const QJsonValue& profileValue : profileArray)
        {
            const QJsonObject profileObject = profileValue.toObject();
            const QString profileGuidText = normalizeGuidText(jsonString(profileObject, QStringLiteral("pdbGuid"), QString()));
            const std::uint32_t profileAge = jsonHexUInt32(profileObject, QStringLiteral("pdbAge"), 0U);
            if (profileGuidText != deepGuidText || profileAge != deepAge)
            {
                continue;
            }

            const std::uint32_t profileTimeDateStamp =
                jsonHexUInt32(profileObject, QStringLiteral("timeDateStamp"), 0U);
            const std::uint32_t profileSizeOfImage =
                jsonHexUInt32(profileObject, QStringLiteral("sizeOfImage"), 0U);
            const QString profileName =
                jsonString(profileObject, QStringLiteral("profileName"), QStringLiteral("<unnamed profile>"));
            candidateProfiles.field(profileName, QStringLiteral("TimeDateStamp=%1 SizeOfImage=%2")
                .arg(uint64ToHex(profileTimeDateStamp), uint64ToHex(profileSizeOfImage)));

            if (profileTimeDateStamp == timeDateStamp && profileSizeOfImage == sizeOfImage)
            {
                detailDocument.field(QStringLiteral("匹配 profile"), QStringLiteral("%1").arg(profileName));
                return finishWithDetail(true, QStringLiteral("deep JSON 的 PDB identity 与当前 ntoskrnl PE identity 经 v4 pack 校验一致。"));
            }
        }

        if (candidateProfiles.isEmpty())
        {
            return finishWithDetail(false, QStringLiteral("v4 pack 中没有与 deep JSON PDB GUID/Age 对应的 profile。"));
        }

        detailDocument.note(QStringLiteral("同 PDB GUID/Age 的 pack profile 候选:"));
        appendFields(detailDocument, candidateProfiles);
        return finishWithDetail(false, QStringLiteral("当前 ntoskrnl PE identity 与 deep JSON 对应 profile 不一致，避免发送错误 offset。"));
    }

    std::vector<ksword::ark::RuntimeFieldSampleRequestItem> buildPdbRuntimeSampleItems(
        const QString& domainName,
        const int maxItems)
    {
        // 函数用途：
        // - 从 deep offset JSON 中提取 R0 sampler 可安全消费的小字段；
        // - 仅选 _EPROCESS/_KPROCESS 或 _ETHREAD/_KTHREAD 这种对象基址可直接解释的类型；
        // - 先收集候选再按“身份/链表/Token/栈/启动地址/IO计数”等人读价值排序；
        // - 返回值可直接传给 ArkDriverClient::query*RuntimeFieldSamples。
        std::vector<ksword::ark::RuntimeFieldSampleRequestItem> items;
        std::vector<RuntimeSampleCandidate> candidates;
        int sourceOrder = 0;
        if (maxItems <= 0)
        {
            return items;
        }

        const QString jsonPath = findNtosDeepOffsetJsonPath();
        if (jsonPath.isEmpty())
        {
            return items;
        }

        QJsonParseError parseError{};
        const QJsonDocument document = ks::profile::readProfileJsonDocument(jsonPath, &parseError);
        if (parseError.error != QJsonParseError::NoError || !document.isObject())
        {
            return items;
        }

        const QJsonObject catalogObject = document.object().value(QStringLiteral("runtimeDetailCatalog")).toObject();
        const QJsonArray domainArray = catalogObject.value(QStringLiteral("domains")).toArray();
        for (const QJsonValue& domainValue : domainArray)
        {
            const QJsonObject domainObject = domainValue.toObject();
            if (jsonString(domainObject, QStringLiteral("domain"), QString()) != domainName)
            {
                continue;
            }

            const QJsonArray typeArray = domainObject.value(QStringLiteral("types")).toArray();
            for (const QJsonValue& typeValue : typeArray)
            {
                const QJsonObject typeObject = typeValue.toObject();
                const QString typeName = jsonString(typeObject, QStringLiteral("typeName"), QString());
                if (!typeAllowedForRuntimeSample(domainName, typeName))
                {
                    continue;
                }

                const QJsonArray fieldArray = typeObject.value(QStringLiteral("fields")).toArray();
                for (const QJsonValue& fieldValue : fieldArray)
                {
                    const QJsonObject fieldObject = fieldValue.toObject();
                    if (fieldObject.isEmpty())
                    {
                        continue;
                    }

                    const QString fieldTypeText = jsonString(fieldObject, QStringLiteral("fieldType"), QString());
                    const std::uint32_t sampleSize = inferRuntimeSampleSize(
                        fieldTypeText,
                        fieldObject.value(QStringLiteral("bitField")).toObject());
                    const std::uint32_t runtimeItemId = jsonHexUInt32(
                        fieldObject,
                        QStringLiteral("runtimeItemIdHex"),
                        jsonHexUInt32(fieldObject, QStringLiteral("runtimeItemId"), 0U));
                    const std::uint32_t offset = jsonHexUInt32(
                        fieldObject,
                        QStringLiteral("offsetHex"),
                        jsonHexUInt32(fieldObject, QStringLiteral("offset"), KSWORD_ARK_PROCESS_OFFSET_UNAVAILABLE));
                    if (sampleSize == 0U || runtimeItemId == 0U || offset >= KSWORD_ARK_RUNTIME_FIELD_SAMPLE_MAX_OFFSET)
                    {
                        continue;
                    }

                    ksword::ark::RuntimeFieldSampleRequestItem item;
                    item.runtimeItemId = runtimeItemId;
                    item.offset = offset;
                    item.size = sampleSize;
                    item.flags = 0U;
                    item.name = jsonString(
                        fieldObject,
                        QStringLiteral("qualifiedName"),
                        jsonString(fieldObject, QStringLiteral("fieldName"), QStringLiteral("<unknown>"))).toStdString();
                    item.type = fieldTypeText.toStdString();

                    RuntimeSampleCandidate candidate;
                    candidate.item = std::move(item);
                    candidate.priority = runtimeSamplePriority(domainName, typeName, fieldObject);
                    candidate.sourceOrder = sourceOrder++;
                    candidates.push_back(std::move(candidate));
                }
            }

            std::stable_sort(
                candidates.begin(),
                candidates.end(),
                [](const RuntimeSampleCandidate& left, const RuntimeSampleCandidate& right)
                {
                    if (left.priority != right.priority)
                    {
                        return left.priority < right.priority;
                    }
                    return left.sourceOrder < right.sourceOrder;
                });

            items.reserve(static_cast<std::size_t>(qMin(maxItems, static_cast<int>(candidates.size()))));
            for (const RuntimeSampleCandidate& candidate : candidates)
            {
                items.push_back(candidate.item);
                if (items.size() >= static_cast<std::size_t>(maxItems))
                {
                    break;
                }
            }
            return items;
        }

        return items;
    }

}
