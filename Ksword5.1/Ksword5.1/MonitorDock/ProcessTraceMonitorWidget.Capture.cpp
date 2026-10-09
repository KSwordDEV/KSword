#include "ProcessTraceMonitorWidget.h"

// ============================================================
// ProcessTraceMonitorWidget.Capture.cpp
// 作用：
// 1) 实现 ETW 会话启动、停止与事件回调；
// 2) 维护目标进程树，把根进程与运行期子进程关联起来；
// 3) 使用 ETW 为主、进程快照为辅，只保留与目标有关的事件。
// ============================================================

#include <QApplication>
#include <QByteArray>
#include <QDateTime>
#include <QMetaObject>
#include <QMessageBox>
#include <QPointer>
#include <QTableWidget>
#include <QTimer>

#include <algorithm>
#include <cstring>
#include <set>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Objbase.h>
#include <evntrace.h>
#include <evntcons.h>
#include <sddl.h>
#include <tdh.h>

#pragma comment(lib, "Tdh.lib")

namespace
{
    // trimUnicodeBuffer：
    // - 作用：把 Unicode 缓冲转成 QString，并裁掉尾部 NUL；
    // - 调用：ETW 属性解析时复用。
    QString trimUnicodeBuffer(const wchar_t* textPointer, const int charCount)
    {
        if (textPointer == nullptr || charCount <= 0)
        {
            return QString();
        }

        QString textValue = QString::fromWCharArray(textPointer, charCount);
        const int nullIndex = textValue.indexOf(QChar(u'\0'));
        if (nullIndex >= 0)
        {
            textValue.truncate(nullIndex);
        }
        return textValue.trimmed();
    }

    // trimAnsiBuffer：
    // - 作用：把 ANSI 缓冲转成 QString，并裁掉尾部 NUL；
    // - 调用：ETW 属性解析时复用。
    QString trimAnsiBuffer(const char* textPointer, const int charCount)
    {
        if (textPointer == nullptr || charCount <= 0)
        {
            return QString();
        }

        QByteArray textBytes(textPointer, charCount);
        const int nullIndex = textBytes.indexOf('\0');
        if (nullIndex >= 0)
        {
            textBytes.truncate(nullIndex);
        }
        return QString::fromLocal8Bit(textBytes).trimmed();
    }

    // binaryPreviewText：
    // - 作用：把二进制属性转成十六进制预览；
    // - 调用：属性类型无法直接友好格式化时的兜底输出。
    QString binaryPreviewText(const unsigned char* dataPointer, const std::size_t dataSize)
    {
        if (dataPointer == nullptr || dataSize == 0)
        {
            return QStringLiteral("<empty>");
        }

        QStringList byteTextList;
        const std::size_t previewSize = std::min<std::size_t>(dataSize, 16);
        for (std::size_t indexValue = 0; indexValue < previewSize; ++indexValue)
        {
            byteTextList << QStringLiteral("%1").arg(dataPointer[indexValue], 2, 16, QChar(u'0')).toUpper();
        }
        QString previewText = byteTextList.join(' ');
        if (dataSize > previewSize)
        {
            previewText += QStringLiteral(" ... (%1 bytes)").arg(dataSize);
        }
        return previewText;
    }

    // normalizePropertyName：
    // - 作用：把 ETW 属性名标准化为仅含小写字母数字的文本；
    // - 调用：后续做 PID、父 PID、进程名等启发式识别时统一复用。
    QString normalizePropertyName(const QString& propertyNameText)
    {
        QString normalizedText;
        normalizedText.reserve(propertyNameText.size());
        for (const QChar ch : propertyNameText.toLower())
        {
            if (ch.isLetterOrNumber())
            {
                normalizedText.push_back(ch);
            }
        }
        return normalizedText;
    }

    // parseGuidText：
    // - 作用：支持从 “{...}” 或裸 GUID 文本解析结构 GUID；
    // - 调用：解析 Provider GUID 文本时复用。
    bool parseGuidText(const QString& guidText, GUID* guidOut)
    {
        if (guidOut == nullptr)
        {
            return false;
        }

        QString normalizedText = guidText.trimmed();
        if (normalizedText.isEmpty())
        {
            return false;
        }
        if (!normalizedText.startsWith('{'))
        {
            normalizedText = QStringLiteral("{%1}").arg(normalizedText);
        }

        const std::wstring guidWideText = normalizedText.toStdWString();
        return SUCCEEDED(::CLSIDFromString(const_cast<LPOLESTR>(guidWideText.c_str()), guidOut));
    }

    // guidToTextLocal：
    // - 作用：把 GUID 转成标准字符串；
    // - 调用：匿名命名空间中的属性解码逻辑无法直接访问类私有静态函数，所以单独提供本地版本。
    QString guidToTextLocal(const GUID& guidValue)
    {
        wchar_t guidBuffer[64] = {};
        if (::StringFromGUID2(guidValue, guidBuffer, static_cast<int>(std::size(guidBuffer))) <= 0)
        {
            return QStringLiteral("{00000000-0000-0000-0000-000000000000}");
        }
        return QString::fromWCharArray(guidBuffer);
    }

    // isProcessCreateEvent：
    // - 作用：按 Provider 类型与事件名判断是否是“进程创建/开始”类事件；
    // - 调用：用于把新子进程纳入目标进程树。
    bool isProcessCreateEvent(const QString& providerTypeText, const QString& eventNameText)
    {
        if (providerTypeText != QStringLiteral("进程"))
        {
            return false;
        }

        return eventNameText.contains(QStringLiteral("Start"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("Create"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("DCStart"), Qt::CaseInsensitive);
    }

    // isProcessStopEvent：
    // - 作用：按 Provider 类型与事件名判断是否是“进程结束/停止”类事件；
    // - 调用：用于把运行期子进程标记为已退出。
    bool isProcessStopEvent(const QString& providerTypeText, const QString& eventNameText)
    {
        if (providerTypeText != QStringLiteral("进程"))
        {
            return false;
        }

        return eventNameText.contains(QStringLiteral("Stop"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("End"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("Terminate"), Qt::CaseInsensitive)
            || eventNameText.contains(QStringLiteral("DCStop"), Qt::CaseInsensitive);
    }

    // 前置声明：
    // - propertyNameLooksLikeProcessId 内部会先排除父 PID 属性；
    // - 因此这里先声明，避免定义顺序导致当前编译单元找不到符号。
    bool propertyNameLooksLikeParentProcessId(const QString& normalizedName);

    // propertyNameLooksLikeProcessId：
    // - 作用：启发式识别“这个属性像是某种 PID/ProcessId”；
    // - 调用：构造候选关联 PID 集合时复用。
    bool propertyNameLooksLikeProcessId(const QString& normalizedName)
    {
        if (propertyNameLooksLikeParentProcessId(normalizedName))
        {
            return false;
        }

        return normalizedName == QStringLiteral("processid")
            || normalizedName == QStringLiteral("pid")
            || normalizedName == QStringLiteral("targetprocessid")
            || normalizedName == QStringLiteral("newprocessid")
            || normalizedName == QStringLiteral("oldprocessid")
            || normalizedName == QStringLiteral("clientprocessid")
            || normalizedName == QStringLiteral("serverprocessid")
            || normalizedName == QStringLiteral("owningprocessid")
            || normalizedName == QStringLiteral("originatingprocessid")
            || normalizedName == QStringLiteral("requestorprocessid")
            || normalizedName == QStringLiteral("requesterprocessid")
            || normalizedName == QStringLiteral("applicationprocessid")
            || normalizedName == QStringLiteral("relatedprocessid")
            || normalizedName == QStringLiteral("subjectprocessid")
            || normalizedName == QStringLiteral("processidnew")
            || normalizedName == QStringLiteral("processidold");
    }

    // propertyNameLooksLikeParentProcessId：
    // - 作用：启发式识别父 PID 相关属性；
    // - 调用：判定子进程是否由目标进程树成员拉起时使用。
    bool propertyNameLooksLikeParentProcessId(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("parentprocessid")
            || normalizedName == QStringLiteral("parentid")
            || normalizedName == QStringLiteral("creatingprocessid")
            || normalizedName == QStringLiteral("creatorprocessid")
            || normalizedName == QStringLiteral("sourceprocessid")
            || normalizedName == QStringLiteral("callingprocessid");
    }

    // propertyNameLooksLikeProcessName：
    // - 作用：启发式识别进程名或映像路径相关属性；
    // - 调用：新增子进程节点时为其补名称/路径。
    bool propertyNameLooksLikeProcessName(const QString& normalizedName)
    {
        return normalizedName == QStringLiteral("imagename")
            || normalizedName == QStringLiteral("imagefilename")
            || normalizedName == QStringLiteral("processname")
            || normalizedName == QStringLiteral("applicationname")
            || normalizedName == QStringLiteral("commandline")
            || normalizedName == QStringLiteral("filename");
    }

    // readScalarNumber：
    // - 作用：从固定宽度二进制缓冲中读取整数；
    // - 调用：ETW 属性为数值类型时复用。
    template <typename TValue>
    bool readScalarNumber(const std::vector<unsigned char>& dataBuffer, TValue* valueOut)
    {
        if (valueOut == nullptr || dataBuffer.size() < sizeof(TValue))
        {
            return false;
        }

        TValue localValue{};
        std::memcpy(&localValue, dataBuffer.data(), sizeof(TValue));
        *valueOut = localValue;
        return true;
    }

    // decodePropertyValue：
    // - 作用：尽可能把 ETW 顶层属性格式化成可读文本，并提取数值；
    // - 调用：extractEventProperties 内部逐个属性调用。
    QString decodePropertyValue(
        const EVENT_PROPERTY_INFO& propertyInfo,
        const std::vector<unsigned char>& dataBuffer,
        bool* numericAvailableOut,
        std::uint64_t* numericValueOut)
    {
        if (numericAvailableOut != nullptr)
        {
            *numericAvailableOut = false;
        }
        if (numericValueOut != nullptr)
        {
            *numericValueOut = 0;
        }

        const USHORT inTypeValue = propertyInfo.nonStructType.InType;
        switch (inTypeValue)
        {
        case TDH_INTYPE_UNICODESTRING:
            return trimUnicodeBuffer(
                reinterpret_cast<const wchar_t*>(dataBuffer.data()),
                static_cast<int>(dataBuffer.size() / sizeof(wchar_t)));

        case TDH_INTYPE_ANSISTRING:
            return trimAnsiBuffer(
                reinterpret_cast<const char*>(dataBuffer.data()),
                static_cast<int>(dataBuffer.size()));

        case TDH_INTYPE_INT8:
        {
            std::int8_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = static_cast<std::uint64_t>(value); }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_UINT8:
        {
            std::uint8_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_INT16:
        {
            std::int16_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = static_cast<std::uint64_t>(value); }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_UINT16:
        {
            std::uint16_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_INT32:
        case TDH_INTYPE_HEXINT32:
        {
            std::uint32_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                if (inTypeValue == TDH_INTYPE_HEXINT32)
                {
                    return QStringLiteral("0x%1").arg(value, 8, 16, QChar(u'0')).toUpper();
                }
                return QString::number(static_cast<std::int32_t>(value));
            }
            break;
        }

        case TDH_INTYPE_UINT32:
        {
            std::uint32_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(value);
            }
            break;
        }

        case TDH_INTYPE_INT64:
        case TDH_INTYPE_HEXINT64:
        {
            std::uint64_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                if (inTypeValue == TDH_INTYPE_HEXINT64)
                {
                    return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar(u'0')).toUpper();
                }
                return QString::number(static_cast<qlonglong>(value));
            }
            break;
        }

        case TDH_INTYPE_UINT64:
        {
            std::uint64_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return QString::number(static_cast<qulonglong>(value));
            }
            break;
        }

        case TDH_INTYPE_BOOLEAN:
        {
            std::uint32_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                if (numericAvailableOut != nullptr) { *numericAvailableOut = true; }
                if (numericValueOut != nullptr) { *numericValueOut = value; }
                return value == 0 ? QStringLiteral("false") : QStringLiteral("true");
            }
            break;
        }

        case TDH_INTYPE_GUID:
        {
            GUID guidValue{};
            if (readScalarNumber(dataBuffer, &guidValue))
            {
                return guidToTextLocal(guidValue);
            }
            break;
        }

        case TDH_INTYPE_FILETIME:
        {
            std::uint64_t value = 0;
            if (readScalarNumber(dataBuffer, &value))
            {
                return QString::number(static_cast<qulonglong>(value));
            }
            break;
        }

        case TDH_INTYPE_POINTER:
        {
            std::uint64_t value = 0;
            if (dataBuffer.size() >= sizeof(std::uint64_t) && readScalarNumber(dataBuffer, &value))
            {
                return QStringLiteral("0x%1").arg(static_cast<qulonglong>(value), 16, 16, QChar(u'0')).toUpper();
            }

            std::uint32_t value32 = 0;
            if (readScalarNumber(dataBuffer, &value32))
            {
                return QStringLiteral("0x%1").arg(value32, 8, 16, QChar(u'0')).toUpper();
            }
            break;
        }

        case TDH_INTYPE_SID:
        {
            LPWSTR sidTextPointer = nullptr;
            if (::ConvertSidToStringSidW(
                reinterpret_cast<PSID>(const_cast<unsigned char*>(dataBuffer.data())),
                &sidTextPointer) != FALSE
                && sidTextPointer != nullptr)
            {
                const QString sidText = QString::fromWCharArray(sidTextPointer);
                ::LocalFree(sidTextPointer);
                return sidText;
            }
            break;
        }
        }

        return binaryPreviewText(dataBuffer.data(), dataBuffer.size());
    }

    // findNumericProperty：
    // - 作用：按“标准化属性名”从属性列表中寻找第一个可解析的数值；
    // - 调用：识别 ParentPid、ProcessId 等关键字段时复用。
    bool findNumericProperty(
        const std::vector<ProcessTraceMonitorWidget::EtwPropertyValue>& propertyList,
        bool (*predicate)(const QString&),
        std::uint32_t* valueOut)
    {
        if (valueOut == nullptr)
        {
            return false;
        }

        for (const ProcessTraceMonitorWidget::EtwPropertyValue& property : propertyList)
        {
            if (!property.numericAvailable)
            {
                continue;
            }

            const QString normalizedName = normalizePropertyName(property.nameText);
            if (!predicate(normalizedName))
            {
                continue;
            }

            if (property.numericValue == 0 || property.numericValue > UINT32_MAX)
            {
                continue;
            }

            *valueOut = static_cast<std::uint32_t>(property.numericValue);
            return true;
        }
        return false;
    }

    // firstMeaningfulProcessText：
    // - 作用：从属性列表中找第一条像“进程名/映像路径”的文本；
    // - 调用：创建新子进程节点时优先用属性补齐名称和路径。
    QString firstMeaningfulProcessText(
        const std::vector<ProcessTraceMonitorWidget::EtwPropertyValue>& propertyList)
    {
        for (const ProcessTraceMonitorWidget::EtwPropertyValue& property : propertyList)
        {
            const QString normalizedName = normalizePropertyName(property.nameText);
            if (!propertyNameLooksLikeProcessName(normalizedName))
            {
                continue;
            }

            const QString textValue = property.valueText.trimmed();
            if (!textValue.isEmpty())
            {
                return textValue;
            }
        }
        return QString();
    }
}

void WINAPI ProcessTraceMonitorWidget::processTraceEtwCallback(struct _EVENT_RECORD* eventRecordPtr)
{
    if (eventRecordPtr == nullptr)
    {
        return;
    }

    EVENT_RECORD* eventRecord = reinterpret_cast<EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || eventRecord->UserContext == nullptr)
    {
        return;
    }

    auto* widgetPointer = reinterpret_cast<ProcessTraceMonitorWidget*>(eventRecord->UserContext);
    widgetPointer->enqueueEventFromRecord(eventRecordPtr);
}

void ProcessTraceMonitorWidget::enqueueEventFromRecord(const struct _EVENT_RECORD* eventRecordPtr)
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr || m_captureStopFlag.load() || m_capturePaused.load())
    {
        return;
    }

    const QString providerGuidText = guidToText(eventRecord->EventHeader.ProviderId);
    QString providerNameText = providerGuidText;
    QString providerTypeText = providerTypeFromName(providerGuidText);
    {
        std::lock_guard<std::mutex> lock(m_runtimeMutex);
        const auto found = std::find_if(
            m_activeProviderList.begin(),
            m_activeProviderList.end(),
            [providerGuidText](const ProviderEntry& entry) {
                return entry.providerGuidText.compare(providerGuidText, Qt::CaseInsensitive) == 0;
            });
        if (found != m_activeProviderList.end())
        {
            providerNameText = found->providerName;
            providerTypeText = found->providerTypeText;
        }
    }

    std::vector<EtwPropertyValue> propertyList;
    extractEventProperties(eventRecordPtr, &propertyList);

    CapturedEventRow rowValue;
    if (!buildRelevantEventRow(eventRecordPtr, providerNameText, providerTypeText, propertyList, &rowValue))
    {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(m_pendingMutex);
        if (m_pendingRows.size() >= kPendingRowCapacity)
        {
            m_pendingRows.pop_front();
            ++m_pendingDroppedRows;
        }
        m_pendingRows.push_back(std::move(rowValue));
    }
}

bool ProcessTraceMonitorWidget::extractEventProperties(
    const struct _EVENT_RECORD* eventRecordPtr,
    std::vector<EtwPropertyValue>* propertyListOut) const
{
    if (propertyListOut == nullptr)
    {
        return false;
    }
    propertyListOut->clear();

    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return false;
    }

    DWORD infoBufferSize = 0;
    ULONG status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        nullptr,
        &infoBufferSize);
    if (status != ERROR_INSUFFICIENT_BUFFER || infoBufferSize == 0)
    {
        return false;
    }

    std::vector<unsigned char> infoBuffer(infoBufferSize, 0);
    auto* eventInfo = reinterpret_cast<PTRACE_EVENT_INFO>(infoBuffer.data());
    status = ::TdhGetEventInformation(
        const_cast<EVENT_RECORD*>(eventRecord),
        0,
        nullptr,
        eventInfo,
        &infoBufferSize);
    if (status != ERROR_SUCCESS || eventInfo == nullptr)
    {
        return false;
    }

    propertyListOut->reserve(eventInfo->TopLevelPropertyCount);
    for (ULONG indexValue = 0; indexValue < eventInfo->TopLevelPropertyCount; ++indexValue)
    {
        const EVENT_PROPERTY_INFO& propertyInfo = eventInfo->EventPropertyInfoArray[indexValue];
        const wchar_t* propertyNamePointer = reinterpret_cast<const wchar_t*>(
            reinterpret_cast<const unsigned char*>(eventInfo) + propertyInfo.NameOffset);
        const QString propertyNameText = propertyNamePointer != nullptr
            ? QString::fromWCharArray(propertyNamePointer)
            : QStringLiteral("<Unknown>");

        if ((propertyInfo.Flags & PropertyStruct) != 0)
        {
            QStringList memberNameList;
            const ULONG propertyCount = eventInfo->PropertyCount;
            const ULONG structStartIndex = static_cast<ULONG>(propertyInfo.structType.StructStartIndex);
            const ULONG structMemberCount = static_cast<ULONG>(propertyInfo.structType.NumOfStructMembers);
            for (ULONG memberOffset = 0; memberOffset < structMemberCount; ++memberOffset)
            {
                const ULONG memberIndex = structStartIndex + memberOffset;
                if (memberIndex >= propertyCount)
                {
                    break;
                }

                const EVENT_PROPERTY_INFO& memberInfo = eventInfo->EventPropertyInfoArray[memberIndex];
                const wchar_t* memberNamePointer = reinterpret_cast<const wchar_t*>(
                    reinterpret_cast<const unsigned char*>(eventInfo) + memberInfo.NameOffset);
                const QString memberNameText = memberNamePointer != nullptr
                    ? QString::fromWCharArray(memberNamePointer)
                    : QStringLiteral("<UnknownMember>");
                memberNameList << memberNameText;
            }

            QString rawPreviewText;
            PROPERTY_DATA_DESCRIPTOR descriptor{};
            descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyNamePointer);
            descriptor.ArrayIndex = ULONG_MAX;

            ULONG propertySize = 0;
            status = ::TdhGetPropertySize(
                const_cast<EVENT_RECORD*>(eventRecord),
                0,
                nullptr,
                1,
                &descriptor,
                &propertySize);
            if (status == ERROR_SUCCESS && propertySize > 0)
            {
                std::vector<unsigned char> propertyBuffer(propertySize, 0);
                status = ::TdhGetProperty(
                    const_cast<EVENT_RECORD*>(eventRecord),
                    0,
                    nullptr,
                    1,
                    &descriptor,
                    propertySize,
                    propertyBuffer.data());
                if (status == ERROR_SUCCESS)
                {
                    rawPreviewText = binaryPreviewText(propertyBuffer.data(), propertyBuffer.size());
                }
            }

            EtwPropertyValue propertyValue;
            propertyValue.nameText = propertyNameText;
            propertyValue.valueText = QStringLiteral("[Struct] members={%1}%2")
                .arg(memberNameList.isEmpty() ? QStringLiteral("<none>") : memberNameList.join(QStringLiteral(", ")))
                .arg(rawPreviewText.isEmpty() ? QString() : QStringLiteral(" raw=%1").arg(rawPreviewText));
            propertyListOut->push_back(std::move(propertyValue));
            continue;
        }

        PROPERTY_DATA_DESCRIPTOR descriptor{};
        descriptor.PropertyName = reinterpret_cast<ULONGLONG>(propertyNamePointer);
        descriptor.ArrayIndex = ULONG_MAX;

        ULONG propertySize = 0;
        status = ::TdhGetPropertySize(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            &propertySize);
        if (status != ERROR_SUCCESS || propertySize == 0)
        {
            continue;
        }

        std::vector<unsigned char> propertyBuffer(propertySize, 0);
        status = ::TdhGetProperty(
            const_cast<EVENT_RECORD*>(eventRecord),
            0,
            nullptr,
            1,
            &descriptor,
            propertySize,
            propertyBuffer.data());
        if (status != ERROR_SUCCESS)
        {
            continue;
        }

        EtwPropertyValue propertyValue;
        propertyValue.nameText = propertyNameText;
        propertyValue.valueText = decodePropertyValue(
            propertyInfo,
            propertyBuffer,
            &propertyValue.numericAvailable,
            &propertyValue.numericValue);
        propertyListOut->push_back(std::move(propertyValue));
    }

    return !propertyListOut->empty();
}

ks::ui::FieldDocument ProcessTraceMonitorWidget::buildEventDetailDocument(
    const QString& providerGuidText,
    const struct _EVENT_RECORD* eventRecordPtr,
    const std::vector<EtwPropertyValue>& propertyList) const
{
    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr) return {};
    ks::ui::FieldDocument document;
    document.section(QStringLiteral("ETW"));
    document.field(QStringLiteral("ProviderGuid"), providerGuidText);
    document.field(QStringLiteral("Level"), QString::number(eventRecord->EventHeader.EventDescriptor.Level));
    document.field(QStringLiteral("Task"), QString::number(eventRecord->EventHeader.EventDescriptor.Task));
    document.field(QStringLiteral("Opcode"), QString::number(eventRecord->EventHeader.EventDescriptor.Opcode));
    document.field(QStringLiteral("Keyword"), QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(eventRecord->EventHeader.EventDescriptor.Keyword), 0, 16).toUpper());
    document.section(QStringLiteral("Properties"));
    for (const EtwPropertyValue& property : propertyList)
    {
        ks::ui::FieldNode field;
        field.name = property.nameText;
        field.value = property.valueText;
        field.translateName = false;
        document.nodes.last().children.push_back(std::move(field));
    }
    return document;
}

bool ProcessTraceMonitorWidget::buildRelevantEventRow(
    const struct _EVENT_RECORD* eventRecordPtr,
    const QString& providerNameText,
    const QString& providerTypeText,
    const std::vector<EtwPropertyValue>& propertyList,
    CapturedEventRow* rowOut)
{
    if (rowOut == nullptr)
    {
        return false;
    }

    const EVENT_RECORD* eventRecord = reinterpret_cast<const EVENT_RECORD*>(eventRecordPtr);
    if (eventRecord == nullptr)
    {
        return false;
    }

    const int eventIdValue = static_cast<int>(eventRecord->EventHeader.EventDescriptor.Id);
    QString eventNameText = queryEtwEventName(eventRecordPtr);
    if (eventNameText.trimmed().isEmpty())
    {
        eventNameText = QStringLiteral("Event_%1").arg(eventIdValue);
    }

    const std::uint32_t headerPidValue = static_cast<std::uint32_t>(eventRecord->EventHeader.ProcessId);
    const std::uint32_t tidValue = static_cast<std::uint32_t>(eventRecord->EventHeader.ThreadId);
    const QString providerGuidText = guidToText(eventRecord->EventHeader.ProviderId);
    const std::uint64_t eventTimestamp100ns = static_cast<std::uint64_t>(eventRecord->EventHeader.TimeStamp.QuadPart);

    std::uint32_t parentPidValue = 0;
    std::uint32_t propertyPidValue = 0;
    findNumericProperty(propertyList, propertyNameLooksLikeParentProcessId, &parentPidValue);
    findNumericProperty(propertyList, propertyNameLooksLikeProcessId, &propertyPidValue);

    const QString processHintText = firstMeaningfulProcessText(propertyList);
    std::uint32_t displayPidValue = headerPidValue != 0 ? headerPidValue : propertyPidValue;
    std::uint32_t rootPidValue = 0;
    QString relationText;
    QString processNameText;
    QString processPathText;
    bool relevant = false;
    bool needsLazyDetailLookup = false;
    // shouldSyncAutoAddTargetList：标记是否需要把新子进程写入监听列表（UI 线程执行）。
    bool shouldSyncAutoAddTargetList = false;
    // autoAdd*：承载“自动加入监听列表”所需参数，锁外通过 invokeMethod 投递到 UI。
    std::uint32_t autoAddPidValue = 0;
    std::uint32_t autoAddParentPidValue = 0;
    QString autoAddProcessNameText;
    QString autoAddProcessPathText;
    std::uint64_t autoAddCreationTime100ns = 0;
    // shouldAutoRemoveTargetList：标记是否需要把退出进程从监听列表移除（UI 线程执行）。
    bool shouldAutoRemoveTargetList = false;
    // autoRemovePidValue：承载“自动移除监听列表”所需 PID。
    std::uint32_t autoRemovePidValue = 0;
    // allowStopAutoRemove：仅在“明确命中退出进程 PID”时才允许自动移除监听项。
    bool allowStopAutoRemove = false;

    {
        std::lock_guard<std::mutex> lock(m_runtimeMutex);
        auto markTrackedAlive = [this](const std::uint32_t pidValue) {
            const auto found = m_trackedProcessMap.find(pidValue);
            if (found != m_trackedProcessMap.end())
            {
                found->second.alive = true;
                found->second.staleSnapshotRounds = 0;
            }
        };

        const auto trackedByPid = [this](const std::uint32_t pidValue) -> RuntimeTrackedProcess* {
            const auto found = m_trackedProcessMap.find(pidValue);
            return found != m_trackedProcessMap.end() ? &found->second : nullptr;
        };

        RuntimeTrackedProcess* matchedTrackedProcess = nullptr;
        if (headerPidValue != 0)
        {
            matchedTrackedProcess = trackedByPid(headerPidValue);
        }
        if (matchedTrackedProcess == nullptr && propertyPidValue != 0)
        {
            matchedTrackedProcess = trackedByPid(propertyPidValue);
            if (matchedTrackedProcess != nullptr)
            {
                displayPidValue = propertyPidValue;
            }
        }

        if (matchedTrackedProcess != nullptr
            && !matchedTrackedProcess->alive
            && !isProcessStopEvent(providerTypeText, eventNameText))
        {
            matchedTrackedProcess = nullptr;
        }

        if (matchedTrackedProcess != nullptr)
        {
            relevant = true;
            rootPidValue = matchedTrackedProcess->rootPid;
            relationText = matchedTrackedProcess->isRoot
                ? QStringLiteral("根进程")
                : QStringLiteral("子进程(%1)").arg(matchedTrackedProcess->parentPid);
            processNameText = matchedTrackedProcess->processName;
            processPathText = matchedTrackedProcess->imagePath;
            markTrackedAlive(matchedTrackedProcess->pid);
            needsLazyDetailLookup = matchedTrackedProcess->alive
                && processNameText.trimmed().isEmpty()
                && displayPidValue != 0;
            allowStopAutoRemove = true;
        }

        // 进程创建事件的特殊处理：
        // - 即使当前事件头 PID 已经命中父进程，也要把“新子进程 PID”纳入监听列表；
        // - 因此这里不使用 else-if，而是独立再执行一轮父子关系处理。
        const bool isCreateEvent = isProcessCreateEvent(providerTypeText, eventNameText);
        if (parentPidValue != 0
            && propertyPidValue != 0
            && isCreateEvent)
        {
            RuntimeTrackedProcess* parentTrackedProcess = trackedByPid(parentPidValue);
            if (parentTrackedProcess != nullptr)
            {
                // parentRootPidValue：先拷贝父根 PID，避免 map 插入导致指针失效后仍访问父节点。
                const std::uint32_t parentRootPidValue = parentTrackedProcess->rootPid;
                auto childIt = m_trackedProcessMap.find(propertyPidValue);
                if (childIt == m_trackedProcessMap.end())
                {
                    RuntimeTrackedProcess childTrackedProcess;
                    childTrackedProcess.pid = propertyPidValue;
                    childTrackedProcess.parentPid = parentPidValue;
                    childTrackedProcess.rootPid = parentRootPidValue;
                    childTrackedProcess.processName = processHintText;
                    childTrackedProcess.imagePath = processHintText;
                    childTrackedProcess.creationTime100ns = 0;
                    childTrackedProcess.alive = true;
                    childTrackedProcess.isRoot = false;
                    childTrackedProcess.staleSnapshotRounds = 0;
                    childTrackedProcess.lastRelatedEventTime100ns = eventTimestamp100ns;
                    m_trackedProcessMap[propertyPidValue] = childTrackedProcess;
                    childIt = m_trackedProcessMap.find(propertyPidValue);
                }
                else
                {
                    childIt->second.parentPid = parentPidValue;
                    childIt->second.rootPid = parentRootPidValue;
                    childIt->second.alive = true;
                    childIt->second.isRoot = false;
                    childIt->second.staleSnapshotRounds = 0;
                    childIt->second.lastRelatedEventTime100ns = eventTimestamp100ns;
                    if (!processHintText.trimmed().isEmpty())
                    {
                        childIt->second.processName = processHintText;
                        childIt->second.imagePath = processHintText;
                    }
                }

                const RuntimeTrackedProcess& childTrackedProcess = childIt->second;
                relevant = true;
                displayPidValue = propertyPidValue;
                rootPidValue = childTrackedProcess.rootPid;
                relationText = QStringLiteral("子进程(%1)").arg(parentPidValue);
                processNameText = childTrackedProcess.processName;
                processPathText = childTrackedProcess.imagePath;
                needsLazyDetailLookup = childTrackedProcess.alive
                    && processNameText.trimmed().isEmpty()
                    && displayPidValue != 0;
                shouldSyncAutoAddTargetList = true;
                autoAddPidValue = childTrackedProcess.pid;
                autoAddParentPidValue = childTrackedProcess.parentPid;
                autoAddProcessNameText = childTrackedProcess.processName;
                autoAddProcessPathText = childTrackedProcess.imagePath;
                autoAddCreationTime100ns = childTrackedProcess.creationTime100ns;
            }
        }

        if (!relevant)
        {
            for (const EtwPropertyValue& property : propertyList)
            {
                if (!property.numericAvailable || property.numericValue == 0 || property.numericValue > UINT32_MAX)
                {
                    continue;
                }

                const QString normalizedName = normalizePropertyName(property.nameText);
                if (!propertyNameLooksLikeProcessId(normalizedName)
                    && !propertyNameLooksLikeParentProcessId(normalizedName))
                {
                    continue;
                }
                const bool matchedByProcessIdProperty = propertyNameLooksLikeProcessId(normalizedName);

                RuntimeTrackedProcess* linkedTrackedProcess = trackedByPid(static_cast<std::uint32_t>(property.numericValue));
                if (linkedTrackedProcess == nullptr || !linkedTrackedProcess->alive)
                {
                    continue;
                }

                relevant = true;
                displayPidValue = static_cast<std::uint32_t>(property.numericValue);
                rootPidValue = linkedTrackedProcess->rootPid;
                relationText = QStringLiteral("属性关联");
                processNameText = linkedTrackedProcess->processName;
                processPathText = linkedTrackedProcess->imagePath;
                markTrackedAlive(displayPidValue);
                needsLazyDetailLookup = linkedTrackedProcess->alive
                    && processNameText.trimmed().isEmpty()
                    && displayPidValue != 0;
                allowStopAutoRemove = matchedByProcessIdProperty;
                break;
            }
        }

        if (relevant
            && displayPidValue != 0
            && allowStopAutoRemove
            && isProcessStopEvent(providerTypeText, eventNameText))
        {
            auto found = m_trackedProcessMap.find(displayPidValue);
            if (found != m_trackedProcessMap.end())
            {
                found->second.alive = false;
                found->second.lastRelatedEventTime100ns = eventTimestamp100ns;
                m_trackedProcessMap.erase(found);
            }
            shouldAutoRemoveTargetList = true;
            autoRemovePidValue = displayPidValue;
        }
    }

    if (!relevant)
    {
        return false;
    }

    // 延迟补详情：
    // - 只在目标树命中新节点但尚未拿到静态详情时触发一次；
    // - 这样能降低每条事件都查 Win32 的开销。
    if (needsLazyDetailLookup && displayPidValue != 0)
    {
        ks::process::ProcessRecord detailRecord;
        // ETW 捕获线程只需要名称/路径用于显示，不能同步做签名校验。
        // includeSignatureCheck=false 可避免事件处理被 WinVerifyTrust 拖慢。
        if (ks::process::QueryProcessStaticDetailByPid(displayPidValue, detailRecord, false))
        {
            processNameText = QString::fromStdString(detailRecord.processName);
            processPathText = QString::fromStdString(detailRecord.imagePath);

            std::lock_guard<std::mutex> lock(m_runtimeMutex);
            auto found = m_trackedProcessMap.find(displayPidValue);
            if (found != m_trackedProcessMap.end())
            {
                found->second.processName = processNameText;
                found->second.imagePath = processPathText;
                found->second.creationTime100ns = detailRecord.creationTime100ns;
                found->second.alive = true;
                found->second.staleSnapshotRounds = 0;
            }
        }
    }

    if (processNameText.trimmed().isEmpty())
    {
        processNameText = processHintText.trimmed();
    }
    if (processNameText.trimmed().isEmpty())
    {
        processNameText = QStringLiteral("PID=%1").arg(displayPidValue);
    }

    rowOut->time100ns = eventTimestamp100ns;
    rowOut->time100nsText = QString::number(static_cast<qulonglong>(eventTimestamp100ns));
    rowOut->typeText = providerTypeText;
    rowOut->providerText = providerNameText;
    rowOut->eventId = eventIdValue;
    rowOut->eventName = eventNameText;
    rowOut->pidText = QStringLiteral("%1 / %2").arg(displayPidValue).arg(tidValue);
    rowOut->processText = processPathText.trimmed().isEmpty()
        ? processNameText
        : QStringLiteral("%1 | %2").arg(processNameText, processPathText);
    rowOut->rootPidText = rootPidValue == 0
        ? QStringLiteral("-")
        : QString::number(rootPidValue);
    rowOut->relationText = relationText.trimmed().isEmpty()
        ? QStringLiteral("命中")
        : relationText;
    rowOut->detailDocument = buildEventDetailDocument(providerGuidText, eventRecordPtr, propertyList);
    rowOut->activityIdText = guidToText(eventRecord->EventHeader.ActivityId);

    // UI 同步：
    // - ETW 线程只负责判定；
    // - 监听列表变更统一回到 UI 线程，避免并发写 m_targetProcessList。
    if (shouldSyncAutoAddTargetList && autoAddPidValue != 0)
    {
        m_uiDispatcher->post(
            [this,
             autoAddPidValue,
             autoAddParentPidValue,
             autoAddProcessNameText,
             autoAddProcessPathText,
             autoAddCreationTime100ns]() {
                upsertAutoTrackedProcessInTargetList(
                    autoAddPidValue,
                    autoAddParentPidValue,
                    autoAddProcessNameText,
                    autoAddProcessPathText,
                    autoAddCreationTime100ns);
            });
    }

    if (shouldAutoRemoveTargetList && autoRemovePidValue != 0)
    {
        m_uiDispatcher->post(
            [this, autoRemovePidValue]() {
                removeTrackedProcessFromTargetListByPid(
                    autoRemovePidValue,
                    QStringLiteral("ETW 进程退出事件"));
            });
    }

    if (displayPidValue != 0 && !shouldAutoRemoveTargetList)
    {
        std::lock_guard<std::mutex> lock(m_runtimeMutex);
        const auto found = m_trackedProcessMap.find(displayPidValue);
        if (found != m_trackedProcessMap.end())
        {
            found->second.lastRelatedEventTime100ns = eventTimestamp100ns;
        }
    }
    return true;
}
