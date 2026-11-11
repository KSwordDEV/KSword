#pragma once

#include "WinAPIParameterDecode.h"
#include "WinAPIFilterRules.h"
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSet>

namespace ks::monitor
{
    // Declaration metadata is loaded only from the project's published definition
    // catalog. A matching declaration is not evidence that a hook was installed.
    struct WinAPISignatureParameter { QString name, type, direction; };
    struct WinAPISignature {
        QString module, function, callingConvention, returnType;
        QStringList architectures;
        QVector<WinAPISignatureParameter> parameters;
        bool referenceOnly = false;
        bool sdkAbiVerified = false;
        QString referenceSource;
    };

    class WinAPISignatureCatalog final
    {
    public:
        static QString key(QString module, const QString& function)
        { return WinAPIFilterSnapshot::moduleKey(module) + QChar(0x1f) + function.trimmed(); }

        bool load(const QByteArray& json)
        {
            if (json.size() > 16 * 1024 * 1024) return false;
            QJsonParseError error{};
            const auto doc = QJsonDocument::fromJson(json, &error);
            if (error.error != QJsonParseError::NoError || !doc.isObject()) return false;
            const auto root = doc.object();
            if (root.value(QStringLiteral("schema_version")).toInt(-1) != 1
                || !root.value(QStringLiteral("apis")).isArray()) return false;
            const auto entries = root.value(QStringLiteral("apis")).toArray();
            if (entries.size() > 65536) return false;
            QHash<QString, WinAPISignature> loaded; loaded.reserve(entries.size());
            const auto validText = [](const QString& value) {
                return !value.trimmed().isEmpty() && value.size() <= 512 && !value.contains(QChar(0x1f));
            };
            for (const auto& entry : entries) {
                if (!entry.isObject()) return false;
                const auto obj = entry.toObject();
                WinAPISignature s;
                s.module = obj.value(QStringLiteral("module")).toString().trimmed();
                s.function = obj.value(QStringLiteral("export")).toString().trimmed();
                s.callingConvention = obj.value(QStringLiteral("calling_convention")).toString().trimmed();
                s.returnType = obj.value(QStringLiteral("return_type")).toString().trimmed();
                if (!validText(s.module) || !validText(s.function) || !validText(s.callingConvention)
                    || !validText(s.returnType) || !obj.value(QStringLiteral("architectures")).isArray()
                    || !obj.value(QStringLiteral("parameters")).isArray()) return false;
                for (const auto& a : obj.value(QStringLiteral("architectures")).toArray()) {
                    if (!a.isString() || (a.toString() != QStringLiteral("x86") && a.toString() != QStringLiteral("x64"))) return false;
                    if (!s.architectures.contains(a.toString())) s.architectures.push_back(a.toString());
                }
                if (s.architectures.isEmpty()) return false;
                const auto parameters = obj.value(QStringLiteral("parameters")).toArray();
                if (parameters.size() > 64) return false;
                for (const auto& p : parameters) {
                    if (!p.isObject()) return false;
                    const auto item = p.toObject();
                    WinAPISignatureParameter parameter{item.value(QStringLiteral("name")).toString().trimmed(),
                        item.value(QStringLiteral("type")).toString().trimmed(),
                        item.value(QStringLiteral("direction")).toString().trimmed()};
                    if (!validText(parameter.name) || !validText(parameter.type)
                        || (parameter.direction != QStringLiteral("in") && parameter.direction != QStringLiteral("out")
                            && parameter.direction != QStringLiteral("inout"))) return false;
                    s.parameters.push_back(std::move(parameter));
                }
                const auto identity = key(s.module, s.function);
                if (loaded.contains(identity)) return false;
                loaded.insert(identity, std::move(s));
            }
            const auto refValue = root.value(QStringLiteral("reference_signatures"));
            if (!refValue.isUndefined()) {
                if (!refValue.isObject()) return false;
                const auto refs = refValue.toObject();
                if (refs.value(QStringLiteral("schema_version")).toInt(-1) != 1
                    || refs.value(QStringLiteral("status")).toString() != QStringLiteral("unverified")
                    || !refs.value(QStringLiteral("entries")).isArray()) return false;
                const auto rows = refs.value(QStringLiteral("entries")).toArray();
                if (rows.size() > 65536 || loaded.size() + rows.size() > 65536) return false;
                for (const auto& row : rows) {
                    if (!row.isArray()) return false;
                    const auto fields = row.toArray();
                    if (fields.size() != 6 || !fields[4].isArray()) return false;
                    WinAPISignature s;
                    s.module = fields[0].toString().trimmed();
                    s.function = fields[1].toString().trimmed();
                    s.callingConvention = fields[2].toString().trimmed();
                    s.returnType = fields[3].toString().trimmed();
                    s.referenceSource = fields[5].toString().trimmed();
                    if (!validText(s.module) || !validText(s.function) || !validText(s.callingConvention)
                        || !validText(s.returnType) || !validText(s.referenceSource)) return false;
                    s.referenceOnly = true;
                    // The XML did not establish a verified ABI on either target.
                    // Keep the declaration visible but do not map captured slots.
                    const auto parameters = fields[4].toArray();
                    if (parameters.size() > 64) return false;
                    for (const auto& p : parameters) {
                        if (!p.isArray()) return false;
                        const auto pair = p.toArray();
                        if (pair.size() != 2) return false;
                        WinAPISignatureParameter parameter{pair[0].toString().trimmed(), pair[1].toString().trimmed(), QStringLiteral("unknown")};
                        if (!validText(parameter.name) || !validText(parameter.type)) return false;
                        s.parameters.push_back(std::move(parameter));
                    }
                    const auto identity = key(s.module, s.function);
                    if (loaded.contains(identity)) return false;
                    loaded.insert(identity, std::move(s));
                }
                const auto verifiedValue = refs.value(QStringLiteral("verified_abis"));
                if (!verifiedValue.isUndefined()) {
                    if (!verifiedValue.isObject()) return false;
                    const auto verified = verifiedValue.toObject();
                    if (!verified.value(QStringLiteral("entries")).isArray()
                        || !validText(verified.value(QStringLiteral("sdk")).toString())
                        || !validText(verified.value(QStringLiteral("header_sha256")).toString())) return false;
                    const auto abis = verified.value(QStringLiteral("entries")).toArray();
                    if (abis.size() > rows.size()) return false;
                    for (const auto& entry : abis) {
                        if (!entry.isArray()) return false;
                        const auto fields = entry.toArray();
                        if (fields.size() != 5 || !fields[4].isArray()) return false;
                        const auto identity = key(fields[0].toString(), fields[1].toString());
                        auto it = loaded.find(identity);
                        const auto returnType = fields[2].toString().trimmed();
                        const auto convention = fields[3].toString().trimmed();
                        const auto parameters = fields[4].toArray();
                        if (it == loaded.end() || !it->referenceOnly || it->sdkAbiVerified
                            || !validText(returnType) || convention != QStringLiteral("WINAPI")
                            || parameters.size() != it->parameters.size()) return false;
                        for (qsizetype i = 0; i < parameters.size(); ++i) {
                            const auto type = parameters[i].toString().trimmed();
                            if (!validText(type)) return false;
                            it->parameters[i].type = type;
                        }
                        it->returnType = returnType;
                        it->callingConvention = convention;
                        it->architectures = {QStringLiteral("x86"), QStringLiteral("x64")};
                        it->sdkAbiVerified = true;
                    }
                }
            }
            m_signatures = std::move(loaded);
            return true;
        }
        const WinAPISignature* find(const QString& module, const QString& function) const
        {
            const auto it = m_signatures.constFind(key(module, function));
            return it == m_signatures.cend() ? nullptr : &it.value();
        }
        qsizetype size() const { return m_signatures.size(); }
    private:
        QHash<QString, WinAPISignature> m_signatures;
    };

    inline QString FormatWinAPISignature(const WinAPISignature& s)
    {
        QStringList params;
        for (const auto& p : s.parameters) params.push_back(p.type + QChar(' ') + p.name);
        return s.returnType + QChar(' ') + s.function + QChar('(') + params.join(QStringLiteral(", ")) + QChar(')');
    }

    struct WinAPIRawArgument {
        QString name, type, direction, rawHex;
        bool available = false;
    };

    // Only scalar/pointer types with known x86 stack footprints are decoded.
    // On an unrecognised x86 type, stop mapping subsequent parameters as well.
    // No pointers are dereferenced and these are raw ABI words, not typed values.
    inline int WinAPISignatureX86SlotCount(const QString& type)
    {
        const QString t = type.trimmed();
        if (t.contains(QChar('*'))) return 1;
        static const QSet<QString> wide{QStringLiteral("LARGE_INTEGER"), QStringLiteral("ULONGLONG"),
            QStringLiteral("ULONG64"), QStringLiteral("TRACEHANDLE"), QStringLiteral("REGHANDLE")};
        if (wide.contains(t)) return 2;
        static const QSet<QString> scalar{
            QStringLiteral("BOOL"), QStringLiteral("BOOLEAN"), QStringLiteral("BYTE"), QStringLiteral("WORD"),
            QStringLiteral("SHORT"), QStringLiteral("WPARAM"), QStringLiteral("LPMSG"), QStringLiteral("LPPOINT"), QStringLiteral("LPRECT"),
            QStringLiteral("DWORD"), QStringLiteral("LONG"), QStringLiteral("ULONG"), QStringLiteral("USHORT"),
            QStringLiteral("UCHAR"), QStringLiteral("INT"), QStringLiteral("UINT"), QStringLiteral("int"),
            QStringLiteral("long"), QStringLiteral("unsigned int"), QStringLiteral("unsigned long"),
            QStringLiteral("ACCESS_MASK"), QStringLiteral("ALG_ID"), QStringLiteral("REGSAM"),
            QStringLiteral("SIZE_T"), QStringLiteral("DWORD_PTR"), QStringLiteral("ULONG_PTR"),
            QStringLiteral("LPARAM"), QStringLiteral("SOCKET"), QStringLiteral("INTERNET_PORT"),
            QStringLiteral("HANDLE"), QStringLiteral("HMODULE"), QStringLiteral("HKEY"), QStringLiteral("HWND"),
            QStringLiteral("HINTERNET"), QStringLiteral("HINSTANCE"), QStringLiteral("SC_HANDLE"),
            QStringLiteral("LPVOID"), QStringLiteral("LPCVOID"), QStringLiteral("LPSTR"), QStringLiteral("LPCSTR"),
            QStringLiteral("LPWSTR"), QStringLiteral("LPCWSTR"), QStringLiteral("LPDWORD"), QStringLiteral("LPBYTE"),
            QStringLiteral("LPHANDLE"), QStringLiteral("LPOVERLAPPED"), QStringLiteral("LPSECURITY_ATTRIBUTES"),
            QStringLiteral("PVOID"), QStringLiteral("PULONG"), QStringLiteral("PUNICODE_STRING"),
            QStringLiteral("POBJECT_ATTRIBUTES"), QStringLiteral("PIO_STATUS_BLOCK")};
        return scalar.contains(t) ? 1 : 0;
    }

    inline bool WinAPISignatureHasDirectReturn(const QString& returnType)
    {
        const QString type = returnType.trimmed();
        if (type.contains(QChar('*'))) return true;
        static const QSet<QString> known{
            QStringLiteral("BOOL"), QStringLiteral("BOOLEAN"), QStringLiteral("DLL_DIRECTORY_COOKIE"),
            QStringLiteral("DNS_STATUS"), QStringLiteral("DWORD"), QStringLiteral("FARPROC"),
            QStringLiteral("HANDLE"), QStringLiteral("HBITMAP"), QStringLiteral("HCERTSTORE"),
            QStringLiteral("HDC"), QStringLiteral("HHOOK"), QStringLiteral("HINSTANCE"),
            QStringLiteral("HINTERNET"), QStringLiteral("HMODULE"), QStringLiteral("HRESULT"),
            QStringLiteral("LRESULT"), QStringLiteral("SHORT"),
            QStringLiteral("HWND"), QStringLiteral("HostEntPtr"), QStringLiteral("INT"),
            QStringLiteral("LONG"), QStringLiteral("LPVOID"), QStringLiteral("LSTATUS"),
            QStringLiteral("NTSTATUS"), QStringLiteral("PCCERT_CONTEXT"), QStringLiteral("PVOID"),
            QStringLiteral("RPC_STATUS"), QStringLiteral("SC_HANDLE"), QStringLiteral("SECURITY_STATUS"),
            QStringLiteral("SOCKET"), QStringLiteral("TRACEHANDLE"), QStringLiteral("UINT"),
            QStringLiteral("ULONG"), QStringLiteral("VOID"), QStringLiteral("int"), QStringLiteral("void")};
        return known.contains(type);
    }

    inline QVector<WinAPIRawArgument> MapWinAPIRawArguments(const WinAPISignature& signature,
        const RawParameterData& data)
    {
        QVector<WinAPIRawArgument> result;
        result.reserve(signature.parameters.size());
        const bool x64 = data.slotBytes == 8 && signature.architectures.contains(QStringLiteral("x64"));
        const bool x86 = data.slotBytes == 4 && signature.architectures.contains(QStringLiteral("x86"));
        const auto convention = signature.callingConvention.toUpper();
        const bool knownConvention = convention == QStringLiteral("WINAPI") || convention == QStringLiteral("NTAPI")
            || convention == QStringLiteral("WSAAPI") || convention == QStringLiteral("RPC_ENTRY")
            || convention == QStringLiteral("CDECL") || convention == QStringLiteral("__CDECL")
            || convention == QStringLiteral("STDCALL") || convention == QStringLiteral("__STDCALL");
        bool canMap = (x64 || x86) && knownConvention && WinAPISignatureHasDirectReturn(signature.returnType);
        qsizetype offset = 0;
        for (const auto& p : signature.parameters) {
            WinAPIRawArgument value{p.name, p.type, p.direction, {}, false};
            const QString type = p.type.trimmed().toUpper();
            // FP/vector registers are not captured by the Raw ABI snapshot.
            const bool fp = type == QStringLiteral("FLOAT") || type == QStringLiteral("DOUBLE")
                || type.contains(QStringLiteral("__M128")) || type.contains(QStringLiteral("__M256"));
            const int slotCount = x64 ? 1 : (x86 ? WinAPISignatureX86SlotCount(p.type) : 0);
            if (!slotCount || (x86 && fp)) canMap = false;
            const bool knownScalar = WinAPISignatureX86SlotCount(p.type) > 0;
            if (canMap && !fp && knownScalar && offset + slotCount <= data.rawWords.size()) {
                std::uint64_t word = data.rawWords[offset];
                if (x86 && slotCount == 2) word |= data.rawWords[offset + 1] << 32;
                value.rawHex = QStringLiteral("0x%1").arg(static_cast<qulonglong>(word), x86 ? slotCount * 8 : 16, 16, QLatin1Char('0'));
                value.available = true;
            }
            if (canMap) offset += slotCount;
            result.push_back(std::move(value));
        }
        return result;
    }

    inline QString FormatWinAPIRawSummary(const WinAPISignature& signature, const RawParameterData& data)
    {
        QStringList values;
        for (const auto& p : MapWinAPIRawArguments(signature, data))
            values.push_back(p.name + QChar('=') + (p.available ? p.rawHex : QStringLiteral("?")));
        return signature.function + QChar('(') + values.join(QStringLiteral(", ")) + QChar(')');
    }
}
