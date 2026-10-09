#include "TypedSyntaxDocument.h"

#include <QJsonDocument>
#include <QJsonParseError>
#include <QJsonValue>
#include <QSet>
#include <QXmlStreamReader>

#include <utility>
#include <limits>

namespace
{
    ks::ui::FieldNode syntaxField(const QString& name, const QString& value = {})
    {
        ks::ui::FieldNode node;
        node.name = name;
        node.value = value;
        node.translateName = false;
        return node;
    }

    // Qt validates JSON grammar; this second pass retains exact numeric lexemes
    // and original key order, rejecting decoded duplicate keys rather than losing evidence.
    class JsonFieldReader final
    {
    public:
        explicit JsonFieldReader(const QString& source, const ks::ui::TypedSyntaxLimits& limits)
            : m_source(source), m_limits(limits) {}
        bool read(ks::ui::FieldNode& root)
        {
            if (!value(QStringLiteral("JSON"), root, 0)) return false;
            whitespace();
            return m_at == m_source.size();
        }
    private:
        void whitespace()
        {
            while (m_at < m_source.size() && m_source.at(m_at).isSpace()) ++m_at;
        }
        bool consume(const QChar expected)
        {
            whitespace();
            if (m_at >= m_source.size() || m_source.at(m_at) != expected) return false;
            ++m_at;
            return true;
        }
        bool string(QString& decoded)
        {
            whitespace();
            if (m_at >= m_source.size() || m_source.at(m_at) != QLatin1Char('"')) return false;
            const qsizetype beginning = m_at++;
            bool escaped = false;
            while (m_at < m_source.size())
            {
                const QChar character = m_source.at(m_at++);
                if (escaped) escaped = false;
                else if (character == QLatin1Char('\\')) escaped = true;
                else if (character == QLatin1Char('"'))
                {
                    QJsonParseError error;
                    const QJsonValue token = QJsonValue::fromJson(m_source.mid(beginning, m_at - beginning).toUtf8(), &error);
                    if (error.error != QJsonParseError::NoError || !token.isString()) return false;
                    decoded = token.toString();
                    return true;
                }
            }
            return false;
        }
        bool value(const QString& name, ks::ui::FieldNode& node, const int depth)
        {
            whitespace();
            if (++m_nodes > m_limits.maximumNodes || depth > m_limits.maximumDepth || m_at >= m_source.size()) return false;
            node = syntaxField(name);
            const QChar first = m_source.at(m_at);
            if (first == QLatin1Char('"')) return string(node.value);
            if (first == QLatin1Char('{') || first == QLatin1Char('['))
            {
                const bool object = first == QLatin1Char('{');
                const QChar closing = object ? QLatin1Char('}') : QLatin1Char(']');
                ++m_at;
                whitespace();
                QSet<QString> keys;
                if (m_at >= m_source.size()) return false;
                if (m_source.at(m_at) != closing)
                {
                    while (true)
                    {
                        QString name;
                        if (object)
                        {
                            if (!string(name) || keys.contains(name) || !consume(QLatin1Char(':'))) return false;
                            keys.insert(name);
                        }
                        else name = QStringLiteral("[%1]").arg(node.children.size());
                        ks::ui::FieldNode child;
                        if (!value(name, child, depth + 1)) return false;
                        node.children.append(std::move(child));
                        whitespace();
                        if (m_at >= m_source.size()) return false;
                        if (m_source.at(m_at) == closing) break;
                        if (!consume(QLatin1Char(','))) return false;
                    }
                }
                if (!consume(closing)) return false;
                node.value = object ? QStringLiteral("{%1}").arg(node.children.size())
                    : QStringLiteral("[%1]").arg(node.children.size());
                return true;
            }
            const qsizetype beginning = m_at;
            while (m_at < m_source.size())
            {
                const QChar character = m_source.at(m_at);
                if (character.isSpace() || character == QLatin1Char(',') || character == QLatin1Char('}') || character == QLatin1Char(']')) break;
                ++m_at;
            }
            if (m_at == beginning) return false;
            node.value = m_source.mid(beginning, m_at - beginning);
            return true;
        }
        const QString& m_source;
        const ks::ui::TypedSyntaxLimits& m_limits;
        qsizetype m_at = 0;
        int m_nodes = 0;
    };
}

namespace ks::ui
{
    std::optional<TypedSyntaxDocument> ParseTypedSyntaxDocument(const QString& source, const TypedSyntaxLimits& limits)
    {
        if (limits.maximumCharacters <= 0 || limits.maximumNodes <= 0 || limits.maximumNodes > std::numeric_limits<int>::max() / 4
            || limits.maximumDepth <= 0 || limits.maximumDepth > 256 || source.size() > limits.maximumCharacters) return std::nullopt;
        QString syntax = source.trimmed();
        if (syntax.startsWith(QChar(0xFEFF))) syntax = syntax.mid(1).trimmed();
        if (syntax.isEmpty()) return std::nullopt;
        const QChar first = syntax.front();
        TypedSyntaxDocument result;
        if (first == QLatin1Char('{') || first == QLatin1Char('['))
        {
            QJsonParseError error;
            const QJsonDocument parsed = QJsonDocument::fromJson(syntax.toUtf8(), &error);
            if (error.error != QJsonParseError::NoError || parsed.isNull()) return std::nullopt;
            FieldNode root;
            JsonFieldReader reader(syntax, limits);
            if (!reader.read(root)) return std::nullopt;
            result.kind = TypedSyntaxDocument::Kind::Json;
            result.fields.nodes.append(std::move(root));
            return result;
        }
        if (first != QLatin1Char('<')) return std::nullopt;

        result.kind = TypedSyntaxDocument::Kind::Xml;
        QXmlStreamReader reader(syntax);
        QVector<FieldNode*> parents;
        int nodes = 0;
        int tokens = 0;
        while (!reader.atEnd())
        {
            const auto token = reader.readNext();
            // No DTD or entity expansion; the original bytes remain available to the host.
            if (++tokens > limits.maximumNodes * 4 || token == QXmlStreamReader::DTD || token == QXmlStreamReader::EntityReference)
                return std::nullopt;
            if (token == QXmlStreamReader::StartElement)
            {
                if (++nodes > limits.maximumNodes || parents.size() >= limits.maximumDepth) return std::nullopt;
                FieldNode node = syntaxField(reader.qualifiedName().toString());
                for (const auto& attribute : reader.attributes())
                {
                    if (++nodes > limits.maximumNodes) return std::nullopt;
                    node.children.append(syntaxField(QLatin1Char('@') + attribute.qualifiedName().toString(), attribute.value().toString()));
                }
                for (const auto& declaration : reader.namespaceDeclarations())
                {
                    if (++nodes > limits.maximumNodes) return std::nullopt;
                    const QString prefix = declaration.prefix().toString();
                    node.children.append(syntaxField(prefix.isEmpty() ? QStringLiteral("@xmlns") : QStringLiteral("@xmlns:") + prefix,
                        declaration.namespaceUri().toString()));
                }
                auto& children = parents.isEmpty() ? result.fields.nodes : parents.back()->children;
                children.append(std::move(node));
                parents.append(&children.back());
            }
            else if (token == QXmlStreamReader::EndElement)
            {
                if (parents.isEmpty()) return std::nullopt;
                parents.pop_back();
            }
            else if ((token == QXmlStreamReader::Characters && (!reader.isWhitespace() || !parents.isEmpty()))
                || token == QXmlStreamReader::Comment || token == QXmlStreamReader::ProcessingInstruction)
            {
                if (++nodes > limits.maximumNodes) return std::nullopt;
                const QString name = token == QXmlStreamReader::Characters ? QStringLiteral("#text")
                    : token == QXmlStreamReader::Comment ? QStringLiteral("#comment") : reader.processingInstructionTarget().toString();
                const QString value = token == QXmlStreamReader::ProcessingInstruction
                    ? reader.processingInstructionData().toString() : reader.text().toString();
                auto& children = parents.isEmpty() ? result.fields.nodes : parents.back()->children;
                children.append(syntaxField(name, value));
            }
        }
        return reader.hasError() || !parents.isEmpty() || result.fields.nodes.isEmpty()
            ? std::nullopt : std::optional<TypedSyntaxDocument>(std::move(result));
    }
}
