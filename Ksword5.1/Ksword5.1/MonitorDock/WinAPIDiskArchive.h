#pragma once
#include "WinApiMonitorProtocol.h"
#include <QDir>
#include <QJsonDocument>
#include <QJsonObject>
#include <QByteArray>
#include <atomic>
#include <mutex>

// Raw protocol packets are recorded before the bounded UI queue. The JSONL
// stream is directly readable and also retains the exact packet bytes.
class WinAPIDiskArchive final
{
public:
    explicit WinAPIDiskArchive(QString directory) : m_directory(std::move(directory)) {}
    ~WinAPIDiskArchive() { if (m_file != INVALID_HANDLE_VALUE) ::CloseHandle(m_file); }
    bool open()
    {
        if (!QDir().mkpath(m_directory)) return fail(ERROR_PATH_NOT_FOUND);
        const QString path = QDir(m_directory).filePath(QStringLiteral("events.jsonl"));
        m_file = ::CreateFileW(reinterpret_cast<LPCWSTR>(path.utf16()), GENERIC_WRITE, FILE_SHARE_READ,
            nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, nullptr);
        if (m_file == INVALID_HANDLE_VALUE) return fail(::GetLastError());
        m_lastFlush = ::GetTickCount64(); return true;
    }
    bool append(const ks::winapi_monitor::ApiMonitorEventPacket& packet, std::uint32_t readerPid)
    {
        try {
            std::lock_guard<std::mutex> lock(m_mutex);
            if (m_failed || m_file == INVALID_HANDLE_VALUE || m_closed) return false;
            const auto bounded = [](const wchar_t* value, std::size_t size) {
                std::size_t length = 0; while (length < size && value[length]) ++length;
                return QString::fromWCharArray(value, static_cast<qsizetype>(length));
            };
            QJsonObject object;
            object.insert(QStringLiteral("sequence"), QString::number(m_accepted + 1));
            object.insert(QStringLiteral("readerPid"), static_cast<qint64>(readerPid));
            object.insert(QStringLiteral("pid"), static_cast<qint64>(packet.pid));
            object.insert(QStringLiteral("tid"), static_cast<qint64>(packet.tid));
            object.insert(QStringLiteral("time100ns"), QString::number(packet.timestamp100ns));
            object.insert(QStringLiteral("category"), static_cast<qint64>(packet.category));
            object.insert(QStringLiteral("kind"), static_cast<qint64>(packet.eventKind));
            object.insert(QStringLiteral("resultKind"), static_cast<qint64>(packet.resultKind));
            object.insert(QStringLiteral("result"), packet.resultKind == static_cast<std::uint32_t>(ks::winapi_monitor::EventResultKind::StatusCode)
                ? QJsonValue(packet.resultCode) : QJsonValue(QJsonValue::Null));
            object.insert(QStringLiteral("module"), bounded(packet.moduleName, ks::winapi_monitor::kMaxModuleNameChars));
            object.insert(QStringLiteral("api"), bounded(packet.apiName, ks::winapi_monitor::kMaxApiNameChars));
            object.insert(QStringLiteral("detail"), bounded(packet.detailText, ks::winapi_monitor::kMaxDetailChars));
            object.insert(QStringLiteral("packetBase64"), QString::fromLatin1(QByteArray(
                reinterpret_cast<const char*>(&packet), sizeof(packet)).toBase64()));
            m_buffer += QJsonDocument(object).toJson(QJsonDocument::Compact); m_buffer += '\n';
            ++m_accepted;
            if (!ks::winapi_monitor::isCoverageEvent(packet.eventKind)) ++m_events;
            if (m_buffer.size() >= 1024 * 1024 || ::GetTickCount64() - m_lastFlush >= 1000)
                return flushLocked();
            return true;
        } catch (...) { return fail(ERROR_NOT_ENOUGH_MEMORY); }
    }
    bool finish()
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_closed) return !m_failed;
        bool ok = !m_failed && flushLocked();
        if (m_file != INVALID_HANDLE_VALUE) {
            if (ok && !::FlushFileBuffers(m_file)) ok = fail(::GetLastError());
            ::CloseHandle(m_file); m_file = INVALID_HANDLE_VALUE;
        }
        m_closed = true; return ok;
    }
    QString directory() const { return m_directory; }
    std::uint64_t accepted() const { return m_accepted.load(); }
    std::uint64_t written() const { return m_written.load(); }
    std::uint64_t events() const { return m_events.load(); }
    DWORD error() const { return m_error.load(); }
    bool failed() const { return m_failed.load(); }
    bool closed() const { return m_closed.load(); }
private:
    bool fail(DWORD error) { m_error.store(error ? error : ERROR_WRITE_FAULT); m_failed.store(true); return false; }
    bool flushLocked()
    {
        qsizetype offset = 0;
        while (offset < m_buffer.size()) {
            DWORD written = 0; const DWORD length = static_cast<DWORD>(m_buffer.size() - offset);
            if (!::WriteFile(m_file, m_buffer.constData() + offset, length, &written, nullptr) || written == 0)
                return fail(::GetLastError());
            offset += written;
        }
        m_buffer.clear(); m_written.store(m_accepted.load()); m_lastFlush = ::GetTickCount64(); return true;
    }
    QString m_directory;
    HANDLE m_file = INVALID_HANDLE_VALUE;
    std::mutex m_mutex;
    QByteArray m_buffer;
    ULONGLONG m_lastFlush = 0;
    std::atomic<std::uint64_t> m_accepted{0}, m_written{0}, m_events{0};
    std::atomic<DWORD> m_error{0};
    std::atomic_bool m_failed{false}, m_closed{false};
};
