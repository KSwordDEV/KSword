#include "NetworkDock.NavigationData.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/ToolbarMetrics.h"
#include <QAbstractItemModel>
#include <QApplication>
#include <QEvent>
#include <QFontMetrics>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QIcon>
#include <QList>
#include <QMouseEvent>
#include <QPersistentModelIndex>
#include <QPointer>
#include <QPushButton>
#include <QScrollBar>
#include <QStyleOptionViewItem>
#include <QStyledItemDelegate>
#include <QTableView>
#include <QTimer>
#include <QVariant>
#include <functional>
#include <utility>
#include "NetworkDock.InternalCommon.h"
#include "../UI/ToolbarMetrics.h"
#include "../UI/ParameterWorkspace.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/VisibleTableWidget.h"
#include "../UI/AsyncUiDispatcher.h"
#include "../UI/ThemeAccentIcon.h"
#include "../UI/TableContextMenu.h"
#include "../UI/TableColumnAutoFit.h"
#include "../Internationalization/LanguageManager.h"
#include <QAbstractTableModel>
#include <QSortFilterProxyModel>
#include <QStyledItemDelegate>
#include <QItemSelectionModel>
#include <QPersistentModelIndex>
#include <QScrollBar>
#include <QApplication>
#include <QEvent>
#include <QFocusEvent>
#include <array>
#include <unordered_set>

#include "../theme.h"

// ============================================================
// NetworkDock.MultiThreadDownload.cpp
// 作用：
// 1) 新增“多线程下载”Tab（类似 IDM 分段下载）；
// 2) 下载前支持设置线程数（默认 16）；
// 3) 展示任务级百分比、分段级百分比与断节式总进度条。
// ============================================================

#include <QDir>
#include <QFormLayout>
#include <QFileDialog>
#include <QFileInfo>
#include <QPainter>
#include <QSignalBlocker>
#include <QStandardPaths>
#include <QUrl>

#include <cwchar>
#include <cerrno>
#include <functional>
#include <limits>
#include <string>

#include <winhttp.h>

#pragma comment(lib, "Winhttp.lib")

using namespace network_dock_detail;

namespace
{
    enum MultiDownloadTaskColumn
    {
        MultiDownloadTaskColumnId = 0,
        MultiDownloadTaskColumnFile,
        MultiDownloadTaskColumnUrl,
        MultiDownloadTaskColumnThread,
        MultiDownloadTaskColumnTotal,
        MultiDownloadTaskColumnDownloaded,
        MultiDownloadTaskColumnProgress,
        MultiDownloadTaskColumnStatus,
        MultiDownloadTaskColumnAction,
        MultiDownloadTaskColumnCount
    };

    enum MultiDownloadSegmentColumn
    {
        MultiDownloadSegmentColumnIndex = 0,
        MultiDownloadSegmentColumnRange,
        MultiDownloadSegmentColumnDownloaded,
        MultiDownloadSegmentColumnProgress,
        MultiDownloadSegmentColumnStatus,
        MultiDownloadSegmentColumnCount
    };

    constexpr DWORD kReadBufferBytes = 64U * 1024U;

    struct WinHttpUrlParts
    {
        std::wstring hostText;
        std::wstring pathAndQueryText;
        INTERNET_PORT portValue = INTERNET_DEFAULT_HTTP_PORT;
        bool isHttps = false;
    };

    class WinHttpHandleGuard final
    {
    public:
        explicit WinHttpHandleGuard(HINTERNET handleValue = nullptr)
            : m_handleValue(handleValue)
        {
        }

        ~WinHttpHandleGuard()
        {
            if (m_handleValue != nullptr)
            {
                ::WinHttpCloseHandle(m_handleValue);
                m_handleValue = nullptr;
            }
        }

        WinHttpHandleGuard(const WinHttpHandleGuard&) = delete;
        WinHttpHandleGuard& operator=(const WinHttpHandleGuard&) = delete;

        [[nodiscard]] bool valid() const
        {
            return m_handleValue != nullptr;
        }

        [[nodiscard]] HINTERNET get() const
        {
            return m_handleValue;
        }

    private:
        HINTERNET m_handleValue = nullptr;
    };

    QString formatBytesText(const std::uint64_t bytesValue)
    {
        return QString::fromStdString(ks::network::FormatByteCount(bytesValue));
    }

    std::wstring queryHeaderWideText(HINTERNET requestHandle, const DWORD headerFlag)
    {
        DWORD headerBytes = 0;
        const BOOL firstOk = ::WinHttpQueryHeaders(
            requestHandle,
            headerFlag,
            WINHTTP_HEADER_NAME_BY_INDEX,
            WINHTTP_NO_OUTPUT_BUFFER,
            &headerBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (firstOk != FALSE || ::GetLastError() != ERROR_INSUFFICIENT_BUFFER)
        {
            return std::wstring();
        }

        std::wstring outputText;
        outputText.resize(headerBytes / sizeof(wchar_t));
        const BOOL secondOk = ::WinHttpQueryHeaders(
            requestHandle,
            headerFlag,
            WINHTTP_HEADER_NAME_BY_INDEX,
            outputText.data(),
            &headerBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (secondOk == FALSE)
        {
            return std::wstring();
        }

        while (!outputText.empty() && outputText.back() == L'\0')
        {
            outputText.pop_back();
        }
        return outputText;
    }

    bool parseWinHttpUrlParts(
        const QString& urlText,
        WinHttpUrlParts* urlPartsOut,
        QString* errorTextOut)
    {
        if (urlPartsOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("内部错误：URL输出参数为空。");
            }
            return false;
        }

        URL_COMPONENTS components{};
        components.dwStructSize = sizeof(components);

        wchar_t hostBuffer[512] = {};
        wchar_t pathBuffer[2048] = {};
        wchar_t extraBuffer[2048] = {};
        components.lpszHostName = hostBuffer;
        components.dwHostNameLength = static_cast<DWORD>((sizeof(hostBuffer) / sizeof(hostBuffer[0])) - 1);
        components.lpszUrlPath = pathBuffer;
        components.dwUrlPathLength = static_cast<DWORD>((sizeof(pathBuffer) / sizeof(pathBuffer[0])) - 1);
        components.lpszExtraInfo = extraBuffer;
        components.dwExtraInfoLength = static_cast<DWORD>((sizeof(extraBuffer) / sizeof(extraBuffer[0])) - 1);

        const std::wstring wideUrlText = urlText.toStdWString();
        const BOOL crackOk = ::WinHttpCrackUrl(
            wideUrlText.c_str(),
            static_cast<DWORD>(wideUrlText.size()),
            0,
            &components);
        if (crackOk == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("URL解析失败。");
            }
            return false;
        }

        urlPartsOut->hostText = std::wstring(components.lpszHostName, components.dwHostNameLength);
        urlPartsOut->pathAndQueryText = std::wstring(components.lpszUrlPath, components.dwUrlPathLength);
        const std::wstring extraText(components.lpszExtraInfo, components.dwExtraInfoLength);
        if (urlPartsOut->pathAndQueryText.empty())
        {
            urlPartsOut->pathAndQueryText = L"/";
        }
        if (!extraText.empty())
        {
            urlPartsOut->pathAndQueryText += extraText;
        }
        urlPartsOut->portValue = components.nPort;
        urlPartsOut->isHttps = (components.nScheme == INTERNET_SCHEME_HTTPS);
        return true;
    }

    bool queryRemoteFileMeta(
        const WinHttpUrlParts& urlParts,
        std::uint64_t* totalBytesOut,
        bool* supportsRangeOut,
        QString* errorTextOut)
    {
        if (totalBytesOut == nullptr || supportsRangeOut == nullptr)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("内部错误：元信息输出参数为空。");
            }
            return false;
        }

        WinHttpHandleGuard sessionHandle(::WinHttpOpen(
            L"Ksword-MultiDownload/2026.04",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0));
        if (!sessionHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 WinHTTP 会话失败。");
            }
            return false;
        }

        // All waits run in a worker. A canceled request leaves at the next bounded network step.
        if (::WinHttpSetTimeouts(sessionHandle.get(), 5000, 10000, 10000, 10000) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载会话失败。");
            }
            return false;
        }

        WinHttpHandleGuard connectHandle(::WinHttpConnect(
            sessionHandle.get(),
            urlParts.hostText.c_str(),
            urlParts.portValue,
            0));
        if (!connectHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("连接目标主机失败。");
            }
            return false;
        }

        const DWORD requestFlags = urlParts.isHttps ? WINHTTP_FLAG_SECURE : 0;
        WinHttpHandleGuard headRequestHandle(::WinHttpOpenRequest(
            connectHandle.get(),
            L"HEAD",
            urlParts.pathAndQueryText.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            requestFlags));
        if (!headRequestHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建 HEAD 请求失败。");
            }
            return false;
        }

        if (::WinHttpSendRequest(headRequestHandle.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE
            || ::WinHttpReceiveResponse(headRequestHandle.get(), nullptr) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("发送或接收 HEAD 请求失败。");
            }
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusBytes = sizeof(statusCode);
        ::WinHttpQueryHeaders(
            headRequestHandle.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (statusCode >= 400)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("HEAD 状态码异常：%1").arg(statusCode);
            }
            return false;
        }

        const std::wstring contentLengthText = queryHeaderWideText(headRequestHandle.get(), WINHTTP_QUERY_CONTENT_LENGTH);
        if (contentLengthText.empty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("响应中缺少 Content-Length。");
            }
            return false;
        }

        errno = 0;
        wchar_t* lengthEnd = nullptr;
        const std::uint64_t totalBytes = static_cast<std::uint64_t>(std::wcstoull(contentLengthText.c_str(), &lengthEnd, 10));
        if (contentLengthText.find_first_not_of(L"0123456789") != std::wstring::npos || errno == ERANGE || lengthEnd == contentLengthText.c_str()
            || lengthEnd == nullptr || *lengthEnd != L'\0'
            || totalBytes > static_cast<std::uint64_t>(std::numeric_limits<LONGLONG>::max()))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("响应中的 Content-Length 无效或超出文件大小上限。");
            }
            return false;
        }
        const std::wstring acceptRangesText = queryHeaderWideText(headRequestHandle.get(), WINHTTP_QUERY_ACCEPT_RANGES);
        const QString acceptRangesQString = QString::fromWCharArray(acceptRangesText.c_str()).toLower();

        *totalBytesOut = totalBytes;
        *supportsRangeOut = acceptRangesQString.contains(QStringLiteral("bytes"));
        return true;
    }

    bool ensureDirectoryReady(const QString& directoryPathText, QString* errorTextOut)
    {
        if (directoryPathText.trimmed().isEmpty())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("下载目录为空。");
            }
            return false;
        }

        QDir directory(directoryPathText);
        if (directory.exists())
        {
            return true;
        }

        if (!directory.mkpath(QStringLiteral(".")))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载目录失败：%1").arg(directoryPathText);
            }
            return false;
        }
        return true;
    }

    void setCellText(QTableWidget* tableWidget, const int rowIndex, const int columnIndex, const QString& text)
    {
        if (tableWidget == nullptr)
        {
            return;
        }

        QTableWidgetItem* itemPointer = tableWidget->item(rowIndex, columnIndex);
        if (itemPointer == nullptr)
        {
            itemPointer = new QTableWidgetItem();
            itemPointer->setFlags(itemPointer->flags() & ~Qt::ItemIsEditable);
            tableWidget->setItem(rowIndex, columnIndex, itemPointer);
        }
        if (itemPointer->text() != text)
        {
            itemPointer->setText(text);
        }
    }
}
namespace
{
    QString buildSafeOutputFileName(const QUrl& downloadUrl, const int taskId)
    {
        QString fileNameText = QFileInfo(downloadUrl.path()).fileName().trimmed();
        if (fileNameText.isEmpty())
        {
            fileNameText = QStringLiteral("download_task_%1.bin").arg(taskId);
        }

        static const QChar invalidCharList[] = {
            QChar('<'), QChar('>'), QChar(':'), QChar('"'),
            QChar('/'), QChar('\\'), QChar('|'), QChar('?'), QChar('*')
        };
        for (const QChar invalidChar : invalidCharList)
        {
            fileNameText.replace(invalidChar, QChar('_'));
        }
        return fileNameText;
    }

    // Reserve each name with CREATE_NEW: concurrent preparations can never truncate each other.
    bool prepareUniqueOutputFile(
        const QString& directoryPathText, const QString& fileNameText,
        const std::uint64_t totalBytes, const std::function<bool()>& isCanceled,
        QString* outputPathOut, QString* errorTextOut)
    {
        const QDir directory(directoryPathText);
        const QFileInfo nameInfo(fileNameText);
        for (int index = 0; index < 10000; ++index)
        {
            if (isCanceled())
            {
                *errorTextOut = QStringLiteral("任务已取消。");
                return false;
            }
            const QString candidateName = index == 0 ? fileNameText
                : nameInfo.suffix().isEmpty()
                    ? QStringLiteral("%1(%2)").arg(nameInfo.completeBaseName()).arg(index)
                    : QStringLiteral("%1(%2).%3").arg(nameInfo.completeBaseName()).arg(index).arg(nameInfo.suffix());
            const QString outputPath = directory.filePath(candidateName);
            const std::wstring outputPathWide = outputPath.toStdWString();
            HANDLE outputHandle = ::CreateFileW(outputPathWide.c_str(), GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
            if (outputHandle == INVALID_HANDLE_VALUE)
            {
                const DWORD error = ::GetLastError();
                if (error == ERROR_FILE_EXISTS || error == ERROR_ALREADY_EXISTS)
                {
                    continue;
                }
                *errorTextOut = QStringLiteral("创建输出文件失败，错误码=%1").arg(error);
                return false;
            }

            // Publish ownership even on cancellation/allocation failure; retain the partial file as before.
            *outputPathOut = outputPath;
            bool ready = !isCanceled();
            if (ready && totalBytes > 0)
            {
                LARGE_INTEGER size{};
                size.QuadPart = static_cast<LONGLONG>(totalBytes);
                ready = ::SetFilePointerEx(outputHandle, size, nullptr, FILE_BEGIN) != FALSE
                    && ::SetEndOfFile(outputHandle) != FALSE;
                if (!ready)
                {
                    *errorTextOut = QStringLiteral("预分配输出文件失败，错误码=%1").arg(::GetLastError());
                }
            }
            ::CloseHandle(outputHandle);
            if (isCanceled())
            {
                *errorTextOut = QStringLiteral("任务已取消。");
                return false;
            }
            return ready;
        }
        *errorTextOut = QStringLiteral("创建输出文件失败，错误码=%1").arg(ERROR_FILE_EXISTS);
        return false;
    }

    struct DownloadPreparationResult
    {
        WinHttpUrlParts urlParts;
        QString outputPath;
        QString errorText;
        std::uint64_t totalBytes = 0;
        bool supportsRange = false;
    };

    // No QObject/widget is borrowed by this transaction; only the immutable request and cancel flag.
    DownloadPreparationResult prepareDownload(
        const QString& urlText, const QString& directoryText, const QString& fileNameText,
        const std::function<bool()>& isCanceled)
    {
        DownloadPreparationResult result;
        if (isCanceled())
        {
            return result;
        }
        if (!ensureDirectoryReady(directoryText, &result.errorText) || isCanceled())
        {
            return result;
        }
        if (!parseWinHttpUrlParts(urlText, &result.urlParts, &result.errorText) || isCanceled())
        {
            return result;
        }
        QString metaError;
        if (!queryRemoteFileMeta(result.urlParts, &result.totalBytes, &result.supportsRange, &metaError))
        {
            result.errorText = QStringLiteral("读取远端文件信息失败：%1").arg(metaError);
            return result;
        }
        if (isCanceled())
        {
            return result;
        }
        prepareUniqueOutputFile(directoryText, fileNameText, result.totalBytes,
            isCanceled, &result.outputPath, &result.errorText);
        return result;
    }

    // Count unlaunched slots explicitly: a resource failure must not escape the Qt delivery callback.
    template<class Launch, class Failure>
    std::size_t launchDownloadWorkersSafely(const std::size_t count, Launch&& launch, Failure&& failure)
    {
        for (std::size_t index = 0; index < count; ++index)
        {
            try
            {
                launch(index);
            }
            catch (...)
            {
                failure(index, count - index);
                return index;
            }
        }
        return count;
    }

    bool downloadSegmentToFile(
        const WinHttpUrlParts& urlParts,
        const QString& outputFilePathText,
        const std::uint64_t beginByte,
        const std::uint64_t endByte,
        const bool enableRange,
        const std::atomic_bool* cancelFlag,
        const std::atomic_bool* pauseFlag,
        const std::function<void(std::uint64_t)>& chunkCallback,
        QString* errorTextOut)
    {
        if (cancelFlag != nullptr && cancelFlag->load())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("任务已取消。");
            }
            return false;
        }
        WinHttpHandleGuard sessionHandle(::WinHttpOpen(
            L"Ksword-MultiDownload/2026.04",
            WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS,
            0));
        if (!sessionHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载会话失败。");
            }
            return false;
        }

        // All waits run in a worker. A canceled request leaves at the next bounded network step.
        if (::WinHttpSetTimeouts(sessionHandle.get(), 5000, 10000, 10000, 10000) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载会话失败。");
            }
            return false;
        }

        WinHttpHandleGuard connectHandle(::WinHttpConnect(
            sessionHandle.get(),
            urlParts.hostText.c_str(),
            urlParts.portValue,
            0));
        if (!connectHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("连接下载主机失败。");
            }
            return false;
        }

        const DWORD requestFlags = urlParts.isHttps ? WINHTTP_FLAG_SECURE : 0;
        WinHttpHandleGuard requestHandle(::WinHttpOpenRequest(
            connectHandle.get(),
            L"GET",
            urlParts.pathAndQueryText.c_str(),
            nullptr,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            requestFlags));
        if (!requestHandle.valid())
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建下载请求失败。");
            }
            return false;
        }

        if (enableRange)
        {
            const std::wstring rangeHeaderText = QString::fromStdString(
                ks::network::BuildHttpRangeHeader(beginByte, endByte)).toStdWString();
            if (::WinHttpAddRequestHeaders(
                requestHandle.get(),
                rangeHeaderText.c_str(),
                static_cast<DWORD>(rangeHeaderText.size()),
                WINHTTP_ADDREQ_FLAG_ADD | WINHTTP_ADDREQ_FLAG_REPLACE) == FALSE)
            {
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("附加 Range 请求头失败。");
                }
                return false;
            }
        }

        if (::WinHttpSendRequest(requestHandle.get(), WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) == FALSE
            || ::WinHttpReceiveResponse(requestHandle.get(), nullptr) == FALSE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("发送或接收下载请求失败。");
            }
            return false;
        }

        DWORD statusCode = 0;
        DWORD statusBytes = sizeof(statusCode);
        ::WinHttpQueryHeaders(
            requestHandle.get(),
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &statusCode,
            &statusBytes,
            WINHTTP_NO_HEADER_INDEX);
        if (statusCode >= 400 || (enableRange && statusCode != 206))
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("下载响应状态码异常=%1").arg(statusCode);
            }
            return false;
        }

        const std::wstring outputPathWideText = outputFilePathText.toStdWString();
        HANDLE outputFileHandle = ::CreateFileW(
            outputPathWideText.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (outputFileHandle == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("打开输出文件失败，错误码=%1").arg(::GetLastError());
            }
            return false;
        }

        LARGE_INTEGER offsetValue{};
        offsetValue.QuadPart = static_cast<LONGLONG>(beginByte);
        if (::SetFilePointerEx(outputFileHandle, offsetValue, nullptr, FILE_BEGIN) == FALSE)
        {
            ::CloseHandle(outputFileHandle);
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("设置文件偏移失败，错误码=%1").arg(::GetLastError());
            }
            return false;
        }

        // expectedBytes 复用 ks::network 纯逻辑，避免下载线程和 UI 进度表各自维护范围长度算法。
        const std::uint64_t expectedBytes = ks::network::CalculateSegmentByteCount(beginByte, endByte);
        std::uint64_t writtenBytes = 0;
        std::vector<std::uint8_t> buffer(kReadBufferBytes);

        bool resultOk = true;
        while (writtenBytes < expectedBytes)
        {
            // 暂停采用线程内短周期等待：
            // - 不关闭当前 WinHTTP 请求，继续时可从当前连接继续读取；
            // - 等待期间仍然检查取消标志，确保用户点“取消”后能尽快退出。
            while (pauseFlag != nullptr && pauseFlag->load())
            {
                if (cancelFlag != nullptr && cancelFlag->load())
                {
                    resultOk = false;
                    if (errorTextOut != nullptr)
                    {
                        *errorTextOut = QStringLiteral("任务已取消。");
                    }
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(120));
            }
            if (!resultOk)
            {
                break;
            }

            if (cancelFlag != nullptr && cancelFlag->load())
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("任务已取消。");
                }
                break;
            }

            DWORD readBytes = 0;
            if (::WinHttpReadData(requestHandle.get(), buffer.data(), static_cast<DWORD>(buffer.size()), &readBytes) == FALSE)
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("读取网络数据失败。");
                }
                break;
            }
            if (readBytes == 0)
            {
                break;
            }

            const std::uint64_t remainBytes = expectedBytes - writtenBytes;
            const DWORD writeBytes = static_cast<DWORD>(std::min<std::uint64_t>(remainBytes, readBytes));
            DWORD realWriteBytes = 0;
            if (::WriteFile(outputFileHandle, buffer.data(), writeBytes, &realWriteBytes, nullptr) == FALSE
                || realWriteBytes != writeBytes)
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("写入输出文件失败，错误码=%1").arg(::GetLastError());
                }
                break;
            }

            writtenBytes += static_cast<std::uint64_t>(realWriteBytes);
            if (chunkCallback)
            {
                chunkCallback(static_cast<std::uint64_t>(realWriteBytes));
            }
        }

        ::CloseHandle(outputFileHandle);

        if (!resultOk)
        {
            return false;
        }
        if (writtenBytes != expectedBytes)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("分段长度不匹配，期望=%1，实际=%2")
                    .arg(static_cast<qulonglong>(expectedBytes))
                    .arg(static_cast<qulonglong>(writtenBytes));
            }
            return false;
        }
        return true;
    }
}

// Task identity is independent of source/proxy row order.
namespace
{
    enum DownloadTaskRole
    {
        TaskIdRole = Qt::UserRole + 1,
        PausedRole,
        PauseEnabledRole,
        CancelEnabledRole
    };
}

class NetworkDock::MultiThreadDownloadTaskModel final : public QAbstractTableModel
{
public:
    explicit MultiThreadDownloadTaskModel(QObject* parent)
        : QAbstractTableModel(parent)
    {
    }

    int rowCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : static_cast<int>(m_rows.size());
    }
    int columnCount(const QModelIndex& parent = QModelIndex()) const override
    {
        return parent.isValid() ? 0 : MultiDownloadTaskColumnCount;
    }
    QVariant data(const QModelIndex& index, const int role = Qt::DisplayRole) const override
    {
        if (!index.isValid() || index.row() < 0 || index.row() >= rowCount()
            || index.column() < 0 || index.column() >= columnCount())
        {
            return {};
        }
        const Row& row = m_rows[static_cast<std::size_t>(index.row())];
        switch (role)
        {
        case TaskIdRole: return row.task->taskId;
        case PausedRole: return row.paused;
        case PauseEnabledRole: return row.pauseEnabled;
        case CancelEnabledRole: return row.cancelEnabled;
        case Qt::DisplayRole:
            return index.column() == MultiDownloadTaskColumnStatus
                ? QVariant(ks::i18n::sourceText(row.texts[static_cast<std::size_t>(index.column())]))
                : QVariant(row.texts[static_cast<std::size_t>(index.column())]);
        case Qt::ToolTipRole:
            if (index.column() == MultiDownloadTaskColumnFile && !row.outputPath.isEmpty())
            {
                return row.outputPath;
            }
            return data(index, Qt::DisplayRole);
        case Qt::UserRole:
            return row.sortValues[static_cast<std::size_t>(index.column())];
        default: return {};
        }
    }
    QVariant headerData(const int section, const Qt::Orientation orientation,
        const int role = Qt::DisplayRole) const override
    {
        if (orientation != Qt::Horizontal || role != Qt::DisplayRole
            || section < 0 || section >= MultiDownloadTaskColumnCount)
        {
            return {};
        }
        static const QStringList headers = {
            QStringLiteral("任务ID"), QStringLiteral("文件名"), QStringLiteral("URL"),
            QStringLiteral("线程"), QStringLiteral("总大小"), QStringLiteral("已下载"),
            QStringLiteral("进度"), QStringLiteral("状态"), QStringLiteral("操作")
        };
        return ks::i18n::displayText(headers.at(section));
    }
    Qt::ItemFlags flags(const QModelIndex& index) const override
    {
        if (!index.isValid())
        {
            return Qt::NoItemFlags;
        }
        auto result = Qt::ItemIsSelectable | Qt::ItemIsEnabled;
        if (index.column() == MultiDownloadTaskColumnAction)
        {
            result |= Qt::ItemIsEditable; // Only viewport persistent editors; the view has NoEditTriggers.
        }
        return result;
    }

    void appendTask(const std::shared_ptr<MultiThreadDownloadTaskState>& task)
    {
        if (!task || m_rowsById.find(task->taskId) != m_rowsById.end())
        {
            return;
        }
        const int sourceRow = rowCount();
        Row row;
        row.task = task;
        updateProjection(row);
        beginInsertRows(QModelIndex(), sourceRow, sourceRow);
        m_rows.push_back(std::move(row));
        m_rowsById.emplace(task->taskId, sourceRow);
        m_activeRows.insert(sourceRow);
        ++m_counts[static_cast<std::size_t>(m_rows.back().category)];
        endInsertRows();
    }

    // All canonical history stays in m_rows. Terminal tasks leave the periodic polling set.
    std::size_t refreshActive()
    {
        std::size_t visited = 0;
        for (auto it = m_activeRows.begin(); it != m_activeRows.end();)
        {
            const int sourceRow = *it;
            Row& row = m_rows[static_cast<std::size_t>(sourceRow)];
            const auto oldTexts = row.texts;
            const auto oldSortValues = row.sortValues;
            const int oldCategory = row.category;
            const bool oldPaused = row.paused;
            const bool oldPauseEnabled = row.pauseEnabled;
            const bool oldCancelEnabled = row.cancelEnabled;
            const QString oldPath = row.outputPath;
            updateProjection(row);
            ++visited;
            if (oldCategory != row.category)
            {
                --m_counts[static_cast<std::size_t>(oldCategory)];
                ++m_counts[static_cast<std::size_t>(row.category)];
            }
            int firstChanged = -1;
            int lastChanged = -1;
            for (int column = 0; column < MultiDownloadTaskColumnCount; ++column)
            {
                const auto col = static_cast<std::size_t>(column);
                bool changed = oldTexts[col] != row.texts[col] || oldSortValues[col] != row.sortValues[col];
                if (column == MultiDownloadTaskColumnFile)
                {
                    changed = changed || oldPath != row.outputPath;
                }
                if (column == MultiDownloadTaskColumnAction)
                {
                    changed = changed || oldPaused != row.paused || oldPauseEnabled != row.pauseEnabled
                        || oldCancelEnabled != row.cancelEnabled;
                }
                if (changed)
                {
                    if (firstChanged < 0) firstChanged = column;
                    lastChanged = column;
                }
            }
            if (firstChanged >= 0)
            {
                emit dataChanged(index(sourceRow, firstChanged), index(sourceRow, lastChanged));
            }
            // Retire only a snapshot that began after the worker's final release publication.
            if (row.terminal)
            {
                it = m_activeRows.erase(it);
            }
            else
            {
                ++it;
            }
        }
        return visited;
    }
    int categoryCount(const int category) const
    {
        return category >= 0 && category < static_cast<int>(m_counts.size())
            ? m_counts[static_cast<std::size_t>(category)] : 0;
    }
    std::shared_ptr<MultiThreadDownloadTaskState> taskById(const int taskId) const
    {
        const auto found = m_rowsById.find(taskId);
        return found == m_rowsById.end() ? nullptr : m_rows[static_cast<std::size_t>(found->second)].task;
    }
    QModelIndex indexForTask(const int taskId) const
    {
        const auto found = m_rowsById.find(taskId);
        return found == m_rowsById.end() ? QModelIndex() : index(found->second, 0);
    }
    int firstTaskId() const
    {
        return m_rows.empty() ? 0 : m_rows.front().task->taskId;
    }

private:
    struct Row
    {
        std::shared_ptr<MultiThreadDownloadTaskState> task;
        std::array<QString, MultiDownloadTaskColumnCount> texts;
        std::array<QVariant, MultiDownloadTaskColumnCount> sortValues;
        QString outputPath;
        bool terminal = false;
        bool paused = false;
        bool pauseEnabled = false;
        bool cancelEnabled = false;
        int category = 0; // Running, finished, failed, canceled (same precedence as the prior view).
    };
    void updateProjection(Row& row)
    {
        const auto& task = row.task;
        const bool finished = task->finished.load(); // Acquire terminal status before reading its final data.
        const std::uint64_t downloaded = task->downloadedBytes.load();
        const std::uint64_t total = task->totalBytes;
        const double percent = ks::network::CalculateProgressPercent(downloaded, total);
        const bool failed = task->failed.load();
        const bool canceled = task->canceled.load();
        QString status;
        {
            std::lock_guard<std::mutex> guard(task->statusMutex);
            status = task->statusText;
            if (failed && !task->errorReasonText.isEmpty())
            {
                status += QStringLiteral("（%1）").arg(task->errorReasonText);
            }
        }
        row.texts = {
            QString::number(task->taskId), task->fileNameText, task->urlText,
            QStringLiteral("%1/%2").arg(task->actualThreadCount).arg(task->requestedThreadCount),
            formatBytesText(total), formatBytesText(downloaded), QStringLiteral("%1%").arg(percent, 0, 'f', 2),
            status, QString()
        };
        row.sortValues = {
            task->taskId, task->fileNameText, task->urlText, task->actualThreadCount,
            QVariant::fromValue(static_cast<qulonglong>(total)), QVariant::fromValue(static_cast<qulonglong>(downloaded)),
            percent, status, task->taskId
        };
        row.outputPath = task->savePathText;
        row.terminal = finished;
        row.paused = task->pauseRequested.load();
        row.cancelEnabled = !finished && !task->cancelRequested.load();
        row.pauseEnabled = row.cancelEnabled && !task->preparing.load();
        row.category = canceled ? 3 : failed ? 2 : finished ? 1 : 0;
    }
    std::deque<Row> m_rows;
    std::unordered_map<int, int> m_rowsById;
    std::unordered_set<int> m_activeRows;
    std::array<int, 4> m_counts{};
};

namespace
{
    // The source model must return these roles on the ACTION index as well.
    // Keep just one definition when integrating with the task model.

    using DownloadTaskAction = std::function<void(int taskId, bool cancel)>;
    using DownloadEditorChanged = std::function<void()>;

    int downloadActionNaturalRowHeight(const QFont& font)
    {
        return qMax(28, QFontMetrics(font).height() + 12) + 4;
    }

    // Original SVGs are shared; each live button owns its theme-context wrapper.
    const QIcon& downloadPauseSourceIcon()
    {
        static const QIcon icon(QStringLiteral(":/Icon/process_pause.svg"));
        return icon;
    }
    const QIcon& downloadResumeSourceIcon()
    {
        static const QIcon icon(QStringLiteral(":/Icon/process_start.svg"));
        return icon;
    }
    const QIcon& downloadCancelSourceIcon()
    {
        static const QIcon icon(QStringLiteral(":/Icon/log_cancel_track.svg"));
        return icon;
    }

    class DownloadTaskActionEditor final : public QWidget
    {
    public:
        DownloadTaskActionEditor(QWidget* parent, const QModelIndex& index,
            QObject* actionContext, DownloadTaskAction action, DownloadEditorChanged changed)
            : QWidget(parent), m_index(index), m_taskId(index.data(TaskIdRole).toInt()),
              m_actionContext(actionContext), m_action(std::move(action)),
              m_changed(std::move(changed))
        {
            auto* row = new QHBoxLayout(this);
            row->setContentsMargins(2, 2, 2, 2);
            m_pause = new QPushButton(this);
            m_cancel = new QPushButton(QStringLiteral("取消"), this);
            ks::ui::ApplyFlatButtonTheme(m_pause, ks::ui::FlatButtonTone::Neutral,
                ks::ui::FlatButtonAppearance::Solid);
            ks::ui::ApplyFlatButtonTheme(m_cancel, ks::ui::FlatButtonTone::Danger,
                ks::ui::FlatButtonAppearance::Solid);
            m_pauseIcon = ks::ui::MakeThemeButtonAccentIcon(downloadPauseSourceIcon(), QColor(), m_pause);
            m_resumeIcon = ks::ui::MakeThemeButtonAccentIcon(downloadResumeSourceIcon(), QColor(), m_pause);
            m_cancel->setIcon(ks::ui::MakeThemeButtonAccentIcon(downloadCancelSourceIcon(), QColor(), m_cancel));
            m_cancel->setToolTip(QStringLiteral("取消当前下载任务，已写入的临时文件内容会保留"));
            row->addWidget(m_pause);
            row->addWidget(m_cancel);
            row->addStretch(1);
            ks::ui::NormalizeToolbarRow(row);
            m_pause->installEventFilter(this);
            m_cancel->installEventFilter(this);
            connect(m_pause, &QPushButton::clicked, this, [this]() { trigger(false); });
            connect(m_cancel, &QPushButton::clicked, this, [this]() { trigger(true); });
            synchronize();
        }

        bool identityMatches() const
        {
            return m_index.isValid() && m_taskId > 0
                && m_index.data(TaskIdRole).toInt() == m_taskId;
        }

        bool containsFocusWidget(const QWidget* widget) const
        {
            return widget != nullptr && (widget == this || isAncestorOf(widget));
        }

        bool hasActiveInteraction() const
        {
            // isDown alone is insufficient: dragging out of a pressed button clears it.
            return m_pointerDown || m_actionRunning || m_pause->isDown() || m_cancel->isDown()
                || containsFocusWidget(QApplication::focusWidget());
        }

        void synchronize()
        {
            const bool live = identityMatches() && !m_actionContext.isNull();
            const bool paused = live && m_index.data(PausedRole).toBool();
            if (!m_captionKnown || paused != m_paused)
            {
                m_captionKnown = true;
                m_paused = paused;
                m_pause->setText(paused ? QStringLiteral("继续") : QStringLiteral("暂停"));
                m_pause->setIcon(paused ? m_resumeIcon : m_pauseIcon);
                m_pause->setToolTip(paused ? QStringLiteral("继续当前下载任务")
                    : QStringLiteral("暂停当前下载任务"));
            }
            const bool pauseEnabled = live && m_index.data(PauseEnabledRole).toBool();
            const bool cancelEnabled = live && m_index.data(CancelEnabledRole).toBool();
            if (!m_enablementKnown || m_pauseEnabled != pauseEnabled)
            {
                m_pause->setEnabled(pauseEnabled);
                m_pauseEnabled = pauseEnabled;
            }
            if (!m_enablementKnown || m_cancelEnabled != cancelEnabled)
            {
                m_cancel->setEnabled(cancelEnabled);
                m_cancelEnabled = cancelEnabled;
            }
            m_enablementKnown = true; // effective isEnabled() may differ while an ancestor is disabled.
            const bool mismatch = !identityMatches();
            if (mismatch && !m_identityMismatchReported)
                notifyChanged(); // replace a changed identity only after press/focus ends.
            m_identityMismatchReported = mismatch; // do not queue continuously while pinned.
        }

    protected:
        bool focusNextPrevChild(const bool next) override
        {
            QWidget* const origin = QApplication::focusWidget();
            if (!containsFocusWidget(origin))
                return QWidget::focusNextPrevChild(next);
            // QTableView normally converts descendant Tab into cell navigation. Follow the
            // existing window focus chain for these real buttons instead; the view itself
            // retains its normal Tab/cursor handling when it owns keyboard focus.
            QWidget* candidate = next ? origin->nextInFocusChain() : origin->previousInFocusChain();
            while (candidate && candidate != origin)
            {
                QWidget* const proxy = candidate->focusProxy();
                if (candidate->window() == window() && candidate->isVisible() && candidate->isEnabled()
                    && (candidate->focusPolicy() & Qt::TabFocus) && candidate != this && proxy != origin)
                {
                    candidate->setFocus(next ? Qt::TabFocusReason : Qt::BacktabFocusReason);
                    return true;
                }
                candidate = next ? candidate->nextInFocusChain() : candidate->previousInFocusChain();
            }
            return false;
        }

        bool eventFilter(QObject* source, QEvent* event) override
        {
            switch (event->type())
            {
            case QEvent::MouseButtonPress:
            case QEvent::MouseButtonDblClick:
                if (static_cast<QMouseEvent*>(event)->button() == Qt::LeftButton)
                    m_pointerDown = true;
                notifyChanged();
                break;
            case QEvent::MouseButtonRelease:
                if (static_cast<QMouseEvent*>(event)->button() == Qt::LeftButton)
                    m_pointerDown = false;
                notifyChanged(); // queued; QPushButton finishes release/click first.
                break;
            case QEvent::UngrabMouse:
                m_pointerDown = false;
                notifyChanged();
                break;
            case QEvent::FocusIn:
            case QEvent::FocusOut:
            case QEvent::KeyPress:
            case QEvent::KeyRelease:
            case QEvent::FontChange:
            case QEvent::ApplicationFontChange:
            case QEvent::StyleChange:
            case QEvent::LanguageChange:
                notifyChanged();
                break;
            default:
                break;
            }
            return QWidget::eventFilter(source, event);
        }

    private:
        void notifyChanged() const
        {
            if (m_changed)
                m_changed();
        }

        void trigger(const bool cancel)
        {
            // Re-read the persistent index at click time; never capture a row number.
            if (m_actionContext.isNull() || !identityMatches() || !m_action
                || !m_index.data(cancel ? CancelEnabledRole : PauseEnabledRole).toBool())
                return;
            const DownloadTaskAction action = m_action;
            const int taskId = m_taskId;
            const QPointer<DownloadTaskActionEditor> guard(this);
            m_actionRunning = true; // a host callback may enter a nested event loop.
            action(taskId, cancel); // host revalidates its task state before changing it.
            if (guard)
            {
                guard->m_actionRunning = false;
                guard->notifyChanged();
            }
        }

        const QPersistentModelIndex m_index;
        const int m_taskId; // immutable even if model reset/replacement reuses a row.
        QPointer<QObject> m_actionContext;
        DownloadTaskAction m_action;
        DownloadEditorChanged m_changed;
        QPushButton* m_pause = nullptr;
        QPushButton* m_cancel = nullptr;
        QIcon m_pauseIcon;
        QIcon m_resumeIcon;
        bool m_captionKnown = false;
        bool m_paused = false;
        bool m_enablementKnown = false;
        bool m_pauseEnabled = false;
        bool m_cancelEnabled = false;
        bool m_pointerDown = false;
        bool m_actionRunning = false;
        bool m_identityMismatchReported = false;
    };

    class DownloadTaskActionDelegate final : public QStyledItemDelegate
    {
    public:
        using Created = std::function<void(const QPersistentModelIndex&, DownloadTaskActionEditor*)>;
        DownloadTaskActionDelegate(QObject* parent, const int column, QObject* actionContext,
            DownloadTaskAction action, DownloadEditorChanged changed, Created created)
            : QStyledItemDelegate(parent), m_column(column), m_actionContext(actionContext),
              m_action(std::move(action)), m_changed(std::move(changed)), m_created(std::move(created)) {}

        QWidget* createEditor(QWidget* parent, const QStyleOptionViewItem&,
            const QModelIndex& index) const override
        {
            if (index.column() != m_column || index.data(TaskIdRole).toInt() <= 0)
                return nullptr;
            auto* editor = new DownloadTaskActionEditor(parent, index, m_actionContext.data(),
                m_action, m_changed);
            m_created(QPersistentModelIndex(index), editor);
            return editor;
        }

        void setEditorData(QWidget* widget, const QModelIndex&) const override
        {
            static_cast<DownloadTaskActionEditor*>(widget)->synchronize();
        }
        void setModelData(QWidget*, QAbstractItemModel*, const QModelIndex&) const override {}
        QSize sizeHint(const QStyleOptionViewItem& option, const QModelIndex& index) const override
        {
            QSize size = QStyledItemDelegate::sizeHint(option, index);
            size.setHeight(qMax(size.height(), downloadActionNaturalRowHeight(option.font)));
            return size;
        }
        void updateEditorGeometry(QWidget* editor, const QStyleOptionViewItem& option,
            const QModelIndex&) const override { editor->setGeometry(option.rect); }

    protected:
        bool eventFilter(QObject* source, QEvent* event) override
        {
            // The container is an action surface, not a commit/close text editor.
            // Keep button Tab/focus/keyboard processing; the controller owns its lifetime.
            return QObject::eventFilter(source, event);
        }

    private:
        const int m_column;
        QPointer<QObject> m_actionContext;
        DownloadTaskAction m_action;
        DownloadEditorChanged m_changed;
        Created m_created;
    };

    class VisibleDownloadTaskEditors final : public QObject
    {
    public:
        // Construct AFTER view->setModel(proxy). The controller lives as long as this view.
        // The actual host remains ks::ui::TableActionTableView with Compact action bar.
        VisibleDownloadTaskEditors(QTableView* view, const int actionColumn,
            QObject* actionContext, DownloadTaskAction action)
            : QObject(view), m_view(view), m_model(view->model()), m_column(actionColumn)
        {
            view->setProperty("ksword_preserve_custom_row_height", true);
            const QPointer<VisibleDownloadTaskEditors> guard(this);
            auto changed = [guard]() { if (guard) guard->schedule(); };
            auto created = [guard](const QPersistentModelIndex& index, DownloadTaskActionEditor* editor)
            {
                if (!guard)
                    return;
                guard->m_open.append({index, editor});
                QObject::connect(editor, &QObject::destroyed, guard.data(),
                    [guard]() { if (guard) guard->schedule(); });
            };
            m_delegate = new DownloadTaskActionDelegate(this, m_column, actionContext,
                std::move(action), changed, std::move(created));
            view->setItemDelegateForColumn(m_column, m_delegate);
            view->horizontalHeader()->setSectionResizeMode(m_column, QHeaderView::Interactive);
            view->setEditTriggers(QAbstractItemView::NoEditTriggers);
            view->installEventFilter(this);
            view->viewport()->installEventFilter(this);
            connect(view->verticalScrollBar(), &QScrollBar::valueChanged, this, changed);
            connect(view->horizontalScrollBar(), &QScrollBar::valueChanged, this, changed);
            connect(view->verticalScrollBar(), &QScrollBar::rangeChanged, this, changed);
            connect(view->horizontalScrollBar(), &QScrollBar::rangeChanged, this, changed);
            connect(view->verticalHeader(), &QHeaderView::geometriesChanged, this, changed);
            connect(view->verticalHeader(), &QHeaderView::sectionResized, this, changed);
            connect(view->verticalHeader(), &QHeaderView::sectionMoved, this, changed);
            connect(view->horizontalHeader(), &QHeaderView::geometriesChanged, this, changed);
            connect(view->horizontalHeader(), &QHeaderView::sectionResized, this, changed);
            connect(view->horizontalHeader(), &QHeaderView::sectionMoved, this, changed);
            if (m_model)
            {
                connect(m_model.data(), &QAbstractItemModel::rowsInserted, this, changed);
                connect(m_model.data(), &QAbstractItemModel::rowsRemoved, this, changed);
                connect(m_model.data(), &QAbstractItemModel::rowsMoved, this, changed);
                connect(m_model.data(), &QAbstractItemModel::modelReset, this, changed);
                connect(m_model.data(), &QAbstractItemModel::layoutChanged, this, changed);
                connect(m_model.data(), &QAbstractItemModel::destroyed, this, changed);
                connect(m_model.data(), &QAbstractItemModel::dataChanged, this,
                    [changed](const QModelIndex&, const QModelIndex&, const QList<int>& roles)
                    {
                        if (roles.isEmpty() || roles.contains(TaskIdRole))
                            changed();
                    });
            }
            connect(qApp, &QApplication::focusChanged, this,
                [this](QWidget* oldFocus, QWidget* newFocus)
                {
                    for (const Entry& entry : m_open)
                    {
                        if (entry.editor && (entry.editor->containsFocusWidget(oldFocus)
                            || entry.editor->containsFocusWidget(newFocus)))
                        {
                            schedule();
                            return;
                        }
                    }
                });
            schedule();
        }

        void schedule()
        {
            if (m_pending)
                return;
            m_pending = true;
            QTimer::singleShot(0, this, [this]()
                {
                    m_pending = false;
                    synchronize();
                });
        }

    protected:
        bool eventFilter(QObject* source, QEvent* event) override
        {
            switch (event->type())
            {
            case QEvent::Show:
            case QEvent::Hide:
            case QEvent::Resize:
            case QEvent::FontChange:
            case QEvent::ApplicationFontChange:
            case QEvent::StyleChange:
            case QEvent::LanguageChange:
                schedule();
                break;
            default:
                break; // deliberately no Paint or LayoutRequest observer.
            }
            return QObject::eventFilter(source, event);
        }

    private:
        struct Entry
        {
            QPersistentModelIndex index;
            QPointer<DownloadTaskActionEditor> editor;
        };

        QList<QPersistentModelIndex> visibleIndexes() const
        {
            QList<QPersistentModelIndex> indexes;
            if (!m_view || !m_model || m_view->model() != m_model.data()
                || !m_view->isVisible() || !m_view->viewport()->isVisible()
                || m_view->isColumnHidden(m_column))
                return indexes;
            // rowAt/rowViewportPosition respect pixel/item scrolling and hidden/moved rows.
            // Scan only the viewport, including partial first/last rows, never rowCount().
            const int height = m_view->viewport()->height();
            for (int y = 0; y < height; )
            {
                const int row = m_view->rowAt(y);
                if (row < 0)
                    break;
                const QModelIndex index = m_model->index(row, m_column, m_view->rootIndex());
                if (index.isValid())
                    indexes.append(QPersistentModelIndex(index));
                y = qMax(y + 1, m_view->rowViewportPosition(row) + m_view->rowHeight(row));
            }
            return indexes;
        }

        void synchronize()
        {
            if (!m_view)
                return;
            const QPointer<VisibleDownloadTaskEditors> guard(this);
            QHeaderView* const header = m_view->verticalHeader();
            const int naturalRowHeight = downloadActionNaturalRowHeight(m_view->font());
            // Preserve taller user sections/defaults. Only raise values below the natural
            // action row height; equal values must not create another geometry feedback.
            if (header->minimumSectionSize() < naturalRowHeight)
                header->setMinimumSectionSize(naturalRowHeight);
            if (header->defaultSectionSize() < naturalRowHeight)
                header->setDefaultSectionSize(naturalRowHeight);
            if (!guard || !m_view)
                return;
            const QList<QPersistentModelIndex> wanted = visibleIndexes();
            for (qsizetype i = m_open.size(); i > 0; )
            {
                --i;
                const Entry entry = m_open.at(i);
                if (!entry.editor)
                {
                    m_open.removeAt(i);
                    continue;
                }
                entry.editor->synchronize();
                if (!guard || !m_view)
                    return;
                const bool keep = wanted.contains(entry.index) && entry.editor->identityMatches();
                if (!keep && !entry.editor->hasActiveInteraction())
                {
                    m_open.removeAt(i);
                    // Reset/row removal already retires Qt's invalid editors.
                    if (entry.index.isValid() && entry.index.model() == m_view->model())
                        m_view->closePersistentEditor(entry.index);
                    if (!guard || !m_view)
                        return;
                }
            }
            for (const QPersistentModelIndex& index : wanted)
            {
                if (index.isValid() && !m_view->isPersistentEditorOpen(index))
                {
                    m_view->openPersistentEditor(index);
                    if (!guard || !m_view)
                        return;
                }
            }
            // Size only the live editors, never ResizeToContents across retained history.
            int actionWidth = 0;
            for (const Entry& entry : m_open)
                if (entry.editor)
                    actionWidth = qMax(actionWidth, entry.editor->minimumSizeHint().width());
            QHeaderView* const horizontal = m_view->horizontalHeader();
            if (actionWidth > horizontal->sectionSize(m_column))
                horizontal->resizeSection(m_column, actionWidth);
        }

        QPointer<QTableView> m_view;
        QPointer<QAbstractItemModel> m_model;
        const int m_column;
        DownloadTaskActionDelegate* m_delegate = nullptr;
        // Do not hash mutable QPersistentModelIndex keys across a model layout change.
        // Size is visible rows plus any pressed/focused editor awaiting release/focus-out.
        QList<Entry> m_open;
        bool m_pending = false;
    };
}


class MultiThreadDownloadSegmentBarWidget final : public QWidget
{
public:
    explicit MultiThreadDownloadSegmentBarWidget(QWidget* parent = nullptr)
        : QWidget(parent)
    {
        setMinimumHeight(28);
        setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    }

    void setSegmentRatios(const QVector<double>& segmentRatios, const double totalRatio, const bool finished)
    {
        m_segmentRatios = segmentRatios;
        m_totalRatio = std::clamp(totalRatio, 0.0, 1.0);
        m_finished = finished;
        update();
    }

protected:
    void paintEvent(QPaintEvent* event) override
    {
        Q_UNUSED(event);

        QPainter painter(this);
        painter.setRenderHint(QPainter::Antialiasing, true);

        const QRectF outerRect = rect().adjusted(1.0, 1.0, -1.0, -1.0);
        painter.setPen(QPen(KswordTheme::BorderStrongColor(), 1.0));
        painter.setBrush(KswordTheme::SurfaceColor());
        painter.drawRoundedRect(outerRect, 4.0, 4.0);

        const QRectF contentRect = outerRect.adjusted(2.0, 2.0, -2.0, -2.0);
        if (m_segmentRatios.isEmpty())
        {
            painter.setPen(Qt::NoPen);
            painter.setBrush(KswordTheme::WithAlpha(
                KswordTheme::AccentColor(KswordTheme::AccentRole::Blue), 180));
            painter.drawRect(QRectF(contentRect.left(), contentRect.top(), contentRect.width() * m_totalRatio, contentRect.height()));
            return;
        }

        const int countValue = m_segmentRatios.size();
        const double gapWidth = m_finished ? 0.0 : 2.0;
        const double allGapWidth = gapWidth * static_cast<double>(std::max(0, countValue - 1));
        const double eachWidth = (contentRect.width() - allGapWidth) / static_cast<double>(countValue);

        for (int index = 0; index < countValue; ++index)
        {
            const QRectF segmentRect(
                contentRect.left() + index * (eachWidth + gapWidth),
                contentRect.top(),
                eachWidth,
                contentRect.height());
            painter.setPen(Qt::NoPen);
            painter.setBrush(KswordTheme::SurfaceAltColor());
            painter.drawRect(segmentRect);

            const double ratioValue = std::clamp(m_segmentRatios.at(index), 0.0, 1.0);
            if (ratioValue > 0.0)
            {
                painter.setBrush(KswordTheme::AccentColor(KswordTheme::AccentRole::Blue));
                painter.drawRect(QRectF(segmentRect.left(), segmentRect.top(), segmentRect.width() * ratioValue, segmentRect.height()));
            }
        }
    }

private:
    QVector<double> m_segmentRatios;
    double m_totalRatio = 0.0;
    bool m_finished = false;
};
void NetworkDock::initializeMultiThreadDownloadTab()
{
    if (m_multiThreadDownloadPage == nullptr) m_multiThreadDownloadPage = new QWidget(this);
    m_multiThreadDownloadLayout = new QVBoxLayout(m_multiThreadDownloadPage);
    m_multiThreadDownloadLayout->setContentsMargins(0, 0, 0, 0);
    auto* workspace = new ks::ui::ParameterWorkspace(m_multiThreadDownloadPage, 420); // 下载输入与任务进度分栏。
    m_multiThreadDownloadLayout->addWidget(workspace);

    m_multiThreadDownloadControlLayout = workspace->actions();
    auto* downloadForm = new QFormLayout; // URL/目录占满一行，避免旧工具条挤压路径。
    downloadForm->setRowWrapPolicy(QFormLayout::WrapAllRows);

    QLabel* urlLabel = new QLabel(QStringLiteral("URL:"), m_multiThreadDownloadPage);
    m_multiDownloadUrlEdit = new QLineEdit(m_multiThreadDownloadPage);
    m_multiDownloadUrlEdit->setPlaceholderText(QStringLiteral("输入 http/https 下载地址"));
    m_multiDownloadUrlEdit->setToolTip(QStringLiteral("仅支持 HTTP/HTTPS 下载。"));

    QLabel* dirLabel = new QLabel(QStringLiteral("下载目录:"), m_multiThreadDownloadPage);
    m_multiDownloadSaveDirEdit = new QLineEdit(m_multiThreadDownloadPage);
    m_multiDownloadSaveDirEdit->setToolTip(QStringLiteral("默认目录为用户 Downloads。"));

    const QString defaultDownloadPath = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    m_multiDownloadSaveDirEdit->setText(defaultDownloadPath.isEmpty() ? QDir::homePath() : defaultDownloadPath);

    QLabel* threadLabel = new QLabel(QStringLiteral("线程:"), m_multiThreadDownloadPage);
    m_multiDownloadThreadCountSpin = new QSpinBox(m_multiThreadDownloadPage);
    m_multiDownloadThreadCountSpin->setRange(1, 64);
    m_multiDownloadThreadCountSpin->setValue(16);
    m_multiDownloadThreadCountSpin->setToolTip(QStringLiteral("下载开始前可调整线程数，默认 16。"));

    m_multiDownloadBrowseDirButton = new QPushButton(m_multiThreadDownloadPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_multiDownloadBrowseDirButton, ks::ui::FlatButtonTone::Neutral,
        ks::ui::FlatButtonAppearance::Solid);
    m_multiDownloadBrowseDirButton->setIcon(QIcon(":/Icon/file_find.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_multiDownloadBrowseDirButton);
    m_multiDownloadBrowseDirButton->setToolTip(QStringLiteral("选择下载目录"));

    m_multiDownloadStartButton = new QPushButton(m_multiThreadDownloadPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_multiDownloadStartButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);
    m_multiDownloadStartButton->setIcon(QIcon(":/Icon/process_start.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_multiDownloadStartButton);
    m_multiDownloadStartButton->setToolTip(QStringLiteral("启动新的多线程下载任务"));

    m_multiDownloadStatusLabel = new QLabel(QStringLiteral("状态：等待下载任务"), m_multiThreadDownloadPage);
    m_multiDownloadStatusLabel->setWordWrap(true);
    m_multiDownloadStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    auto* directoryRow = new QHBoxLayout; // 目录选择按钮继续紧邻路径。
    directoryRow->addWidget(m_multiDownloadSaveDirEdit, 1);
    directoryRow->addWidget(m_multiDownloadBrowseDirButton);
    // 路径与浏览动作作为同一工具行对齐，保持输入伸缩和统一的 8px 间距。
    ks::ui::NormalizeToolbarRow(directoryRow);
    downloadForm->addRow(urlLabel, m_multiDownloadUrlEdit);
    downloadForm->addRow(dirLabel, directoryRow);
    downloadForm->addRow(threadLabel, m_multiDownloadThreadCountSpin);
    workspace->parameters()->addLayout(downloadForm);
    m_multiDownloadDraftLabel = new QLabel(m_multiThreadDownloadPage);
    m_multiDownloadDraftLabel->setTextFormat(Qt::PlainText); m_multiDownloadDraftLabel->setWordWrap(true);
    m_multiDownloadDraftLabel->hide(); workspace->parameters()->addWidget(m_multiDownloadDraftLabel);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadStartButton);
    m_multiThreadDownloadControlLayout->addStretch();
    workspace->results()->addWidget(m_multiDownloadStatusLabel);

    // 下载捕获设置栏：
    // - 提供“剪贴板自动捕获下载链接”开关；
    // - 提供“可识别后缀名”可编辑输入框；
    // - 通过独立保存按钮将设置写入 JSON。
    QGroupBox* captureSettingsGroup = new QGroupBox(QStringLiteral("下载捕获设置"), m_multiThreadDownloadPage); // captureSettingsGroup：下载捕获设置分组容器。
    QGridLayout* captureSettingsLayout = new QGridLayout(captureSettingsGroup); // captureSettingsLayout：下载捕获设置分组布局。
    captureSettingsLayout->setHorizontalSpacing(6);
    captureSettingsLayout->setVerticalSpacing(6);
    captureSettingsLayout->setColumnStretch(1, 1);

    m_multiDownloadAutoCaptureClipboardCheck = new QCheckBox(QStringLiteral("自动捕获剪贴板链接"), captureSettingsGroup);
    m_multiDownloadAutoCaptureClipboardCheck->setToolTip(
        QStringLiteral("启用后，当剪贴板出现匹配后缀的 HTTP/HTTPS 链接时自动弹出下载询问框。"));

    QLabel* suffixLabel = new QLabel(QStringLiteral("识别后缀:"), captureSettingsGroup); // suffixLabel：后缀输入框标题标签。
    m_multiDownloadCaptureSuffixEdit = new QLineEdit(captureSettingsGroup);
    m_multiDownloadCaptureSuffixEdit->setPlaceholderText(QStringLiteral("示例：.zip;.7z;.iso;.exe"));
    m_multiDownloadCaptureSuffixEdit->setToolTip(
        QStringLiteral("支持以 ; , 空格 分隔后缀名，自动补全前导点。"));

    m_multiDownloadSaveCaptureSettingsButton = new QPushButton(captureSettingsGroup);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_multiDownloadSaveCaptureSettingsButton, ks::ui::FlatButtonTone::Accent,
        ks::ui::FlatButtonAppearance::Solid);
    m_multiDownloadSaveCaptureSettingsButton->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    KswordTheme::ApplyCompactIconButtonMetrics(m_multiDownloadSaveCaptureSettingsButton);
    m_multiDownloadSaveCaptureSettingsButton->setToolTip(QStringLiteral("保存下载捕获设置到 JSON"));
    ks::ui::NormalizeToolbarControl(m_multiDownloadSaveCaptureSettingsButton);

    QLabel* captureHintLabel = new QLabel(
        QStringLiteral("提示：剪贴板询问框为非阻塞窗口，不会阻塞主界面操作。"),
        captureSettingsGroup); // captureHintLabel：下载捕获设置使用提示标签。
    captureHintLabel->setWordWrap(true);
    captureHintLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));

    captureSettingsLayout->addWidget(m_multiDownloadAutoCaptureClipboardCheck, 0, 0, 1, 3);
    captureSettingsLayout->addWidget(suffixLabel, 1, 0, 1, 3);
    captureSettingsLayout->addWidget(m_multiDownloadCaptureSuffixEdit, 2, 0, 1, 2);
    captureSettingsLayout->addWidget(m_multiDownloadSaveCaptureSettingsButton, 2, 2);
    captureSettingsLayout->addWidget(captureHintLabel, 3, 0, 1, 3);
    workspace->parameters()->addWidget(ks::ui::FoldParameterSection(captureSettingsGroup));

    m_multiDownloadTaskTable = new ks::ui::TableActionTableView(m_multiThreadDownloadPage);
    // Same Compact host contract: all canonical rows remain available to copy/export.
    ks::ui::SetTableActionBarMode(m_multiDownloadTaskTable, ks::ui::TableActionBarMode::Compact);
    m_multiDownloadTaskModel = new MultiThreadDownloadTaskModel(m_multiDownloadTaskTable);
    auto* taskProxy = new QSortFilterProxyModel(m_multiDownloadTaskTable);
    taskProxy->setSourceModel(m_multiDownloadTaskModel);
    taskProxy->setSortRole(Qt::UserRole);
    taskProxy->setDynamicSortFilter(false); // Explicit user sorting; progress never moves a pressed target.
    m_multiDownloadTaskTable->setModel(taskProxy);
    m_multiDownloadTaskTable->setProperty("ks_i18n_preserve_model_data", true); // Model translates only state/header text.
    m_multiDownloadTaskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_multiDownloadTaskTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_multiDownloadTaskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_multiDownloadTaskTable->horizontalHeader()->setSortIndicator(0, Qt::AscendingOrder);
    m_multiDownloadTaskTable->setSortingEnabled(true);
    m_multiDownloadTaskTable->verticalHeader()->setVisible(false);
    ks::ui::SetTableColumnAutoFitEnabled(m_multiDownloadTaskTable, false);
    m_multiDownloadTaskTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_multiDownloadTaskTable->horizontalHeader()->setSectionResizeMode(MultiDownloadTaskColumnAction, QHeaderView::Interactive);
    m_multiDownloadTaskTable->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_multiDownloadTaskTable, &QWidget::customContextMenuRequested, this, [this](const QPoint& position)
        {
            const QModelIndex clicked = m_multiDownloadTaskTable->indexAt(position);
            if (clicked.isValid())
            {
                m_multiDownloadTaskTable->setCurrentIndex(clicked);
                m_multiDownloadTaskTable->selectRow(clicked.row());
            }
            const QModelIndex current = m_multiDownloadTaskTable->currentIndex();
            const int taskId = current.isValid() ? current.data(TaskIdRole).toInt() : 0;
            const auto task = findMultiThreadDownloadTaskById(taskId);
            QStringList fields;
            if (current.isValid())
            {
                for (int column = 0; column < m_multiDownloadTaskTable->model()->columnCount(); ++column)
                {
                    fields.push_back(m_multiDownloadTaskTable->model()->index(current.row(), column).data().toString());
                }
            }
            QMenu menu(m_multiDownloadTaskTable);
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            auto* copyRow = menu.addAction(QIcon(QStringLiteral(":/Icon/process_copy_row.svg")), QStringLiteral("复制当前行"));
            ks::ui::SetTableContextActionRole(copyRow, ks::ui::TableContextActionRole::CopyRows);
            copyRow->setEnabled(current.isValid());
            auto* draft = menu.addAction(ks::i18n::sourceText(QStringLiteral("载入为新任务…")));
            draft->setEnabled(task && task->finished.load() && (task->failed.load() || task->canceled.load()));
            const QPointer<NetworkDock> owner(this);
            const auto* chosen = menu.exec(m_multiDownloadTaskTable->viewport()->mapToGlobal(position));
            if (!owner) return;
            if (chosen == draft) { loadMultiThreadDownloadTaskDraft(taskId); return; }
            if (chosen == copyRow)
            {
                if (auto* clipboard = QGuiApplication::clipboard())
                {
                    clipboard->setText(fields.join(QLatin1Char('\t')));
                }
            }
        });
    new VisibleDownloadTaskEditors(m_multiDownloadTaskTable, MultiDownloadTaskColumnAction, this,
        [host = QPointer<NetworkDock>(this)](const int taskId, const bool cancel)
        {
            if (!host) return;
            if (cancel)
            {
                host->cancelMultiThreadDownloadTask(taskId);
            }
            else if (const auto task = host->findMultiThreadDownloadTaskById(taskId))
            {
                host->setMultiThreadDownloadTaskPaused(taskId, !task->pauseRequested.load());
            }
        });
    workspace->results()->addWidget(m_multiDownloadTaskTable, 1);

    QLabel* progressTitleLabel = new QLabel(
        QStringLiteral("当前选中任务总进度（未完成时会断成多节）："),
        m_multiThreadDownloadPage);
    progressTitleLabel->setWordWrap(true);
    workspace->results()->addWidget(progressTitleLabel);

    m_multiDownloadSegmentBar = new MultiThreadDownloadSegmentBarWidget(m_multiThreadDownloadPage);
    workspace->results()->addWidget(m_multiDownloadSegmentBar);

    m_multiDownloadTotalProgressLabel = new QLabel(QStringLiteral("总进度：0.00%"), m_multiThreadDownloadPage);
    workspace->results()->addWidget(m_multiDownloadTotalProgressLabel);

    m_multiDownloadSegmentTable = new ks::ui::VisibleTableWidget(m_multiThreadDownloadPage);
    // 分段是所选任务的附属进度，快照/对比不适用且挤占进度空间。
    ks::ui::SetTableActionBarMode(m_multiDownloadSegmentTable, ks::ui::TableActionBarMode::None);
    m_multiDownloadSegmentTable->setColumnCount(MultiDownloadSegmentColumnCount);
    m_multiDownloadSegmentTable->setHorizontalHeaderLabels({
        QStringLiteral("分段"),
        QStringLiteral("字节范围"),
        QStringLiteral("已下载"),
        QStringLiteral("进度"),
        QStringLiteral("状态")
        });
    m_multiDownloadSegmentTable->setSelectionMode(QAbstractItemView::NoSelection);
    m_multiDownloadSegmentTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_multiDownloadSegmentTable->verticalHeader()->setVisible(false);
    m_multiDownloadSegmentTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // 横向滚动条不强制关闭：默认由全局列宽自适应压入 viewport，用户拖宽列后按需出现。
    installCopyCurrentRowMenu(m_multiDownloadSegmentTable);
    workspace->results()->addWidget(m_multiDownloadSegmentTable, 1);
    workspace->finish();

    network_navigation_detail::AddTab(m_sideTabWidget, m_multiThreadDownloadPage, QStringLiteral("download"), QIcon(":/Icon/process_start.svg"));

    // 设置值已在宿主启动时加载；首次建UI只回填，不重读文件或重置剪贴板去重值。
    updateMultiThreadDownloadCaptureSettingsUi();

    kLogEvent initEvent;
    info << initEvent << "[NetworkDock] 多线程下载页初始化完成。" << eol;
}

void NetworkDock::browseMultiThreadDownloadDirectory()
{
    if (m_multiDownloadSaveDirEdit == nullptr)
    {
        return;
    }

    const QString selectedDirectory = QFileDialog::getExistingDirectory(
        this,
        QStringLiteral("选择下载目录"),
        m_multiDownloadSaveDirEdit->text().trimmed().isEmpty() ? QDir::homePath() : m_multiDownloadSaveDirEdit->text().trimmed(),
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (selectedDirectory.isEmpty())
    {
        return;
    }

    m_multiDownloadSaveDirEdit->setText(selectedDirectory);

    kLogEvent browseEvent;
    info << browseEvent
        << "[NetworkDock] 用户切换多线程下载目录, path="
        << selectedDirectory.toStdString()
        << eol;
}

void NetworkDock::startMultiThreadDownloadTask()
{
    if (m_multiDownloadUrlEdit == nullptr
        || m_multiDownloadSaveDirEdit == nullptr
        || m_multiDownloadThreadCountSpin == nullptr)
    {
        return;
    }

    kLogEvent startEvent;
    const QString urlText = m_multiDownloadUrlEdit->text().trimmed();
    const QUrl downloadUrl(urlText);
    if (!downloadUrl.isValid()
        || (downloadUrl.scheme().compare(QStringLiteral("http"), Qt::CaseInsensitive) != 0
            && downloadUrl.scheme().compare(QStringLiteral("https"), Qt::CaseInsensitive) != 0))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), QStringLiteral("请输入合法的 HTTP/HTTPS 地址。"));
        warn << startEvent << "[NetworkDock] 多线程下载启动失败：URL非法。" << eol;
        return;
    }

    const QString directoryText = m_multiDownloadSaveDirEdit->text().trimmed();
    m_multiDownloadDraftLabel->hide();
    const int taskId = m_multiDownloadNextTaskId++;
    auto taskState = std::make_shared<MultiThreadDownloadTaskState>();
    taskState->taskId = taskId;
    taskState->urlText = urlText;
    taskState->requestedDirectoryText = directoryText;
    taskState->fileNameText = buildSafeOutputFileName(downloadUrl, taskId);
    taskState->requestedThreadCount = std::max(1, m_multiDownloadThreadCountSpin->value());
    taskState->actualThreadCount = 0;
    taskState->preparing.store(true);
    taskState->statusText = QStringLiteral("等待中");
    {
        std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
        m_multiDownloadTaskList.push_back(taskState);
    }
    m_multiDownloadTaskModel->appendTask(taskState);
    if (m_multiDownloadSelectedTaskId == 0)
    {
        m_multiDownloadSelectedTaskId = taskId;
    }
    if (m_multiDownloadDispatcher == nullptr)
    {
        m_multiDownloadDispatcher = std::make_shared<ks::ui::AsyncUiDispatcher>(this);
    }
    const auto dispatcher = m_multiDownloadDispatcher;
    try
    {
        std::thread([owner = this, dispatcher, taskState, directoryText]()
            {
                const auto canceled = [taskState]() { return taskState->cancelRequested.load(); };
                DownloadPreparationResult result;
                try
                {
                    result = prepareDownload(taskState->urlText, directoryText, taskState->fileNameText, canceled);
                }
                catch (...)
                {
                    result.errorText = QStringLiteral("创建下载会话失败。");
                }
                const auto retireUndeliveredPreparation = [taskState]()
                {
                    // This value fallback must also cover argument/functor allocation
                    // before AsyncUiDispatcher can own its onCanceled callback.
                    taskState->canceled.store(true);
                    taskState->cancelRequested.store(true);
                    taskState->preparing.store(false);
                    taskState->finished.store(true);
                };
                try
                {
                dispatcher->post([owner, taskState, result]()
                    {
                        QString errorForDialog;
                        taskState->preparing.store(false);
                        taskState->savePathText = result.outputPath;
                        if (taskState->cancelRequested.load())
                        {
                            taskState->canceled.store(true);
                            taskState->finished.store(true);
                            std::lock_guard<std::mutex> lock(taskState->statusMutex);
                            taskState->statusText = QStringLiteral("已取消");
                        }
                        else if (!result.errorText.isEmpty() || result.outputPath.isEmpty())
                        {
                            taskState->failed.store(true);
                            taskState->finished.store(true);
                            std::lock_guard<std::mutex> lock(taskState->statusMutex);
                            taskState->statusText = QStringLiteral("失败");
                            taskState->errorReasonText = result.errorText;
                            errorForDialog = result.errorText;
                        }
                        else
                        {
                            taskState->supportsRange = result.supportsRange;
                            taskState->totalBytes = result.totalBytes;
                            taskState->statusText = QStringLiteral("下载中");
                            const ks::network::DownloadPlan downloadPlan = ks::network::BuildDownloadSegmentPlan(
                                taskState->totalBytes,
                                taskState->requestedThreadCount,
                                taskState->supportsRange);
                            taskState->actualThreadCount = downloadPlan.actualThreadCount;

                            if (downloadPlan.emptyFile)
                            {
                                std::shared_ptr<MultiThreadDownloadSegmentState> segmentState = std::make_shared<MultiThreadDownloadSegmentState>();
                                segmentState->rangeBeginByte = downloadPlan.segments.front().beginByte;
                                segmentState->rangeEndByte = downloadPlan.segments.front().endByte;
                                segmentState->finished.store(true);
                                segmentState->statusText = QStringLiteral("空文件");
                                taskState->segmentStateList.push_back(segmentState);
                                taskState->finished.store(true);
                                taskState->statusText = QStringLiteral("已完成（空文件）");
                            }
                            else
                            {
                                for (const ks::network::DownloadSegmentPlan& segmentPlan : downloadPlan.segments)
                                {
                                    std::shared_ptr<MultiThreadDownloadSegmentState> segmentState = std::make_shared<MultiThreadDownloadSegmentState>();
                                    segmentState->rangeBeginByte = segmentPlan.beginByte;
                                    segmentState->rangeEndByte = segmentPlan.endByte;
                                    segmentState->statusText = QStringLiteral("等待中");
                                    taskState->segmentStateList.push_back(segmentState);
                                }

                                taskState->runningWorkerCount.store(downloadPlan.actualThreadCount);
                                const bool useRange = downloadPlan.useRange;
                                const std::size_t launchedCount = launchDownloadWorkersSafely(
                                    taskState->segmentStateList.size(),
                                    [taskState, urlParts = result.urlParts, useRange](const std::size_t index)
                                    {
                                        const auto segmentState = taskState->segmentStateList[index];
                                        std::thread([taskState, segmentState, urlParts, useRange]()
                                        {
                                            {
                                                std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
                                                segmentState->statusText = QStringLiteral("下载中");
                                            }

                                            QString downloadErrorText;
                                            const bool downloadOk = downloadSegmentToFile(
                                                urlParts,
                                                taskState->savePathText,
                                                segmentState->rangeBeginByte,
                                                segmentState->rangeEndByte,
                                                useRange,
                                                &taskState->cancelRequested,
                                                &taskState->pauseRequested,
                                                [taskState, segmentState](const std::uint64_t chunkBytes)
                                                {
                                                    segmentState->downloadedBytes.fetch_add(chunkBytes);
                                                    taskState->downloadedBytes.fetch_add(chunkBytes);
                                                },
                                                &downloadErrorText);

                                            if (!downloadOk)
                                            {
                                                taskState->cancelRequested.store(true);
                                                const bool canceledByUser = taskState->canceled.load();
                                                if (!canceledByUser)
                                                {
                                                    taskState->failed.store(true);
                                                }
                                                {
                                                    std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
                                                    segmentState->statusText = canceledByUser ? QStringLiteral("已取消") : QStringLiteral("失败");
                                                }
                                                {
                                                    std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                                                    taskState->statusText = canceledByUser ? QStringLiteral("已取消") : QStringLiteral("失败");
                                                    if (!canceledByUser && taskState->errorReasonText.isEmpty())
                                                    {
                                                        taskState->errorReasonText = downloadErrorText;
                                                    }
                                                }
                                            }
                                            else
                                            {
                                                segmentState->finished.store(true);
                                                std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
                                                segmentState->statusText = QStringLiteral("完成");
                                            }

                                            const int remainWorker = taskState->runningWorkerCount.fetch_sub(1) - 1;
                                            if (remainWorker <= 0)
                                            {
                                                if (taskState->canceled.load())
                                                {
                                                    std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                                                    taskState->statusText = QStringLiteral("已取消");
                                                }
                                                else if (!taskState->failed.load())
                                                {
                                                    taskState->downloadedBytes.store(taskState->totalBytes);
                                                    std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                                                    taskState->statusText = QStringLiteral("已完成");
                                                }
                                                taskState->finished.store(true);
                                            }
                                        }).detach();
                                    },
                                    [taskState, &errorForDialog](const std::size_t firstNotLaunched, const std::size_t notLaunched)
                                    {
                                        taskState->failed.store(true);
                                        taskState->cancelRequested.store(true);
                                        errorForDialog = QStringLiteral("创建下载会话失败。");
                                        {
                                            std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
                                            taskState->statusText = QStringLiteral("失败");
                                            if (taskState->errorReasonText.isEmpty())
                                            {
                                                taskState->errorReasonText = errorForDialog;
                                            }
                                        }
                                        for (std::size_t index = firstNotLaunched; index < taskState->segmentStateList.size(); ++index)
                                        {
                                            const auto& segment = taskState->segmentStateList[index];
                                            std::lock_guard<std::mutex> segmentGuard(segment->statusMutex);
                                            segment->statusText = QStringLiteral("失败");
                                        }
                                        // Planned slots prevent an early worker from finishing the task during launch.
                                        // Retire only the slots with no worker; already launched workers retire themselves.
                                        const int unstarted = static_cast<int>(notLaunched);
                                        if (taskState->runningWorkerCount.fetch_sub(unstarted) - unstarted <= 0)
                                        {
                                            taskState->finished.store(true);
                                        }
                                    });
                                taskState->actualThreadCount = static_cast<int>(launchedCount);
                            }

                            kLogEvent startEvent;
                            info << startEvent
                                << "[NetworkDock] 多线程下载任务启动, taskId=" << taskState->taskId
                                << ", requestedThreads=" << taskState->requestedThreadCount
                                << ", actualThreads=" << taskState->actualThreadCount
                                << ", totalBytes=" << static_cast<unsigned long long>(taskState->totalBytes)
                                << ", supportsRange=" << (taskState->supportsRange ? "true" : "false")
                                << ", outputPath=" << taskState->savePathText.toStdString()
                                << eol;

                        }
                        // Errors and the reserved output path remain in the main task row, including clipboard jobs.
                        owner->refreshMultiThreadDownloadUi();
                        if (!errorForDialog.isEmpty() && !taskState->canceled.load())
                        {
                            QMessageBox::warning(owner, QStringLiteral("多线程下载"), errorForDialog);
                        }
                    }, retireUndeliveredPreparation);
                }
                catch (...)
                {
                    retireUndeliveredPreparation();
                }
            }).detach();
    }
    catch (...)
    {
        taskState->preparing.store(false);
        taskState->failed.store(true);
        taskState->finished.store(true);
        taskState->statusText = QStringLiteral("失败");
        taskState->errorReasonText = QStringLiteral("创建下载会话失败。");
    }
    refreshMultiThreadDownloadUi();
}

bool NetworkDock::startMultiThreadDownloadTaskFromInput(
    const QString& urlText,
    const QString& saveDirectoryText)
{
    const QPointer<NetworkDock> owner(this);
    if (!ensureNetworkToolPage(m_multiThreadDownloadPage) || !owner) return false;
    if (m_multiDownloadUrlEdit == nullptr || m_multiDownloadSaveDirEdit == nullptr)
    {
        return false;
    }

    // True means the preparation transaction was accepted, not that HEAD/file preparation succeeded.
    // Later errors and the reserved output path are reported on the main download task row.
    std::size_t taskCountBefore = 0;
    {
        std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
        taskCountBefore = m_multiDownloadTaskList.size();
    }

    // 将询问框确认值同步回主下载页输入框，保持用户可见状态一致。
    m_multiDownloadUrlEdit->setText(urlText.trimmed());
    m_multiDownloadSaveDirEdit->setText(saveDirectoryText.trimmed());
    startMultiThreadDownloadTask();

    std::size_t taskCountAfter = 0;
    {
        std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
        taskCountAfter = m_multiDownloadTaskList.size();
    }

    return taskCountAfter > taskCountBefore;
}

std::shared_ptr<NetworkDock::MultiThreadDownloadTaskState> NetworkDock::findMultiThreadDownloadTaskById(const int taskId) const
{
    return m_multiDownloadTaskModel != nullptr ? m_multiDownloadTaskModel->taskById(taskId) : nullptr;
}

void NetworkDock::loadMultiThreadDownloadTaskDraft(const int taskId)
{
    const auto task = findMultiThreadDownloadTaskById(taskId);
    if (!task || !task->finished.load() || (!task->failed.load() && !task->canceled.load())) return;
    const QString directory = task->savePathText.isEmpty() ? task->requestedDirectoryText : QFileInfo(task->savePathText).absolutePath();
    const QPointer<NetworkDock> owner(this);
    const QString chosen = QFileDialog::getExistingDirectory(this,
        ks::i18n::sourceText(QStringLiteral("复核新任务保存目录")), directory,
        QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
    if (!owner || chosen.isEmpty()) return;
    m_multiDownloadUrlEdit->setText(task->urlText);
    m_multiDownloadSaveDirEdit->setText(QDir::toNativeSeparators(chosen));
    m_multiDownloadThreadCountSpin->setValue(task->requestedThreadCount);
    m_multiDownloadDraftLabel->setText(ks::i18n::sourceText(QStringLiteral(
        "已载入任务 %1 的新任务草稿；请核对地址与保存目录，再点击开始。原任务和已有文件保留，新任务重新下载并使用独立文件名。" )).arg(taskId));
    m_multiDownloadDraftLabel->show();
    m_multiDownloadUrlEdit->setFocus(Qt::OtherFocusReason);
}

void NetworkDock::setMultiThreadDownloadTaskPaused(const int taskId, const bool paused)
{
    const std::shared_ptr<MultiThreadDownloadTaskState> taskState = findMultiThreadDownloadTaskById(taskId);
    if (taskState == nullptr || taskState->preparing.load() || taskState->finished.load() || taskState->cancelRequested.load())
    {
        return;
    }

    taskState->pauseRequested.store(paused);
    {
        std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
        taskState->statusText = paused ? QStringLiteral("已暂停") : QStringLiteral("下载中");
    }

    for (const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState : taskState->segmentStateList)
    {
        if (segmentState == nullptr || segmentState->finished.load())
        {
            continue;
        }

        std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
        segmentState->statusText = paused ? QStringLiteral("已暂停") : QStringLiteral("下载中");
    }

    kLogEvent pauseEvent;
    info << pauseEvent
        << "[NetworkDock] 多线程下载任务"
        << (paused ? "暂停" : "继续")
        << ", taskId="
        << taskId
        << eol;
    refreshMultiThreadDownloadUi();
}

void NetworkDock::cancelMultiThreadDownloadTask(const int taskId)
{
    const std::shared_ptr<MultiThreadDownloadTaskState> taskState = findMultiThreadDownloadTaskById(taskId);
    if (taskState == nullptr || taskState->finished.load())
    {
        return;
    }

    taskState->canceled.store(true);
    taskState->cancelRequested.store(true);
    taskState->pauseRequested.store(false);
    {
        std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
        taskState->statusText = QStringLiteral("取消中");
        taskState->errorReasonText.clear();
    }

    for (const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState : taskState->segmentStateList)
    {
        if (segmentState == nullptr || segmentState->finished.load())
        {
            continue;
        }

        std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
        segmentState->statusText = QStringLiteral("取消中");
    }

    kLogEvent cancelEvent;
    info << cancelEvent
        << "[NetworkDock] 多线程下载任务取消请求, taskId="
        << taskId
        << eol;
    refreshMultiThreadDownloadUi();
}

void NetworkDock::refreshMultiThreadDownloadUi()
{
    if (m_multiDownloadTaskTable == nullptr || m_multiDownloadTaskModel == nullptr
        || m_multiDownloadSegmentTable == nullptr || m_multiDownloadSegmentBar == nullptr
        || m_multiDownloadTotalProgressLabel == nullptr)
    {
        return;
    }
    m_multiDownloadTaskModel->refreshActive();
    if (m_multiDownloadStatusLabel != nullptr)
    {
        const QString status = ks::i18n::sourceText(QStringLiteral("状态：运行中 %1，已完成 %2，失败 %3，已取消 %4")
            .arg(m_multiDownloadTaskModel->categoryCount(0)).arg(m_multiDownloadTaskModel->categoryCount(1))
            .arg(m_multiDownloadTaskModel->categoryCount(2)).arg(m_multiDownloadTaskModel->categoryCount(3)));
        if (m_multiDownloadStatusLabel->text() != status)
        {
            m_multiDownloadStatusLabel->setText(status);
        }
    }
    if (m_multiDownloadSelectedTaskId <= 0)
    {
        m_multiDownloadSelectedTaskId = m_multiDownloadTaskModel->firstTaskId();
    }
    const QModelIndex current = m_multiDownloadTaskTable->currentIndex();
    if (m_multiDownloadSelectedTaskId > 0 && (!current.isValid()
        || current.data(TaskIdRole).toInt() != m_multiDownloadSelectedTaskId))
    {
        if (auto* proxy = qobject_cast<QSortFilterProxyModel*>(m_multiDownloadTaskTable->model()))
        {
            const QModelIndex desired = proxy->mapFromSource(m_multiDownloadTaskModel->indexForTask(m_multiDownloadSelectedTaskId));
            if (desired.isValid())
            {
                const QSignalBlocker blocker(m_multiDownloadTaskTable->selectionModel());
                m_multiDownloadTaskTable->selectionModel()->setCurrentIndex(desired,
                    QItemSelectionModel::ClearAndSelect | QItemSelectionModel::Rows);
            }
        }
    }
    const auto selectedTask = findMultiThreadDownloadTaskById(m_multiDownloadSelectedTaskId);
    if (!selectedTask)
    {
        m_multiDownloadLastSegmentTaskId = 0;
        m_multiDownloadSegmentProjectionTerminal = false;
        m_multiDownloadSegmentTable->setRowCount(0);
        m_multiDownloadSegmentBar->setSegmentRatios(QVector<double>(), 0.0, false);
        m_multiDownloadTotalProgressLabel->setText(QStringLiteral("总进度：0.00%"));
        return;
    }

    const bool selectedTerminal = selectedTask->finished.load();
    if (m_multiDownloadLastSegmentTaskId == selectedTask->taskId
        && m_multiDownloadSegmentProjectionTerminal && selectedTerminal)
    {
        return; // A completed selection has no new progress; theme paints use existing dynamic tokens.
    }
    m_multiDownloadLastSegmentTaskId = selectedTask->taskId;
    m_multiDownloadSegmentProjectionTerminal = selectedTerminal;
    const auto& segmentList = selectedTask->segmentStateList;
    const bool segmentTableUpdatesEnabled = m_multiDownloadSegmentTable->updatesEnabled();
    m_multiDownloadSegmentTable->setUpdatesEnabled(false);
    m_multiDownloadSegmentTable->setRowCount(static_cast<int>(segmentList.size()));

    QVector<double> segmentRatios;
    segmentRatios.reserve(static_cast<int>(segmentList.size()));
    for (int index = 0; index < static_cast<int>(segmentList.size()); ++index)
    {
        const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState = segmentList[static_cast<std::size_t>(index)];
        if (segmentState == nullptr)
        {
            segmentRatios.push_back(0.0);
            continue;
        }

        const std::uint64_t rangeBytes = ks::network::CalculateSegmentByteCount(
            segmentState->rangeBeginByte,
            segmentState->rangeEndByte);
        const std::uint64_t downloaded = segmentState->downloadedBytes.load();
        const double ratio = ks::network::CalculateProgressRatio(downloaded, rangeBytes);
        const double percent = ks::network::CalculateProgressPercent(downloaded, rangeBytes);

        QString segmentStatus;
        {
            std::lock_guard<std::mutex> segmentGuard(segmentState->statusMutex);
            segmentStatus = segmentState->statusText;
        }

        setCellText(m_multiDownloadSegmentTable, index, MultiDownloadSegmentColumnIndex, QStringLiteral("#%1").arg(index + 1));
        setCellText(
            m_multiDownloadSegmentTable,
            index,
            MultiDownloadSegmentColumnRange,
            QStringLiteral("%1-%2")
            .arg(static_cast<qulonglong>(segmentState->rangeBeginByte))
            .arg(static_cast<qulonglong>(segmentState->rangeEndByte)));
        setCellText(
            m_multiDownloadSegmentTable,
            index,
            MultiDownloadSegmentColumnDownloaded,
            QStringLiteral("%1 / %2").arg(formatBytesText(downloaded)).arg(formatBytesText(rangeBytes)));
        setCellText(
            m_multiDownloadSegmentTable,
            index,
            MultiDownloadSegmentColumnProgress,
            QStringLiteral("%1%").arg(percent, 0, 'f', 2));
        setCellText(m_multiDownloadSegmentTable, index, MultiDownloadSegmentColumnStatus, segmentStatus);

        segmentRatios.push_back(ratio);
    }

    const std::uint64_t selectedDownloaded = selectedTask->downloadedBytes.load();
    const std::uint64_t selectedTotal = selectedTask->totalBytes;
    const double selectedRatio = ks::network::CalculateProgressRatio(selectedDownloaded, selectedTotal);
    const double selectedPercent = ks::network::CalculateProgressPercent(selectedDownloaded, selectedTotal);

    m_multiDownloadSegmentBar->setSegmentRatios(
        segmentRatios,
        selectedRatio,
        selectedTask->finished.load() && !selectedTask->failed.load());
    m_multiDownloadTotalProgressLabel->setText(
        QStringLiteral("总进度：%1%    已下载：%2 / %3")
        .arg(selectedPercent, 0, 'f', 2)
        .arg(formatBytesText(selectedDownloaded))
        .arg(formatBytesText(selectedTotal)));

    m_multiDownloadSegmentTable->setUpdatesEnabled(segmentTableUpdatesEnabled);
    if (segmentTableUpdatesEnabled && m_multiDownloadSegmentTable->viewport() != nullptr)
    {
        m_multiDownloadSegmentTable->viewport()->update();
    }
}
