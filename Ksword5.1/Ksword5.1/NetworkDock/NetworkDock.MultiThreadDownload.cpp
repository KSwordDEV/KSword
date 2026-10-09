#include "NetworkDock.InternalCommon.h"
#include "../UI/FlatButtonTheme.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

// ============================================================
// NetworkDock.MultiThreadDownload.cpp
// 作用：
// 1) 新增“多线程下载”Tab（类似 IDM 分段下载）；
// 2) 下载前支持设置线程数（默认 16）；
// 3) 展示任务级百分比、分段级百分比与断节式总进度条。
// ============================================================

#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QPainter>
#include <QSignalBlocker>
#include <QStandardPaths>
#include <QUrl>

#include <cwchar>
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

        const std::uint64_t totalBytes = static_cast<std::uint64_t>(std::wcstoull(contentLengthText.c_str(), nullptr, 10));
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

    QString buildUniqueOutputPath(const QString& directoryPathText, const QString& fileNameText)
    {
        QDir directory(directoryPathText);
        QString outputPathText = directory.filePath(fileNameText);
        if (!QFileInfo::exists(outputPathText))
        {
            return outputPathText;
        }

        const QFileInfo info(fileNameText);
        const QString baseNameText = info.completeBaseName();
        const QString suffixText = info.suffix();
        int indexValue = 1;
        while (indexValue < 10000)
        {
            const QString candidateNameText = suffixText.isEmpty()
                ? QStringLiteral("%1(%2)").arg(baseNameText).arg(indexValue)
                : QStringLiteral("%1(%2).%3").arg(baseNameText).arg(indexValue).arg(suffixText);
            outputPathText = directory.filePath(candidateNameText);
            if (!QFileInfo::exists(outputPathText))
            {
                return outputPathText;
            }
            ++indexValue;
        }
        return directory.filePath(fileNameText);
    }

    bool prepareOutputFile(const QString& outputFilePathText, const std::uint64_t totalBytes, QString* errorTextOut)
    {
        const std::wstring outputPathWideText = outputFilePathText.toStdWString();
        HANDLE outputFileHandle = ::CreateFileW(
            outputPathWideText.c_str(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            nullptr,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            nullptr);
        if (outputFileHandle == INVALID_HANDLE_VALUE)
        {
            if (errorTextOut != nullptr)
            {
                *errorTextOut = QStringLiteral("创建输出文件失败，错误码=%1").arg(::GetLastError());
            }
            return false;
        }

        bool resultOk = true;
        if (totalBytes > 0)
        {
            LARGE_INTEGER sizeValue{};
            sizeValue.QuadPart = static_cast<LONGLONG>(totalBytes);
            if (::SetFilePointerEx(outputFileHandle, sizeValue, nullptr, FILE_BEGIN) == FALSE
                || ::SetEndOfFile(outputFileHandle) == FALSE)
            {
                resultOk = false;
                if (errorTextOut != nullptr)
                {
                    *errorTextOut = QStringLiteral("预分配输出文件失败，错误码=%1").arg(::GetLastError());
                }
            }
        }

        ::CloseHandle(outputFileHandle);
        return resultOk;
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
    m_multiThreadDownloadPage = new QWidget(this);
    m_multiThreadDownloadLayout = new QVBoxLayout(m_multiThreadDownloadPage);
    m_multiThreadDownloadLayout->setContentsMargins(6, 6, 6, 6);
    m_multiThreadDownloadLayout->setSpacing(6);

    m_multiThreadDownloadControlLayout = new QHBoxLayout();
    m_multiThreadDownloadControlLayout->setSpacing(6);

    QLabel* urlLabel = new QLabel(QStringLiteral("URL:"), m_multiThreadDownloadPage);
    m_multiDownloadUrlEdit = new QLineEdit(m_multiThreadDownloadPage);
    m_multiDownloadUrlEdit->setPlaceholderText(QStringLiteral("输入 http/https 下载地址"));
    m_multiDownloadUrlEdit->setToolTip(QStringLiteral("仅支持 HTTP/HTTPS 下载。"));

    QLabel* dirLabel = new QLabel(QStringLiteral("下载目录:"), m_multiThreadDownloadPage);
    m_multiDownloadSaveDirEdit = new QLineEdit(m_multiThreadDownloadPage);
    m_multiDownloadSaveDirEdit->setToolTip(QStringLiteral("默认目录为用户 Downloads。"));
    m_multiDownloadSaveDirEdit->setMinimumWidth(180);
    m_multiDownloadSaveDirEdit->setMaximumWidth(360);

    const QString defaultDownloadPath = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    m_multiDownloadSaveDirEdit->setText(defaultDownloadPath.isEmpty() ? QDir::homePath() : defaultDownloadPath);

    QLabel* threadLabel = new QLabel(QStringLiteral("线程:"), m_multiThreadDownloadPage);
    m_multiDownloadThreadCountSpin = new QSpinBox(m_multiThreadDownloadPage);
    m_multiDownloadThreadCountSpin->setRange(1, 64);
    m_multiDownloadThreadCountSpin->setValue(16);
    m_multiDownloadThreadCountSpin->setToolTip(QStringLiteral("下载开始前可调整线程数，默认 16。"));

    m_multiDownloadBrowseDirButton = new QPushButton(m_multiThreadDownloadPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_multiDownloadBrowseDirButton, ks::ui::FlatButtonTone::Neutral);
    m_multiDownloadBrowseDirButton->setIcon(QIcon(":/Icon/file_find.svg"));
    m_multiDownloadBrowseDirButton->setToolTip(QStringLiteral("选择下载目录"));

    m_multiDownloadStartButton = new QPushButton(m_multiThreadDownloadPage);
    // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
    ks::ui::ApplyFlatButtonTheme(m_multiDownloadStartButton, ks::ui::FlatButtonTone::Accent);
    m_multiDownloadStartButton->setIcon(QIcon(":/Icon/process_start.svg"));
    m_multiDownloadStartButton->setToolTip(QStringLiteral("启动新的多线程下载任务"));

    m_multiDownloadStatusLabel = new QLabel(QStringLiteral("状态：等待下载任务"), m_multiThreadDownloadPage);
    m_multiDownloadStatusLabel->setWordWrap(true);
    m_multiDownloadStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);

    m_multiThreadDownloadControlLayout->addWidget(urlLabel);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadUrlEdit, 1);
    m_multiThreadDownloadControlLayout->addWidget(dirLabel);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadSaveDirEdit);
    m_multiThreadDownloadControlLayout->addWidget(threadLabel);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadThreadCountSpin);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadBrowseDirButton);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadStartButton);
    m_multiThreadDownloadControlLayout->addWidget(m_multiDownloadStatusLabel, 1);
    m_multiThreadDownloadLayout->addLayout(m_multiThreadDownloadControlLayout);

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
    ks::ui::ApplyFlatButtonTheme(m_multiDownloadSaveCaptureSettingsButton, ks::ui::FlatButtonTone::Accent);
    m_multiDownloadSaveCaptureSettingsButton->setIcon(QIcon(":/Icon/codeeditor_save.svg"));
    m_multiDownloadSaveCaptureSettingsButton->setToolTip(QStringLiteral("保存下载捕获设置到 JSON"));

    QLabel* captureHintLabel = new QLabel(
        QStringLiteral("提示：剪贴板询问框为非阻塞窗口，不会阻塞主界面操作。"),
        captureSettingsGroup); // captureHintLabel：下载捕获设置使用提示标签。
    captureHintLabel->setWordWrap(true);
    captureHintLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));

    captureSettingsLayout->addWidget(m_multiDownloadAutoCaptureClipboardCheck, 0, 0, 1, 3);
    captureSettingsLayout->addWidget(suffixLabel, 1, 0);
    captureSettingsLayout->addWidget(m_multiDownloadCaptureSuffixEdit, 1, 1);
    captureSettingsLayout->addWidget(m_multiDownloadSaveCaptureSettingsButton, 1, 2);
    captureSettingsLayout->addWidget(captureHintLabel, 2, 0, 1, 3);
    m_multiThreadDownloadLayout->addWidget(captureSettingsGroup);

    m_multiDownloadTaskTable = new ks::ui::VisibleTableWidget(m_multiThreadDownloadPage);
    m_multiDownloadTaskTable->setColumnCount(MultiDownloadTaskColumnCount);
    m_multiDownloadTaskTable->setHorizontalHeaderLabels({
        QStringLiteral("任务ID"),
        QStringLiteral("文件名"),
        QStringLiteral("URL"),
        QStringLiteral("线程"),
        QStringLiteral("总大小"),
        QStringLiteral("已下载"),
        QStringLiteral("进度"),
        QStringLiteral("状态"),
        QStringLiteral("操作")
        });
    m_multiDownloadTaskTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_multiDownloadTaskTable->setSelectionMode(QAbstractItemView::SingleSelection);
    m_multiDownloadTaskTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_multiDownloadTaskTable->verticalHeader()->setVisible(false);
    m_multiDownloadTaskTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    // 横向滚动条不强制关闭：默认由全局列宽自适应压入 viewport，用户拖宽列后按需出现。
    installCopyCurrentRowMenu(m_multiDownloadTaskTable);
    m_multiThreadDownloadLayout->addWidget(m_multiDownloadTaskTable, 1);

    QLabel* progressTitleLabel = new QLabel(
        QStringLiteral("当前选中任务总进度（未完成时会断成多节）："),
        m_multiThreadDownloadPage);
    progressTitleLabel->setWordWrap(true);
    m_multiThreadDownloadLayout->addWidget(progressTitleLabel);

    m_multiDownloadSegmentBar = new MultiThreadDownloadSegmentBarWidget(m_multiThreadDownloadPage);
    m_multiThreadDownloadLayout->addWidget(m_multiDownloadSegmentBar);

    m_multiDownloadTotalProgressLabel = new QLabel(QStringLiteral("总进度：0.00%"), m_multiThreadDownloadPage);
    m_multiThreadDownloadLayout->addWidget(m_multiDownloadTotalProgressLabel);

    m_multiDownloadSegmentTable = new ks::ui::VisibleTableWidget(m_multiThreadDownloadPage);
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
    m_multiThreadDownloadLayout->addWidget(m_multiDownloadSegmentTable, 1);

    m_sideTabWidget->addTab(
        m_multiThreadDownloadPage,
        QIcon(":/Icon/process_start.svg"),
        QStringLiteral("多线程下载"));

    // 设置加载时机：
    // - 必须在控件构建完成后调用，才能把 JSON 值正确回填到 UI；
    // - 若设置文件不存在，会自动回退默认值并写入内存状态。
    loadMultiThreadDownloadCaptureSettings();

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
    QString directoryErrorText;
    if (!ensureDirectoryReady(directoryText, &directoryErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), directoryErrorText);
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：目录不可用, reason="
            << directoryErrorText.toStdString()
            << eol;
        return;
    }

    WinHttpUrlParts urlParts;
    QString parseErrorText;
    if (!parseWinHttpUrlParts(urlText, &urlParts, &parseErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), parseErrorText);
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：URL解析失败, reason="
            << parseErrorText.toStdString()
            << eol;
        return;
    }

    std::uint64_t totalBytes = 0;
    bool supportsRange = false;
    QString metaErrorText;
    if (!queryRemoteFileMeta(urlParts, &totalBytes, &supportsRange, &metaErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), QStringLiteral("读取远端文件信息失败：%1").arg(metaErrorText));
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：读取远端文件信息失败, reason="
            << metaErrorText.toStdString()
            << eol;
        return;
    }

    const int taskId = m_multiDownloadNextTaskId++;
    const QString fileNameText = buildSafeOutputFileName(downloadUrl, taskId);
    const QString outputPathText = buildUniqueOutputPath(directoryText, fileNameText);

    QString prepareErrorText;
    if (!prepareOutputFile(outputPathText, totalBytes, &prepareErrorText))
    {
        QMessageBox::warning(this, QStringLiteral("多线程下载"), prepareErrorText);
        warn << startEvent
            << "[NetworkDock] 多线程下载启动失败：输出文件准备失败, reason="
            << prepareErrorText.toStdString()
            << eol;
        return;
    }

    std::shared_ptr<MultiThreadDownloadTaskState> taskState = std::make_shared<MultiThreadDownloadTaskState>();
    taskState->taskId = taskId;
    taskState->urlText = urlText;
    taskState->savePathText = outputPathText;
    taskState->fileNameText = fileNameText;
    taskState->requestedThreadCount = std::max(1, m_multiDownloadThreadCountSpin->value());
    taskState->supportsRange = supportsRange;
    taskState->totalBytes = totalBytes;
    taskState->statusText = QStringLiteral("下载中");

    const ks::network::DownloadPlan downloadPlan = ks::network::BuildDownloadSegmentPlan(
        totalBytes,
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
        for (const std::shared_ptr<MultiThreadDownloadSegmentState>& segmentState : taskState->segmentStateList)
        {
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
                        taskState->finished.store(true);
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
                    }
                }).detach();
        }
    }

    {
        std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
        m_multiDownloadTaskList.push_back(taskState);
    }

    if (m_multiDownloadSelectedTaskId == 0)
    {
        m_multiDownloadSelectedTaskId = taskState->taskId;
    }

    if (m_multiDownloadStatusLabel != nullptr)
    {
        m_multiDownloadStatusLabel->setText(
            QStringLiteral("状态：任务 #%1 已启动，输出=%2")
            .arg(taskState->taskId)
            .arg(taskState->savePathText));
    }

    info << startEvent
        << "[NetworkDock] 多线程下载任务启动, taskId=" << taskState->taskId
        << ", requestedThreads=" << taskState->requestedThreadCount
        << ", actualThreads=" << taskState->actualThreadCount
        << ", totalBytes=" << static_cast<unsigned long long>(taskState->totalBytes)
        << ", supportsRange=" << (taskState->supportsRange ? "true" : "false")
        << ", outputPath=" << taskState->savePathText.toStdString()
        << eol;

    refreshMultiThreadDownloadUi();
}

bool NetworkDock::startMultiThreadDownloadTaskFromInput(
    const QString& urlText,
    const QString& saveDirectoryText)
{
    if (m_multiDownloadUrlEdit == nullptr || m_multiDownloadSaveDirEdit == nullptr)
    {
        return false;
    }

    // 启动前后快照：
    // - 通过任务数量是否增长判断“是否成功创建了新任务”；
    // - 该方法复用原有 startMultiThreadDownloadTask 校验和下载逻辑。
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
    if (taskId <= 0)
    {
        return nullptr;
    }

    std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
    for (const std::shared_ptr<MultiThreadDownloadTaskState>& taskState : m_multiDownloadTaskList)
    {
        if (taskState != nullptr && taskState->taskId == taskId)
        {
            return taskState;
        }
    }
    return nullptr;
}

void NetworkDock::setMultiThreadDownloadTaskPaused(const int taskId, const bool paused)
{
    const std::shared_ptr<MultiThreadDownloadTaskState> taskState = findMultiThreadDownloadTaskById(taskId);
    if (taskState == nullptr || taskState->finished.load() || taskState->cancelRequested.load())
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
    if (m_multiDownloadTaskTable == nullptr
        || m_multiDownloadSegmentTable == nullptr
        || m_multiDownloadSegmentBar == nullptr
        || m_multiDownloadTotalProgressLabel == nullptr)
    {
        return;
    }

    std::vector<std::shared_ptr<MultiThreadDownloadTaskState>> snapshotList;
    {
        std::lock_guard<std::mutex> guard(m_multiDownloadTaskMutex);
        snapshotList = m_multiDownloadTaskList;
    }

    const QSignalBlocker taskTableSignalBlocker(m_multiDownloadTaskTable);
    const bool taskTableUpdatesEnabled = m_multiDownloadTaskTable->updatesEnabled();
    m_multiDownloadTaskTable->setUpdatesEnabled(false);
    m_multiDownloadTaskTable->setRowCount(static_cast<int>(snapshotList.size()));

    int runningCount = 0;
    int finishedCount = 0;
    int failedCount = 0;
    int canceledCount = 0;
    for (int row = 0; row < static_cast<int>(snapshotList.size()); ++row)
    {
        const std::shared_ptr<MultiThreadDownloadTaskState>& taskState = snapshotList[static_cast<std::size_t>(row)];
        if (taskState == nullptr)
        {
            continue;
        }

        const std::uint64_t downloaded = taskState->downloadedBytes.load();
        const std::uint64_t total = taskState->totalBytes;
        const double percent = ks::network::CalculateProgressPercent(downloaded, total);

        QString statusText;
        {
            std::lock_guard<std::mutex> taskGuard(taskState->statusMutex);
            statusText = taskState->statusText;
            if (taskState->failed.load() && !taskState->errorReasonText.isEmpty())
            {
                statusText += QStringLiteral("（%1）").arg(taskState->errorReasonText);
            }
        }

        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnId, QString::number(taskState->taskId));
        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnFile, taskState->fileNameText);
        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnUrl, taskState->urlText);
        setCellText(
            m_multiDownloadTaskTable,
            row,
            MultiDownloadTaskColumnThread,
            QStringLiteral("%1/%2").arg(taskState->actualThreadCount).arg(taskState->requestedThreadCount));
        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnTotal, formatBytesText(total));
        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnDownloaded, formatBytesText(downloaded));
        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnProgress, QStringLiteral("%1%").arg(percent, 0, 'f', 2));
        setCellText(m_multiDownloadTaskTable, row, MultiDownloadTaskColumnStatus, statusText);

        const bool taskFinished = taskState->finished.load();
        const bool taskCanceled = taskState->canceled.load();
        const bool taskPaused = taskState->pauseRequested.load();
        const bool taskActionEnabled = !taskFinished && !taskState->cancelRequested.load();
        QWidget* actionWidget = m_multiDownloadTaskTable->cellWidget(row, MultiDownloadTaskColumnAction);
        if (actionWidget == nullptr)
        {
            actionWidget = new QWidget(m_multiDownloadTaskTable);
            QHBoxLayout* actionLayout = new QHBoxLayout(actionWidget);
            actionLayout->setContentsMargins(2, 2, 2, 2);
            actionLayout->setSpacing(4);

            QPushButton* pauseButton = new QPushButton(actionWidget);
            // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
            ks::ui::ApplyFlatButtonTheme(pauseButton, ks::ui::FlatButtonTone::Neutral);
            connect(pauseButton, &QPushButton::clicked, this, [this, taskId = taskState->taskId]()
                {
                    const std::shared_ptr<MultiThreadDownloadTaskState> currentTask = findMultiThreadDownloadTaskById(taskId);
                    if (currentTask != nullptr)
                    {
                        setMultiThreadDownloadTaskPaused(taskId, !currentTask->pauseRequested.load());
                    }
                });

            QPushButton* cancelButton = new QPushButton(actionWidget);
            // 此动作使用纯色主题，保留页面原有图标、状态和业务连接。
            ks::ui::ApplyFlatButtonTheme(cancelButton, ks::ui::FlatButtonTone::Danger);
            connect(cancelButton, &QPushButton::clicked, this, [this, taskId = taskState->taskId]()
                {
                    cancelMultiThreadDownloadTask(taskId);
                });

            actionLayout->addWidget(pauseButton);
            actionLayout->addWidget(cancelButton);
            actionLayout->addStretch(1);
            m_multiDownloadTaskTable->setCellWidget(row, MultiDownloadTaskColumnAction, actionWidget);
        }

        QHBoxLayout* actionLayout = qobject_cast<QHBoxLayout*>(actionWidget->layout());
        QPushButton* pauseButton = actionLayout != nullptr && actionLayout->count() > 0
            ? qobject_cast<QPushButton*>(actionLayout->itemAt(0)->widget())
            : nullptr;
        QPushButton* cancelButton = actionLayout != nullptr && actionLayout->count() > 1
            ? qobject_cast<QPushButton*>(actionLayout->itemAt(1)->widget())
            : nullptr;
        if (pauseButton != nullptr)
        {
            pauseButton->setText(taskPaused ? QStringLiteral("继续") : QStringLiteral("暂停"));
            pauseButton->setIcon(QIcon(taskPaused ? ":/Icon/process_start.svg" : ":/Icon/process_pause.svg"));
            pauseButton->setToolTip(taskPaused ? QStringLiteral("继续当前下载任务") : QStringLiteral("暂停当前下载任务"));
            pauseButton->setEnabled(taskActionEnabled);
        }
        if (cancelButton != nullptr)
        {
            cancelButton->setText(QStringLiteral("取消"));
            cancelButton->setIcon(QIcon(":/Icon/log_cancel_track.svg"));
            cancelButton->setToolTip(QStringLiteral("取消当前下载任务，已写入的临时文件内容会保留"));
            cancelButton->setEnabled(taskActionEnabled);
        }

        if (taskCanceled)
        {
            ++canceledCount;
        }
        else if (taskState->failed.load())
        {
            ++failedCount;
        }
        else if (taskState->finished.load())
        {
            ++finishedCount;
        }
        else
        {
            ++runningCount;
        }
    }

    if (m_multiDownloadStatusLabel != nullptr)
    {
        m_multiDownloadStatusLabel->setText(
            QStringLiteral("状态：运行中 %1，已完成 %2，失败 %3，已取消 %4")
            .arg(runningCount)
            .arg(finishedCount)
            .arg(failedCount)
            .arg(canceledCount));
    }

    m_multiDownloadTaskTable->setUpdatesEnabled(taskTableUpdatesEnabled);
    if (taskTableUpdatesEnabled && m_multiDownloadTaskTable->viewport() != nullptr)
    {
        m_multiDownloadTaskTable->viewport()->update();
    }

    if (m_multiDownloadSelectedTaskId <= 0 && !snapshotList.empty())
    {
        m_multiDownloadSelectedTaskId = snapshotList.front()->taskId;
    }

    if (m_multiDownloadSelectedTaskId > 0)
    {
        for (int row = 0; row < m_multiDownloadTaskTable->rowCount(); ++row)
        {
            QTableWidgetItem* idItem = m_multiDownloadTaskTable->item(row, MultiDownloadTaskColumnId);
            if (idItem == nullptr)
            {
                continue;
            }

            bool parseOk = false;
            const int taskId = idItem->text().toInt(&parseOk, 10);
            if (parseOk && taskId == m_multiDownloadSelectedTaskId)
            {
                m_multiDownloadTaskTable->selectRow(row);
                break;
            }
        }
    }

    std::shared_ptr<MultiThreadDownloadTaskState> selectedTask = findMultiThreadDownloadTaskById(m_multiDownloadSelectedTaskId);
    if (selectedTask == nullptr)
    {
        m_multiDownloadSegmentTable->setRowCount(0);
        m_multiDownloadSegmentBar->setSegmentRatios(QVector<double>(), 0.0, false);
        m_multiDownloadTotalProgressLabel->setText(QStringLiteral("总进度：0.00%"));
        return;
    }

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
