#include "NetworkDock.InternalCommon.h"
#include "../UI/ToolbarMetrics.h"

#include "../SettingsDock/AppearanceSettings.h"
#include "../theme.h"

#include <QCoreApplication>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QUrl>

namespace
{
    // JSON 键名常量：
    // - 统一维护，避免读写路径分散硬编码；
    // - 后续升级字段时可集中修改。
    constexpr const char* kCaptureSettingsFileName = "network_multidownload_settings.json";
    constexpr const char* kCaptureEnabledKey = "clipboard_auto_capture_enabled";
    constexpr const char* kCaptureSuffixArrayKey = "clipboard_recognize_suffixes";

    // buildCaptureSettingsJsonPath 作用：
    // - 解析下载捕获设置 JSON 绝对路径；
    // - 调用方式：加载/保存设置前调用；
    // - 传入：无；
    // - 传出：返回设置文件绝对路径。
    QString buildCaptureSettingsJsonPath()
    {
        // appearanceSettingsPath 用途：借用统一设置模块的“稳定写路径”定位 style 目录。
        const QString appearanceSettingsPath = ks::settings::resolveSettingsJsonPathForWrite();
        QFileInfo appearanceFileInfo(appearanceSettingsPath);
        QString styleDirectoryPath = appearanceFileInfo.absolutePath();
        if (styleDirectoryPath.trimmed().isEmpty())
        {
            styleDirectoryPath = QDir(QCoreApplication::applicationDirPath())
                .absoluteFilePath(QStringLiteral("style"));
        }
        return QDir(styleDirectoryPath).filePath(QString::fromLatin1(kCaptureSettingsFileName));
    }

    // buildDefaultCaptureSuffixList 作用：
    // - 提供默认的“可自动识别下载链接后缀”集合；
    // - 调用方式：设置文件不存在或用户输入为空时调用；
    // - 传入：无；
    // - 传出：返回默认后缀列表（小写、带前导点）。
    QStringList buildDefaultCaptureSuffixList()
    {
        return {
            // 图片文件：覆盖网页、相机、设计稿和常见图标资源，避免图片下载链接无法自动识别。
            QStringLiteral(".jpg"),
            QStringLiteral(".jpeg"),
            QStringLiteral(".png"),
            QStringLiteral(".gif"),
            QStringLiteral(".webp"),
            QStringLiteral(".bmp"),
            QStringLiteral(".svg"),
            QStringLiteral(".ico"),
            QStringLiteral(".tif"),
            QStringLiteral(".tiff"),
            QStringLiteral(".heic"),
            QStringLiteral(".heif"),
            QStringLiteral(".avif"),
            QStringLiteral(".raw"),
            QStringLiteral(".psd"),
            QStringLiteral(".ai"),
            QStringLiteral(".eps"),

            // 视频文件：覆盖主流封装、网页视频、摄像机素材和传输流文件。
            QStringLiteral(".mp4"),
            QStringLiteral(".mkv"),
            QStringLiteral(".avi"),
            QStringLiteral(".mov"),
            QStringLiteral(".wmv"),
            QStringLiteral(".flv"),
            QStringLiteral(".webm"),
            QStringLiteral(".m4v"),
            QStringLiteral(".mpg"),
            QStringLiteral(".mpeg"),
            QStringLiteral(".ts"),
            QStringLiteral(".mts"),
            QStringLiteral(".m2ts"),
            QStringLiteral(".3gp"),

            // 音频文件：覆盖有损、无损、移动端、语音和 MIDI 类下载资源。
            QStringLiteral(".mp3"),
            QStringLiteral(".wav"),
            QStringLiteral(".flac"),
            QStringLiteral(".aac"),
            QStringLiteral(".m4a"),
            QStringLiteral(".ogg"),
            QStringLiteral(".opus"),
            QStringLiteral(".wma"),
            QStringLiteral(".ape"),
            QStringLiteral(".alac"),
            QStringLiteral(".mid"),
            QStringLiteral(".midi"),
            QStringLiteral(".amr"),

            // 文档文件：覆盖办公文档、电子书、纯文本、数据表和常见配置说明文件。
            QStringLiteral(".pdf"),
            QStringLiteral(".doc"),
            QStringLiteral(".docx"),
            QStringLiteral(".xls"),
            QStringLiteral(".xlsx"),
            QStringLiteral(".ppt"),
            QStringLiteral(".pptx"),
            QStringLiteral(".txt"),
            QStringLiteral(".md"),
            QStringLiteral(".rtf"),
            QStringLiteral(".csv"),
            QStringLiteral(".json"),
            QStringLiteral(".xml"),
            QStringLiteral(".yaml"),
            QStringLiteral(".yml"),
            QStringLiteral(".log"),
            QStringLiteral(".chm"),
            QStringLiteral(".epub"),
            QStringLiteral(".mobi"),

            // 开发文件：覆盖源码、脚本、网页资源、数据库脚本和常见构建/部署脚本。
            QStringLiteral(".c"),
            QStringLiteral(".cpp"),
            QStringLiteral(".h"),
            QStringLiteral(".hpp"),
            QStringLiteral(".cs"),
            QStringLiteral(".java"),
            QStringLiteral(".py"),
            QStringLiteral(".js"),
            QStringLiteral(".html"),
            QStringLiteral(".css"),
            QStringLiteral(".php"),
            QStringLiteral(".go"),
            QStringLiteral(".rs"),
            QStringLiteral(".swift"),
            QStringLiteral(".kt"),
            QStringLiteral(".sh"),
            QStringLiteral(".bat"),
            QStringLiteral(".cmd"),
            QStringLiteral(".ps1"),
            QStringLiteral(".sql"),

            // 可执行与安装包：覆盖 Windows、Android、macOS、Linux 和 Java 应用交付文件。
            QStringLiteral(".exe"),
            QStringLiteral(".msi"),
            QStringLiteral(".msix"),
            QStringLiteral(".appx"),
            QStringLiteral(".apk"),
            QStringLiteral(".dmg"),
            QStringLiteral(".pkg"),
            QStringLiteral(".deb"),
            QStringLiteral(".rpm"),
            QStringLiteral(".run"),
            QStringLiteral(".bin"),
            QStringLiteral(".com"),
            QStringLiteral(".scr"),
            QStringLiteral(".dll"),
            QStringLiteral(".sys"),
            QStringLiteral(".jar"),
            QStringLiteral(".war"),

            // 压缩包与镜像：覆盖单文件压缩、多文件归档、分发镜像和常见跨平台压缩格式。
            QStringLiteral(".zip"),
            QStringLiteral(".7z"),
            QStringLiteral(".rar"),
            QStringLiteral(".iso"),
            QStringLiteral(".cab"),
            QStringLiteral(".gz"),
            QStringLiteral(".xz"),
            QStringLiteral(".bz2"),
            QStringLiteral(".tar"),
            QStringLiteral(".tgz"),
            QStringLiteral(".tbz2"),
            QStringLiteral(".txz"),
            QStringLiteral(".tar.gz"),
            QStringLiteral(".tar.bz2"),
            QStringLiteral(".tar.xz"),
            QStringLiteral(".zst"),
            QStringLiteral(".lz"),
            QStringLiteral(".lzma"),
            QStringLiteral(".arj")
        };
    }

    // normalizeSuffixText 作用：
    // - 对单个后缀词元做规范化（去空白、补前导点、转小写）；
    // - 调用方式：解析用户输入后缀列表时调用；
    // - 传入 suffixText：原始后缀文本；
    // - 传出：返回规范化后缀（无效则返回空字符串）。
    QString normalizeSuffixText(const QString& suffixText)
    {
        QString normalizedText = suffixText.trimmed().toLower();
        if (normalizedText.isEmpty())
        {
            return QString();
        }
        if (normalizedText == QStringLiteral("*") || normalizedText == QStringLiteral(".*"))
        {
            return QStringLiteral("*");
        }
        if (!normalizedText.startsWith('.'))
        {
            normalizedText.prepend('.');
        }
        if (normalizedText.size() <= 1)
        {
            return QString();
        }
        return normalizedText;
    }

    // normalizeSuffixList 作用：
    // - 解析并规范化后缀集合，自动去重；
    // - 调用方式：读取 JSON 或读取输入框文本后调用；
    // - 传入 rawSuffixList：原始后缀列表；
    // - 传出：返回规范化去重后列表。
    QStringList normalizeSuffixList(const QStringList& rawSuffixList)
    {
        QStringList normalizedList;
        for (const QString& rawSuffixText : rawSuffixList)
        {
            const QString normalizedSuffix = normalizeSuffixText(rawSuffixText);
            if (normalizedSuffix.isEmpty())
            {
                continue;
            }
            if (!normalizedList.contains(normalizedSuffix, Qt::CaseInsensitive))
            {
                normalizedList.push_back(normalizedSuffix);
            }
        }
        return normalizedList;
    }

    // parseSuffixLineEditText 作用：
    // - 将单行编辑框输入切分成后缀列表；
    // - 调用方式：保存设置前调用；
    // - 传入 suffixLineEditText：输入框文本；
    // - 传出：返回规范化去重后缀列表。
    QStringList parseSuffixLineEditText(const QString& suffixLineEditText)
    {
        // tokenSeparatorPattern 用途：分隔符规则，支持 ; , 空格 和换行。
        static const QRegularExpression tokenSeparatorPattern(QStringLiteral("[,;\\s]+"));
        const QStringList rawTokenList = suffixLineEditText.split(tokenSeparatorPattern, Qt::SkipEmptyParts);
        return normalizeSuffixList(rawTokenList);
    }

    // joinSuffixListForLineEdit 作用：
    // - 把后缀列表拼接回可编辑字符串；
    // - 调用方式：加载配置后回填 UI 时调用；
    // - 传入 suffixList：后缀集合；
    // - 传出：返回 ; 分隔文本。
    QString joinSuffixListForLineEdit(const QStringList& suffixList)
    {
        return suffixList.join(QStringLiteral(";"));
    }

    // extractFirstHttpUrlText 作用：
    // - 从剪贴板文本中提取首个 HTTP/HTTPS 链接；
    // - 调用方式：剪贴板变更处理时调用；
    // - 传入 clipboardText：原始剪贴板文本；
    // - 传出：返回匹配到的 URL 字符串，未匹配返回空。
    QString extractFirstHttpUrlText(const QString& clipboardText)
    {
        static const QRegularExpression urlPattern(
            QStringLiteral("(https?://[^\\s\"'<>]+)"),
            QRegularExpression::CaseInsensitiveOption);
        const QRegularExpressionMatch matchObject = urlPattern.match(clipboardText);
        if (!matchObject.hasMatch())
        {
            return QString();
        }

        // extractedUrlText 用途：候选 URL 文本，后续会裁剪尾部常见标点。
        QString extractedUrlText = matchObject.captured(1).trimmed();
        while (!extractedUrlText.isEmpty())
        {
            const QChar tailCharacter = extractedUrlText.back();
            const bool needTrimTail = (
                tailCharacter == '.' ||
                tailCharacter == ',' ||
                tailCharacter == ';' ||
                tailCharacter == ')' ||
                tailCharacter == ']' ||
                tailCharacter == '}' ||
                tailCharacter == '!' ||
                tailCharacter == '?');
            if (!needTrimTail)
            {
                break;
            }
            extractedUrlText.chop(1);
        }
        return extractedUrlText;
    }
}

void NetworkDock::loadMultiThreadDownloadCaptureSettings()
{
    // loadEvent 用途：贯穿“读取下载捕获设置”流程的统一日志事件对象。
    kLogEvent loadEvent;
    const QString settingsJsonPath = buildCaptureSettingsJsonPath(); // settingsJsonPath：下载捕获设置 JSON 绝对路径。

    bool autoCaptureEnabled = true; // autoCaptureEnabled：是否启用剪贴板自动捕获。
    QStringList suffixList = buildDefaultCaptureSuffixList(); // suffixList：当前生效的后缀匹配列表。
    QFile settingsFile(settingsJsonPath); // settingsFile：下载捕获设置文件对象。
    if (settingsFile.exists() && settingsFile.open(QIODevice::ReadOnly | QIODevice::Text))
    {
        QJsonParseError parseError;
        const QJsonDocument jsonDocument = QJsonDocument::fromJson(settingsFile.readAll(), &parseError);
        settingsFile.close();
        if (parseError.error == QJsonParseError::NoError && jsonDocument.isObject())
        {
            const QJsonObject rootObject = jsonDocument.object();
            autoCaptureEnabled = rootObject.value(QString::fromLatin1(kCaptureEnabledKey)).toBool(autoCaptureEnabled);
            if (rootObject.contains(QString::fromLatin1(kCaptureSuffixArrayKey))
                && rootObject.value(QString::fromLatin1(kCaptureSuffixArrayKey)).isArray())
            {
                const QJsonArray suffixArray = rootObject.value(QString::fromLatin1(kCaptureSuffixArrayKey)).toArray(); // suffixArray：JSON 中的后缀数组。
                QStringList rawSuffixList; // rawSuffixList：未规范化后缀列表。
                rawSuffixList.reserve(suffixArray.size());
                for (const QJsonValue& suffixValue : suffixArray)
                {
                    rawSuffixList.push_back(suffixValue.toString());
                }
                const QStringList normalizedSuffixList = normalizeSuffixList(rawSuffixList);
                if (!normalizedSuffixList.isEmpty())
                {
                    suffixList = normalizedSuffixList;
                }
            }
        }
        else
        {
            warn << loadEvent
                << "[NetworkDock] 下载捕获设置 JSON 解析失败，将回退默认设置, path="
                << settingsJsonPath.toStdString()
                << eol;
        }
    }

    m_multiDownloadAutoCaptureClipboardEnabled = autoCaptureEnabled;
    m_multiDownloadCaptureSuffixList = suffixList;
    if (m_multiDownloadAutoCaptureClipboardCheck != nullptr)
    {
        const QSignalBlocker blocker(m_multiDownloadAutoCaptureClipboardCheck);
        m_multiDownloadAutoCaptureClipboardCheck->setChecked(m_multiDownloadAutoCaptureClipboardEnabled);
    }
    if (m_multiDownloadCaptureSuffixEdit != nullptr)
    {
        const QSignalBlocker blocker(m_multiDownloadCaptureSuffixEdit);
        m_multiDownloadCaptureSuffixEdit->setText(joinSuffixListForLineEdit(m_multiDownloadCaptureSuffixList));
    }

    if (QGuiApplication::clipboard() != nullptr)
    {
        m_multiDownloadLastClipboardText = QGuiApplication::clipboard()->text(QClipboard::Clipboard).trimmed();
    }

    info << loadEvent
        << "[NetworkDock] 下载捕获设置加载完成, autoCapture="
        << (m_multiDownloadAutoCaptureClipboardEnabled ? "true" : "false")
        << ", suffixCount=" << m_multiDownloadCaptureSuffixList.size()
        << ", path=" << settingsJsonPath.toStdString()
        << eol;
}

void NetworkDock::saveMultiThreadDownloadCaptureSettings()
{
    // saveEvent 用途：贯穿“保存下载捕获设置”流程的统一日志事件对象。
    kLogEvent saveEvent;
    const QString settingsJsonPath = buildCaptureSettingsJsonPath(); // settingsJsonPath：下载捕获设置 JSON 绝对路径。

    const bool autoCaptureEnabled = (m_multiDownloadAutoCaptureClipboardCheck != nullptr) // autoCaptureEnabled：待保存的自动捕获开关值。
        ? m_multiDownloadAutoCaptureClipboardCheck->isChecked()
        : m_multiDownloadAutoCaptureClipboardEnabled;
    QStringList suffixList = (m_multiDownloadCaptureSuffixEdit != nullptr) // suffixList：待保存的后缀列表。
        ? parseSuffixLineEditText(m_multiDownloadCaptureSuffixEdit->text())
        : m_multiDownloadCaptureSuffixList;
    if (suffixList.isEmpty())
    {
        suffixList = buildDefaultCaptureSuffixList();
    }

    m_multiDownloadAutoCaptureClipboardEnabled = autoCaptureEnabled;
    m_multiDownloadCaptureSuffixList = suffixList;
    if (m_multiDownloadCaptureSuffixEdit != nullptr)
    {
        const QSignalBlocker blocker(m_multiDownloadCaptureSuffixEdit);
        m_multiDownloadCaptureSuffixEdit->setText(joinSuffixListForLineEdit(m_multiDownloadCaptureSuffixList));
    }

    const QFileInfo settingsFileInfo(settingsJsonPath); // settingsFileInfo：设置文件路径信息。
    QDir settingsDirectory(settingsFileInfo.absolutePath()); // settingsDirectory：设置目录对象。
    if (!settingsDirectory.exists() && !settingsDirectory.mkpath(QStringLiteral(".")))
    {
        warn << saveEvent
            << "[NetworkDock] 下载捕获设置保存失败：创建目录失败, path="
            << settingsDirectory.absolutePath().toStdString()
            << eol;
        return;
    }

    QJsonObject rootObject; // rootObject：待序列化的设置 JSON 根对象。
    rootObject.insert(QString::fromLatin1(kCaptureEnabledKey), m_multiDownloadAutoCaptureClipboardEnabled);
    QJsonArray suffixArray; // suffixArray：待序列化后缀数组。
    for (const QString& suffixText : m_multiDownloadCaptureSuffixList)
    {
        suffixArray.push_back(suffixText);
    }
    rootObject.insert(QString::fromLatin1(kCaptureSuffixArrayKey), suffixArray);

    QFile settingsFile(settingsJsonPath); // settingsFile：用于写入设置 JSON 的文件对象。
    if (!settingsFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text))
    {
        warn << saveEvent
            << "[NetworkDock] 下载捕获设置保存失败：打开文件失败, path="
            << settingsJsonPath.toStdString()
            << eol;
        return;
    }

    settingsFile.write(QJsonDocument(rootObject).toJson(QJsonDocument::Indented));
    settingsFile.close();
    info << saveEvent
        << "[NetworkDock] 下载捕获设置已保存, autoCapture="
        << (m_multiDownloadAutoCaptureClipboardEnabled ? "true" : "false")
        << ", suffixCount=" << m_multiDownloadCaptureSuffixList.size()
        << ", path=" << settingsJsonPath.toStdString()
        << eol;
}

bool NetworkDock::isMultiThreadDownloadClipboardUrlSupported(const QUrl& urlObject) const
{
    if (!urlObject.isValid())
    {
        return false;
    }

    const QString urlSchemeText = urlObject.scheme().toLower(); // urlSchemeText：URL 协议小写文本。
    if (urlSchemeText != QStringLiteral("http") && urlSchemeText != QStringLiteral("https"))
    {
        return false;
    }

    if (m_multiDownloadCaptureSuffixList.contains(QStringLiteral("*")))
    {
        return true;
    }

    const QString decodedPathText = QUrl::fromPercentEncoding(urlObject.path().toUtf8()).toLower(); // decodedPathText：URL 解码后的路径文本。
    const QString fileNameText = QFileInfo(decodedPathText).fileName().toLower(); // fileNameText：路径末尾文件名（含扩展名）。
    if (fileNameText.isEmpty())
    {
        return false;
    }
    for (const QString& suffixText : m_multiDownloadCaptureSuffixList)
    {
        if (fileNameText.endsWith(suffixText, Qt::CaseInsensitive))
        {
            return true;
        }
    }
    return false;
}

void NetworkDock::onMultiThreadDownloadClipboardChanged()
{
    if (!m_multiDownloadAutoCaptureClipboardEnabled || QGuiApplication::clipboard() == nullptr)
    {
        return;
    }

    const QString clipboardText = QGuiApplication::clipboard()->text(QClipboard::Clipboard).trimmed(); // clipboardText：当前主剪贴板文本。
    if (clipboardText.isEmpty() || clipboardText == m_multiDownloadLastClipboardText)
    {
        return;
    }
    m_multiDownloadLastClipboardText = clipboardText;

    const QString urlText = extractFirstHttpUrlText(clipboardText); // urlText：从剪贴板文本中提取出的首个 URL。
    if (urlText.isEmpty())
    {
        return;
    }

    const QUrl candidateUrl = QUrl::fromUserInput(urlText); // candidateUrl：候选下载 URL 对象。
    if (!isMultiThreadDownloadClipboardUrlSupported(candidateUrl))
    {
        return;
    }

    showMultiThreadDownloadClipboardPrompt(candidateUrl.toString());
}

void NetworkDock::showMultiThreadDownloadClipboardPrompt(const QString& urlText)
{
    if (urlText.trimmed().isEmpty())
    {
        return;
    }

    if (m_multiDownloadClipboardPromptDialog != nullptr)
    {
        m_multiDownloadClipboardPromptDialog->raise();
        m_multiDownloadClipboardPromptDialog->activateWindow();
        return;
    }

    // defaultSaveDirectoryText 用途：询问框初始保存目录，优先复用下载页当前目录。
    QString defaultSaveDirectoryText = (m_multiDownloadSaveDirEdit != nullptr)
        ? m_multiDownloadSaveDirEdit->text().trimmed()
        : QString();
    if (defaultSaveDirectoryText.isEmpty())
    {
        defaultSaveDirectoryText = QStandardPaths::writableLocation(QStandardPaths::DownloadLocation);
    }
    if (defaultSaveDirectoryText.isEmpty())
    {
        defaultSaveDirectoryText = QDir::homePath();
    }

    QDialog* promptDialog = new QDialog(this); // promptDialog：非阻塞下载询问框对象。
    m_multiDownloadClipboardPromptDialog = promptDialog;
    promptDialog->setAttribute(Qt::WA_DeleteOnClose, true);
    promptDialog->setObjectName(QStringLiteral("NetworkMultiDownloadPromptDialog"));
    promptDialog->setWindowFlag(Qt::Window, true);
    promptDialog->setWindowModality(Qt::NonModal);
    promptDialog->setModal(false);
    promptDialog->setWindowTitle(QStringLiteral("检测到可下载链接"));
    promptDialog->resize(760, 200);
    // 弹窗背景显式填充，避免浅色模式下继承透明样式出现黑底。
    promptDialog->setStyleSheet(KswordTheme::OpaqueDialogStyle(promptDialog->objectName()));

    QVBoxLayout* rootLayout = new QVBoxLayout(promptDialog); // rootLayout：询问框根布局。
    QLabel* descriptionLabel = new QLabel(
        QStringLiteral("已在剪贴板检测到匹配后缀的下载链接，请确认 URL 与保存目录。"),
        promptDialog); // descriptionLabel：询问框顶部说明文本。
    descriptionLabel->setWordWrap(true);

    QLabel* urlLabel = new QLabel(QStringLiteral("下载 URL:"), promptDialog); // urlLabel：URL 输入框标题标签。
    QLineEdit* urlEdit = new QLineEdit(urlText, promptDialog); // urlEdit：可编辑确认的下载 URL 输入框。
    urlEdit->setToolTip(QStringLiteral("确认本次要下载的 HTTP/HTTPS 链接。"));

    QLabel* saveDirLabel = new QLabel(QStringLiteral("保存目录:"), promptDialog); // saveDirLabel：保存目录输入框标题标签。
    QLineEdit* saveDirEdit = new QLineEdit(defaultSaveDirectoryText, promptDialog); // saveDirEdit：可编辑确认的保存目录输入框。
    saveDirEdit->setToolTip(QStringLiteral("确认下载文件保存目录。"));
    QPushButton* browseButton = new QPushButton(promptDialog); // browseButton：保存目录浏览按钮。
    browseButton->setIcon(QIcon(":/Icon/file_find.svg"));
    browseButton->setToolTip(QStringLiteral("浏览并选择保存目录"));

    QHBoxLayout* saveDirLayout = new QHBoxLayout(); // saveDirLayout：保存目录行布局（输入框+浏览按钮）。
    saveDirLayout->addWidget(saveDirEdit, 1);
    saveDirLayout->addWidget(browseButton);
    ks::ui::NormalizeToolbarRow(saveDirLayout);

    QPushButton* startButton = new QPushButton(QStringLiteral("开始下载"), promptDialog); // startButton：确认并启动下载按钮。
    startButton->setIcon(QIcon(":/Icon/process_start.svg"));
    startButton->setToolTip(QStringLiteral("按当前 URL 和保存目录创建下载任务"));
    QPushButton* cancelButton = new QPushButton(QStringLiteral("取消下载"), promptDialog); // cancelButton：取消本次询问按钮。
    cancelButton->setIcon(QIcon(":/Icon/titlebar_close.svg"));
    cancelButton->setToolTip(QStringLiteral("关闭本次下载询问框，不创建任务"));

    QHBoxLayout* actionLayout = new QHBoxLayout(); // actionLayout：底部动作按钮布局。
    actionLayout->addStretch(1);
    actionLayout->addWidget(startButton);
    actionLayout->addWidget(cancelButton);
    ks::ui::NormalizeToolbarRow(actionLayout);

    rootLayout->addWidget(descriptionLabel);
    rootLayout->addWidget(urlLabel);
    rootLayout->addWidget(urlEdit);
    rootLayout->addWidget(saveDirLabel);
    rootLayout->addLayout(saveDirLayout);
    rootLayout->addLayout(actionLayout);

    connect(promptDialog, &QDialog::destroyed, this, [this]()
        {
            m_multiDownloadClipboardPromptDialog = nullptr;
        });
    connect(browseButton, &QPushButton::clicked, promptDialog, [promptDialog, saveDirEdit]()
        {
            const QString selectedDirectory = QFileDialog::getExistingDirectory(
                promptDialog,
                QStringLiteral("选择保存目录"),
                saveDirEdit->text().trimmed().isEmpty() ? QDir::homePath() : saveDirEdit->text().trimmed(),
                QFileDialog::ShowDirsOnly | QFileDialog::DontResolveSymlinks);
            if (!selectedDirectory.isEmpty())
            {
                saveDirEdit->setText(selectedDirectory);
            }
        });
    connect(startButton, &QPushButton::clicked, promptDialog, [this, promptDialog, urlEdit, saveDirEdit]()
        {
            const bool started = startMultiThreadDownloadTaskFromInput(
                urlEdit->text().trimmed(),
                saveDirEdit->text().trimmed());
            if (started)
            {
                promptDialog->close();
            }
        });
    connect(cancelButton, &QPushButton::clicked, promptDialog, [promptDialog]()
        {
            promptDialog->close();
        });

    kLogEvent promptEvent;
    info << promptEvent
        << "[NetworkDock] 检测到剪贴板下载链接并弹出非阻塞询问框, url="
        << urlText.toStdString()
        << eol;
    promptDialog->show();
    promptDialog->raise();
    promptDialog->activateWindow();
}
