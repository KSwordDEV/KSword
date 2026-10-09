#include "RegistryDock.h"
#include "RegistryWorkbenchAccess.h"
#include "../UI/TableInteractionSupport.h"

#include <QApplication>
#include <QCheckBox>
#include <QComboBox>
#include <QElapsedTimer>
#include <QLineEdit>
#include <QMessageBox>
#include <QPointer>
#include <QPushButton>
#include <QRegularExpression>
#include <QTabWidget>
#include <QTableWidget>
#include <QTimer>

void RegistryDock::startSearchAsync()
{
    if (m_searchRunning.load()) return;
    if (m_searchThread && m_searchThread->joinable()) m_searchThread->join();
    m_searchThread.reset();
    QString keyword = m_searchEdit->text();
    if (keyword.isEmpty()) return;
    SearchOptions options;
    options.searchKeyName = m_matchKeysCheck->isChecked();
    options.searchValueName = m_matchNamesCheck->isChecked();
    options.searchValueData = m_matchDataCheck->isChecked();
    options.caseSensitive = m_matchCaseCheck->isChecked();
    options.exactMatch = m_matchExactCheck->isChecked();
    options.recursive = m_searchScopeCombo->currentData().toInt() != 0;
    options.viewBits = m_viewBits;
    options.valueType = m_searchTypeCombo->currentData().toInt();
    options.generation = ++m_searchGeneration;
    if (!options.searchKeyName && !options.searchValueName && !options.searchValueData)
    { QMessageBox::information(this, QStringLiteral("搜索"), QStringLiteral("至少选择一种搜索范围。")); return; }
    if (keyword.startsWith(QStringLiteral("hex:"), Qt::CaseInsensitive))
    {
        QString pattern = keyword.mid(4);
        pattern.remove(QRegularExpression(QStringLiteral("\\s+")));
        if (pattern.isEmpty() || (pattern.size() % 2) != 0
            || !QRegularExpression(QStringLiteral("^[0-9a-fA-F]+$")).match(pattern).hasMatch())
        { QMessageBox::warning(this, QStringLiteral("搜索"), QStringLiteral("hex: 后请输入成对的十六进制字节。")); return; }
        options.binaryPattern = QByteArray::fromHex(pattern.toLatin1());
        options.searchKeyName = false;
        options.searchValueName = false;
        options.searchValueData = true;
    }
    QStringList roots;
    if (m_searchScopeCombo->currentData().toInt() == 2)
        roots = {QStringLiteral("HKEY_CLASSES_ROOT"), QStringLiteral("HKEY_CURRENT_USER"),
            QStringLiteral("HKEY_LOCAL_MACHINE"), QStringLiteral("HKEY_USERS"), QStringLiteral("HKEY_CURRENT_CONFIG")};
    else roots.append(m_currentPath);
    const bool r0 = shouldUseRegistryR0();
    m_searchRunning.store(true);
    m_searchStopFlag.store(false);
    m_searchSkipped.store(0);
    m_searchDropped.store(0);
    m_searchScannedKeys = 0;
    m_searchHitCount = 0;
    m_lastSearchStopped = false;
    { std::lock_guard<std::mutex> lock(m_pendingMutex); m_pendingRows.clear(); }
    m_searchResultTable->setRowCount(0);
    m_rightTabWidget->setCurrentWidget(m_searchResultTable);
    m_searchButton->setEnabled(false);
    m_stopSearchButton->setEnabled(true);
    m_searchFlushTimer->start();
    if (m_progressPid == 0) m_progressPid = kPro.addReusable(this, "注册表", "搜索");
    kPro.set(m_progressPid, "搜索中", 0, 0.0f);
    const QPointer<RegistryDock> guarded(this);
    const auto dispatcher = m_uiDispatcher;
    m_searchThread = std::make_unique<std::thread>([this, guarded, dispatcher, roots, keyword, options, r0]() {
        std::size_t scanned = 0, hits = 0;
        for (const auto& root : roots)
        {
            if (m_searchStopFlag.load()) break;
            const bool useR0 = r0 && root != QStringLiteral("HKEY_CLASSES_ROOT")
                && !root.startsWith(QStringLiteral("HKEY_CLASSES_ROOT\\"), Qt::CaseInsensitive);
            searchRegistryPath(root, useR0, keyword, options, &scanned, &hits);
        }
        dispatcher->post([guarded, scanned, hits, generation = options.generation]() {
            if (!guarded || guarded->m_searchGeneration != generation) return;
            guarded->m_lastSearchStopped = guarded->m_searchStopFlag.load();
            if (guarded->m_searchThread && guarded->m_searchThread->joinable()) guarded->m_searchThread->join();
            guarded->m_searchThread.reset();
            guarded->m_searchRunning.store(false);
            guarded->m_searchStopFlag.store(false);
            guarded->m_searchScannedKeys = scanned;
            guarded->m_searchHitCount = hits;
            guarded->m_searchButton->setEnabled(true);
            guarded->m_stopSearchButton->setEnabled(false);
            guarded->flushPendingSearchRows();
            kPro.set(guarded->m_progressPid, guarded->m_lastSearchStopped ? "搜索停止" : "搜索完成", 0, 100.0f);
        });
    });
}

void RegistryDock::searchRegistryPath(const QString& start, bool useR0, const QString& keyword,
    const SearchOptions& options, std::size_t* scanned, std::size_t* hits)
{
    struct Location { QString path; int depth; };
    QVector<Location> stack{{start, 0}};
    QElapsedTimer progress;
    progress.start();
    const auto sensitivity = options.caseSensitive ? Qt::CaseSensitive : Qt::CaseInsensitive;
    const auto matches = [&](const QString& text) {
        return options.exactMatch ? text.compare(keyword, sensitivity) == 0 : text.contains(keyword, sensitivity);
    };
    const RegistryAccessContext context{options.viewBits, useR0};
    while (!stack.isEmpty() && !m_searchStopFlag.load())
    {
        const Location location = stack.takeLast();
        if (location.depth > options.maximumDepth) { ++m_searchSkipped; continue; }
        RegistryKeyListing listing;
        QString error;
        if (!RegistryWorkbenchAccess::enumerate(location.path, context, &listing, &error, options.recursive))
        { ++m_searchSkipped; continue; }
        ++*scanned;
        if (!listing.complete) ++m_searchSkipped;
        const QString keyName = location.path.mid(location.path.lastIndexOf(QLatin1Char('\\')) + 1);
        if (options.searchKeyName && options.valueType < 0 && matches(keyName))
        {
            PendingSearchRow row;
            row.viewBits = context.viewBits;
            row.useR0 = context.useR0;
            row.keyPathText = location.path; row.valueNameText = QStringLiteral("<Key>");
            row.valueTypeText = QStringLiteral("<Key>"); row.hitSourceText = QStringLiteral("KeyName");
            row.isKeyResult = true; enqueuePendingSearchRow(std::move(row)); ++*hits;
        }
        for (auto value : listing.values)
        {
            if (m_searchStopFlag.load()) break;
            if (options.valueType >= 0 && value.type != static_cast<quint32>(options.valueType)) continue;
            bool matched = options.searchValueName && matches(value.name);
            QString source = matched ? QStringLiteral("ValueName") : QString();
            if (!matched && options.searchValueData)
            {
                if (!value.complete)
                {
                    RegistryValueState full;
                    if (!RegistryWorkbenchAccess::read(location.path, value.name, context, &full, &error) || !full.exists || !full.complete)
                    { ++m_searchSkipped; continue; }
                    value = std::move(full);
                }
                if (!options.binaryPattern.isEmpty())
                    matched = options.exactMatch ? value.data == options.binaryPattern : value.data.contains(options.binaryPattern);
                else if (value.type == REG_SZ || value.type == REG_EXPAND_SZ || value.type == REG_MULTI_SZ)
                {
                    if ((value.data.size() % 2) != 0) { ++m_searchSkipped; continue; }
                    const QString dataText = QString::fromUtf16(reinterpret_cast<const char16_t*>(value.data.constData()), value.data.size() / 2);
                    if (options.exactMatch)
                    {
                        for (const auto& part : dataText.split(QChar::Null)) if (matches(part)) { matched = true; break; }
                    }
                    else matched = matches(dataText);
                }
                else if (value.type == REG_DWORD || value.type == REG_QWORD) matched = matches(formatValueData(value.type, value.data));
                else matched = options.exactMatch ? value.data == keyword.toUtf8() : value.data.contains(keyword.toUtf8());
                if (matched) source = QStringLiteral("ValueData");
            }
            if (!matched) continue;
            PendingSearchRow row;
            row.viewBits = context.viewBits;
            row.useR0 = context.useR0;
            row.keyPathText = location.path; row.rawValueName = value.name;
            row.valueNameText = value.name.isEmpty() ? QStringLiteral("(默认)") : value.name;
            row.valueTypeText = valueTypeToText(value.type);
            row.valueDataPreviewText = formatValueData(value.type, value.data);
            if (!value.complete) row.valueDataPreviewText += QStringLiteral(" <数据摘要不完整>");
            row.hitSourceText = source + (useR0 ? QStringLiteral(" / R0") : QStringLiteral(" / Win32"));
            enqueuePendingSearchRow(std::move(row)); ++*hits;
        }
        if (options.recursive)
            for (auto it = listing.subKeys.crbegin(); it != listing.subKeys.crend(); ++it)
            {
                if (stack.size() >= 100000) { ++m_searchSkipped; break; }
                stack.push_back({location.path + QLatin1Char('\\') + *it, location.depth + 1});
            }
        if (progress.elapsed() >= 150)
        {
            const auto scannedCount = *scanned, hitCount = *hits;
            const QPointer<RegistryDock> guarded(this);
            m_uiDispatcher->post([guarded, scannedCount, hitCount, generation = options.generation]() {
                if (guarded && guarded->m_searchGeneration == generation) guarded->updateStatusBar(QStringLiteral("搜索中：扫描 %1 键，命中 %2 项。")
                    .arg(scannedCount).arg(hitCount));
            });
            progress.restart();
        }
    }
}

void RegistryDock::searchRegistryRecursive(HKEY root, const QString& subPath, const QString& keyword,
    const SearchOptions& options, std::size_t* scanned, std::size_t* hits)
{
    searchRegistryPath(rootKeyToText(root) + (subPath.isEmpty() ? QString() : QLatin1Char('\\') + subPath),
        false, keyword, options, scanned, hits);
}

void RegistryDock::searchRegistryRecursiveByR0(const QString&, const QString& path,
    const QString& keyword, const SearchOptions& options, std::size_t* scanned, std::size_t* hits)
{
    searchRegistryPath(path, true, keyword, options, scanned, hits);
}
