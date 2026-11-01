#include "ProcessDock.h"
#include "../UI/FlatTableModel.h"

#include <QImage>
#include <QMetaObject>
#include <QPixmap>
#include <QRunnable>
#include <QSortFilterProxyModel>
#include <QTableView>

#include <algorithm>
#include <cstddef>
#include <utility>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>
#include <Shellapi.h>

#pragma comment(lib, "Shell32.lib")

namespace
{
    // 图标缓存上限：按可执行文件路径去重后仍保留足够大的空间，防止长期运行无限增长。
    constexpr qsizetype ProcessIconCacheMaximumCount = 4096;

    // processPlaceholderIcon：未完成或无法解析时使用稳定的进程占位图标。
    // 返回值：共享 QIcon，避免每个空图标单元格重复读取资源。
    const QIcon& processPlaceholderIcon()
    {
        static const QIcon icon(QStringLiteral(":/Icon/process_main.svg"));
        return icon;
    }

    // isProcessIconPathUsable：过滤进程枚举中的空路径和非文件占位文本。
    // 参数 imagePath：进程记录给出的映像路径；返回 true 时允许提交 Shell 图标查询。
    bool isProcessIconPathUsable(const QString& imagePath)
    {
        return !imagePath.isEmpty() &&
            !imagePath.startsWith('[') &&
            imagePath != QStringLiteral("历史快照");
    }

    // extractProcessIconImageFromPath：在线程池工作线程中向 Windows Shell 查询小图标。
    // 参数 imagePath：已规范化的可执行文件路径；返回值为独立 QImage，不携带 GUI 线程专属 QPixmap。
    QImage extractProcessIconImageFromPath(const QString& imagePath)
    {
        // shellInfo 保存 Shell 分配的 HICON，调用者必须在转换为 QImage 后销毁该句柄。
        SHFILEINFOW shellInfo{};
        const DWORD_PTR shellQueryResult = ::SHGetFileInfoW(
            reinterpret_cast<const wchar_t*>(imagePath.utf16()),
            0,
            &shellInfo,
            sizeof(shellInfo),
            SHGFI_ICON | SHGFI_SMALLICON);
        if (shellQueryResult == 0 || shellInfo.hIcon == nullptr)
        {
            return QImage();
        }

        // QImage 可在线程间安全传递，QImage::fromHICON 会复制 HICON 的像素数据。
        QImage iconImage = QImage::fromHICON(shellInfo.hIcon);
        ::DestroyIcon(shellInfo.hIcon);
        return iconImage;
    }
}

QIcon ProcessDock::resolveProcessIcon(const ks::process::ProcessRecord& processRecord)
{
    // processNameText 用于历史活动缓存键，pathText 只来自后台刷新结果，UI 线程不按 PID 查询路径。
    const QString processNameText = QString::fromStdString(processRecord.processName).trimmed();
    const QString pathText = QString::fromStdString(processRecord.imagePath).trimmed();
    const QString activityIconKey = processNameText + QStringLiteral("|") + pathText;

    // 历史活动快照优先复用采样时固定下来的图标，避免回看历史记录时图标随着当前进程变化。
    const auto activityIconIt = m_activityIconCacheByProcessKey.constFind(activityIconKey);
    if (activityIconIt != m_activityIconCacheByProcessKey.constEnd())
    {
        return activityIconIt.value();
    }

    // 当前列表与历史列表共用路径缓存，缓存命中时绘制路径不再触发任何异步工作。
    const auto iconIt = m_iconCacheByPath.constFind(pathText);
    if (iconIt != m_iconCacheByPath.constEnd())
    {
        return iconIt.value();
    }

    // 某个未进入本轮缓存的历史行仍可补投任务，但当前绘制立即返回占位图，不阻塞主线程。
    if (isProcessIconPathUsable(pathText))
    {
        queueProcessIconExtraction(pathText);
    }
    return processPlaceholderIcon();
}

void ProcessDock::queueProcessIconExtractionsForCurrentProcesses()
{
    // 本轮缓存包含所有当前进程和短暂保留的退出行，先收集路径可避免同一应用实例重复提交。
    QSet<QString> imagePaths;
    for (const auto& cachePair : m_cacheByIdentity)
    {
        const QString imagePath = QString::fromStdString(cachePair.second.record.imagePath).trimmed();
        if (isProcessIconPathUsable(imagePath))
        {
            imagePaths.insert(imagePath);
        }
    }

    // 每个未命中的应用路径立即提交到专属线程池，不再等待滚动停止或鼠标移出表格。
    for (const QString& imagePath : imagePaths)
    {
        queueProcessIconExtraction(imagePath);
    }
}

void ProcessDock::queueProcessIconExtraction(const QString& imagePath)
{
    // normalizedPath 是缓存与在途集合的唯一键，所有相关容器只在主线程访问。
    const QString normalizedPath = imagePath.trimmed();
    if (!m_monitoringEnabled ||
        !isProcessIconPathUsable(normalizedPath) ||
        m_iconCacheByPath.contains(normalizedPath) ||
        m_processIconPathsInFlight.contains(normalizedPath))
    {
        return;
    }

    // 记录本次任务代次：暂停后代次递增，旧任务即使完成也不能覆盖新一轮图标缓存。
    const std::uint64_t extractionGeneration = m_processIconExtractionGeneration;
    QPointer<ProcessDock> guard(this);
    m_processIconPathsInFlight.insert(normalizedPath);

    // 每个不同映像路径各自创建任务，线程池按并发上限同时执行多个 Shell 查询。
    QRunnable* const extractionTask = QRunnable::create([
        guard,
        normalizedPath,
        extractionGeneration]() {
            QImage iconImage = extractProcessIconImageFromPath(normalizedPath);
            if (guard == nullptr)
            {
                return;
            }

            // 工作线程只返回 QImage，QPixmap/QIcon 构造与表格重绘全部留给主线程执行。
            QMetaObject::invokeMethod(
                guard,
                [guard, normalizedPath, extractionGeneration, iconImage = std::move(iconImage)]() mutable {
                    if (guard != nullptr)
                    {
                        guard->applyProcessIconExtractionResult(
                            normalizedPath,
                            std::move(iconImage),
                            extractionGeneration);
                    }
                },
                Qt::QueuedConnection);
        });
    extractionTask->setAutoDelete(true);
    m_processIconExtractionPool.start(extractionTask);
}

void ProcessDock::applyProcessIconExtractionResult(
    const QString& imagePath,
    QImage iconImage,
    const std::uint64_t extractionGeneration)
{
    // 代次不一致表示用户已暂停后重新开始，当前在途集合属于新一轮任务，旧回传不能修改它。
    if (extractionGeneration != m_processIconExtractionGeneration)
    {
        return;
    }
    m_processIconPathsInFlight.remove(imagePath);

    // 暂停后的任务结果不写入缓存，避免继续改变已暂停的进程页显示。
    if (!m_monitoringEnabled || m_iconCacheByPath.contains(imagePath))
    {
        return;
    }

    // QPixmap 只能在 GUI 线程创建，空图像统一回退到进程占位图，缓存结果避免重复失败查询。
    const QIcon resolvedIcon = iconImage.isNull()
        ? processPlaceholderIcon()
        : QIcon(QPixmap::fromImage(iconImage));
    if (m_iconCacheByPath.size() >= ProcessIconCacheMaximumCount)
    {
        m_iconCacheByPath.erase(m_iconCacheByPath.begin());
    }
    m_iconCacheByPath.insert(imagePath, resolvedIcon);

    // 只要求视口重绘引用该路径的名称单元格，其他行会在进入视口后自然读取新缓存。
    refreshProcessTableRowsForIcon(imagePath);
    scheduleMetricAreaRefresh();
}

void ProcessDock::refreshProcessTableRowsForIcon(const QString& imagePath)
{
    // 主线程只更新可见名称单元格，避免单个图标回传时造成整张进程表重新布局。
    if (m_processTable == nullptr ||
        m_processTableModel == nullptr ||
        m_processSortProxy == nullptr ||
        m_processTable->viewport() == nullptr)
    {
        return;
    }

    // normalizedImagePath 保证与进程记录中的路径文本使用相同的比较规则。
    const QString normalizedImagePath = imagePath.trimmed();
    if (normalizedImagePath.isEmpty())
    {
        return;
    }

    // tableRows 是模型当前源行快照，viewIndex 用于转换排序/过滤后真正显示的行位置。
    QWidget* const tableViewport = m_processTable->viewport();
    const std::vector<ProcessTableRow>& tableRows = m_processTableModel->rows();
    const int nameColumn = toColumnIndex(TableColumn::Name);
    for (int sourceRow = 0; sourceRow < static_cast<int>(tableRows.size()); ++sourceRow)
    {
        const ProcessTableRow& tableRow = tableRows[static_cast<std::size_t>(sourceRow)];
        if (QString::fromStdString(tableRow.record.imagePath).trimmed() != normalizedImagePath)
        {
            continue;
        }

        const QModelIndex sourceIndex = m_processTableModel->index(sourceRow, nameColumn);
        const QModelIndex viewIndex = m_processSortProxy->mapFromSource(sourceIndex);
        const QRect visibleRect = m_processTable->visualRect(viewIndex);
        if (visibleRect.isValid() && visibleRect.intersects(tableViewport->rect()))
        {
            tableViewport->update(visibleRect);
        }
    }
}
