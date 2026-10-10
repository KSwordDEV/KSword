#include "HandleDock.h"
#include "../UI/ToolbarMetrics.h"

// ============================================================
// HandleDock.Filter.cpp
// 作用：
// - 承载句柄模块的本地过滤、状态文本与右键菜单逻辑；
// - 避免主 UI 文件过长；
// - 让“枚举”和“本地交互”职责分离。
// ============================================================

#include "../theme.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/TableInteractionSupport.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QComboBox>
#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QPushButton>
#include <QSaveFile>
#include <QSet>
#include <QSettings>
#include <QSignalBlocker>
#include <QSpinBox>
#include <QTreeWidget>
#include <QTreeWidgetItem>
#include <QVBoxLayout>

#include <algorithm>
#include <functional>
#include <limits>
#include <set>

namespace
{
    constexpr std::size_t kHandleRulePageSize = 300;

    QString sanitizeTsvField(QString value)
    {
        value.replace('\t', QStringLiteral("\\t"));
        value.replace('\r', QStringLiteral("\\r"));
        value.replace('\n', QStringLiteral("\\n"));
        value.replace(QChar::Null, QStringLiteral("\\0"));
        qsizetype firstMeaningfulIndex = 0;
        while (firstMeaningfulIndex < value.size()
            && value.at(firstMeaningfulIndex).isSpace())
        {
            ++firstMeaningfulIndex;
        }
        if (firstMeaningfulIndex < value.size()
            && (value.at(firstMeaningfulIndex) == QLatin1Char('=')
                || value.at(firstMeaningfulIndex) == QLatin1Char('+')
                || value.at(firstMeaningfulIndex) == QLatin1Char('-')
                || value.at(firstMeaningfulIndex) == QLatin1Char('@')))
        {
            // 防止进程名、对象名或规则名在电子表格中被解释成公式。
            value.prepend(QLatin1Char('\''));
        }
        return value;
    }

    QString processIdsToText(const QVector<std::uint32_t>& processIds)
    {
        QStringList textList;
        textList.reserve(processIds.size());
        for (const std::uint32_t processId : processIds)
        {
            textList.push_back(QString::number(processId));
        }
        return textList.join(QStringLiteral(", "));
    }

    bool sameGlobalSettings(
        const ks::handle::HandleFilterGlobalSettings& left,
        const ks::handle::HandleFilterGlobalSettings& right)
    {
        return left.enumMode == right.enumMode
            && left.resolveObjectName == right.resolveObjectName
            && left.nameResolveBudget == right.nameResolveBudget;
    }
}

void HandleDock::applyLocalHandleFilters()
{
    applyLocalHandleFilters(true);
}

void HandleDock::applyLocalHandleFilters(const bool rebuildTable)
{
    m_ruleMatchStates.clear();
    m_totalRuleMatchCount = 0;

    const QVector<ks::handle::HandleFilterRule> activeRuleList = m_temporaryFilterActive
        ? QVector<ks::handle::HandleFilterRule>{ m_temporaryFilterRule }
        : m_filterDocument.rules;
    m_ruleMatchStates.reserve(static_cast<std::size_t>(activeRuleList.size()));
    for (const ks::handle::HandleFilterRule& rule : activeRuleList)
    {
        HandleRuleMatchState state;
        state.ruleId = rule.id;
        state.ruleName = rule.name;
        state.enabled = rule.enabled;
        if (rule.enabled)
        {
            state.rowIndices.reserve(std::min<std::size_t>(m_allRows.size(), 4096));
            for (std::size_t sourceRowIndex = 0;
                sourceRowIndex < m_allRows.size();
                ++sourceRowIndex)
            {
                if (handleRowMatchesRule(m_allRows[sourceRowIndex], rule))
                {
                    state.rowIndices.push_back(sourceRowIndex);
                }
            }
            m_totalRuleMatchCount += state.rowIndices.size();
        }
        m_ruleMatchStates.push_back(std::move(state));
    }

    if (!rebuildTable)
    {
        return;
    }

    rebuildHandleTable();
    updateHandleSummaryStatus();
}

bool HandleDock::handleRowMatchesRule(
    const HandleRow& row,
    const ks::handle::HandleFilterRule& rule) const
{
    if (!rule.processIds.isEmpty() && !rule.processIds.contains(row.processId))
    {
        return false;
    }
    if (!rule.typeName.trimmed().isEmpty() &&
        row.typeName.compare(rule.typeName.trimmed(), Qt::CaseInsensitive) != 0)
    {
        return false;
    }
    switch (rule.diffStatus)
    {
    case ks::handle::FilterDiffStatus::UserOnly:
        if (row.diffStatus != HandleDiffStatus::UserOnly) return false;
        break;
    case ks::handle::FilterDiffStatus::KernelOnly:
        if (row.diffStatus != HandleDiffStatus::KernelOnly) return false;
        break;
    case ks::handle::FilterDiffStatus::Both:
        if (row.diffStatus != HandleDiffStatus::Both) return false;
        break;
    case ks::handle::FilterDiffStatus::Any:
    default:
        break;
    }
    if (rule.onlyNamed && row.objectName.trimmed().isEmpty())
    {
        return false;
    }

    const QString keyword = rule.keyword.trimmed().toLower();
    if (keyword.isEmpty())
    {
        return true;
    }
    const QString pidValueText = QString::number(row.processId);
    const QString typeIndexText = QString::number(row.typeIndex);
    const QString handleText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(row.handleValue), 0, 16).toLower();
    const QString addressText = QStringLiteral("0x%1")
        .arg(static_cast<qulonglong>(row.objectAddress), 0, 16).toLower();
    const QString accessText = QStringLiteral("0x%1")
        .arg(row.grantedAccess, 8, 16, QChar('0')).toLower();
    return row.processName.toLower().contains(keyword)
        || row.typeName.toLower().contains(keyword)
        || row.objectName.toLower().contains(keyword)
        || pidValueText.contains(keyword)
        || typeIndexText.contains(keyword)
        || handleText.contains(keyword)
        || addressText.contains(keyword)
        || accessText.contains(keyword)
        || decodeGrantedAccessText(row.typeName, row.grantedAccess).toLower().contains(keyword)
        || formatHandleSourceText(row.sourceMode).toLower().contains(keyword)
        || formatHandleDecodeStatusText(row.decodeStatus).toLower().contains(keyword)
        || formatHandleDiffStatusText(row.diffStatus).toLower().contains(keyword);
}

HandleDock::HandleRuleMatchState* HandleDock::findRuleMatchState(const QString& ruleId)
{
    for (HandleRuleMatchState& state : m_ruleMatchStates)
    {
        if (state.ruleId == ruleId)
        {
            return &state;
        }
    }
    return nullptr;
}

const HandleDock::HandleRuleMatchState* HandleDock::findRuleMatchState(const QString& ruleId) const
{
    for (const HandleRuleMatchState& state : m_ruleMatchStates)
    {
        if (state.ruleId == ruleId)
        {
            return &state;
        }
    }
    return nullptr;
}

const ks::handle::HandleFilterRule* HandleDock::findActiveRule(const QString& ruleId) const
{
    if (m_temporaryFilterActive)
    {
        return m_temporaryFilterRule.id == ruleId ? &m_temporaryFilterRule : nullptr;
    }
    for (const ks::handle::HandleFilterRule& rule : m_filterDocument.rules)
    {
        if (rule.id == ruleId)
        {
            return &rule;
        }
    }
    return nullptr;
}

void HandleDock::rebuildRuleSummaryTree()
{
    if (m_tableWidget == nullptr)
    {
        return;
    }
    ++m_processIconResolveGeneration;
    if (m_processIconResolveCancelFlag != nullptr)
    {
        m_processIconResolveCancelFlag->store(true);
    }
    m_processIconResolveCancelFlag = std::make_shared<std::atomic_bool>(false);
    m_tableWidget->clear();

    for (std::size_t ruleIndex = 0; ruleIndex < m_ruleMatchStates.size(); ++ruleIndex)
    {
        HandleRuleMatchState& state = m_ruleMatchStates[ruleIndex];
        auto* summaryItem = new QTreeWidgetItem();
        summaryItem->setData(0, ks::handle::HandleTreeItemKindRole,
            static_cast<int>(ks::handle::HandleTreeItemKind::RuleSummary));
        summaryItem->setData(0, ks::handle::HandleTreeRuleIdRole, state.ruleId);
        summaryItem->setData(0, ks::handle::HandleTreeRuleOrderRole,
            static_cast<qulonglong>(ruleIndex));
        summaryItem->setText(
            static_cast<int>(HandleTableColumn::ProcessId),
            state.enabled
                ? ks::i18n::sourceText(QStringLiteral("%1 命中 %2 条"))
                    .arg(state.ruleName).arg(state.rowIndices.size())
                : ks::i18n::sourceText(QStringLiteral("%1 已停用"))
                    .arg(state.ruleName));
        const ks::handle::HandleFilterRule* rule = findActiveRule(state.ruleId);
        if (rule != nullptr)
        {
            summaryItem->setToolTip(0, buildRuleConditionSummary(*rule));
        }
        for (int column = 0; column < static_cast<int>(HandleTableColumn::Count); ++column)
        {
            summaryItem->setForeground(column, KswordTheme::PrimaryBlueColor);
        }
        if (state.enabled && !state.rowIndices.empty())
        {
            auto* placeholderItem = new QTreeWidgetItem(summaryItem);
            placeholderItem->setData(0, ks::handle::HandleTreeItemKindRole,
                static_cast<int>(ks::handle::HandleTreeItemKind::LazyPlaceholder));
            placeholderItem->setData(0, ks::handle::HandleTreeRuleIdRole, state.ruleId);
        }
        m_tableWidget->addTopLevelItem(summaryItem);
        state.summaryItem = summaryItem;
        state.loadedCount = 0;
    }

    if (m_tableWidget->topLevelItemCount() > 0)
    {
        m_tableWidget->setCurrentItem(m_tableWidget->topLevelItem(0));
    }
    else
    {
        showHandleDetailPlaceholder(QStringLiteral("没有可用的句柄筛选规则。"));
    }
}

void HandleDock::appendNextRuleResultBatch(const QString& ruleId)
{
    HandleRuleMatchState* state = findRuleMatchState(ruleId);
    if (state == nullptr || state->summaryItem == nullptr || !state->enabled)
    {
        return;
    }
    QTreeWidgetItem* const summaryItem = state->summaryItem;
    for (int childIndex = summaryItem->childCount() - 1; childIndex >= 0; --childIndex)
    {
        QTreeWidgetItem* childItem = summaryItem->child(childIndex);
        const int kind = childItem->data(0, ks::handle::HandleTreeItemKindRole).toInt();
        if (kind == static_cast<int>(ks::handle::HandleTreeItemKind::LazyPlaceholder)
            || kind == static_cast<int>(ks::handle::HandleTreeItemKind::LoadMore))
        {
            delete summaryItem->takeChild(childIndex);
        }
    }
    if (state->loadedCount >= state->rowIndices.size())
    {
        return;
    }

    const std::size_t batchEnd = std::min(
        state->loadedCount + kHandleRulePageSize,
        state->rowIndices.size());
    QVector<qulonglong> sourceRowIndices;
    QVector<QTreeWidgetItem*> newItems;
    sourceRowIndices.reserve(static_cast<qsizetype>(batchEnd - state->loadedCount));
    newItems.reserve(static_cast<qsizetype>(batchEnd - state->loadedCount));
    for (std::size_t matchIndex = state->loadedCount; matchIndex < batchEnd; ++matchIndex)
    {
        const std::size_t sourceRowIndex = state->rowIndices[matchIndex];
        QTreeWidgetItem* item = createHandleTreeRow(sourceRowIndex);
        if (item == nullptr)
        {
            continue;
        }
        item->setData(0, ks::handle::HandleTreeRuleIdRole, ruleId);
        summaryItem->addChild(item);
        sourceRowIndices.push_back(static_cast<qulonglong>(sourceRowIndex));
        newItems.push_back(item);
    }
    state->loadedCount = batchEnd;
    if (state->loadedCount < state->rowIndices.size())
    {
        auto* loadMoreItem = new QTreeWidgetItem(summaryItem);
        loadMoreItem->setData(0, ks::handle::HandleTreeItemKindRole,
            static_cast<int>(ks::handle::HandleTreeItemKind::LoadMore));
        loadMoreItem->setData(0, ks::handle::HandleTreeRuleIdRole, ruleId);
        loadMoreItem->setText(
            0,
            ks::i18n::sourceText(QStringLiteral("继续加载（已显示 %1 / %2）"))
                .arg(state->loadedCount)
                .arg(state->rowIndices.size()));
        loadMoreItem->setForeground(0, KswordTheme::PrimaryBlueColor);
    }
    sortLoadedRuleRows(m_handleSortColumn, m_handleSortOrder);
    scheduleProcessIconResolution(sourceRowIndices, newItems);
}

void HandleDock::sortLoadedRuleRows(const int column, const Qt::SortOrder order)
{
    if (column < 0 || column >= static_cast<int>(HandleTableColumn::Count))
    {
        return;
    }
    for (HandleRuleMatchState& state : m_ruleMatchStates)
    {
        QTreeWidgetItem* summaryItem = state.summaryItem;
        if (summaryItem == nullptr || summaryItem->childCount() < 2)
        {
            continue;
        }
        QList<QTreeWidgetItem*> handleItems;
        QList<QTreeWidgetItem*> trailingItems;
        while (summaryItem->childCount() > 0)
        {
            QTreeWidgetItem* childItem = summaryItem->takeChild(0);
            if (childItem->data(0, ks::handle::HandleTreeItemKindRole).toInt() ==
                static_cast<int>(ks::handle::HandleTreeItemKind::HandleRow))
            {
                handleItems.push_back(childItem);
            }
            else
            {
                trailingItems.push_back(childItem);
            }
        }
        const auto compareItems = [this, column, order](QTreeWidgetItem* left, QTreeWidgetItem* right)
        {
            const std::size_t leftIndex = static_cast<std::size_t>(
                left->data(0, ks::handle::HandleTreeSourceRowIndexRole).toULongLong());
            const std::size_t rightIndex = static_cast<std::size_t>(
                right->data(0, ks::handle::HandleTreeSourceRowIndexRole).toULongLong());
            if (leftIndex >= m_allRows.size() || rightIndex >= m_allRows.size())
            {
                return false;
            }
            const HandleRow& leftRow = m_allRows[leftIndex];
            const HandleRow& rightRow = m_allRows[rightIndex];
            int comparison = 0;
            switch (static_cast<HandleTableColumn>(column))
            {
            case HandleTableColumn::ProcessId:
                comparison = leftRow.processId < rightRow.processId ? -1 : leftRow.processId > rightRow.processId ? 1 : 0;
                break;
            case HandleTableColumn::HandleValue:
                comparison = leftRow.handleValue < rightRow.handleValue ? -1 : leftRow.handleValue > rightRow.handleValue ? 1 : 0;
                break;
            case HandleTableColumn::TypeIndex:
                comparison = leftRow.typeIndex < rightRow.typeIndex ? -1 : leftRow.typeIndex > rightRow.typeIndex ? 1 : 0;
                break;
            case HandleTableColumn::ObjectAddress:
                comparison = leftRow.objectAddress < rightRow.objectAddress ? -1 : leftRow.objectAddress > rightRow.objectAddress ? 1 : 0;
                break;
            case HandleTableColumn::GrantedAccess:
                comparison = leftRow.grantedAccess < rightRow.grantedAccess ? -1 : leftRow.grantedAccess > rightRow.grantedAccess ? 1 : 0;
                break;
            case HandleTableColumn::HandleCount:
                comparison = leftRow.handleCount < rightRow.handleCount ? -1 : leftRow.handleCount > rightRow.handleCount ? 1 : 0;
                break;
            case HandleTableColumn::PointerCount:
                comparison = leftRow.pointerCount < rightRow.pointerCount ? -1 : leftRow.pointerCount > rightRow.pointerCount ? 1 : 0;
                break;
            default:
                comparison = QString::localeAwareCompare(left->text(column), right->text(column));
                break;
            }
            return order == Qt::AscendingOrder ? comparison < 0 : comparison > 0;
        };
        std::stable_sort(handleItems.begin(), handleItems.end(), compareItems);
        summaryItem->addChildren(handleItems);
        summaryItem->addChildren(trailingItems);
    }
}

void HandleDock::updateHandleSummaryStatus()
{
    QString statusText = ks::i18n::sourceText(
        QStringLiteral("● 已匹配 %1 条结果 | 规则:%2 | 快照:%3"))
        .arg(m_totalRuleMatchCount)
        .arg(m_ruleMatchStates.size())
        .arg(m_allRows.size());
    if (m_temporaryFilterActive)
    {
        statusText += ks::i18n::sourceText(QStringLiteral(" | 临时筛选"));
    }
    if (!m_lastRefreshDiagnosticText.trimmed().isEmpty())
    {
        statusText += QStringLiteral(" | 有诊断");
    }
    updateHandleStatusLabel(statusText, false);
}

void HandleDock::loadFilterConfiguration()
{
    QSettings settings;
    const QByteArray storedJson = settings.value(
        QStringLiteral("HandleDock/FilterConfigurationV1")).toByteArray();
    if (storedJson.isEmpty())
    {
        m_filterDocument = ks::handle::CreateDefaultHandleFilterDocument();
        if (!m_filterDocument.rules.isEmpty())
        {
            m_filterDocument.rules.front().name =
                ks::i18n::sourceText(QStringLiteral("全部句柄"));
        }
        saveFilterConfiguration();
        return;
    }

    ks::handle::HandleFilterDocument loadedDocument;
    QStringList warningList;
    QString errorText;
    if (!ks::handle::DeserializeHandleFilterDocument(
        storedJson,
        &loadedDocument,
        &warningList,
        &errorText))
    {
        m_filterDocument = ks::handle::CreateDefaultHandleFilterDocument();
        if (!m_filterDocument.rules.isEmpty())
        {
            m_filterDocument.rules.front().name =
                ks::i18n::sourceText(QStringLiteral("全部句柄"));
        }
        kLogEvent loadFilterEvent;
        warn << loadFilterEvent
            << "[HandleDock] loadFilterConfiguration: invalid saved configuration, reset to default: "
            << errorText.toStdString()
            << eol;
        saveFilterConfiguration();
        return;
    }
    m_filterDocument = std::move(loadedDocument);
}

void HandleDock::saveFilterConfiguration() const
{
    ks::handle::HandleFilterDocument storedDocument = m_filterDocument;
    storedDocument.exportedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    QString errorText;
    const QByteArray jsonBytes =
        ks::handle::SerializeHandleFilterDocument(storedDocument, &errorText);
    if (jsonBytes.isEmpty())
    {
        kLogEvent saveFilterEvent;
        err << saveFilterEvent
            << "[HandleDock] saveFilterConfiguration: "
            << errorText.toStdString()
            << eol;
        return;
    }
    QSettings settings;
    settings.setValue(QStringLiteral("HandleDock/FilterConfigurationV1"), jsonBytes);
}

void HandleDock::applyFilterGlobalSettingsToControls()
{
    if (m_enumModeCombo == nullptr || m_resolveNameCheckBox == nullptr || m_nameBudgetSpinBox == nullptr)
    {
        return;
    }
    const QSignalBlocker enumBlocker(m_enumModeCombo);
    const QSignalBlocker resolveBlocker(m_resolveNameCheckBox);
    const QSignalBlocker budgetBlocker(m_nameBudgetSpinBox);
    const int enumValue = static_cast<int>(m_filterDocument.globalSettings.enumMode);
    const int enumIndex = m_enumModeCombo->findData(enumValue);
    m_enumModeCombo->setCurrentIndex(enumIndex >= 0 ? enumIndex : 1);
    m_resolveNameCheckBox->setChecked(m_filterDocument.globalSettings.resolveObjectName);
    m_nameBudgetSpinBox->setValue(m_filterDocument.globalSettings.nameResolveBudget);
}

void HandleDock::collectFilterGlobalSettingsFromControls()
{
    if (m_enumModeCombo == nullptr || m_resolveNameCheckBox == nullptr || m_nameBudgetSpinBox == nullptr)
    {
        return;
    }
    const int enumValue = m_enumModeCombo->currentData().toInt();
    switch (static_cast<ks::handle::FilterEnumMode>(enumValue))
    {
    case ks::handle::FilterEnumMode::UserSnapshot:
    case ks::handle::FilterEnumMode::KernelHandleTable:
    case ks::handle::FilterEnumMode::DuplicateHandle:
        m_filterDocument.globalSettings.enumMode =
            static_cast<ks::handle::FilterEnumMode>(enumValue);
        break;
    default:
        m_filterDocument.globalSettings.enumMode = ks::handle::FilterEnumMode::DuplicateHandle;
        break;
    }
    m_filterDocument.globalSettings.resolveObjectName = m_resolveNameCheckBox->isChecked();
    m_filterDocument.globalSettings.nameResolveBudget = m_nameBudgetSpinBox->value();
}

QString HandleDock::buildRuleConditionSummary(
    const ks::handle::HandleFilterRule& rule) const
{
    QStringList conditionList;
    if (!rule.processIds.isEmpty())
    {
        conditionList.push_back(
            ks::i18n::sourceText(QStringLiteral("PID：%1"))
                .arg(processIdsToText(rule.processIds)));
    }
    if (!rule.keyword.trimmed().isEmpty())
    {
        conditionList.push_back(
            ks::i18n::sourceText(QStringLiteral("关键字：%1"))
                .arg(rule.keyword.trimmed()));
    }
    if (!rule.typeName.trimmed().isEmpty())
    {
        conditionList.push_back(
            ks::i18n::sourceText(QStringLiteral("对象类型：%1"))
                .arg(rule.typeName.trimmed()));
    }
    switch (rule.diffStatus)
    {
    case ks::handle::FilterDiffStatus::UserOnly:
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("差异：仅用户态可见")));
        break;
    case ks::handle::FilterDiffStatus::KernelOnly:
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("差异：仅内核可见")));
        break;
    case ks::handle::FilterDiffStatus::Both:
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("差异：两者均可见")));
        break;
    case ks::handle::FilterDiffStatus::Any:
    default:
        break;
    }
    if (rule.onlyNamed)
    {
        conditionList.push_back(ks::i18n::sourceText(QStringLiteral("仅命名对象")));
    }
    return conditionList.isEmpty()
        ? ks::i18n::sourceText(QStringLiteral("全部句柄"))
        : conditionList.join(QStringLiteral("；"));
}

bool HandleDock::showRuleEditorDialog(
    ks::handle::HandleFilterRule* ruleInOut,
    const QVector<ks::handle::HandleFilterRule>& existingRules)
{
    if (ruleInOut == nullptr)
    {
        return false;
    }

    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("编辑句柄筛选规则"));
    dialog.resize(520, 360);
    auto* layout = new QVBoxLayout(&dialog);
    auto* formLayout = new QFormLayout();

    auto* nameEdit = new QLineEdit(ruleInOut->name, &dialog);
    auto* enabledCheck = new QCheckBox(QStringLiteral("启用此规则"), &dialog);
    enabledCheck->setChecked(ruleInOut->enabled);
    auto* pidEdit = new QLineEdit(processIdsToText(ruleInOut->processIds), &dialog);
    pidEdit->setPlaceholderText(QStringLiteral("多个 PID 使用逗号或空格分隔，留空表示不限"));
    auto* keywordEdit = new QLineEdit(ruleInOut->keyword, &dialog);
    keywordEdit->setPlaceholderText(QStringLiteral("不区分大小写，匹配现有句柄搜索字段"));
    auto* typeCombo = new QComboBox(&dialog);
    typeCombo->setEditable(true);
    typeCombo->addItem(QStringLiteral("全部类型"), QString());
    for (const QString& typeName : m_availableHandleTypeList)
    {
        typeCombo->addItem(typeName, typeName);
    }
    if (ruleInOut->typeName.trimmed().isEmpty())
    {
        typeCombo->setCurrentIndex(0);
    }
    else
    {
        typeCombo->setEditText(ruleInOut->typeName);
    }
    auto* diffCombo = new QComboBox(&dialog);
    diffCombo->addItem(QStringLiteral("全部差异"), static_cast<int>(ks::handle::FilterDiffStatus::Any));
    diffCombo->addItem(QStringLiteral("仅用户态可见"), static_cast<int>(ks::handle::FilterDiffStatus::UserOnly));
    diffCombo->addItem(QStringLiteral("仅内核可见"), static_cast<int>(ks::handle::FilterDiffStatus::KernelOnly));
    diffCombo->addItem(QStringLiteral("两者均可见"), static_cast<int>(ks::handle::FilterDiffStatus::Both));
    diffCombo->setCurrentIndex(std::max(
        0,
        diffCombo->findData(static_cast<int>(ruleInOut->diffStatus))));
    auto* onlyNamedCheck = new QCheckBox(QStringLiteral("仅匹配对象名非空的句柄"), &dialog);
    onlyNamedCheck->setChecked(ruleInOut->onlyNamed);

    formLayout->addRow(QStringLiteral("规则名称"), nameEdit);
    formLayout->addRow(QStringLiteral("状态"), enabledCheck);
    formLayout->addRow(QStringLiteral("PID 列表"), pidEdit);
    formLayout->addRow(QStringLiteral("关键字"), keywordEdit);
    formLayout->addRow(QStringLiteral("对象类型"), typeCombo);
    formLayout->addRow(QStringLiteral("差异状态"), diffCombo);
    formLayout->addRow(QStringLiteral("命名条件"), onlyNamedCheck);
    layout->addLayout(formLayout);

    auto* helpLabel = new QLabel(
        QStringLiteral("同一规则内的有效条件按 AND 匹配；启用规则之间按 OR 分组展示。"),
        &dialog);
    helpLabel->setWordWrap(true);
    helpLabel->setStyleSheet(
        QStringLiteral("color:%1;").arg(KswordTheme::TextSecondaryHex()));
    layout->addWidget(helpLabel);

    auto* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("保存"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    layout->addWidget(buttonBox);

    while (dialog.exec() == QDialog::Accepted)
    {
        const QString requestedName = nameEdit->text().trimmed();
        if (requestedName.isEmpty())
        {
            QMessageBox::warning(&dialog, QStringLiteral("规则名称"), QStringLiteral("规则名称不能为空。"));
            continue;
        }

        QString normalizedPidText = pidEdit->text();
        normalizedPidText.replace(',', ' ');
        normalizedPidText.replace(';', ' ');
        normalizedPidText.replace('\n', ' ');
        normalizedPidText.replace('\t', ' ');
        QVector<std::uint32_t> processIds;
        QSet<std::uint32_t> seenProcessIds;
        bool invalidPid = false;
        for (const QString& token : normalizedPidText.split(' ', Qt::SkipEmptyParts))
        {
            bool parseOk = false;
            const quint64 value = token.toULongLong(&parseOk, 10);
            if (!parseOk || value == 0 || value > std::numeric_limits<std::uint32_t>::max())
            {
                invalidPid = true;
                break;
            }
            const std::uint32_t processId = static_cast<std::uint32_t>(value);
            if (!seenProcessIds.contains(processId))
            {
                seenProcessIds.insert(processId);
                processIds.push_back(processId);
            }
        }
        if (invalidPid)
        {
            QMessageBox::warning(&dialog, QStringLiteral("PID 列表"), QStringLiteral("PID 列表包含无效值。"));
            continue;
        }

        ruleInOut->name = ks::handle::MakeUniqueHandleFilterRuleName(
            requestedName,
            existingRules,
            ruleInOut->id);
        ruleInOut->enabled = enabledCheck->isChecked();
        ruleInOut->processIds = processIds;
        ruleInOut->keyword = keywordEdit->text().trimmed();
        const QString selectedType = typeCombo->currentText().trimmed();
        const bool allTypesSelected = typeCombo->currentIndex() == 0
            && selectedType == typeCombo->itemText(0).trimmed();
        ruleInOut->typeName = allTypesSelected
            ? QString()
            : selectedType;
        ruleInOut->diffStatus = static_cast<ks::handle::FilterDiffStatus>(
            diffCombo->currentData().toInt());
        ruleInOut->onlyNamed = onlyNamedCheck->isChecked();
        return true;
    }
    return false;
}

void HandleDock::showRuleManagerDialog(const QString& initiallySelectedRuleId)
{
    QDialog dialog(this);
    dialog.setWindowTitle(QStringLiteral("句柄筛选规则管理"));
    dialog.resize(760, 460);
    auto* rootLayout = new QVBoxLayout(&dialog);
    auto* contentLayout = new QHBoxLayout();
    auto* ruleList = new QListWidget(&dialog);
    ruleList->setContextMenuPolicy(Qt::CustomContextMenu);
    contentLayout->addWidget(ruleList, 1);

    auto* actionLayout = new QVBoxLayout();
    auto* newButton = new QPushButton(QStringLiteral("新建"), &dialog);
    auto* editButton = new QPushButton(QStringLiteral("编辑"), &dialog);
    auto* copyButton = new QPushButton(QStringLiteral("复制"), &dialog);
    auto* deleteButton = new QPushButton(QStringLiteral("删除"), &dialog);
    auto* toggleButton = new QPushButton(QStringLiteral("启用/停用"), &dialog);
    auto* moveUpButton = new QPushButton(QStringLiteral("上移"), &dialog);
    auto* moveDownButton = new QPushButton(QStringLiteral("下移"), &dialog);
    for (QPushButton* button : {
        newButton, editButton, copyButton, deleteButton,
        toggleButton, moveUpButton, moveDownButton })
    {
        actionLayout->addWidget(button);
        ks::ui::NormalizeToolbarControl(button);
    }
    actionLayout->setSpacing(8);
    actionLayout->addStretch(1);
    contentLayout->addLayout(actionLayout);
    rootLayout->addLayout(contentLayout, 1);

    QVector<ks::handle::HandleFilterRule> workingRules = m_filterDocument.rules;
    std::function<void(int)> refreshRuleList =
        [this, ruleList, &workingRules, &refreshRuleList](const int selectedIndex)
        {
            const QSignalBlocker listBlocker(ruleList);
            ruleList->clear();
            for (const ks::handle::HandleFilterRule& rule : workingRules)
            {
                auto* item = new QListWidgetItem(
                    ks::i18n::sourceText(QStringLiteral("%1  [%2]\n%3"))
                        .arg(rule.name)
                        .arg(rule.enabled
                            ? ks::i18n::sourceText(QStringLiteral("启用"))
                            : ks::i18n::sourceText(QStringLiteral("停用")))
                        .arg(buildRuleConditionSummary(rule)),
                    ruleList);
                item->setData(Qt::UserRole, rule.id);
            }
            if (!workingRules.isEmpty())
            {
                ruleList->setCurrentRow(std::clamp(
                    selectedIndex,
                    0,
                    static_cast<int>(workingRules.size()) - 1));
            }
        };

    int initialIndex = 0;
    for (qsizetype ruleIndex = 0; ruleIndex < workingRules.size(); ++ruleIndex)
    {
        if (workingRules.at(ruleIndex).id == initiallySelectedRuleId)
        {
            initialIndex = static_cast<int>(ruleIndex);
            break;
        }
    }
    refreshRuleList(initialIndex);

    connect(ruleList, &QListWidget::customContextMenuRequested, &dialog,
        [ruleList](const QPoint& point)
        {
            QListWidgetItem* item = ruleList->itemAt(point);
            if (item == nullptr)
            {
                return;
            }
            QMenu menu(ruleList);
            menu.setStyleSheet(KswordTheme::ContextMenuStyle());
            QAction* copyAction = menu.addAction(QStringLiteral("复制"));
            if (menu.exec(ruleList->viewport()->mapToGlobal(point)) == copyAction)
            {
                QApplication::clipboard()->setText(item->text());
            }
        });

    connect(newButton, &QPushButton::clicked, &dialog,
        [this, ruleList, &workingRules, &refreshRuleList]()
        {
            ks::handle::HandleFilterRule rule;
            rule.id = ks::handle::CreateHandleFilterRuleId();
            rule.name = ks::handle::MakeUniqueHandleFilterRuleName(
                ks::i18n::sourceText(QStringLiteral("规则 %1"))
                    .arg(workingRules.size() + 1),
                workingRules);
            if (showRuleEditorDialog(&rule, workingRules))
            {
                workingRules.push_back(std::move(rule));
                refreshRuleList(workingRules.size() - 1);
            }
        });
    const auto editCurrentRule =
        [this, ruleList, &workingRules, &refreshRuleList]()
        {
            const int row = ruleList->currentRow();
            if (row < 0 || row >= workingRules.size())
            {
                return;
            }
            ks::handle::HandleFilterRule editedRule = workingRules.at(row);
            if (showRuleEditorDialog(&editedRule, workingRules))
            {
                workingRules[row] = std::move(editedRule);
                refreshRuleList(row);
            }
        };
    connect(editButton, &QPushButton::clicked, &dialog, editCurrentRule);
    connect(ruleList, &QListWidget::itemDoubleClicked, &dialog,
        [editCurrentRule](QListWidgetItem*) { editCurrentRule(); });
    connect(copyButton, &QPushButton::clicked, &dialog,
        [this, ruleList, &workingRules, &refreshRuleList]()
        {
            const int row = ruleList->currentRow();
            if (row < 0 || row >= workingRules.size())
            {
                return;
            }
            ks::handle::HandleFilterRule copiedRule = workingRules.at(row);
            copiedRule.id = ks::handle::CreateHandleFilterRuleId();
            copiedRule.name = ks::handle::MakeUniqueHandleFilterRuleName(
                copiedRule.name + ks::i18n::sourceText(QStringLiteral(" 副本")),
                workingRules);
            workingRules.insert(row + 1, std::move(copiedRule));
            refreshRuleList(row + 1);
        });
    connect(deleteButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int row = ruleList->currentRow();
            if (row < 0 || row >= workingRules.size())
            {
                return;
            }
            workingRules.removeAt(row);
            refreshRuleList(std::min(
                row,
                static_cast<int>(workingRules.size()) - 1));
        });
    connect(toggleButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int row = ruleList->currentRow();
            if (row < 0 || row >= workingRules.size())
            {
                return;
            }
            workingRules[row].enabled = !workingRules[row].enabled;
            refreshRuleList(row);
        });
    connect(moveUpButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int row = ruleList->currentRow();
            if (row <= 0 || row >= workingRules.size())
            {
                return;
            }
            workingRules.swapItemsAt(row, row - 1);
            refreshRuleList(row - 1);
        });
    connect(moveDownButton, &QPushButton::clicked, &dialog,
        [ruleList, &workingRules, &refreshRuleList]()
        {
            const int row = ruleList->currentRow();
            if (row < 0 || row + 1 >= workingRules.size())
            {
                return;
            }
            workingRules.swapItemsAt(row, row + 1);
            refreshRuleList(row + 1);
        });

    auto* buttonBox = new QDialogButtonBox(
        QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
        &dialog);
    buttonBox->button(QDialogButtonBox::Ok)->setText(QStringLiteral("应用"));
    buttonBox->button(QDialogButtonBox::Cancel)->setText(QStringLiteral("取消"));
    connect(buttonBox, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttonBox, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    rootLayout->addWidget(buttonBox);

    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    m_filterDocument.rules = std::move(workingRules);
    m_temporaryFilterActive = false;
    if (m_returnSavedFilterButton != nullptr)
    {
        m_returnSavedFilterButton->setVisible(false);
    }
    saveFilterConfiguration();
    if (m_snapshotScopedToTemporarySinglePid)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
}

void HandleDock::importFilterConfiguration()
{
    const QString filePath = QFileDialog::getOpenFileName(
        this,
        ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
        QString(),
        ks::i18n::sourceText(QStringLiteral("JSON 配置 (*.json);;所有文件 (*)")));
    if (filePath.isEmpty())
    {
        return;
    }
    QFile sourceFile(filePath);
    if (!sourceFile.open(QIODevice::ReadOnly))
    {
        QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
            ks::i18n::sourceText(QStringLiteral("无法读取配置文件：%1"))
                .arg(sourceFile.errorString()));
        return;
    }

    ks::handle::HandleFilterDocument importedDocument;
    QStringList warningList;
    QString errorText;
    if (!ks::handle::DeserializeHandleFilterDocument(
        sourceFile.readAll(),
        &importedDocument,
        &warningList,
        &errorText))
    {
        QMessageBox::warning(
            this,
            ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
            ks::i18n::sourceText(QStringLiteral("配置文件无效：%1"))
                .arg(ks::i18n::displayText(errorText)));
        return;
    }

    QMessageBox choiceBox(this);
    choiceBox.setWindowTitle(ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")));
    choiceBox.setText(ks::i18n::sourceText(QStringLiteral("选择配置导入方式。")));
    QPushButton* replaceButton = choiceBox.addButton(
        ks::i18n::sourceText(QStringLiteral("替换全部")), QMessageBox::AcceptRole);
    QPushButton* appendButton = choiceBox.addButton(
        ks::i18n::sourceText(QStringLiteral("追加导入")), QMessageBox::ActionRole);
    QPushButton* cancelButton = choiceBox.addButton(
        ks::i18n::sourceText(QStringLiteral("取消")), QMessageBox::RejectRole);
    choiceBox.setDefaultButton(replaceButton);
    choiceBox.setEscapeButton(cancelButton);
    choiceBox.exec();
    if (choiceBox.clickedButton() == cancelButton || choiceBox.clickedButton() == nullptr)
    {
        return;
    }

    const ks::handle::HandleFilterGlobalSettings previousGlobalSettings =
        m_filterDocument.globalSettings;
    if (choiceBox.clickedButton() == replaceButton)
    {
        m_filterDocument = std::move(importedDocument);
    }
    else if (choiceBox.clickedButton() == appendButton)
    {
        for (ks::handle::HandleFilterRule importedRule : importedDocument.rules)
        {
            importedRule.id = ks::handle::CreateHandleFilterRuleId();
            importedRule.name = ks::handle::MakeUniqueHandleFilterRuleName(
                importedRule.name,
                m_filterDocument.rules);
            m_filterDocument.rules.push_back(std::move(importedRule));
        }
    }

    m_temporaryFilterActive = false;
    if (m_returnSavedFilterButton != nullptr)
    {
        m_returnSavedFilterButton->setVisible(false);
    }
    applyFilterGlobalSettingsToControls();
    saveFilterConfiguration();
    const bool globalSettingsChanged = !sameGlobalSettings(
        previousGlobalSettings,
        m_filterDocument.globalSettings);
    if (globalSettingsChanged || m_snapshotScopedToTemporarySinglePid)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
    QStringList displayWarningList;
    displayWarningList.reserve(warningList.size());
    for (const QString& warningText : warningList)
    {
        displayWarningList.push_back(ks::i18n::displayText(warningText));
    }
    QMessageBox::information(
        this,
        ks::i18n::sourceText(QStringLiteral("导入句柄筛选配置")),
        displayWarningList.isEmpty()
            ? ks::i18n::sourceText(QStringLiteral("筛选配置已导入。"))
            : ks::i18n::sourceText(QStringLiteral("筛选配置已导入。\n%1"))
                .arg(displayWarningList.join('\n')));
}

void HandleDock::exportFilterConfiguration() const
{
    const QString filePath = QFileDialog::getSaveFileName(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
        ks::i18n::sourceText(QStringLiteral("句柄筛选配置.json")),
        ks::i18n::sourceText(QStringLiteral("JSON 配置 (*.json);;所有文件 (*)")));
    if (filePath.isEmpty())
    {
        return;
    }
    ks::handle::HandleFilterDocument exportDocument = m_filterDocument;
    exportDocument.exportedAtUtc = QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs);
    QString errorText;
    const QByteArray jsonBytes =
        ks::handle::SerializeHandleFilterDocument(exportDocument, &errorText);
    if (jsonBytes.isEmpty())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
            ks::i18n::displayText(errorText));
        return;
    }
    QSaveFile targetFile(filePath);
    if (!targetFile.open(QIODevice::WriteOnly)
        || targetFile.write(jsonBytes) != jsonBytes.size()
        || !targetFile.commit())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
            ks::i18n::sourceText(QStringLiteral("配置文件写入失败：%1"))
                .arg(targetFile.errorString()));
        return;
    }
    QMessageBox::information(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选配置")),
        ks::i18n::sourceText(QStringLiteral("筛选配置已导出。")));
}

void HandleDock::exportRuleResults(const QString& ruleId) const
{
    const QString filePath = QFileDialog::getSaveFileName(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
        ks::i18n::sourceText(QStringLiteral("句柄筛选结果.tsv")),
        ks::i18n::sourceText(QStringLiteral("TSV 文件 (*.tsv);;所有文件 (*)")));
    if (filePath.isEmpty())
    {
        return;
    }

    QSaveFile targetFile(filePath);
    if (!targetFile.open(QIODevice::WriteOnly))
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                .arg(targetFile.errorString()));
        return;
    }
    if (targetFile.write("\xEF\xBB\xBF", 3) != 3)
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                .arg(targetFile.errorString()));
        targetFile.cancelWriting();
        return;
    }
    const QStringList headerList{
        ks::i18n::sourceText(QStringLiteral("规则名")),
        ks::i18n::sourceText(QStringLiteral("PID")),
        ks::i18n::sourceText(QStringLiteral("进程名")),
        ks::i18n::sourceText(QStringLiteral("句柄")),
        ks::i18n::sourceText(QStringLiteral("TypeIndex/类型")),
        ks::i18n::sourceText(QStringLiteral("对象名")),
        ks::i18n::sourceText(QStringLiteral("对象地址")),
        ks::i18n::sourceText(QStringLiteral("访问掩码")),
        ks::i18n::sourceText(QStringLiteral("属性")),
        ks::i18n::sourceText(QStringLiteral("HandleCount")),
        ks::i18n::sourceText(QStringLiteral("PointerCount")),
        ks::i18n::sourceText(QStringLiteral("来源")),
        ks::i18n::sourceText(QStringLiteral("解码状态")),
        ks::i18n::sourceText(QStringLiteral("差异"))
    };
    const QByteArray headerBytes = (headerList.join('\t') + '\n').toUtf8();
    if (targetFile.write(headerBytes) != headerBytes.size())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                .arg(targetFile.errorString()));
        targetFile.cancelWriting();
        return;
    }

    std::size_t exportedRowCount = 0;
    for (const HandleRuleMatchState& state : m_ruleMatchStates)
    {
        if (!state.enabled || (!ruleId.isEmpty() && state.ruleId != ruleId))
        {
            continue;
        }
        for (const std::size_t sourceRowIndex : state.rowIndices)
        {
            if (sourceRowIndex >= m_allRows.size())
            {
                continue;
            }
            const HandleRow& row = m_allRows[sourceRowIndex];
            QStringList fieldList{
                state.ruleName,
                QString::number(row.processId),
                row.processName,
                formatHex(row.handleValue, 0),
                ks::i18n::displayText(formatTypeIndexDisplayText(row.typeIndex, row.typeName)),
                ks::i18n::displayText(formatObjectNameDisplayText(row)),
                formatHex(row.objectAddress, 0),
                formatHex(row.grantedAccess, 8),
                ks::i18n::displayText(formatHandleAttributes(row.attributes)),
                ks::i18n::displayText(formatOptionalObjectCount(row.handleCount, row.basicInfoAvailable)),
                ks::i18n::displayText(formatOptionalObjectCount(row.pointerCount, row.basicInfoAvailable)),
                ks::i18n::displayText(formatHandleSourceText(row.sourceMode)),
                ks::i18n::displayText(formatHandleDecodeStatusText(row.decodeStatus)),
                ks::i18n::displayText(formatHandleDiffStatusText(row.diffStatus))
            };
            for (QString& field : fieldList)
            {
                field = sanitizeTsvField(field);
            }
            const QByteArray lineBytes = (fieldList.join('\t') + '\n').toUtf8();
            if (targetFile.write(lineBytes) != lineBytes.size())
            {
                QMessageBox::warning(
                    const_cast<HandleDock*>(this),
                    ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
                    ks::i18n::sourceText(QStringLiteral("结果文件写入失败：%1"))
                        .arg(targetFile.errorString()));
                targetFile.cancelWriting();
                return;
            }
            ++exportedRowCount;
        }
    }
    if (!targetFile.commit())
    {
        QMessageBox::warning(
            const_cast<HandleDock*>(this),
            ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
            ks::i18n::sourceText(QStringLiteral("结果文件提交失败：%1"))
                .arg(targetFile.errorString()));
        return;
    }
    QMessageBox::information(
        const_cast<HandleDock*>(this),
        ks::i18n::sourceText(QStringLiteral("导出句柄筛选结果")),
        ks::i18n::sourceText(QStringLiteral("已导出 %1 条命中结果。"))
            .arg(exportedRowCount));
}

void HandleDock::returnToSavedFilters()
{
    if (!m_temporaryFilterActive)
    {
        return;
    }
    m_temporaryFilterActive = false;
    m_temporaryFilterRule = ks::handle::HandleFilterRule{};
    if (m_returnSavedFilterButton != nullptr)
    {
        m_returnSavedFilterButton->setVisible(false);
    }
    if (m_snapshotScopedToTemporarySinglePid)
    {
        requestAsyncRefresh(true);
    }
    else
    {
        applyLocalHandleFilters(true);
    }
}

void HandleDock::updateTypeFilterItems(const std::vector<QString>& availableTypeList)
{
    m_availableHandleTypeList = availableTypeList;
}

void HandleDock::refreshTypeFilterItemsFromAllRows()
{
    std::set<QString> typeNameSet;
    for (const HandleRow& row : m_allRows)
    {
        if (!row.typeName.trimmed().isEmpty())
        {
            typeNameSet.insert(row.typeName);
        }
    }

    std::vector<QString> availableTypeList;
    availableTypeList.reserve(typeNameSet.size());
    for (const QString& typeNameText : typeNameSet)
    {
        availableTypeList.push_back(typeNameText);
    }
    updateTypeFilterItems(availableTypeList);
}

void HandleDock::syncHandleTypeNamesFromObjectTypeMap()
{
    if (m_allRows.empty() || m_typeNameMapByIndexFromObjectTab.empty())
    {
        if (m_handleRenderDeferredUntilTypeMap && !m_allRows.empty())
        {
            // 对象类型快照可能失败或返回空映射。此时不能永久压住句柄列表，
            // 兜底使用枚举阶段已有类型文本渲染一次，保证用户仍能看到刷新结果。
            m_handleRenderDeferredUntilTypeMap = false;
            refreshTypeFilterItemsFromAllRows();
            applyLocalHandleFilters(true);
        }
        return;
    }

    // 对象类型映射已到达：把当前缓存行转换为最终类型名，然后只触发一次句柄表渲染。
    for (HandleRow& row : m_allRows)
    {
        const auto foundIt = m_typeNameMapByIndexFromObjectTab.find(row.typeIndex);
        if (foundIt != m_typeNameMapByIndexFromObjectTab.end() && !foundIt->second.empty())
        {
            row.typeName = QString::fromStdString(foundIt->second);
        }
    }
    refreshTypeFilterItemsFromAllRows();
    m_handleRenderDeferredUntilTypeMap = false;
    applyLocalHandleFilters();

    kLogEvent syncTypeNameEvent;
    info << syncTypeNameEvent
        << "[HandleDock] syncHandleTypeNamesFromObjectTypeMap: syncedRows="
        << m_allRows.size()
        << ", mappedTypes="
        << m_typeNameMapByIndexFromObjectTab.size()
        << eol;
}

void HandleDock::updateHandleStatusLabel(const QString& statusText, const bool refreshing)
{
    if (m_statusLabel == nullptr)
    {
        return;
    }
    m_statusLabel->setText(statusText);
    if (refreshing)
    {
        m_statusLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:700;")
            .arg(KswordTheme::PrimaryBlueHex));
        return;
    }

    const bool hasDiagnostic =
        statusText.contains(QStringLiteral("失败")) ||
        statusText.contains(QStringLiteral("预算")) ||
        statusText.contains(QStringLiteral("异常")) ||
        statusText.contains(QStringLiteral("截断"));
    const QString textColor = hasDiagnostic
        ? KswordTheme::WarningColor().name(QColor::HexRgb)
        : KswordTheme::SuccessColor().name(QColor::HexRgb);
    m_statusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg(textColor));
}

void HandleDock::updateObjectTypeStatusLabel(const QString& statusText, const bool refreshing)
{
    if (m_objectTypeStatusLabel == nullptr)
    {
        return;
    }
    m_objectTypeStatusLabel->setText(statusText);
    if (refreshing)
    {
        m_objectTypeStatusLabel->setStyleSheet(
            QStringLiteral("color:%1;font-weight:700;")
            .arg(KswordTheme::PrimaryBlueHex));
        return;
    }

    const bool hasDiagnostic = statusText.contains(QStringLiteral("失败"));
    const QString textColor = hasDiagnostic
        ? KswordTheme::WarningColor().name(QColor::HexRgb)
        : KswordTheme::SuccessColor().name(QColor::HexRgb);
    m_objectTypeStatusLabel->setStyleSheet(
        QStringLiteral("color:%1;font-weight:600;")
        .arg(textColor));
}

void HandleDock::focusObjectTypeByIndex(const std::uint16_t typeIndex)
{
    if (m_tabWidget != nullptr && m_objectTypePage != nullptr)
    {
        m_tabWidget->setCurrentWidget(m_objectTypePage);
    }

    if (m_objectTypeRows.empty() && !m_objectTypeRefreshInProgress)
    {
        requestObjectTypeRefreshAsync(true);
        return;
    }

    if (m_objectTypeFilterEdit != nullptr)
    {
        m_objectTypeFilterEdit->setText(QString::number(typeIndex));
    }

    for (int row = 0; row < m_objectTypeTable->topLevelItemCount(); ++row)
    {
        QTreeWidgetItem* item = m_objectTypeTable->topLevelItem(row);
        if (item == nullptr)
        {
            continue;
        }
        if (item->text(static_cast<int>(ObjectTypeTableColumn::TypeIndex)).toUInt() == typeIndex)
        {
            m_objectTypeTable->setCurrentItem(item);
            break;
        }
    }
}

void HandleDock::showHandleTableContextMenu(const QPoint& localPosition)
{
    QTreeWidgetItem* clickedItem = m_tableWidget->itemAt(localPosition);
    if (clickedItem == nullptr)
    {
        return;
    }
    m_tableWidget->setCurrentItem(clickedItem);

    QMenu menu(this);
    menu.setStyleSheet(KswordTheme::ContextMenuStyle());
    QAction* copyCellAction = menu.addAction(QIcon(":/Icon/handle_copy.svg"), QStringLiteral("复制单元格"));
    QAction* copyRowAction = menu.addAction(QIcon(":/Icon/handle_copy_row.svg"), QStringLiteral("复制整行"));
    const auto itemKind = static_cast<ks::handle::HandleTreeItemKind>(
        clickedItem->data(0, ks::handle::HandleTreeItemKindRole).toInt());
    const QString ruleId = clickedItem->data(0, ks::handle::HandleTreeRuleIdRole).toString();

    QAction* loadMoreAction = nullptr;
    QAction* editRuleAction = nullptr;
    QAction* toggleRuleAction = nullptr;
    QAction* exportRuleAction = nullptr;
    QAction* openProcessAction = nullptr;
    QAction* gotoTypeAction = nullptr;
    QAction* refreshAction = nullptr;
    QAction* closeR3Action = nullptr;
    QAction* closeR0Action = nullptr;
    HandleRow closeTarget{};
    if (itemKind == ks::handle::HandleTreeItemKind::LoadMore)
    {
        menu.addSeparator();
        loadMoreAction = menu.addAction(QStringLiteral("加载下一批"));
    }
    else if (itemKind == ks::handle::HandleTreeItemKind::RuleSummary)
    {
        menu.addSeparator();
        editRuleAction = menu.addAction(QStringLiteral("编辑规则"));
        const ks::handle::HandleFilterRule* rule = findActiveRule(ruleId);
        toggleRuleAction = menu.addAction(
            rule != nullptr && rule->enabled
                ? QStringLiteral("停用规则")
                : QStringLiteral("启用规则"));
        exportRuleAction = menu.addAction(QStringLiteral("导出该规则结果"));
    }
    else if (itemKind == ks::handle::HandleTreeItemKind::HandleRow)
    {
        menu.addSeparator();
        HandleRow* selectedRow = selectedHandleRow();
        if (selectedRow != nullptr)
        {
            closeTarget = *selectedRow;
        }
        closeR3Action = menu.addAction(QStringLiteral("R3关闭句柄"));
        closeR0Action = menu.addAction(QStringLiteral("R0关闭句柄"));
        const bool hasCloseIdentity = selectedRow != nullptr && closeTarget.processId > 4U &&
            closeTarget.processId != ::GetCurrentProcessId() && closeTarget.handleValue != 0U &&
            closeTarget.handleValue < 0x80000000ULL && closeTarget.processCreationTime != 0U &&
            closeTarget.objectAddress != 0U;
        closeR3Action->setEnabled(hasCloseIdentity);
        closeR0Action->setEnabled(hasCloseIdentity);
        if (!hasCloseIdentity)
        {
            const QString reason = QStringLiteral("系统/自身进程或缺少进程创建时间、句柄对象身份，无法关闭。");
            closeR3Action->setToolTip(reason);
            closeR0Action->setToolTip(reason);
            menu.setToolTipsVisible(true);
        }
        menu.addSeparator();
        openProcessAction = menu.addAction(
            QIcon(QStringLiteral(":/Icon/process_details.svg")),
            QStringLiteral("转到进程详细信息"));
        openProcessAction->setEnabled(selectedRow != nullptr && selectedRow->processId != 0U);
        gotoTypeAction = menu.addAction(QIcon(":/Icon/process_tree.svg"), QStringLiteral("转到对象类型"));
        refreshAction = menu.addAction(QIcon(":/Icon/handle_refresh.svg"), QStringLiteral("刷新"));
    }

    QAction* selectedAction = menu.exec(m_tableWidget->viewport()->mapToGlobal(localPosition));
    if (selectedAction == nullptr)
    {
        return;
    }
    if (selectedAction == copyCellAction)
    {
        copyCurrentHandleCell();
        return;
    }
    if (selectedAction == closeR3Action || selectedAction == closeR0Action)
    {
        closeHandleRow(closeTarget, selectedAction == closeR0Action);
        return;
    }
    if (selectedAction == copyRowAction)
    {
        copyCurrentHandleRow();
        return;
    }
    if (selectedAction == loadMoreAction)
    {
        appendNextRuleResultBatch(ruleId);
        return;
    }
    if (selectedAction == editRuleAction)
    {
        if (m_temporaryFilterActive && m_temporaryFilterRule.id == ruleId)
        {
            ks::handle::HandleFilterRule editedRule = m_temporaryFilterRule;
            if (showRuleEditorDialog(
                &editedRule,
                QVector<ks::handle::HandleFilterRule>{ m_temporaryFilterRule }))
            {
                m_temporaryFilterRule = std::move(editedRule);
                const bool cachedSnapshotCannotServeEditedRule =
                    m_snapshotScopedToTemporarySinglePid
                    && (m_temporaryFilterRule.processIds.size() != 1
                        || m_temporaryFilterRule.processIds.front() !=
                            m_snapshotScopedProcessId);
                if (cachedSnapshotCannotServeEditedRule)
                {
                    requestAsyncRefresh(true);
                }
                else
                {
                    applyLocalHandleFilters(true);
                }
            }
        }
        else
        {
            for (qsizetype ruleIndex = 0; ruleIndex < m_filterDocument.rules.size(); ++ruleIndex)
            {
                if (m_filterDocument.rules.at(ruleIndex).id != ruleId)
                {
                    continue;
                }
                ks::handle::HandleFilterRule editedRule =
                    m_filterDocument.rules.at(ruleIndex);
                if (showRuleEditorDialog(&editedRule, m_filterDocument.rules))
                {
                    m_filterDocument.rules[ruleIndex] = std::move(editedRule);
                    saveFilterConfiguration();
                    applyLocalHandleFilters(true);
                }
                break;
            }
        }
        return;
    }
    if (selectedAction == toggleRuleAction)
    {
        if (m_temporaryFilterActive && m_temporaryFilterRule.id == ruleId)
        {
            m_temporaryFilterRule.enabled = !m_temporaryFilterRule.enabled;
        }
        else
        {
            for (ks::handle::HandleFilterRule& rule : m_filterDocument.rules)
            {
                if (rule.id == ruleId)
                {
                    rule.enabled = !rule.enabled;
                    break;
                }
            }
            saveFilterConfiguration();
        }
        applyLocalHandleFilters(true);
        return;
    }
    if (selectedAction == exportRuleAction)
    {
        exportRuleResults(ruleId);
        return;
    }
    if (selectedAction == openProcessAction)
    {
        HandleRow* selectedRow = selectedHandleRow();
        if (selectedRow != nullptr)
        {
            ks::ui::OpenProcessDetailByPid(selectedRow->processId);
        }
        return;
    }
    if (selectedAction == gotoTypeAction)
    {
        HandleRow* row = selectedHandleRow();
        if (row != nullptr)
        {
            focusObjectTypeByIndex(row->typeIndex);
        }
        return;
    }
    if (selectedAction == refreshAction)
    {
        requestAsyncRefresh(true);
    }
}
