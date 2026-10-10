#include "ClipboardGuardPage.h"
#include "../../UI/DetailDialogChrome.h"
#include "../../theme.h"
#include "../../UI/CodeEditorWidget.h"
#include "../../UI/StructuredFieldView.h"
#include "../../MonitorDock/WinApiMonitorProtocol.h"

#include <QAction>
#include <QComboBox>
#include <QDialog>
#include <QDialogButtonBox>
#include "../../UI/SecondaryPageLayout.h"
#include <QFile>
#include <QFormLayout>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QRadioButton>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTabWidget>
#include <QVBoxLayout>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <Windows.h>

#include <algorithm>

// ============================================================
// ClipboardGuardPage.RuleEditor.cpp
// 作用：
// 1) 事件表右键菜单：拦截读/写/全部、记录、显示内容、显示调用栈、添加进程规则；
// 2) "添加进程规则"对话框：按映像名/完整路径新增持久规则；
// 3) 剪贴板格式使用原生属性模型；正文和捕获的调用栈日志保留原始数据，
//    按 AGENTS.md 要求显式设置不透明背景。
// ============================================================

namespace ks::misc
{
    namespace
    {
        // buildOpaqueDialogStyle 作用：覆盖父级可能存在的透明样式，保证详情弹窗
        // 在浅色/深色主题下都可读——AGENTS.md 明确点名"详情弹窗是高风险点"。
        QString buildOpaqueDialogStyle(const QString& objectName)
        {
            return QStringLiteral(
                "QDialog#%1{background-color:palette(window) !important;color:palette(text) !important;}"
                "QDialog#%1 QWidget{background-color:palette(window);color:palette(text);}")
                .arg(objectName);
        }

        // buildDetailDialog 作用：新建一个装了只读 CodeEditorWidget 的详情弹窗。
        QDialog* buildDetailDialog(QWidget* const parentWidget, const QString& titleText, const QString& objectNameText, CodeEditorWidget** const editorOut)
        {
            QDialog* const dialogValue = new QDialog(parentWidget);
            dialogValue->setObjectName(objectNameText);
            dialogValue->setAttribute(Qt::WA_StyledBackground, true);
            dialogValue->setAutoFillBackground(true);
            dialogValue->setStyleSheet(buildOpaqueDialogStyle(objectNameText));
            dialogValue->setWindowTitle(titleText);
            dialogValue->resize(720, 480);

            QVBoxLayout* const layoutValue = new QVBoxLayout(dialogValue);
            layoutValue->setContentsMargins(8, 8, 8, 8);
            CodeEditorWidget* const editorValue = new CodeEditorWidget(dialogValue);
            editorValue->setReadOnly(true);
            layoutValue->addWidget(editorValue);
            if (editorOut != nullptr)
            {
                *editorOut = editorValue;
            }
            ks::ui::ApplyDetailDialogChrome(dialogValue);
            return dialogValue;
        }

        // standardClipboardFormatName 作用：给"显示剪贴板内容"用的标准格式名对照表，
        // 与 APIMonitor_x64/hook/ClipboardGuardCommon.cpp 里那份保持一致的展示口径。
        QString standardClipboardFormatName(const UINT formatValue)
        {
            switch (formatValue)
            {
            case CF_TEXT: return QStringLiteral("CF_TEXT");
            case CF_UNICODETEXT: return QStringLiteral("CF_UNICODETEXT");
            case CF_OEMTEXT: return QStringLiteral("CF_OEMTEXT");
            case CF_BITMAP: return QStringLiteral("CF_BITMAP");
            case CF_HDROP: return QStringLiteral("CF_HDROP");
            case CF_DIB: return QStringLiteral("CF_DIB");
            default: return QStringLiteral("0x%1").arg(formatValue, 0, 16);
            }
        }
    }

    int ClipboardGuardPage::selectedEventRow() const
    {
        if (m_eventTable == nullptr)
        {
            return -1;
        }
        const QList<QTableWidgetItem*> selectedItems = m_eventTable->selectedItems();
        if (selectedItems.isEmpty())
        {
            return -1;
        }
        return selectedItems.first()->row();
    }

    void ClipboardGuardPage::showEventTableContextMenu(const QPoint& position)
    {
        const int row = selectedEventRow();
        QMenu menu(m_eventTable);
        menu.setStyleSheet(KswordTheme::ContextMenuStyle());

        QAction* const blockReadAction = menu.addAction(QStringLiteral("拦截剪贴板读取"));
        QAction* const blockWriteAction = menu.addAction(QStringLiteral("拦截剪贴板写入"));
        QAction* const blockAllAction = menu.addAction(QStringLiteral("拦截全部剪贴板访问"));
        QAction* const logOnlyAction = menu.addAction(QStringLiteral("记录剪贴板访问"));
        menu.addSeparator();
        QAction* const showContentsAction = menu.addAction(QStringLiteral("显示剪贴板内容"));
        QAction* const showStackAction = menu.addAction(QStringLiteral("显示调用栈"));
        menu.addSeparator();
        QAction* const addRuleAction = menu.addAction(QStringLiteral("添加进程规则"));

        const bool hasSelection = row >= 0;
        blockReadAction->setEnabled(hasSelection);
        blockWriteAction->setEnabled(hasSelection);
        blockAllAction->setEnabled(hasSelection);
        logOnlyAction->setEnabled(hasSelection);
        showContentsAction->setEnabled(hasSelection);
        showStackAction->setEnabled(hasSelection);

        QAction* const chosenAction = menu.exec(m_eventTable->viewport()->mapToGlobal(position));
        if (chosenAction == blockReadAction) { applyQuickActionToSelectedRow(ClipboardGuardQuickAction::BlockRead); }
        else if (chosenAction == blockWriteAction) { applyQuickActionToSelectedRow(ClipboardGuardQuickAction::BlockWrite); }
        else if (chosenAction == blockAllAction) { applyQuickActionToSelectedRow(ClipboardGuardQuickAction::BlockAll); }
        else if (chosenAction == logOnlyAction) { applyQuickActionToSelectedRow(ClipboardGuardQuickAction::LogOnly); }
        else if (chosenAction == showContentsAction) { showClipboardContentsForSelectedRow(); }
        else if (chosenAction == showStackAction) { showCallStackForSelectedRow(); }
        else if (chosenAction == addRuleAction) { openAddProcessRuleDialog(); }
    }

    void ClipboardGuardPage::applyQuickActionToSelectedRow(const ClipboardGuardQuickAction action)
    {
        const int row = selectedEventRow();
        if (row < 0 || m_eventTable->item(row, ColumnPid) == nullptr)
        {
            return;
        }
        const quint32 pidValue = m_eventTable->item(row, ColumnPid)->data(Qt::UserRole).toUInt();
        if (pidValue == 0)
        {
            return;
        }

        auto ruleIt = std::find_if(m_rules.begin(), m_rules.end(), [pidValue](const ClipboardGuardRule& ruleValue) {
            return ruleValue.targetKind == 1U && ruleValue.targetProcessId == pidValue;
        });
        if (ruleIt == m_rules.end())
        {
            ClipboardGuardRule newRule;
            newRule.ruleId = m_nextLocalRuleId++;
            newRule.targetKind = 1U;
            newRule.targetProcessId = pidValue;
            newRule.ruleName = QStringLiteral("PID %1 快捷规则").arg(pidValue);
            m_rules.push_back(newRule);
            ruleIt = std::prev(m_rules.end());
        }

        switch (action)
        {
        case ClipboardGuardQuickAction::BlockRead:
            ruleIt->readAction = 1U;
            break;
        case ClipboardGuardQuickAction::BlockWrite:
            ruleIt->writeAction = 1U;
            break;
        case ClipboardGuardQuickAction::BlockAll:
            ruleIt->readAction = 1U;
            ruleIt->writeAction = 1U;
            ruleIt->enumAction = 1U;
            break;
        case ClipboardGuardQuickAction::LogOnly:
            // 只把"允许"提升为"仅记录"；已经是"拦截"的方向不因为点了"记录"被悄悄放开。
            if (ruleIt->readAction == 0U) { ruleIt->readAction = 2U; }
            if (ruleIt->writeAction == 0U) { ruleIt->writeAction = 2U; }
            if (ruleIt->enumAction == 0U) { ruleIt->enumAction = 2U; }
            break;
        }
        ruleIt->enabled = true;

        refreshRuleTable();
        syncRulesToDriver();
        // 立刻按新规则重新核对一遍受保护进程，不必等下一次自动轮询才生效。
        refreshProcessListAndSessionsAsync();
    }

    void ClipboardGuardPage::openAddProcessRuleDialog()
    {
        QDialog dialogValue(this);
        dialogValue.setObjectName(QStringLiteral("ClipboardGuardAddRuleDialog"));
        dialogValue.setAttribute(Qt::WA_StyledBackground, true);
        dialogValue.setAutoFillBackground(true);
        dialogValue.setStyleSheet(buildOpaqueDialogStyle(dialogValue.objectName()));
        dialogValue.setWindowTitle(QStringLiteral("添加剪贴板保护规则"));
        ks::ui::StyleSecondaryWindow(&dialogValue);
        dialogValue.resize(640, 380);

        QVBoxLayout* const rootLayout = new QVBoxLayout(&dialogValue);
        ks::ui::StyleSecondaryContentLayout(rootLayout);
        QFormLayout* const formLayout = new QFormLayout();

        QRadioButton* const byNameRadio = new QRadioButton(QStringLiteral("按进程名（例如 notepad.exe）"), &dialogValue);
        QRadioButton* const byPathRadio = new QRadioButton(QStringLiteral("按完整路径"), &dialogValue);
        byNameRadio->setChecked(true);
        // 匹配方式属于同一组选项，单行排布让目标与三种行为保持同屏。
        auto* matchModes = new QHBoxLayout();
        matchModes->setSpacing(12);
        matchModes->addWidget(byNameRadio);
        matchModes->addWidget(byPathRadio);
        matchModes->addStretch(1);
        rootLayout->addLayout(matchModes);

        QLineEdit* const targetEdit = new QLineEdit(&dialogValue);
        targetEdit->setPlaceholderText(QStringLiteral("例如 notepad.exe 或 C:\\Windows\\notepad.exe"));
        formLayout->addRow(QStringLiteral("目标："), targetEdit);

        QLineEdit* const nameEdit = new QLineEdit(&dialogValue);
        formLayout->addRow(QStringLiteral("规则名："), nameEdit);

        const auto buildActionCombo = [&dialogValue]() {
            QComboBox* const comboValue = new QComboBox(&dialogValue);
            comboValue->addItem(QStringLiteral("允许"), 0);
            comboValue->addItem(QStringLiteral("拦截"), 1);
            comboValue->addItem(QStringLiteral("仅记录"), 2);
            return comboValue;
        };
        QComboBox* const readCombo = buildActionCombo();
        QComboBox* const writeCombo = buildActionCombo();
        QComboBox* const enumCombo = buildActionCombo();
        readCombo->setCurrentIndex(1);
        formLayout->addRow(QStringLiteral("读取："), readCombo);
        formLayout->addRow(QStringLiteral("写入："), writeCombo);
        formLayout->addRow(QStringLiteral("枚举："), enumCombo);
        ks::ui::StyleSecondaryForm(formLayout, 104);
        rootLayout->addLayout(formLayout);
        rootLayout->addStretch(1);

        QDialogButtonBox* const buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &dialogValue);
        ks::ui::StyleSecondaryButtonBox(buttonBox);
        ks::ui::StyleSecondaryFooter(buttonBox);
        rootLayout->addWidget(buttonBox);
        QObject::connect(buttonBox, &QDialogButtonBox::accepted, &dialogValue, &QDialog::accept);
        QObject::connect(buttonBox, &QDialogButtonBox::rejected, &dialogValue, &QDialog::reject);

        if (dialogValue.exec() != QDialog::Accepted)
        {
            return;
        }
        const QString targetText = targetEdit->text().trimmed();
        if (targetText.isEmpty())
        {
            QMessageBox::warning(this, QStringLiteral("添加规则"), QStringLiteral("目标不能为空。"));
            return;
        }

        ClipboardGuardRule newRule;
        newRule.ruleId = m_nextLocalRuleId++;
        newRule.targetKind = byNameRadio->isChecked() ? 2U : 3U;
        newRule.targetImage = targetText;
        newRule.ruleName = nameEdit->text().trimmed().isEmpty() ? targetText : nameEdit->text().trimmed();
        newRule.readAction = static_cast<quint32>(readCombo->currentData().toUInt());
        newRule.writeAction = static_cast<quint32>(writeCombo->currentData().toUInt());
        newRule.enumAction = static_cast<quint32>(enumCombo->currentData().toUInt());
        m_rules.push_back(newRule);

        refreshRuleTable();
        syncRulesToDriver();
        refreshProcessListAndSessionsAsync();
    }

    void ClipboardGuardPage::removeSelectedRule()
    {
        if (m_ruleTable == nullptr)
        {
            return;
        }
        const int row = m_ruleTable->currentRow();
        if (row < 0 || static_cast<std::size_t>(row) >= m_rules.size())
        {
            return;
        }
        m_rules.erase(m_rules.begin() + row);
        refreshRuleTable();
        syncRulesToDriver();
        refreshProcessListAndSessionsAsync();
    }

    void ClipboardGuardPage::toggleGlobalMonitor(const bool enabled)
    {
        if (enabled)
        {
            if (hasEnabledGlobalRule())
            {
                // 规则表里已经有一条启用的全局规则（例如从驱动回读时就带着），
                // 不重复添加第二条。
                return;
            }
            ClipboardGuardRule globalRule;
            globalRule.ruleId = m_nextLocalRuleId++;
            globalRule.enabled = true;
            globalRule.targetKind = 4U; // KSWORD_ARK_CLIPBOARD_POLICY_TARGET_KIND_ALL
            globalRule.ruleName = QStringLiteral("全局监控");
            // 默认三个方向都只是"仅记录"：全局监控的目的是看见，不是拦截；
            // 需要真正拦截某个进程时，用规则表针对那个进程单独加一条更具体的规则，
            // findMatchingRule 已经保证具体规则优先于这条全局规则生效。
            globalRule.readAction = 2U;  // LOG_ONLY
            globalRule.writeAction = 2U; // LOG_ONLY
            globalRule.enumAction = 2U;  // LOG_ONLY
            m_rules.push_back(globalRule);
        }
        else
        {
            // 关闭时把已启用的全局规则整条移除（理论上只会有一条，但遍历删除
            // 更稳妥，不假设"只可能有一条"这个不变式永远成立）。
            m_rules.erase(
                std::remove_if(m_rules.begin(), m_rules.end(), [](const ClipboardGuardRule& ruleValue) {
                    return ruleValue.targetKind == 4U;
                }),
                m_rules.end());
        }

        refreshRuleTable();
        syncRulesToDriver();
        // 关闭全局监控后立即重新核对一遍：不再匹配任何规则的进程会话会被这次
        // 扫描回收，不用等到进程真的退出。
        refreshProcessListAndSessionsAsync();
    }

    void ClipboardGuardPage::showClipboardContentsForSelectedRow()
    {
        ks::ui::FieldDocument metadata;
        metadata.section(QStringLiteral("剪贴板内容"));
        QString rawText;
        if (::OpenClipboard(nullptr) == FALSE)
        {
            metadata.note(QStringLiteral("无法打开剪贴板（可能被其它进程占用），请稍后重试。"));
        }
        else
        {
            UINT formatValue = 0;
            int formatCount = 0;
            while ((formatValue = ::EnumClipboardFormats(formatValue)) != 0)
            {
                ++formatCount;
                metadata.field(QStringLiteral("格式"), standardClipboardFormatName(formatValue));
            }
            metadata.field(QStringLiteral("格式数量"), QString::number(formatCount));
            if (formatCount == 0)
            {
                metadata.note(QStringLiteral("当前剪贴板为空。"));
            }
            else
            {
                const HANDLE textHandle = ::GetClipboardData(CF_UNICODETEXT);
                if (textHandle != nullptr)
                {
                    const SIZE_T byteSize = ::GlobalSize(textHandle);
                    const auto* const lockedPointer = static_cast<const wchar_t*>(::GlobalLock(textHandle));
                    if (lockedPointer != nullptr)
                    {
                        metadata.field(QStringLiteral("CF_UNICODETEXT 字节数"), QString::number(byteSize));
                        const SIZE_T characterCount = byteSize / sizeof(wchar_t);
                        const wchar_t* const end = std::find(lockedPointer, lockedPointer + characterCount, L'\0');
                        rawText = QString::fromWCharArray(lockedPointer, static_cast<qsizetype>(end - lockedPointer));
                        ::GlobalUnlock(textHandle);
                    }
                }
                else
                {
                    metadata.note(QStringLiteral("（当前格式不含 CF_UNICODETEXT 文本，仅展示格式列表；位图/文件等二进制格式不在此展开。）"));
                }
            }
            ::CloseClipboard();
        }

        auto* dialog = new QDialog(this);
        dialog->setObjectName(QStringLiteral("ClipboardGuardContentsDialog"));
        dialog->setWindowTitle(QStringLiteral("剪贴板内容"));
        dialog->setStyleSheet(buildOpaqueDialogStyle(dialog->objectName()));
        dialog->resize(720, 480);
        auto* layout = new QVBoxLayout(dialog);
        auto* tabs = new QTabWidget(dialog);
        auto* fields = new ks::ui::StructuredFieldView(tabs);
        fields->setDocument(metadata);
        tabs->addTab(fields, QStringLiteral("属性"));
        auto* raw = new CodeEditorWidget(tabs);
        raw->setReadOnly(true);
        raw->setRawText(rawText);
        tabs->addTab(raw, QStringLiteral("正文"));
        ks::ui::SetDetailTabGroups(tabs, {{ks::ui::DetailNavigationKind::General, {0}},
            {ks::ui::DetailNavigationKind::Content, {1}}});
        layout->addWidget(ks::ui::CreateDetailTabShell(tabs, dialog), 1);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Close, dialog);
        QObject::connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        layout->addWidget(buttons);
        ks::ui::ApplyDetailDialogChrome(dialog);
        dialog->exec();
        dialog->deleteLater();
    }

    void ClipboardGuardPage::showCallStackForSelectedRow()
    {
        const int row = selectedEventRow();
        if (row < 0 || m_eventTable->item(row, ColumnSeq) == nullptr || m_eventTable->item(row, ColumnPid) == nullptr)
        {
            return;
        }
        const quint64 seqValue = m_eventTable->item(row, ColumnSeq)->data(Qt::UserRole).toULongLong();
        const quint32 pidValue = m_eventTable->item(row, ColumnPid)->data(Qt::UserRole).toUInt();

        const QString logPath = QString::fromStdWString(ks::winapi_monitor::joinPath(
            ks::winapi_monitor::buildSessionDirectory(),
            L"clipboard_stacks_" + std::to_wstring(pidValue) + L".log"));

        QString stackText = QStringLiteral("没有找到这一行对应的调用栈记录（可能日志文件已被清理，或这条事件本身没有捕获成功）。");
        QFile logFile(logPath);
        if (logFile.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            const QString fullText = QString::fromUtf8(logFile.readAll());
            const QString markerText = QStringLiteral("[SEQ=%1]").arg(seqValue);
            const int markerIndex = fullText.indexOf(markerText);
            if (markerIndex >= 0)
            {
                const int endIndex = fullText.indexOf(QStringLiteral("=====\r\n"), markerIndex);
                stackText = endIndex >= 0
                    ? fullText.mid(markerIndex, endIndex - markerIndex)
                    : fullText.mid(markerIndex);
            }
            logFile.close();
        }

        CodeEditorWidget* editorPointer = nullptr;
        QDialog* const dialogValue = buildDetailDialog(this, QStringLiteral("调用栈 - 序号 %1").arg(seqValue), QStringLiteral("ClipboardGuardStackDialog"), &editorPointer);
        editorPointer->setRawText(stackText);
        dialogValue->exec();
        dialogValue->deleteLater();
    }
}
