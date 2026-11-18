#include "ProcessDetectionSelector.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/SecondaryPageLayout.h"
#include "../UI/UI_All.h"
#include <QCheckBox>
#include <QDialog>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QFormLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QVBoxLayout>
#include <bit>

namespace ksword::detection
{
    using ks::i18n::sourceText;

    ProcessDetectionSelector::ProcessDetectionSelector(bool deep, QWidget* parent)
        : QPushButton(parent), m_deep(deep), m_selected(Defaults(deep))
    {
        setObjectName(QStringLiteral("process_detection_selector"));
        connect(this, &QPushButton::clicked, this, &ProcessDetectionSelector::edit);
        updateCaption();
    }

    void ProcessDetectionSelector::updateCaption()
    {
        setText(sourceText(QStringLiteral("检测方法（%1）…")).arg(std::popcount(m_selected)));
    }

    void ProcessDetectionSelector::edit()
    {
        auto* dialog = new QDialog(window());
        dialog->setWindowModality(Qt::WindowModal);
        dialog->setAttribute(Qt::WA_DeleteOnClose);
        dialog->setWindowTitle(sourceText(QStringLiteral("选择检测方法")));
        ks::ui::StyleSecondaryWindow(dialog);
        ks::ui::applyResponsiveWindowGeometry(dialog, this, {670, 650}, {360, 320});
        auto* outer = new QVBoxLayout(dialog);
        auto* content = new QWidget(dialog);
        auto* form = new QVBoxLayout(content);
        ks::ui::StyleSecondaryContentLayout(form);
        QVector<QPair<MethodMask, QCheckBox*>> choices;
        const auto catalog = Methods();
        for (const auto cost : {Cost::Fast, Cost::Moderate, Cost::Slow})
        {
            const auto title = cost == Cost::Fast ? sourceText(QStringLiteral("预计较快"))
                : cost == Cost::Moderate ? sourceText(QStringLiteral("预计中等耗时"))
                : sourceText(QStringLiteral("预计较慢"));
            auto* group = new QGroupBox(title, content);
            ks::ui::StyleSecondarySection(group);
            auto* checks = new QVBoxLayout(group);
            for (const auto& method : catalog)
            {
                if (method.cost != cost) continue;
                auto* box = new QCheckBox(sourceText(method.name), group);
                box->setChecked((method.bit & m_selected) != 0);
                choices.append({method.bit, box});
                checks->addWidget(box);
            }
            form->addWidget(group);
        }

        auto* sources = new QGroupBox(sourceText(QStringLiteral("离线取证来源")), content);
        ks::ui::StyleSecondarySection(sources);
        auto* paths = new QFormLayout(sources);
        ks::ui::StyleSecondaryForm(paths);
        auto addPath = [&](const QString& label, const QString& current, bool directory, const QString& filter) {
            auto* row = new QWidget(sources);
            auto* layout = new QHBoxLayout(row);
            layout->setContentsMargins(0, 0, 0, 0);
            auto* edit = new QLineEdit(current, row);
            edit->setClearButtonEnabled(true);
            auto* browse = new QPushButton(sourceText(QStringLiteral("浏览…")), row);
            layout->addWidget(edit, 1);
            layout->addWidget(browse);
            connect(browse, &QPushButton::clicked, dialog, [=]() {
                const auto path = directory ? QFileDialog::getExistingDirectory(dialog, label, edit->text())
                    : QFileDialog::getOpenFileName(dialog, label, edit->text(), filter);
                if (!path.isEmpty()) edit->setText(path);
            });
            paths->addRow(label, row);
            return edit;
        };
        auto* mount = addPath(sourceText(QStringLiteral("MemProcFS 挂载目录")), m_inputs.memProcFsRoot, true, {});
        auto* vol = addPath(sourceText(QStringLiteral("Volatility 3 可执行文件")), m_inputs.volatilityProgram, false, QStringLiteral("*.exe"));
        auto* dump = addPath(sourceText(QStringLiteral("内存镜像")), m_inputs.memoryImage, false, {});
        auto* etl = addPath(sourceText(QStringLiteral("ETW 跟踪文件")), m_inputs.eventTraceFile, false, QStringLiteral("*.etl"));
        auto* flat = addPath(sourceText(QStringLiteral("平坦物理镜像（偏移即物理地址）")), m_inputs.flatPhysicalImage, false, {});
        form->addWidget(sources);
        form->addStretch();
        outer->addWidget(ks::ui::CreateSecondaryFormScroll(content, dialog), 1);
        auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel | QDialogButtonBox::RestoreDefaults, dialog);
        ks::ui::StyleSecondaryButtonBox(buttons);
        outer->addWidget(buttons);
        connect(buttons->button(QDialogButtonBox::RestoreDefaults), &QPushButton::clicked, this, [this, choices]() {
            for (const auto& choice : choices) choice.second->setChecked((Defaults(m_deep) & choice.first) != 0);
        });
        connect(buttons, &QDialogButtonBox::rejected, dialog, &QDialog::reject);
        connect(buttons, &QDialogButtonBox::accepted, dialog, &QDialog::accept);
        connect(dialog, &QDialog::accepted, this, [this, choices, mount, vol, dump, etl, flat]() {
            m_selected = 0;
            for (const auto& choice : choices)
                if (choice.second->isChecked()) m_selected |= choice.first;
            m_inputs.memProcFsRoot = mount->text().trimmed();
            m_inputs.volatilityProgram = vol->text().trimmed();
            m_inputs.memoryImage = dump->text().trimmed();
            m_inputs.eventTraceFile = etl->text().trimmed();
            m_inputs.flatPhysicalImage = flat->text().trimmed();
            updateCaption();
        });
        dialog->open();
    }
}
