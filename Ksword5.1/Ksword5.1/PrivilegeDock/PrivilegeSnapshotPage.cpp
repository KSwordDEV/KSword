#include "PrivilegeSnapshotPage.h"
#include "../UI/PageControlStyle.h"
#include "../UI/ToolbarMetrics.h"
#include "PrivilegeSnapshotModel.h"
#include "PrivilegeAccountPages.h"
#include "PrivilegeTokenPages.h"
#include "../Internationalization/LanguageManager.h"
#include "../UI/VisibleTableWidget.h"
#include "../theme.h"

#include <QApplication>
#include <QCheckBox>
#include <QClipboard>
#include <QDateTime>
#include <QFile>
#include <QFileDialog>
#include <QFutureWatcher>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPromise>
#include <QPushButton>
#include <QPointer>
#include <QRunnable>
#include <QSaveFile>
#include <QSpinBox>
#include <QThreadPool>
#include <QVBoxLayout>

#include <climits>
#include <memory>

#include <Windows.h>

namespace ks::privilege
{
    namespace
    {
        QString snapshotText(const QString& source) { return ks::i18n::sourceText(source); }

        QJsonObject capture(DWORD pid, bool includeToken)
        {
            wchar_t computer[MAX_COMPUTERNAME_LENGTH + 1]{};
            DWORD length = MAX_COMPUTERNAME_LENGTH + 1;
            const bool knownComputer = GetComputerNameW(computer, &length) != FALSE;
            const DWORD computerError = knownComputer ? ERROR_SUCCESS : GetLastError();
            QJsonObject policy = captureAccountPolicySnapshot();
            if (!knownComputer)
            {
                QJsonArray errors = policy.value(QStringLiteral("errors")).toArray();
                errors.append(QStringLiteral("GetComputerNameW: %1").arg(computerError));
                policy.insert(QStringLiteral("errors"), errors);
            }
            QJsonObject token{{QStringLiteral("entries"), QJsonArray{}}, {QStringLiteral("errors"), QJsonArray{}}};
            if (includeToken) token = captureTokenSnapshot(pid);
            return QJsonObject{
                {QStringLiteral("schema"), QStringLiteral("ksword.permission.snapshot")},
                {QStringLiteral("version"), 1},
                {QStringLiteral("computer"), knownComputer ? QString::fromWCharArray(computer) : QStringLiteral("unknown")},
                {QStringLiteral("capturedUtc"), QDateTime::currentDateTimeUtc().toString(Qt::ISODateWithMs)},
                {QStringLiteral("tokenIncluded"), includeToken},
                {QStringLiteral("policy"), policy}, {QStringLiteral("token"), token}};
        }

        class SnapshotPage final : public QWidget
        {
        public:
            explicit SnapshotPage(QWidget* parent) : QWidget(parent)
            {
                setObjectName(QStringLiteral("privilege_snapshot_page"));
                auto* layout = new QVBoxLayout(this);
                auto* selectors = new QHBoxLayout;
                m_includeToken = new QCheckBox(snapshotText(QStringLiteral("包含所选进程令牌")), this);
                m_includeToken->setChecked(true);
                m_pid = new QSpinBox(this);
                m_pid->setRange(1, INT_MAX);
                m_pid->setValue(static_cast<int>(GetCurrentProcessId()));
                selectors->addWidget(m_includeToken);
                selectors->addWidget(new QLabel(QStringLiteral("PID"), this));
                selectors->addWidget(m_pid);
                selectors->addStretch();
                ks::ui::NormalizeToolbarRow(selectors);
                layout->addLayout(selectors);
                auto* toolbar = new QHBoxLayout;
                addButton(toolbar, snapshotText(QStringLiteral("采集设为基线")), [this] { startCapture(true); });
                addButton(toolbar, snapshotText(QStringLiteral("采集当前并对比")), [this] { startCapture(false); });
                addButton(toolbar, snapshotText(QStringLiteral("加载基线")), [this] { load(true); });
                addButton(toolbar, snapshotText(QStringLiteral("加载当前")), [this] { load(false); });
                toolbar->addStretch();
                ks::ui::NormalizeToolbarRow(toolbar);
                layout->addLayout(toolbar);
                auto* saveBar = new QHBoxLayout;
                addButton(saveBar, snapshotText(QStringLiteral("保存基线")), [this] { save(m_baseline); });
                addButton(saveBar, snapshotText(QStringLiteral("保存当前")), [this] { save(m_current); });
                addButton(saveBar, snapshotText(QStringLiteral("复制当前差异")), [this] { copyCurrentRow(); });
                m_search = new QLineEdit(this);
                m_search->setPlaceholderText(snapshotText(QStringLiteral("筛选条目、原值或现值")));
                ks::ui::StyleSearchField(m_search);
                saveBar->addWidget(m_search, 1);
                ks::ui::NormalizeToolbarRow(saveBar);
                layout->addLayout(saveBar);
                auto* explanation = new QLabel(snapshotText(QStringLiteral("手动采集账号状态、组成员、直接权限分配与令牌字段。采集不完整时，缺失条目标为无法确认；快照仅用于比较。")), this);
                explanation->setWordWrap(true);
                layout->addWidget(explanation);
                m_status = new QLabel(snapshotText(QStringLiteral("尚未设置基线。")), this);
                m_status->setWordWrap(true);
                layout->addWidget(m_status);
                m_table = new ks::ui::VisibleTableWidget(this);
                // 页面已有完整基线/当前比较和保存功能，不再叠加通用快照操作栏。
                ks::ui::SetTableActionBarMode(m_table, ks::ui::TableActionBarMode::None);
                m_table->setColumnCount(4);
                m_table->setHorizontalHeaderLabels({snapshotText(QStringLiteral("变化")), snapshotText(QStringLiteral("条目")), snapshotText(QStringLiteral("原值")), snapshotText(QStringLiteral("现值"))});
                m_table->setEditTriggers(QAbstractItemView::NoEditTriggers);
                m_table->setSelectionBehavior(QAbstractItemView::SelectRows);
                m_table->horizontalHeader()->setSectionResizeMode(QHeaderView::Interactive);
                m_table->horizontalHeader()->setStretchLastSection(true);
                layout->addWidget(m_table, 1);
                connect(m_search, &QLineEdit::textChanged, this, [this] { filter(); });
            }

        private:
            template<typename Callback>
            void addButton(QHBoxLayout* bar, const QString& text, Callback callback)
            {
                auto* button = new QPushButton(text, this);
                button->setStyleSheet(KswordTheme::ThemedButtonStyle());
                bar->addWidget(button);
                m_buttons.push_back(button);
                connect(button, &QPushButton::clicked, this, callback);
            }

            void setBusy(bool busy)
            {
                for (auto* button : m_buttons) button->setEnabled(!busy);
                m_pid->setEnabled(!busy);
                m_includeToken->setEnabled(!busy);
            }

            void startCapture(bool baseline)
            {
                setBusy(true);
                m_status->setText(snapshotText(QStringLiteral("正在采集权限快照…")));
                const DWORD pid = static_cast<DWORD>(m_pid->value());
                const bool includeToken = m_includeToken->isChecked();
                auto promise = std::make_shared<QPromise<QJsonObject>>();
                promise->start();
                auto* watcher = new QFutureWatcher<QJsonObject>(this);
                connect(watcher, &QFutureWatcher<QJsonObject>::finished, this, [this, watcher, baseline] {
                    QJsonObject result;
                    try { result = watcher->result(); }
                    catch (const std::exception& exception)
                    {
                        watcher->deleteLater(); setBusy(false);
                        m_status->setText(snapshotText(QStringLiteral("权限快照采集失败：%1")).arg(QString::fromUtf8(exception.what())));
                        return;
                    }
                    watcher->deleteLater();
                    setBusy(false);
                    QString error;
                    if (!validatePermissionSnapshot(result, &error)) { m_status->setText(error); return; }
                    if (baseline) m_baseline = result; else m_current = result;
                    render();
                });
                watcher->setFuture(promise->future());
                QThreadPool::globalInstance()->start(QRunnable::create([promise, pid, includeToken] {
                    try { promise->addResult(capture(pid, includeToken)); }
                    catch (...) { promise->setException(std::current_exception()); }
                    promise->finish();
                }));
            }

            void render()
            {
                m_table->setRowCount(0);
                QStringList diagnostics;
                for (const QJsonObject& snapshot : {m_baseline, m_current})
                    for (const QString& section : {QStringLiteral("policy"), QStringLiteral("token")})
                        for (const QJsonValue& error : snapshot.value(section).toObject().value(QStringLiteral("errors")).toArray())
                            diagnostics.push_back(error.toString());
                diagnostics.removeDuplicates();
                if (m_baseline.isEmpty() || m_current.isEmpty())
                {
                    m_status->setText((m_baseline.isEmpty() ? snapshotText(QStringLiteral("尚未设置基线。")) : snapshotText(QStringLiteral("基线已设置，请采集或加载当前快照。")))
                        + (diagnostics.isEmpty() ? QString() : QLatin1Char('\n') + diagnostics.join(QLatin1Char('\n'))));
                    return;
                }
                if (m_baseline.value(QStringLiteral("tokenIncluded")) != m_current.value(QStringLiteral("tokenIncluded")))
                {
                    m_status->setText(snapshotText(QStringLiteral("两份快照的令牌采集选项不同，请使用相同选项重新采集。")));
                    return;
                }
                QString error;
                const auto changes = comparePermissionSnapshots(m_baseline, m_current, &error);
                if (!error.isEmpty()) { m_status->setText(error); return; }
                m_table->setRowCount(static_cast<int>(changes.size()));
                int row = 0;
                for (const SnapshotDifference& change : changes)
                {
                    QString kind;
                    switch (change.kind)
                    {
                    case SnapshotDifference::Kind::Added: kind = snapshotText(QStringLiteral("新增")); break;
                    case SnapshotDifference::Kind::Removed: kind = snapshotText(QStringLiteral("移除")); break;
                    case SnapshotDifference::Kind::Modified: kind = snapshotText(QStringLiteral("修改")); break;
                    case SnapshotDifference::Kind::Enabled: kind = snapshotText(QStringLiteral("启用")); break;
                    case SnapshotDifference::Kind::Disabled: kind = snapshotText(QStringLiteral("禁用")); break;
                    case SnapshotDifference::Kind::Uncertain: kind = snapshotText(QStringLiteral("无法确认")); break;
                    }
                    const QStringList fields{kind, change.key, change.before, change.after};
                    for (int col = 0; col < fields.size(); ++col)
                        m_table->setItem(row, col, new QTableWidgetItem(fields[col]));
                    ++row;
                }
                m_status->setText(snapshotText(QStringLiteral("共 %1 项差异。基线：%2；当前：%3"))
                    .arg(changes.size()).arg(m_baseline.value(QStringLiteral("capturedUtc")).toString())
                    .arg(m_current.value(QStringLiteral("capturedUtc")).toString())
                    + (diagnostics.isEmpty() ? QString() : QLatin1Char('\n') + diagnostics.join(QLatin1Char('\n'))));
                filter();
            }

            void filter()
            {
                const QString needle = m_search->text();
                for (int row = 0; row < m_table->rowCount(); ++row)
                {
                    bool match = needle.isEmpty();
                    for (int col = 0; col < m_table->columnCount(); ++col)
                        if (const auto* item = m_table->item(row, col)) match |= item->text().contains(needle, Qt::CaseInsensitive);
                    m_table->setRowHidden(row, !match);
                }
            }

            void save(const QJsonObject& snapshot)
            {
                if (snapshot.isEmpty()) { m_status->setText(snapshotText(QStringLiteral("请先采集或加载快照。"))); return; }
                const QPointer<QWidget> pageGuard(this);
                const QString path = QFileDialog::getSaveFileName(this, snapshotText(QStringLiteral("保存权限快照")), QString(), QStringLiteral("JSON (*.json)"));
                if (!pageGuard) return;
                if (path.isEmpty()) return;
                QSaveFile file(path);
                const QByteArray data = QJsonDocument(snapshot).toJson(QJsonDocument::Indented);
                if (!file.open(QIODevice::WriteOnly) || file.write(data) != data.size() || !file.commit())
                    m_status->setText(snapshotText(QStringLiteral("保存失败：%1")).arg(file.errorString()));
                else m_status->setText(snapshotText(QStringLiteral("快照已保存：%1")).arg(path));
            }

            void load(bool baseline)
            {
                const QPointer<QWidget> pageGuard(this);
                const QString path = QFileDialog::getOpenFileName(this, snapshotText(QStringLiteral("加载权限快照")), QString(), QStringLiteral("JSON (*.json)"));
                if (!pageGuard) return;
                if (path.isEmpty()) return;
                QFile file(path);
                if (!file.open(QIODevice::ReadOnly) || file.size() > 64 * 1024 * 1024)
                { m_status->setText(snapshotText(QStringLiteral("快照无法读取或超过 64 MiB。"))); return; }
                const QByteArray bytes = file.read(64 * 1024 * 1024 + 1);
                if (bytes.size() > 64 * 1024 * 1024 || file.error() != QFileDevice::NoError)
                { m_status->setText(snapshotText(QStringLiteral("快照无法读取或超过 64 MiB。"))); return; }
                QJsonParseError parseError;
                const QJsonDocument document = QJsonDocument::fromJson(bytes, &parseError);
                QString error;
                if (parseError.error != QJsonParseError::NoError || !document.isObject()
                    || !validatePermissionSnapshot(document.object(), &error))
                { m_status->setText(error.isEmpty() ? snapshotText(QStringLiteral("快照 JSON 格式无效。")) : error); return; }
                if (baseline) m_baseline = document.object(); else m_current = document.object();
                render();
            }

            void copyCurrentRow()
            {
                const int row = m_table->currentRow();
                if (row < 0) return;
                QStringList fields;
                for (int col = 0; col < m_table->columnCount(); ++col)
                    fields.append(m_table->item(row, col) ? m_table->item(row, col)->text() : QString());
                QApplication::clipboard()->setText(fields.join(QLatin1Char('\t')));
            }

            QJsonObject m_baseline, m_current;
            QVector<QPushButton*> m_buttons;
            QCheckBox* m_includeToken = nullptr;
            QSpinBox* m_pid = nullptr;
            QLineEdit* m_search = nullptr;
            QLabel* m_status = nullptr;
            QTableWidget* m_table = nullptr;
        };
    }

    QWidget* createPermissionSnapshotPage(QWidget* parent) { return new SnapshotPage(parent); }
}
