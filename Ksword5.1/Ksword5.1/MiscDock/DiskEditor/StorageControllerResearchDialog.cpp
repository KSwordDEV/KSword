#include "StorageControllerResearchDialog.h"
#include "../../UI/ToolbarMetrics.h"
#include "../../UI/VisibleTableWidget.h"
#include "StorageControllerInput.h"

#include "../../SettingsDock/AppearanceSettings.h"
#include "../../UI/ThemeStatusRole.h"
#include "../../UI/CodeEditorWidget.h"
#include <QDateTime>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QGridLayout>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QHeaderView>
#include <QLabel>
#include <QLineEdit>
#include <QMessageBox>
#include <QPlainTextEdit>
#include "../../UI/CodeTextEdit.h"
#include <QPushButton>
#include <QPointer>
#include <QScrollArea>
#include <QScrollBar>
#include <QShowEvent>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QVBoxLayout>
#include <QtConcurrent/QtConcurrentRun>

#include <algorithm>
#include <limits>
#include <utility>

namespace ks::misc
{
    StorageControllerResearchDialog::StorageControllerResearchDialog(QWidget* parent)
        : QWidget(parent)
        , m_client(std::make_shared<ksword::ark::ArkStorageControllerClient>())
    {
        initializeUi();
    }

    // 首次显示时异步刷新，避免构造页面即访问设备。
    void StorageControllerResearchDialog::showEvent(QShowEvent* event)
    {
        QWidget::showEvent(event);
        if (!m_initialized)
        {
            m_initialized = true;
            refreshState();
        }
    }

    template<typename Work, typename Apply>
    // 串行执行设备 I/O；共享 client 租约和参数值副本进入后台。
    void StorageControllerResearchDialog::runOperation(Work work, Apply apply)
    {
        if (m_busy || m_confirming) return;
        m_busy = true;
        updateActionState();
        using Result = decltype(work(*m_client));
        auto* watcher = new QFutureWatcher<Result>(this);
        connect(watcher, &QFutureWatcher<Result>::finished, this,
            [this, watcher, apply = std::move(apply)]() mutable
            {
                const auto result = watcher->result();
                watcher->deleteLater();
                m_busy = false;
                apply(result);
                updateActionState();
            });
        // 后台只捕获 client 租约和参数快照，不访问 QWidget 或 LanguageManager。
        watcher->setFuture(QtConcurrent::run(
            [client = m_client, work = std::move(work)]() mutable
            {
                try { return work(*client); }
                catch (...)
                {
                    Result result;
                    result.io.win32Error = ERROR_GEN_FAILURE;
                    return result;
                }
            }));
    }

    // 创建参数、风险说明、审计表与内置日志编辑器。
    void StorageControllerResearchDialog::initializeUi()
    {
        setWindowTitle(QStringLiteral("KSword Controller / 存储控制器"));
        setMinimumSize(0, 0);
        auto* outer = new QVBoxLayout(this);
        outer->setContentsMargins(0, 0, 0, 0);
        auto* scroll = new QScrollArea(this);
        scroll->setWidgetResizable(true);
        auto* content = new QWidget(scroll);
        scroll->setWidget(content);
        outer->addWidget(scroll);
        QVBoxLayout* root = new QVBoxLayout(content);

        m_riskLabel = new QLabel(
            QStringLiteral(
                "持续风险提示：此页直接驱动专用控制器的 BAR、DMA/队列或 IDE task-file。"
                "写入可立即破坏文件系统、分区表和启动数据；控制器重置可使设备离线。"
                "仅允许手动绑定的非启动、无挂载卷控制器。expected-hash 条件比较与写后"
                "复读不是硬件原子操作，不能消除设备并发写、固件缓存或掉电风险。"),
            this);
        m_riskLabel->setWordWrap(true);
        ks::ui::ApplyStatusRole(m_riskLabel, ks::ui::StatusRole::Warning);
        root->addWidget(m_riskLabel);

        QGroupBox* stateGroup = new QGroupBox(QStringLiteral("资源与一致性"), this);
        QVBoxLayout* stateLayout = new QVBoxLayout(stateGroup);
        m_identityLabel = new QLabel(QStringLiteral("控制器：未查询"), stateGroup);
        m_identityLabel->setWordWrap(true);
        m_stateLabel = new QLabel(
            QStringLiteral("ownership=none；coherency=unknown；session=none"),
            stateGroup);
        m_stateLabel->setWordWrap(true);
        stateLayout->addWidget(m_identityLabel);
        stateLayout->addWidget(m_stateLabel);
        root->addWidget(stateGroup);

        QGridLayout* sessionLayout = new QGridLayout();
        m_refreshButton = new QPushButton(QStringLiteral("刷新状态"), this);
        m_acquireButton = new QPushButton(QStringLiteral("取得独占会话"), this);
        m_releaseButton = new QPushButton(QStringLiteral("释放会话"), this);
        m_resetButton = new QPushButton(QStringLiteral("受控复位"), this);
        m_acquireButton->setToolTip(QStringLiteral("取得对该存储控制器的独占访问会话，用于底层 BAR/DMA 操作"));
        m_resetButton->setToolTip(QStringLiteral("对存储控制器执行受控复位（可能使设备暂时离线，操作危险）"));
        m_auditButton = new QPushButton(QStringLiteral("刷新审计"), this);
        sessionLayout->addWidget(m_refreshButton, 0, 0);
        sessionLayout->addWidget(m_acquireButton, 0, 1);
        sessionLayout->addWidget(m_releaseButton, 0, 2);
        sessionLayout->addWidget(m_resetButton, 1, 0);
        sessionLayout->addWidget(m_auditButton, 1, 1);
        // 控制器会话动作是两行栅格，保留布局，只统一动作尺寸与间距。
        sessionLayout->setHorizontalSpacing(8);
        sessionLayout->setVerticalSpacing(8);
        for (QPushButton* button : { m_refreshButton, m_acquireButton, m_releaseButton, m_resetButton, m_auditButton })
        {
            ks::ui::NormalizeToolbarControl(button);
        }
        root->addLayout(sessionLayout);

        QGroupBox* transferGroup = new QGroupBox(QStringLiteral("事务化原始访问"), this);
        QVBoxLayout* transferLayout = new QVBoxLayout(transferGroup);
        QFormLayout* rangeLayout = new QFormLayout();
        m_offsetEdit = new QLineEdit(QStringLiteral("0x0"), transferGroup);
        m_lengthEdit = new QLineEdit(QStringLiteral("0x1000"), transferGroup);
        rangeLayout->addRow(QStringLiteral("字节偏移"), m_offsetEdit);
        rangeLayout->addRow(QStringLiteral("字节长度"), m_lengthEdit);
        transferLayout->addLayout(rangeLayout);
        m_hexEdit = new CodeTextEdit(transferGroup);
        static_cast<CodeTextEdit*>(m_hexEdit)->setSyntaxLanguage(CodeTextEdit::SyntaxLanguage::PlainText);
        m_hexEdit->setPlaceholderText(
            QStringLiteral("读取结果或待写入 HEX，例如：00 11 22 FF"));
        m_hexEdit->setMaximumBlockCount(8192);
        m_hexEdit->setMinimumHeight(160);
        transferLayout->addWidget(m_hexEdit, 1);
        QVBoxLayout* transferButtons = new QVBoxLayout();
        m_readButton = new QPushButton(QStringLiteral("读取并建立条件写快照"), transferGroup);
        m_writeButton = new QPushButton(QStringLiteral("按快照写入并复读验证"), transferGroup);
        m_readButton->setToolTip(QStringLiteral("读取该区间并建立“条件写”比对快照，供后续按快照安全写入"));
        m_writeButton->setToolTip(QStringLiteral("仅当区间内容仍与快照一致时才写入，写完再读回校验，防止误写"));
        m_rollbackButton = new QPushButton(QStringLiteral("回滚最近一次写入"), transferGroup);
        transferButtons->addWidget(m_readButton);
        transferButtons->addWidget(m_writeButton);
        transferButtons->addWidget(m_rollbackButton);
        transferButtons->setSpacing(8);
        ks::ui::NormalizeToolbarControl(m_offsetEdit);
        ks::ui::NormalizeToolbarControl(m_lengthEdit);
        ks::ui::NormalizeToolbarControl(m_readButton);
        ks::ui::NormalizeToolbarControl(m_writeButton);
        ks::ui::NormalizeToolbarControl(m_rollbackButton);
        transferLayout->addLayout(transferButtons);
        root->addWidget(transferGroup, 2);

        m_auditTable = new QTableWidget(this);
        m_auditTable->setColumnCount(7);
        m_auditTable->setHorizontalHeaderLabels({
            QStringLiteral("序号"),
            QStringLiteral("操作"),
            QStringLiteral("偏移"),
            QStringLiteral("长度"),
            QStringLiteral("结果"),
            QStringLiteral("风险"),
            QStringLiteral("进程")
            });
        m_auditTable->horizontalHeader()->setSectionResizeMode(
            QHeaderView::ResizeToContents);
        m_auditTable->setMinimumHeight(160);
        // 事务审计流水已有序号与日志，保留紧凑复制导出。
        ks::ui::SetTableActionBarMode(m_auditTable, ks::ui::TableActionBarMode::Compact);
        root->addWidget(m_auditTable, 1);

        // 内置编辑器负责主题、复制和查找；日志缓冲单独维持 500 块上限。
        m_logEdit = new CodeEditorWidget(this);
        m_logEdit->setObjectName(QStringLiteral("storage_controller_log"));
        m_logEdit->setReadOnly(true);
        m_logEdit->setMaximumHeight(120);
        root->addWidget(m_logEdit);

        connect(m_refreshButton, &QPushButton::clicked, this, [this]() { refreshState(); });
        connect(m_acquireButton, &QPushButton::clicked, this, [this]() { acquireSession(); });
        connect(m_releaseButton, &QPushButton::clicked, this, [this]() { releaseSession(); });
        connect(m_resetButton, &QPushButton::clicked, this, [this]() { resetController(); });
        connect(m_readButton, &QPushButton::clicked, this, [this]() { readRange(); });
        connect(m_writeButton, &QPushButton::clicked, this, [this]() { writeRange(); });
        connect(m_rollbackButton, &QPushButton::clicked, this, [this]() { rollbackRange(); });
        connect(m_auditButton, &QPushButton::clicked, this, [this]() { refreshAudit(); });
        connect(m_offsetEdit, &QLineEdit::textChanged, this, [this]() { updateActionState(); });
        connect(m_lengthEdit, &QLineEdit::textChanged, this, [this]() { updateActionState(); });
        updateActionState();
    }

    // 只查询已绑定的主 ARK 控制器，接口失效后允许下次重新连接。
    void StorageControllerResearchDialog::refreshState()
    {
        runOperation([](ksword::ark::ArkStorageControllerClient& client)
            {
                if (!client.isOpen() && !client.open())
                {
                    ksword::ark::StorageControllerQueryResult result;
                    result.io.win32Error = GetLastError();
                    return result;
                }
                auto result = client.query();
                // Drop a vanished or incompatible interface so manual refresh can
                // enumerate its replacement rather than reusing a dead handle.
                if (!result.io.ok) client.close();
                return result;
            }, [this](const ksword::ark::StorageControllerQueryResult& result)
            {
                applyQuery(result);
            });
    }

    // 清除用户侧原值哈希，后续写入必须重新读取。
    void StorageControllerResearchDialog::clearSnapshot()
    {
        m_snapshotHash.clear();
        m_snapshotOffset = 0ULL;
        m_snapshotLength = 0U;
    }

    // 查询失败后撤销会话、几何和恢复状态，禁止使用旧设备证据。
    void StorageControllerResearchDialog::invalidateQueryState()
    {
        m_queryValid = false;
        m_ready = false;
        m_generation = 0U;
        m_sessionId = 0ULL;
        m_capabilities = 0U;
        m_resetRequired = false;
        m_resetSupported = false;
        m_sectorSize = 0U;
        m_maximumTransfer = 0U;
        m_capacity = 0ULL;
        m_rollbackValid = false;
        clearSnapshot();
    }

    // 验证并显示控制器回执，身份或代次变化时清除旧写入快照。
    void StorageControllerResearchDialog::applyQuery(
        const ksword::ark::StorageControllerQueryResult& result)
    {
        if (!result.io.ok)
        {
            m_connected = false;
            invalidateQueryState();
            m_identityLabel->setText(QStringLiteral("控制器：KswordARK PnP 接口未打开；请先用 KswordARKStorageController.inf 手动绑定专用非启动控制器。"));
            m_stateLabel->setText(
                QStringLiteral("ownership=none；coherency=unknown；无合法 PnP 资源所有权"));
            appendLog(QStringLiteral("状态查询失败：Win32=%1").arg(result.io.win32Error));
            updateActionState();
            return;
        }
        const auto& response = result.response;
        m_connected = true;
        if (m_generation != response.generation || m_sessionId != response.activeSessionId)
        {
            clearSnapshot();
            m_rollbackValid = false;
        }
        const QString bdf =
            response.pciBus == KSWORD_ARK_STORAGE_CONTROLLER_INDEX_UNAVAILABLE
            ? QStringLiteral("unavailable")
            : QStringLiteral("%1:%2.%3")
                .arg(response.pciBus)
                .arg(response.pciDevice)
                .arg(response.pciFunction);
        m_generation = response.generation;
        m_capabilities = response.capabilityFlags;
        m_sessionId = response.activeSessionId;
        m_queryValid = response.generation != 0U &&
            (response.status == KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK ||
             response.status == KSWORD_ARK_STORAGE_CONTROLLER_STATUS_NOT_READY);
        m_ready = m_queryValid && response.status == KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK &&
            response.ownership == KSWORD_ARK_STORAGE_OWNERSHIP_EXCLUSIVE &&
            response.coherency == KSWORD_ARK_STORAGE_COHERENCY_EXCLUSIVE;
        m_sectorSize = response.logicalSectorSize;
        m_maximumTransfer = std::min<std::uint32_t>(response.maximumTransferBytes,
            KSWORD_ARK_STORAGE_CONTROLLER_MAX_TRANSFER_BYTES);
        m_capacity = response.capacityBytes;
        m_resetSupported = response.controllerType == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_NVME;
        m_resetRequired = m_resetSupported &&
            response.status == KSWORD_ARK_STORAGE_CONTROLLER_STATUS_NOT_READY &&
            (response.riskFlags & (
                KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET |
                KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE)) != 0U;
        m_identityLabel->setText(
            QStringLiteral("%1；PCI=%2；型号=%3；序列=%4；容量=%5；扇区=%6；端口/NS=%7")
                .arg(controllerTypeText(response.controllerType))
                .arg(bdf)
                .arg(QString::fromWCharArray(response.model, static_cast<int>(
                    std::find(std::begin(response.model), std::end(response.model), L'\0') - std::begin(response.model))))
                .arg(QString::fromWCharArray(response.serial, static_cast<int>(
                    std::find(std::begin(response.serial), std::end(response.serial), L'\0') - std::begin(response.serial))))
                .arg(static_cast<qulonglong>(response.capacityBytes))
                .arg(response.logicalSectorSize)
                .arg(response.portOrNamespace));
        m_stateLabel->setText(
            QStringLiteral(
                "ownership=%1；coherency=%2；generation=%3；session=0x%4；cap=0x%5；"
                "risk=%6；controller=0x%7；NT=0x%8；%9")
                .arg(ownershipText(response.ownership))
                .arg(coherencyText(response.coherency))
                .arg(response.generation)
                .arg(static_cast<qulonglong>(response.activeSessionId), 0, 16)
                .arg(response.capabilityFlags, 0, 16)
                .arg(riskText(response.riskFlags))
                .arg(response.lastControllerStatus, 0, 16)
                .arg(static_cast<qulonglong>(
                    static_cast<unsigned long>(response.lastStatus)), 0, 16)
                .arg(QString::fromWCharArray(response.detail, static_cast<int>(
                    std::find(std::begin(response.detail), std::end(response.detail), L'\0') - std::begin(response.detail)))));
        updateActionState();
    }

    // 确认危险范围后取得独占会话，再回读当前状态。
    void StorageControllerResearchDialog::acquireSession()
    {
        if (!m_acquireButton->isEnabled()) return;
        if (!confirmDangerousOperation(
                QStringLiteral("取得控制器独占会话"),
                QStringLiteral(
                    "取得会话后命令直接进入 KswordARK.sys 独占拥有的控制器。"
                    "若该控制器承载启动盘或挂载卷，继续可能造成掉盘或数据损坏。")))
        {
            return;
        }
        runOperation([generation = m_generation](ksword::ark::ArkStorageControllerClient& client)
            {
                return client.acquire(generation);
            }, [this](const ksword::ark::StorageControllerControlResult& result)
            {
                if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
                    appendLog(QStringLiteral("取得会话失败：Win32=%1 status=%2 NT=0x%3")
                        .arg(result.io.win32Error).arg(result.response.status)
                        .arg(static_cast<qulonglong>(static_cast<unsigned long>(result.response.lastStatus)), 0, 16));
                invalidateQueryState();
                refreshState();
            });
    }

    // 按会话和代次释放所有权，再回读清除后的状态。
    void StorageControllerResearchDialog::releaseSession()
    {
        if (!m_releaseButton->isEnabled()) return;
        runOperation([generation = m_generation, session = m_sessionId]
            (ksword::ark::ArkStorageControllerClient& client)
            {
                return client.release(generation, session);
            }, [this](const ksword::ark::StorageControllerControlResult& result)
            {
                if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
                    appendLog(QStringLiteral("释放会话失败：Win32=%1 status=%2")
                        .arg(result.io.win32Error).arg(result.response.status));
                invalidateQueryState();
                refreshState();
            });
    }

    // 确认后受控重置 NVMe；复位会让当前会话失效。
    void StorageControllerResearchDialog::resetController()
    {
        if (!m_resetButton->isEnabled()) return;
        if (!confirmDangerousOperation(
                QStringLiteral("受控重置控制器"),
                QStringLiteral(
                    "重置会终止当前硬件队列并使设备短暂离线；未确认写入可能无法恢复。"
                    "重置完成后当前独占会话会失效。")))
        {
            return;
        }
        runOperation([generation = m_generation, session = m_sessionId]
            (ksword::ark::ArkStorageControllerClient& client)
            {
                return client.reset(generation, session);
            }, [this](const ksword::ark::StorageControllerControlResult& result)
            {
                appendLog(QStringLiteral("重置结果：Win32=%1 status=%2 NT=0x%3 risk=%4")
                    .arg(result.io.win32Error).arg(result.response.status)
                    .arg(static_cast<qulonglong>(static_cast<unsigned long>(result.response.lastStatus)), 0, 16)
                    .arg(riskText(result.response.riskFlags)));
                invalidateQueryState();
                refreshState();
            });
    }

    // 解析偏移和长度，拒绝负数、越界及非扇区对齐输入。
    bool StorageControllerResearchDialog::parseRange(
        std::uint64_t& offset,
        std::uint32_t& length) const
    {
        bool offsetOk = false;
        bool lengthOk = false;
        const QString offsetText = m_offsetEdit->text().trimmed();
        const QString lengthText = m_lengthEdit->text().trimmed();
        offset = offsetText.toULongLong(
            &offsetOk,
            offsetText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        length = lengthText.toUInt(
            &lengthOk,
            lengthText.startsWith(QStringLiteral("0x"), Qt::CaseInsensitive) ? 16 : 10);
        return offsetOk && lengthOk && !offsetText.startsWith(QLatin1Char('-')) &&
            !lengthText.startsWith(QLatin1Char('-')) && length != 0U &&
            length <= m_maximumTransfer && m_sectorSize != 0U &&
            offset % m_sectorSize == 0ULL && length % m_sectorSize == 0U &&
            offset <= m_capacity && static_cast<std::uint64_t>(length) <= m_capacity - offset;
    }

    // 按当前会话读取范围并建立后续条件写的原值哈希。
    void StorageControllerResearchDialog::readRange()
    {
        if (!m_readButton->isEnabled()) return;
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        if (!parseRange(offset, length))
        {
            QMessageBox::warning(this, QStringLiteral("控制器研究"), QStringLiteral("偏移或长度无效。"));
            return;
        }
        clearSnapshot();
        runOperation([generation = m_generation, session = m_sessionId, offset, length]
            (ksword::ark::ArkStorageControllerClient& client)
            {
                return client.read(generation, session, offset, length);
            }, [this, offset, length](const ksword::ark::StorageControllerTransferResult& result)
            {
                if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK ||
                    result.bytes.size() != length)
                {
                    appendLog(QStringLiteral("读取失败：Win32=%1 status=%2")
                        .arg(result.io.win32Error).arg(result.response.status));
                    refreshState();
                    return;
                }
                const QByteArray bytes(reinterpret_cast<const char*>(result.bytes.data()),
                    static_cast<qsizetype>(result.bytes.size()));
                m_hexEdit->setPlainText(QString::fromLatin1(bytes.toHex(' ')).toUpper());
                m_snapshotOffset = offset;
                m_snapshotLength = length;
                m_snapshotHash.assign(result.response.afterHash,
                    result.response.afterHash + KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES);
                appendLog(QStringLiteral("读取 %1 字节；expected-hash=%2")
                    .arg(result.bytes.size()).arg(hashText(result.response.afterHash)));
            });
    }

    // 写入前比较原值哈希，展示 flush 和复读验证的真实结果。
    void StorageControllerResearchDialog::writeRange()
    {
        if (!m_writeButton->isEnabled()) return;
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        if (!parseRange(offset, length))
        {
            QMessageBox::warning(this, QStringLiteral("控制器研究"), QStringLiteral("偏移或长度无效。"));
            return;
        }
        std::vector<std::uint8_t> bytes;
        if (!detail::parseControllerHex(m_hexEdit->toPlainText().toStdWString(), length, bytes) ||
            m_snapshotOffset != offset ||
            m_snapshotLength != length ||
            m_snapshotHash.size() != KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES)
        {
            QMessageBox::warning(
                this,
                QStringLiteral("控制器研究"),
                QStringLiteral("写入字节必须与长度一致，并先对完全相同的范围建立条件写快照。"));
            return;
        }
        if (!confirmDangerousOperation(
                QStringLiteral("直接控制器写入"),
                QStringLiteral(
                    "即将绕过 Windows 存储栈写入专用控制器。操作会执行原数据哈希比较、"
                    "写入、flush 和复读验证，但仍可能永久损坏介质内容。")))
        {
            return;
        }
        std::uint32_t writeFlags =
            KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FLUSH;
        if ((m_capabilities &
             KSWORD_ARK_STORAGE_CONTROLLER_CAP_FUA) != 0U)
        {
            writeFlags |= KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_FLAG_FUA;
        }
        runOperation([generation = m_generation, session = m_sessionId, offset,
            bytes = std::move(bytes), hash = m_snapshotHash, writeFlags]
            (ksword::ark::ArkStorageControllerClient& client)
            {
                return client.write(generation, session, offset, bytes, hash, writeFlags);
            }, [this, offset, length, generation = m_generation, session = m_sessionId]
            (const ksword::ark::StorageControllerTransferResult& result)
            {
                appendLog(QStringLiteral("写入结果：Win32=%1 status=%2 bytes=%3 before=%4 after=%5 risk=%6")
                    .arg(result.io.win32Error).arg(result.response.status)
                    .arg(result.response.bytesTransferred).arg(hashText(result.response.beforeHash))
                    .arg(hashText(result.response.afterHash)).arg(riskText(result.response.riskFlags)));
                clearSnapshot();
                const std::uint32_t attemptedGeneration = generation ==
                    std::numeric_limits<std::uint32_t>::max() ? 1U : generation + 1U;
                if (result.io.ok && result.response.generation == attemptedGeneration &&
                    result.response.sessionId == session)
                {
                    // 风险位也可能来自写前拒绝；代次增加才是实际尝试介质 I/O 的回执。
                    m_rollbackValid = true;
                    m_rollbackOffset = offset;
                    m_rollbackLength = length;
                }
                if (result.io.ok && result.response.sessionId == session &&
                    (result.response.generation == generation ||
                     result.response.generation == attemptedGeneration))
                {
                    m_generation = result.response.generation;
                    m_sessionId = result.response.sessionId;
                }
                else invalidateQueryState();
                refreshState();
            });
    }

    // 仅对最近一次写入的相同范围执行条件回滚并回读。
    void StorageControllerResearchDialog::rollbackRange()
    {
        if (!m_rollbackButton->isEnabled()) return;
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        if (!parseRange(offset, length) || offset != m_rollbackOffset || length != m_rollbackLength)
        {
            return;
        }
        if (!confirmDangerousOperation(
                QStringLiteral("回滚控制器写入"),
                QStringLiteral(
                    "回滚本身也是直接写盘。驱动会先确认当前字节仍等于最近写入结果，"
                    "再恢复原始快照并复读验证。")))
        {
            return;
        }
        runOperation([generation = m_generation, session = m_sessionId, offset, length]
            (ksword::ark::ArkStorageControllerClient& client)
            {
                return client.rollback(generation, session, offset, length);
            }, [this, generation = m_generation, session = m_sessionId]
            (const ksword::ark::StorageControllerTransferResult& result)
            {
                appendLog(QStringLiteral("回滚结果：Win32=%1 status=%2 bytes=%3 risk=%4")
                    .arg(result.io.win32Error).arg(result.response.status)
                    .arg(result.response.bytesTransferred).arg(riskText(result.response.riskFlags)));
                clearSnapshot();
                const std::uint32_t attemptedGeneration = generation ==
                    std::numeric_limits<std::uint32_t>::max() ? 1U : generation + 1U;
                if (result.io.ok && result.response.sessionId == session &&
                    (result.response.generation == generation ||
                     result.response.generation == attemptedGeneration))
                {
                    if (result.response.status == KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
                        m_rollbackValid = false;
                    m_generation = result.response.generation;
                    m_sessionId = result.response.sessionId;
                }
                else invalidateQueryState();
                refreshState();
            });
    }

    // 异步读取协议审计行并保持驱动返回顺序。
    void StorageControllerResearchDialog::refreshAudit()
    {
        if (!m_auditButton->isEnabled()) return;
        runOperation([](ksword::ark::ArkStorageControllerClient& client)
        {
            return client.queryAudit();
        }, [this](const ksword::ark::StorageControllerAuditResult& result)
        {
        if (!result.io.ok || result.response.status != KSWORD_ARK_STORAGE_CONTROLLER_STATUS_OK)
        {
            appendLog(QStringLiteral("审计读取失败：Win32=%1 status=%2")
                .arg(result.io.win32Error).arg(result.response.status));
            return;
        }
        m_auditTable->setSortingEnabled(false);
        m_auditTable->setRowCount(static_cast<int>(result.response.rowCount));
        for (unsigned long index = 0U; index < result.response.rowCount; ++index)
        {
            const auto& row = result.response.rows[index];
            const QString operation = row.operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_READ
                ? QStringLiteral("读取")
                : row.operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_WRITE
                    ? QStringLiteral("写入")
                    : row.operation == KSWORD_ARK_STORAGE_CONTROLLER_TRANSFER_ROLLBACK
                        ? QStringLiteral("回滚") : QString::number(row.operation);
            const QStringList values = {
                QString::number(static_cast<qulonglong>(row.sequence)),
                operation,
                QStringLiteral("0x%1").arg(static_cast<qulonglong>(row.offset), 0, 16),
                QString::number(row.length),
                QString::number(row.status),
                riskText(row.riskFlags),
                QString::number(row.processId)
                };
            for (int column = 0; column < values.size(); ++column)
            {
                QTableWidgetItem* item = new QTableWidgetItem(values[column]);
                item->setFlags(item->flags() & ~Qt::ItemIsEditable);
                m_auditTable->setItem(static_cast<int>(index), column, item);
            }
        }
        });
    }

    // 在 GUI 线程确认动作，模态窗口退出后核验页面仍然存活。
    bool StorageControllerResearchDialog::confirmDangerousOperation(
        const QString& title,
        const QString& detail)
    {
        if (ks::settings::dangerousActionConfirmationsSuppressed())
        {
            appendLog(QStringLiteral("重复模态确认已关闭；持续风险提示、确认令牌、expected-hash 和审计仍然生效。"));
            return true;
        }
        QPointer<StorageControllerResearchDialog> guard(this);
        m_confirming = true;
        updateActionState();
        const bool confirmed = QMessageBox::warning(
            this,
            title,
            detail,
            QMessageBox::Yes | QMessageBox::No,
            QMessageBox::No) == QMessageBox::Yes;
        if (!guard) return false;
        m_confirming = false;
        updateActionState();
        return confirmed;
    }

    // 追加带时间戳的原始日志，同时保留块预算和查看位置。
    void StorageControllerResearchDialog::appendLog(const QString& message)
    {
        // 保留用户查看旧日志的位置；只有原来在末尾时才自动跟随新条目。
        auto* textView = m_logEdit->findChild<QPlainTextEdit*>();
        const bool followTail = textView == nullptr ||
            textView->verticalScrollBar()->value() == textView->verticalScrollBar()->maximum();
        const int previousScroll = textView == nullptr ? 0 : textView->verticalScrollBar()->value();
        const QString entry = QStringLiteral("[%1] %2")
            .arg(QDateTime::currentDateTime().toString(QStringLiteral("HH:mm:ss")))
            .arg(message);
        const int discardedBlocks = m_logBuffer.append(entry);
        m_logEdit->setRawText(m_logBuffer.text());
        if (textView != nullptr)
        {
            textView->verticalScrollBar()->setValue(followTail
                ? textView->verticalScrollBar()->maximum()
                : std::max(0, previousScroll - discardedBlocks));
        }
    }

    // 只允许当前状态和能力支持的动作，执行或确认期间禁用参数修改。
    void StorageControllerResearchDialog::updateActionState()
    {
        const bool idle = !m_busy && !m_confirming;
        const bool open = idle && m_connected && m_queryValid;
        const bool session = open && m_sessionId != 0ULL;
        std::uint64_t offset = 0ULL;
        std::uint32_t length = 0U;
        const bool rangeValid = parseRange(offset, length);
        m_refreshButton->setEnabled(idle);
        m_auditButton->setEnabled(open &&
            (m_capabilities & KSWORD_ARK_STORAGE_CONTROLLER_CAP_AUDIT) != 0U);
        m_acquireButton->setEnabled(open && m_ready && !session &&
            (m_capabilities & KSWORD_ARK_STORAGE_CONTROLLER_CAP_EXCLUSIVE) != 0U);
        m_releaseButton->setEnabled(session);
        m_resetButton->setEnabled(open && m_resetSupported && (session || m_resetRequired));
        m_readButton->setEnabled(session && m_ready && rangeValid &&
            (m_capabilities & KSWORD_ARK_STORAGE_CONTROLLER_CAP_READ) != 0U);
        m_writeButton->setEnabled(
            session && m_ready && rangeValid &&
            (m_capabilities & KSWORD_ARK_STORAGE_CONTROLLER_CAP_WRITE) != 0U &&
            (m_capabilities & KSWORD_ARK_STORAGE_CONTROLLER_CAP_WRITE_VERIFY) != 0U &&
            offset == m_snapshotOffset && length == m_snapshotLength &&
            m_snapshotHash.size() == KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES);
        m_rollbackButton->setEnabled(session && m_ready && rangeValid && m_rollbackValid &&
            (m_capabilities & KSWORD_ARK_STORAGE_CONTROLLER_CAP_ROLLBACK) != 0U &&
            offset == m_rollbackOffset && length == m_rollbackLength);
        m_offsetEdit->setEnabled(idle);
        m_lengthEdit->setEnabled(idle);
        m_hexEdit->setReadOnly(!idle);
    }

    // 显示驱动回执的所有权类别，不推断共享控制器可操作。
    QString StorageControllerResearchDialog::ownershipText(const unsigned long ownership)
    {
        if (ownership == KSWORD_ARK_STORAGE_OWNERSHIP_EXCLUSIVE)
        {
            return QStringLiteral("exclusive");
        }
        if (ownership == KSWORD_ARK_STORAGE_OWNERSHIP_SHARED_UNSUPPORTED)
        {
            return QStringLiteral("shared-unsupported");
        }
        return QStringLiteral("none");
    }

    // 显示驱动证明的一致性状态，未知保留 unknown。
    QString StorageControllerResearchDialog::coherencyText(const unsigned long coherency)
    {
        if (coherency == KSWORD_ARK_STORAGE_COHERENCY_EXCLUSIVE)
        {
            return QStringLiteral("exclusive");
        }
        if (coherency == KSWORD_ARK_STORAGE_COHERENCY_UNPROVABLE)
        {
            return QStringLiteral("unprovable");
        }
        return QStringLiteral("unknown");
    }

    // 逐项显示回执风险位，保留未知系统盘和挂载卷边界。
    QString StorageControllerResearchDialog::riskText(const unsigned long flags)
    {
        if (flags == 0U)
        {
            return QStringLiteral("none");
        }
        QStringList rows;
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_SHARED_OWNER) != 0U) rows << QStringLiteral("shared-owner");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_COHERENCY_UNPROVABLE) != 0U) rows << QStringLiteral("coherency-unprovable");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_SYSTEM_DISK) != 0U) rows << QStringLiteral("system-disk");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_LIVE_VOLUMES) != 0U) rows << QStringLiteral("live-volume");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_CONTROLLER_RESET) != 0U) rows << QStringLiteral("controller-reset");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_NO_RECOVERY_GUARANTEE) != 0U) rows << QStringLiteral("recovery-unproven");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_WRITE) != 0U) rows << QStringLiteral("write");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_FORCE_USED) != 0U) rows << QStringLiteral("force-used");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_IDENTITY_CHANGED) != 0U) rows << QStringLiteral("identity-changed");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_BEFORE_MISMATCH) != 0U) rows << QStringLiteral("expected-hash-mismatch");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_VERIFY_FAILED) != 0U) rows << QStringLiteral("verify-failed");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_TIMEOUT) != 0U) rows << QStringLiteral("timeout");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_SYSTEM_DISK_UNKNOWN) != 0U) rows << QStringLiteral("system-disk-unverified");
        if ((flags & KSWORD_ARK_STORAGE_CONTROLLER_RISK_LIVE_VOLUMES_UNKNOWN) != 0U) rows << QStringLiteral("live-volumes-unverified");
        return rows.join(QLatin1Char('|'));
    }

    // 显示控制器后端类型，未识别的值保留 Unknown。
    QString StorageControllerResearchDialog::controllerTypeText(const unsigned long type)
    {
        if (type == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_AHCI) return QStringLiteral("AHCI");
        if (type == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_NVME) return QStringLiteral("NVMe");
        if (type == KSWORD_ARK_STORAGE_CONTROLLER_TYPE_IDE) return QStringLiteral("IDE");
        return QStringLiteral("Unknown");
    }

    // 将固定长度 SHA256 原样显示为十六进制。
    QString StorageControllerResearchDialog::hashText(const unsigned char* hash)
    {
        const QByteArray bytes(
            reinterpret_cast<const char*>(hash),
            KSWORD_ARK_STORAGE_CONTROLLER_HASH_BYTES);
        return QString::fromLatin1(bytes.toHex()).toUpper();
    }
}
