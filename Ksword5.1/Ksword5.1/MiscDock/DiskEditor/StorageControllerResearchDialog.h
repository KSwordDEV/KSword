#pragma once

#include "../../ArkDriverClient/ArkStorageControllerClient.h"
#include "StorageControllerResearchDialogLog.h"

#include <QByteArray>
#include <QWidget>

#include <cstdint>
#include <memory>
#include <vector>

class QLabel;
class QLineEdit;
class QPlainTextEdit;
class CodeEditorWidget;
class QPushButton;
class QTableWidget;
class QShowEvent;

namespace ks::misc
{
    // 保留历史类名，现在作为文件 Tab 的嵌入页面使用。
    class StorageControllerResearchDialog final : public QWidget
    {
    public:
        explicit StorageControllerResearchDialog(QWidget* parent = nullptr);
        ~StorageControllerResearchDialog() override = default;

    protected:
        void showEvent(QShowEvent* event) override;

    private:
        template<typename Work, typename Apply>
        void runOperation(Work work, Apply apply);
        void initializeUi();
        void refreshState();
        void acquireSession();
        void releaseSession();
        void resetController();
        void readRange();
        void writeRange();
        void rollbackRange();
        void refreshAudit();
        void applyQuery(const ksword::ark::StorageControllerQueryResult& result);
        void invalidateQueryState();
        void clearSnapshot();
        bool parseRange(std::uint64_t& offset, std::uint32_t& length) const;
        bool confirmDangerousOperation(const QString& title, const QString& detail);
        void appendLog(const QString& message);
        void updateActionState();
        static QString ownershipText(unsigned long ownership);
        static QString coherencyText(unsigned long coherency);
        static QString riskText(unsigned long flags);
        static QString controllerTypeText(unsigned long type);
        static QString hashText(const unsigned char* hash);

        // 后台共享租约保留句柄直到 IOCTL 完成；页面销毁只断开 watcher，
        // 不会关闭仍有请求执行的设备句柄。
        std::shared_ptr<ksword::ark::ArkStorageControllerClient> m_client;
        std::uint32_t m_capabilities = 0U;
        std::uint32_t m_generation = 0U;
        std::uint32_t m_sectorSize = 0U;
        std::uint32_t m_maximumTransfer = 0U;
        std::uint64_t m_capacity = 0ULL;
        std::uint64_t m_sessionId = 0ULL;
        std::uint64_t m_snapshotOffset = 0ULL;
        std::uint32_t m_snapshotLength = 0U;
        std::uint64_t m_rollbackOffset = 0ULL;
        std::uint32_t m_rollbackLength = 0U;
        bool m_rollbackValid = false;
        bool m_resetRequired = false;
        bool m_resetSupported = false;
        bool m_connected = false;
        bool m_queryValid = false;
        bool m_ready = false;
        bool m_busy = false;
        bool m_confirming = false;
        bool m_initialized = false;
        std::vector<std::uint8_t> m_snapshotHash;
        QLabel* m_riskLabel = nullptr;
        QLabel* m_identityLabel = nullptr;
        QLabel* m_stateLabel = nullptr;
        QLineEdit* m_offsetEdit = nullptr;
        QLineEdit* m_lengthEdit = nullptr;
        QPlainTextEdit* m_hexEdit = nullptr;
        CodeEditorWidget* m_logEdit = nullptr; // 内置只读日志编辑器，跟随全局主题。
        detail::ControllerLogBuffer m_logBuffer; // 限制最后 500 个文本块的原始日志。
        QTableWidget* m_auditTable = nullptr;
        QPushButton* m_refreshButton = nullptr;
        QPushButton* m_auditButton = nullptr;
        QPushButton* m_acquireButton = nullptr;
        QPushButton* m_releaseButton = nullptr;
        QPushButton* m_resetButton = nullptr;
        QPushButton* m_readButton = nullptr;
        QPushButton* m_writeButton = nullptr;
        QPushButton* m_rollbackButton = nullptr;
    };
}
