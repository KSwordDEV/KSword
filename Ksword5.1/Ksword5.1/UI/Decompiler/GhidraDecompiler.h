#pragma once

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>
#include <memory>
#include <optional>

namespace ks::ui
{
    enum class DecompilerInputKind { RawMemory, PortableExecutable };

    // 真实阶段来自宿主或本次隔离脚本；没有工作量时保持不定进度。
    enum class DecompilerStage { PreparingSnapshot, StartingRuntime, Importing, Analyzing,
        LocatingFunction, Decompiling, Rendering };
    struct DecompilerProgress
    {
        DecompilerStage stage = DecompilerStage::PreparingSnapshot;
        qint64 completedUnits = -1;    // 仅在脚本知道实际工作量时填写。
        qint64 totalUnits = -1;        // 当前阶段总量，未知时为 -1。
    };

    struct DecompilerMemorySegment
    {
        quint64 address = 0;
        QByteArray bytes;
        bool operator==(const DecompilerMemorySegment& other) const
        {
            return address == other.address && bytes == other.bytes;
        }
    };

    struct DecompilerAddressRange
    {
        quint64 address = 0;
        quint64 length = 0;
        bool operator==(const DecompilerAddressRange& other) const
        {
            return address == other.address && length == other.length;
        }
    };

    struct DecompilerRequest
    {
        // Always the current captured/staged bytes, never an original file path.
        QByteArray bytes;
        quint64 baseAddress = 0;
        quint64 selectedAddress = 0;
        bool x64 = true;
        DecompilerInputKind inputKind = DecompilerInputKind::RawMemory;
        int timeoutSeconds = 120;
        // Nonempty segments select a frozen sparse RAW plan. Every segment byte
        // is captured evidence; bodyRanges contain only planned instruction bytes.
        std::optional<quint64> entryAddress;
        QVector<DecompilerMemorySegment> segments;
        QVector<DecompilerAddressRange> bodyRanges;
    };

    struct DecompilerResult
    {
        bool success = false;
        QString code;
        // Stable machine code; the owning UI translates it.
        QString error;
        QString diagnostics;
        QString functionName;
        quint64 functionAddress = 0;
        // VA per displayed C line, with validity separate so address 0 works.
        QVector<quint64> lineAddresses;
        QVector<bool> lineAddressValid;
        QByteArray snapshotSha256;
        bool boundaryInferred = false;
        bool rawControlFlow = false;
        quint32 decodedInstructions = 0;
        quint64 capturedBytes = 0;
    };

    // Asynchronous, isolated external Ghidra headless adapter. Does not execute
    // the supplied executable and does not write the source memory/file.
    class GhidraDecompiler final : public QObject
    {
        Q_OBJECT
    public:
        explicit GhidraDecompiler(QObject* parent = nullptr);
        ~GhidraDecompiler() override;
        bool start(const DecompilerRequest& request);
        void cancel();
        bool isRunning() const;
        QString ghidraDirectory() const;
        void setGhidraDirectory(const QString& directory);
        static QString findGhidraDirectory();
        static QString installedPluginDirectory();

        static constexpr qsizetype MaximumRawBytes = 16 * 1024 * 1024;
        static constexpr qsizetype MaximumPeBytes = 64 * 1024 * 1024;

    signals:
        void finished(const ks::ui::DecompilerResult& result);
        void runningChanged(bool running);
        void progressChanged(const ks::ui::DecompilerProgress& progress);

    private:
        struct State;
        std::unique_ptr<State> m_state;
        void launch(const DecompilerRequest& request);
        void launchProcess(const QString& java, const QStringList& arguments, int seconds);
        void publishResult(DecompilerResult result, quint64 revision);
        void complete(const QString& error = QString());
        void stopProcess(const QString& reason);
        void collectOutput();
        bool publishProgress(DecompilerStage stage, qint64 completed = -1, qint64 total = -1);
    };
}

Q_DECLARE_METATYPE(ks::ui::DecompilerResult)
Q_DECLARE_METATYPE(ks::ui::DecompilerProgress)
