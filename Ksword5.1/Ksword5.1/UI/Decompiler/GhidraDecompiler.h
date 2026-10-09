#pragma once

#include <QObject>
#include <QByteArray>
#include <QString>
#include <QVector>
#include <memory>

namespace ks::ui
{
    enum class DecompilerInputKind { RawMemory, PortableExecutable };

    struct DecompilerRequest
    {
        // Always the current captured/staged bytes, never an original file path.
        QByteArray bytes;
        quint64 baseAddress = 0;
        quint64 selectedAddress = 0;
        bool x64 = true;
        DecompilerInputKind inputKind = DecompilerInputKind::RawMemory;
        int timeoutSeconds = 120;
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

    private:
        struct State;
        std::unique_ptr<State> m_state;
        void launch(const DecompilerRequest& request);
        void complete(const QString& error = QString());
        void stopProcess(const QString& reason);
        void collectOutput();
    };
}

Q_DECLARE_METATYPE(ks::ui::DecompilerResult)
