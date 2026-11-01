#pragma once

#include <QWidget>
#include <memory>

// Shared read-only MFT snapshot powers both search and disk-space views.
class NtfsSearchPage final : public QWidget
{
    Q_OBJECT
public:
    explicit NtfsSearchPage(QWidget* parent = nullptr);
    ~NtfsSearchPage() override;

signals:
    void locatePathRequested(const QString& path);

protected:
    void changeEvent(QEvent* event) override;

private:
    struct State;
    std::unique_ptr<State> m_state;
    void discoverVolumes();
    void startIndex(bool incremental);
    void startSearch();
    bool hasSelectedVolumeIndex() const;
    void showDirectory(quint64 reference);
    void updateButtons();
    void updateUnavailableResults(const char* message);
    void cancelOperations();
    void restoreSpaceDirectory();
    void locateSelected();
};
