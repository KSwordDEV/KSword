#pragma once

#include <QWidget>
#include <memory>

// Read-only MFT snapshot and USN refresh power the independent file-search page.
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
    void updateButtons();
    void updateUnavailableResults(const char* message);
    void cancelOperations();
    void locateSelected();
};
