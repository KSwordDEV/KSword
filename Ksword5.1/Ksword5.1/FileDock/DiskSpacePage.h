#pragma once

#include <QWidget>
#include <memory>

// Independent, explicitly started disk/folder analysis. Both scan sources
// publish an immutable directory snapshot to the same presentation.
class DiskSpacePage final : public QWidget
{
    Q_OBJECT
public:
    explicit DiskSpacePage(QWidget* parent = nullptr);
    ~DiskSpacePage() override;
signals:
    void locatePathRequested(const QString& path);
protected:
    void changeEvent(QEvent* event) override;
private:
    struct State;
    std::unique_ptr<State> m_state;
    void startScan();
    void cancelOperations();
    void updateButtons();
    void restoreSpaceDirectory();
    void showDirectory(quint64 reference);
    void loadDirectoryExtensions(quint64 reference, bool allocated);
};
