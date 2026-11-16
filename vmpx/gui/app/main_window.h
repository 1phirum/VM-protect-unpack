#pragma once

#include <QMainWindow>
#include <QMap>
#include "command_runner.h"
#include "inspector_page.h"

class MainWindow final : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget* parent = nullptr);
    void openFile(const QString& path);
    void attachProcess(quint32 pid, const QString& path);
    void saveScreenshot(const QString& path);
    void showPage(const QString& page);
    bool inspectionBusy() const;
    int recordCount(const QString& page) const;

signals:
    void inspectionFinished(bool success);

protected:
    void closeEvent(class QCloseEvent* event) override;

private:
    CommandRunner* runner_;
    class QListWidget* navigation_;
    class QStackedWidget* stack_;
    class QLabel* targetLabel_;
    class QLabel* modeLabel_;
    class QPlainTextEdit* output_;
    class QLineEdit* address_;
    class QSpinBox* readSize_;
    class QProgressBar* progress_;
    QMap<QString, InspectorPage*> pages_;
    QMap<QString, class QAction*> actions_;
    QMap<QString, QList<class QAction*>> operationActions_;
    QString executable_;
    QString artifactDirectory_;
    quint32 pid_ = 0;
    quint64 sessionRevision_ = 0;
    int pendingInspections_ = 0;
    QString liveImportModule_;
    quint32 launchedPid_ = 0;

    void buildWindow();
    void buildActions();
    void updateActions();
    void selectPage(const QString& page);
    QString currentPage() const;
    void refreshPage(const QString& page);
    void refreshArtifacts();
    void readMemory();
    void runOperation(const QString& command);
    void chooseProcess();
    void showSettings();
    void exportLog();
    void stopOperation();
    void appendOutput(const QString& text);
};
