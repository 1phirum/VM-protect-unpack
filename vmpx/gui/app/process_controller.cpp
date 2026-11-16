#include "main_window.h"
#include "query_result.h"
#include <QDateTime>
#include <QDirIterator>
#include <QFile>
#include <QFileInfo>
#include <QFutureWatcher>
#include <QLabel>
#include <QSpinBox>
#include <QStatusBar>
#include <QtConcurrent>

void MainWindow::refreshPage(const QString& name)
{
    if (name == "Overview" || name == "Sections" || name == "Imports")
    {
        if (!executable_.isEmpty())
        {
            openFile(executable_);
        }
        return;
    }
    if (name == "Artifacts" || name == "Analysis")
    {
        refreshArtifacts();
        return;
    }
    if (name == "Hex editor")
    {
        readMemory();
        return;
    }
    const QMap<QString, int> views = {{"Modules", 1}, {"Memory", 2}, {"Windows", 3}, {"Agent", 4}};
    if (!views.contains(name))
    {
        return;
    }
    if (!pid_)
    {
        pages_[name]->setMessage("Attach to an accessible x86 process to collect this view.");
        return;
    }
    const quint32 pid = pid_;
    const quint64 revision = sessionRevision_;
    const int view = views[name];
    ++pendingInspections_;
    pages_[name]->setMessage("Reading process data…");
    auto* watcher = new QFutureWatcher<QueryResult>(this);
    connect(
        watcher, &QFutureWatcher<QueryResult>::finished, this,
        [this, watcher, name, revision]
        {
            QueryResult result = watcher->result();
            watcher->deleteLater();
            --pendingInspections_;
            if (revision != sessionRevision_)
            {
                return;
            }
            const QMap<QString, QStringList> headers = {
                {"Modules", {"Module", "Base address", "Size (bytes)", "Path"}},
                {"Memory",
                 {"Base address", "End address", "Size (bytes)", "State", "Type", "Protection"}},
                {"Windows", {"HWND", "Title", "Class", "Visible", "State"}},
                {"Agent", {"Property", "Value"}}};
            pages_[name]->setRecords(headers[name], result.sections);
            pages_[name]->setMessage(result.error.isEmpty()
                                         ? "Collected from PID " + QString::number(pid_)
                                         : result.error);
            if (!result.error.isEmpty())
            {
                appendOutput(result.error);
            }
        });
    watcher->setFuture(QtConcurrent::run(
        [pid, view]
        {
            QueryResult result;
            vp_error error{};
            if (vp_process_inspect(pid, view, collectRows, &result.sections, &error) != 0)
            {
                result.error = QString::fromWCharArray(error.message);
            }
            return result;
        }));
}
