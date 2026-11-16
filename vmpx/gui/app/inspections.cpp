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

static QString hexValue(quint64 value)
{
    return "0x" + QString::number(value, 16).toUpper().rightJustified(8, '0');
}

void MainWindow::openFile(const QString& path)
{
    if (runner_->busy())
    {
        appendOutput("Wait for the current operation before changing the executable.");
        return;
    }
    const quint64 revision = ++sessionRevision_;
    const std::wstring native = path.toStdWString();
    ++pendingInspections_;
    statusBar()->showMessage("Reading PE headers, sections and imports…");
    auto* watcher = new QFutureWatcher<QueryResult>(this);
    connect(watcher, &QFutureWatcher<QueryResult>::finished, this,
            [this, watcher, revision, path]
            {
                QueryResult result = watcher->result();
                watcher->deleteLater();
                --pendingInspections_;
                if (revision != sessionRevision_)
                {
                    return;
                }
                if (!result.error.isEmpty())
                {
                    appendOutput(result.error);
                    statusBar()->showMessage(result.error);
                    emit inspectionFinished(false);
                    return;
                }
                if (pid_ && executable_ != QFileInfo(path).absoluteFilePath())
                {
                    pid_ = 0;
                    modeLabel_->setText("No process attached");
                }
                executable_ = QFileInfo(path).absoluteFilePath();
                targetLabel_->setText(QFileInfo(path).fileName() + "  |  " + executable_);
                const vp_file_info& info = result.fileInfo;
                pages_["Overview"]->setRecords(
                    {"Property", "Value"},
                    {{"Executable", executable_},
                     {"File bytes", QString::number(info.file_size)},
                     {"Format", info.magic == 0x20B ? "PE32+" : "PE32"},
                     {"Machine", info.machine == 0x14C    ? "x86"
                                 : info.machine == 0x8664 ? "x64"
                                                          : hexValue(info.machine)},
                     {"Image base", hexValue(info.image_base)},
                     {"Image size", QString::number(info.image_size)},
                     {"Entry RVA", hexValue(info.entry)},
                     {"Entry VA", hexValue(info.image_base + info.entry)},
                     {"Sections", QString::number(info.sections)},
                     {"Import functions", QString::number(result.imports.size())}});
                pages_["Sections"]->setRecords({"#", "Section", "RVA", "Virtual size",
                                                "File offset", "Raw size", "Permissions",
                                                "Entropy"},
                                               result.sections);
                pages_["Imports"]->setRecords({"Module", "Function", "IAT RVA", "Kind"},
                                              result.imports);
                pages_["Overview"]->setMessage(
                    "Original-file metadata. Runtime results are collected separately.");
                pages_["Sections"]->setMessage(
                    "Entropy is measured from up to 8 MiB of file-backed bytes per section.");
                pages_["Imports"]->setMessage(
                    "Static import descriptors from the selected executable.");
                appendOutput("Opened " + executable_ + ": " + QString::number(info.sections) +
                             " sections.");
                statusBar()->showMessage("File inspection complete");
                updateActions();
                emit inspectionFinished(true);
            });
    watcher->setFuture(QtConcurrent::run(
        [native]
        {
            QueryResult result;
            vp_error error{};
            struct Context
            {
                QueryResult* result;
            } context{&result};
            auto sections = [](void* data, const wchar_t* const* cells, size_t count)
            { collectRows(&static_cast<Context*>(data)->result->sections, cells, count); };
            auto imports = [](void* data, const wchar_t* const* cells, size_t count)
            { collectRows(&static_cast<Context*>(data)->result->imports, cells, count); };
            if (vp_inspect_file(native.c_str(), &result.fileInfo, sections, imports, &context,
                                &error) != 0)
            {
                result.error = QString::fromWCharArray(error.message);
            }
            return result;
        }));
}

void MainWindow::attachProcess(quint32 pid, const QString& path)
{
    if (runner_->busy())
    {
        appendOutput("Wait for the current operation before switching process.");
        return;
    }
    QList<QStringList> processes;
    vp_error error{};
    if (vp_processes(collectRows, &processes, &error) != 0)
    {
        appendOutput(QString::fromWCharArray(error.message));
        return;
    }
    bool compatible = false;
    for (const QStringList& process : processes)
    {
        if (process.value(1).toUInt() == pid && process.value(2) == "x86")
        {
            compatible = true;
            break;
        }
    }
    if (!compatible)
    {
        appendOutput(
            "The process exited, is inaccessible, or is not compatible with the x86 worker.");
        return;
    }
    pid_ = pid;
    ++sessionRevision_;
    modeLabel_->setText("PID " + QString::number(pid) + " · read-only inspection");
    if (!path.isEmpty() && path != executable_)
    {
        executable_ = QFileInfo(path).absoluteFilePath();
        openFile(path);
    }
    pid_ = pid;
    modeLabel_->setText("PID " + QString::number(pid) + " · read-only inspection");
    appendOutput("Selected PID " + QString::number(pid) + ". No agent was injected by attach.");
    selectPage("Memory");
    refreshPage("Memory");
    updateActions();
}

void MainWindow::refreshArtifacts()
{
    QList<QStringList> rows;
    QList<QStringList> reports;
    QDirIterator files(artifactDirectory_, QDir::Files, QDirIterator::Subdirectories);
    while (files.hasNext() && rows.size() < 10000)
    {
        QFileInfo file(files.next());
        const QStringList row = {file.fileName(), QString::number(file.size()),
                                 file.lastModified().toString(Qt::ISODate),
                                 file.absoluteFilePath()};
        rows.append(row);
        if (file.suffix() == "txt" || file.suffix() == "json" || file.suffix() == "csv")
        {
            reports.append(row);
        }
    }
    pages_["Artifacts"]->setRecords({"Artifact", "Bytes", "Modified", "Path"}, rows);
    pages_["Analysis"]->setRecords({"Report", "Bytes", "Modified", "Path"}, reports);
}
