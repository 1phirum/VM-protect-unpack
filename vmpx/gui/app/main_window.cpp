#include "main_window.h"
#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QDateTime>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QLabel>
#include <QHBoxLayout>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QRegularExpression>
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QSplitter>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStatusBar>
#include <QVBoxLayout>

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent)
{
    runner_ = new CommandRunner(this);
    QSettings settings;
    artifactDirectory_ =
        settings
            .value("artifacts",
                   QStandardPaths::writableLocation(QStandardPaths::DocumentsLocation) +
                       "/VM protect unpack/artifacts")
            .toString();
    runner_->setWorkerPath(settings.value("worker", runner_->workerPath()).toString());
    buildWindow();
    buildActions();
    updateActions();
    restoreGeometry(settings.value("geometry").toByteArray());
    restoreState(settings.value("windowState").toByteArray());

    connect(runner_, &CommandRunner::output, this,
            [this](const QString& line)
            {
                appendOutput(line);
                const QString command = property("activeCommand").toString();
                if (command == "launch")
                {
                    static const QRegularExpression pidPattern("created pid=(\\d+)");
                    const auto match = pidPattern.match(line);
                    if (match.hasMatch())
                    {
                        launchedPid_ = match.captured(1).toUInt();
                    }
                }
                if (command == "watch" && line.startsWith("EVT "))
                {
                    pages_["Watch"]->model->append(
                        {QDateTime::currentDateTime().toString("HH:mm:ss.zzz"), line});
                }
                if (command == "liveimports")
                {
                    pages_["Imports"]->details->appendPlainText(line);
                    if (line.endsWith(".dll", Qt::CaseInsensitive) && !line.startsWith('['))
                    {
                        liveImportModule_ = line;
                    }
                    else if (!liveImportModule_.isEmpty() && !line.isEmpty() &&
                             !line.startsWith('['))
                    {
                        pages_["Imports"]->model->append({liveImportModule_, line, "Live process"});
                    }
                }
            });
    connect(runner_, &CommandRunner::started, this,
            [this](const QString& command)
            {
                setProperty("activeCommand", command);
                progress_->setRange(0, 0);
                progress_->show();
                statusBar()->showMessage("Running " + command);
                updateActions();
            });
    connect(runner_, &CommandRunner::completed, this,
            [this](const QString& command, int code, bool cancelled)
            {
                progress_->hide();
                const QString result = cancelled ? "Cancelled" : code == 0 ? "Completed" : "Failed";
                appendOutput(command + ": " + result + " · exit code " + QString::number(code));
                pages_["Session log"]->model->append(
                    {QDateTime::currentDateTime().toString(Qt::ISODate), command, result,
                     QString::number(code)});
                statusBar()->showMessage(command + ": " + result);
                refreshArtifacts();
                updateActions();
                if (command == "rebuild" || command == "run")
                {
                    pages_["Artifacts"]->setMessage(
                        command + ": " + result +
                        ". File creation and runtime validation are separate results. See output.");
                }
                if (command == "poke" && code == 0)
                {
                    readMemory();
                }
                if (command == "launch" && launchedPid_)
                {
                    const quint32 launchedPid = launchedPid_;
                    launchedPid_ = 0;
                    attachProcess(launchedPid, executable_);
                }
            });
}

void MainWindow::selectPage(const QString& name)
{
    for (int index = 0; index < navigation_->count(); ++index)
    {
        if (navigation_->item(index)->text() == name)
        {
            navigation_->setCurrentRow(index);
            return;
        }
    }
}

void MainWindow::showPage(const QString& page)
{
    selectPage(page);
}

QString MainWindow::currentPage() const
{
    return navigation_->currentItem() ? navigation_->currentItem()->text() : "Overview";
}

void MainWindow::appendOutput(const QString& text)
{
    output_->appendPlainText(text);
}

void MainWindow::saveScreenshot(const QString& path)
{
    grab().save(path);
}

bool MainWindow::inspectionBusy() const
{
    return pendingInspections_ > 0;
}

int MainWindow::recordCount(const QString& name) const
{
    return pages_.contains(name) ? pages_[name]->model->rowCount() : 0;
}

void MainWindow::closeEvent(QCloseEvent* event)
{
    if (runner_->busy())
    {
        if (QMessageBox::question(this, "Operation running",
                                  "Stop the current operation and close?") != QMessageBox::Yes)
        {
            event->ignore();
            return;
        }
        stopOperation();
    }
    QSettings settings;
    settings.setValue("geometry", saveGeometry());
    settings.setValue("windowState", saveState());
    settings.setValue("artifacts", artifactDirectory_);
    settings.setValue("worker", runner_->workerPath());
    event->accept();
}
