#include "main_window.h"
#include "operation_dialog.h"
#include "process_dialog.h"
#include "inspection.h"
#include "ui_icons.h"
#include <QAction>
#include <QCoreApplication>
#include <QDesktopServices>
#include <QDialogButtonBox>
#include <QFile>
#include <QFileDialog>
#include <QFormLayout>
#include <QLabel>
#include <QMenuBar>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QPushButton>
#include <QSettings>
#include <QStatusBar>
#include <QToolBar>
#include <QUrl>
#include <QVBoxLayout>

void MainWindow::buildActions()
{
    auto* file = menuBar()->addMenu("&File");
    auto* edit = menuBar()->addMenu("&Edit");
    auto* view = menuBar()->addMenu("&View");
    auto* capture = menuBar()->addMenu("&Capture");
    auto* tools = menuBar()->addMenu("&Tools");
    auto* help = menuBar()->addMenu("&Help");
    auto* toolbar = addToolBar("Main tools");
    toolbar->setObjectName("MainToolbar");
    toolbar->setMovable(false);
    toolbar->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toolbar->setIconSize(QSize(18, 18));

    auto create = [this](QMenu* menu, const QString& key, const QString& label, const QString& icon,
                         const QKeySequence& shortcut, const std::function<void()>& handler)
    {
        auto* action = new QAction(UiIcons::named(icon), label, this);
        action->setShortcut(shortcut);
        menu->addAction(action);
        actions_[key] = action;
        action->setObjectName("action-" + key);
        connect(action, &QAction::triggered, this, handler);
        return action;
    };

    toolbar->addAction(create(file, "open", "Open file…", "open", QKeySequence::Open,
                              [this]
                              {
                                  QString path = QFileDialog::getOpenFileName(
                                      this, "Open executable", {},
                                      "Executable (*.exe *.dll);;All files (*)");
                                  if (!path.isEmpty())
                                  {
                                      openFile(path);
                                  }
                              }));
    create(file, "launch", "Launch target…", "launch", {}, [this] { runOperation("launch"); });
    toolbar->addAction(
        create(file, "attach", "Attach…", "attach", {}, [this] { chooseProcess(); }));
    create(file, "export", "Export session output…", "save", QKeySequence("Ctrl+Shift+S"),
           [this] { exportLog(); });
    create(file, "detach", "Detach process", "unplug", {},
           [this]
           {
               pid_ = 0;
               ++sessionRevision_;
               modeLabel_->setText("No process attached");
               for (const QString name : {"Modules", "Memory", "Windows", "Agent", "Hex editor"})
               {
                   pages_[name]->setRecords({}, {});
                   pages_[name]->setMessage("No process attached.");
               }
               updateActions();
           });
    file->addSeparator();
    create(file, "exit", "Exit", "x", QKeySequence::Quit, [this] { close(); });
    create(edit, "filter", "Filter current table", "search", QKeySequence::Find,
           [this] { pages_[currentPage()]->focusFilter(); });
    create(edit, "write", "Write memory…", "edit", {}, [this] { runOperation("poke"); });
    create(edit, "settings", "Workspace settings…", "settings", QKeySequence("Ctrl+,"),
           [this] { showSettings(); });

    for (const QString& name : pages_.keys())
    {
        create(view, "view-" + name, name, UiIcons::pageName(name), {},
               [this, name]
               {
                   selectPage(name);
                   refreshPage(name);
               });
    }
    create(view, "refresh", "Refresh", "refresh", QKeySequence("F5"),
           [this] { refreshPage(currentPage()); });
    toolbar->addSeparator();
    const QList<QPair<QString, QString>> operations = {{"dump", "Dump…"},
                                                       {"snap", "Save snapshot…"},
                                                       {"oep", "Entry capture…"},
                                                       {"watch", "Watch…"}};
    for (const auto& operation : operations)
    {
        auto* action = create(capture, operation.first, operation.second,
                              UiIcons::operationName(operation.first), {},
                              [this, command = operation.first] { runOperation(command); });
        if (operation.first == "dump" || operation.first == "watch")
        {
            toolbar->addAction(action);
        }
    }
    toolbar->addAction(create(capture, "stop", "Stop", "stop", {}, [this] { stopOperation(); }));
    create(tools, "memmap", "Memory map options…", "settings-2", {},
           [this] { runOperation("memmap"); });
    for (const auto& operation :
         QList<QPair<QString, QString>>{{"inject", "Load agent DLL…"},
                                        {"liveimports", "Inspect live imports…"},
                                        {"rebuild", "Rebuild PE image…"},
                                        {"run", "Validate reconstructed image…"},
                                        {"deobf", "Offline analysis…"}})
    {
        auto* action = create(tools, operation.first, operation.second,
                              UiIcons::operationName(operation.first), {},
                              [this, command = operation.first] { runOperation(command); });
        if (operation.first == "rebuild")
        {
            toolbar->addAction(action);
        }
    }
    create(help, "about", "About VM protect unpack", "circle-question-mark", {},
           [this]
           {
               QMessageBox::about(this, "VM protect unpack",
                                  "Qt 6 Widgets desktop interface with the existing C backend.\n"
                                  "Built by Olivia — https://discord.gg/ojailbreaks");
           });
}

void MainWindow::updateActions()
{
    const bool busy = runner_->busy();
    for (auto iterator = actions_.begin(); iterator != actions_.end(); ++iterator)
    {
        iterator.value()->setEnabled(!busy);
    }
    for (const QString key : {"dump", "snap", "oep", "watch", "inject", "liveimports", "rebuild",
                              "write", "detach", "memmap"})
    {
        actions_[key]->setEnabled(pid_ != 0 && !busy);
    }
    actions_["launch"]->setEnabled(!executable_.isEmpty() && !busy);
    actions_["stop"]->setEnabled(busy);
    actions_["export"]->setEnabled(true);
    actions_["about"]->setEnabled(true);
    actions_["exit"]->setEnabled(true);
    for (auto iterator = operationActions_.begin(); iterator != operationActions_.end(); ++iterator)
    {
        const QString key = iterator.key();
        const bool enabled = key == "read"            ? pid_ != 0 && !busy
                             : actions_.contains(key) ? actions_[key]->isEnabled()
                                                      : false;
        for (QAction* action : iterator.value())
        {
            action->setEnabled(enabled);
        }
    }
}

void MainWindow::chooseProcess()
{
    if (runner_->busy())
    {
        return;
    }
    ProcessDialog dialog(this);
    if (dialog.exec() == QDialog::Accepted)
    {
        attachProcess(dialog.selectedPid(), dialog.selectedPath());
    }
}

void MainWindow::runOperation(const QString& command)
{
    if (runner_->busy())
    {
        return;
    }
    const bool needsProcess = command != "launch" && command != "run" && command != "deobf";
    if (needsProcess && !pid_)
    {
        appendOutput("Attach to a process before running " + command + ".");
        return;
    }
    OperationContext context;
    context.pid = pid_;
    context.executable = executable_;
    context.artifactDirectory = artifactDirectory_;
    context.agentPath = QCoreApplication::applicationDirPath() + "/vmpxagent.dll";
    context.address = address_->text();
    OperationDialog dialog(command, context, this);
    if (dialog.exec() != QDialog::Accepted)
    {
        return;
    }
    appendOutput("vmpx " + command + " " + dialog.arguments().join(' '));
    if (command == "watch")
    {
        selectPage("Watch");
    }
    else if (command == "deobf")
    {
        selectPage("Analysis");
    }
    else if (command == "liveimports")
    {
        liveImportModule_.clear();
        selectPage("Imports");
        pages_["Imports"]->setRecords({"Module", "Function", "Source"}, {});
        pages_["Imports"]->setMessage("Live import output from the attached process.");
    }
    if (command == "launch")
    {
        launchedPid_ = 0;
    }
    runner_->start(command, dialog.arguments());
    updateActions();
}

void MainWindow::stopOperation()
{
    if (property("activeCommand").toString() == "watch" && pid_)
    {
        vp_error error{};
        if (vp_stop_watch(pid_, &error) != 0)
        {
            appendOutput(QString::fromWCharArray(error.message));
        }
    }
    runner_->cancel();
}

void MainWindow::showSettings()
{
    QDialog dialog(this);
    dialog.setWindowTitle("Workspace settings");
    dialog.setWindowIcon(UiIcons::named("settings-2"));
    dialog.setMinimumWidth(620);
    auto* layout = new QVBoxLayout(&dialog);
    auto* form = new QFormLayout;
    auto* worker = new QLineEdit(runner_->workerPath());
    auto* output = new QLineEdit(artifactDirectory_);
    worker->setCursorPosition(0);
    output->setCursorPosition(0);
    worker->setToolTip(worker->text());
    output->setToolTip(output->text());
    form->addRow("Backend worker", worker);
    form->addRow("Artifact directory", output);
    layout->addLayout(form);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Save | QDialogButtonBox::Cancel);
    buttons->button(QDialogButtonBox::Save)->setIcon(UiIcons::named("save"));
    buttons->button(QDialogButtonBox::Cancel)->setIcon(UiIcons::named("x"));
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dialog, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dialog, &QDialog::reject);
    if (dialog.exec() == QDialog::Accepted)
    {
        runner_->setWorkerPath(worker->text().trimmed());
        artifactDirectory_ = output->text().trimmed();
        QSettings settings;
        settings.setValue("worker", runner_->workerPath());
        settings.setValue("artifacts", artifactDirectory_);
        refreshArtifacts();
    }
}

void MainWindow::exportLog()
{
    QString path = QFileDialog::getSaveFileName(
        this, "Export session output", artifactDirectory_ + "/session-log.txt", "Text (*.txt)");
    if (path.isEmpty())
    {
        return;
    }
    QFile file(path);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate))
    {
        QMessageBox::warning(this, "Export failed", file.errorString());
        return;
    }
    if (file.write(output_->toPlainText().toUtf8()) < 0)
    {
        QMessageBox::warning(this, "Export failed", file.errorString());
    }
}
