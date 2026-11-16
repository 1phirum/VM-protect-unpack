#include "main_window.h"
#include "desktop_splitter.h"
#include "navigation_delegate.h"
#include "ui_icons.h"
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
#include <QPushButton>
#include <QSettings>
#include <QSpinBox>
#include <QStackedWidget>
#include <QStandardPaths>
#include <QStatusBar>
#include <QVBoxLayout>

void MainWindow::buildWindow()
{
    setWindowTitle("VM protect unpack");
    resize(1440, 900);
    setWindowIcon(UiIcons::named("app"));
    auto* central = new QWidget;
    auto* layout = new QVBoxLayout(central);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(0);
    auto* target = new QWidget;
    target->setObjectName("TargetBar");
    target->setMinimumHeight(48);
    auto* targetLayout = new QHBoxLayout(target);
    targetLayout->setContentsMargins(14, 10, 14, 10);
    targetLayout->setSpacing(16);
    targetLabel_ = new QLabel("No executable loaded — open a file or attach to a process.");
    targetLabel_->setObjectName("TargetPath");
    modeLabel_ = new QLabel("No process attached");
    modeLabel_->setObjectName("TargetStatus");
    progress_ = new QProgressBar;
    progress_->setMaximumWidth(120);
    progress_->setMaximumHeight(16);
    progress_->hide();
    targetLayout->addWidget(targetLabel_, 1);
    targetLayout->addWidget(progress_);
    targetLayout->addWidget(modeLabel_);
    layout->addWidget(target);

    auto* split = new DesktopSplitter;
    split->setObjectName("WorkspaceSplitter");
    navigation_ = new QListWidget;
    navigation_->setObjectName("Navigation");
    navigation_->setItemDelegate(new NavigationDelegate(navigation_));
    navigation_->setEditTriggers(QAbstractItemView::NoEditTriggers);
    navigation_->setMinimumWidth(180);
    navigation_->setMaximumWidth(280);
    const QStringList names = {"Overview", "Sections",   "Imports",   "Modules",
                               "Memory",   "Hex editor", "Windows",   "Agent",
                               "Watch",    "Analysis",   "Artifacts", "Session log"};
    navigation_->setIconSize(QSize(17, 17));
    stack_ = new QStackedWidget;
    for (const QString& name : names)
    {
        navigation_->addItem(new QListWidgetItem(UiIcons::named(UiIcons::pageName(name)), name));
        auto* page = new InspectorPage(name);
        page->setMessage(name == "Overview" ? "Open an executable to inspect its real PE metadata."
                                            : "No data collected for this view.");
        pages_.insert(name, page);
        stack_->addWidget(page);
        connect(page, &InspectorPage::refreshRequested, this, [this, name] { refreshPage(name); });
    }
    const QList<QStringList> pageOperations = {
        {"Overview", "Open executable…", "folder-open", "open"},
        {"Overview", "Attach process…", "monitor", "attach"},
        {"Overview", "Launch target…", "play", "launch"},
        {"Imports", "Inspect live imports…", "list-tree", "liveimports"},
        {"Modules", "Load agent DLL…", "plug", "inject"},
        {"Memory", "Dump image…", "download", "dump"},
        {"Memory", "Save snapshot…", "save", "snap"},
        {"Memory", "Entry capture…", "scan-line", "oep"},
        {"Memory", "Map options…", "settings-2", "memmap"},
        {"Watch", "Start watch…", "activity", "watch"},
        {"Analysis", "Analyze capture…", "scan-line", "deobf"},
        {"Artifacts", "Rebuild image…", "recycle", "rebuild"},
        {"Artifacts", "Validate image…", "play", "run"},
        {"Session log", "Export output…", "file-output", "export"}};
    for (const QStringList& operation : pageOperations)
    {
        auto* action = pages_[operation[0]]->addAction(operation[1], operation[2]);
        operationActions_[operation[3]].append(action);
        action->setObjectName("operation-" + operation[3]);
        connect(action, &QAction::triggered, this,
                [this, command = operation[3]]
                {
                    if (command == "open")
                    {
                        actions_["open"]->trigger();
                    }
                    else if (command == "attach")
                    {
                        chooseProcess();
                    }
                    else if (command == "export")
                    {
                        exportLog();
                    }
                    else
                    {
                        runOperation(command);
                    }
                });
    }
    pages_["Session log"]->setRecords({"Time", "Command", "Result", "Exit code"}, {});
    pages_["Watch"]->setRecords({"Time", "Backend event"}, {});
    pages_["Analysis"]->setMessage("Run offline analysis on an image capture. VM lifting and "
                                   "native emission are unavailable.");

    auto* hexControls = new QWidget;
    hexControls->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Fixed);
    auto* hexLayout = new QHBoxLayout(hexControls);
    hexLayout->setContentsMargins(0, 0, 0, 0);
    hexLayout->setSpacing(6);
    address_ = new QLineEdit;
    address_->setPlaceholderText("0x00400000");
    address_->setFont(QFont("Consolas", 10));
    address_->setFixedWidth(180);
    address_->setAccessibleName("Memory address");
    readSize_ = new QSpinBox;
    readSize_->setRange(1, 1048576);
    readSize_->setValue(64);
    readSize_->setFixedWidth(90);
    readSize_->setAccessibleName("Read size in bytes");
    auto* readAction = pages_["Hex editor"]->addAction("Read memory", "search");
    auto* writeAction = pages_["Hex editor"]->addAction("Write bytes…", "pencil");
    readAction->setObjectName("read-memory");
    writeAction->setObjectName("write-memory");
    operationActions_["write"].append(writeAction);
    operationActions_["read"].append(readAction);
    hexLayout->addWidget(new QLabel("Address"));
    hexLayout->addWidget(address_);
    hexLayout->addWidget(new QLabel("Bytes"));
    hexLayout->addWidget(readSize_);
    pages_["Hex editor"]->addControls(hexControls);
    connect(readAction, &QAction::triggered, this, &MainWindow::readMemory);
    connect(writeAction, &QAction::triggered, this, [this] { runOperation("poke"); });
    connect(pages_["Memory"], &InspectorPage::selectionChanged, this,
            [this](const QStringList& row)
            {
                if (!row.isEmpty())
                {
                    address_->setText(row[0]);
                }
            });
    connect(pages_["Memory"]->table, &QTableView::doubleClicked, this,
            [this]
            {
                selectPage("Hex editor");
                readMemory();
            });
    connect(pages_["Sections"], &InspectorPage::selectionChanged, this,
            [this](const QStringList& row)
            {
                if (row.size() < 6 || executable_.isEmpty())
                {
                    return;
                }
                bool valid = false;
                const quint64 offset = row[4].toULongLong(&valid, 16);
                const quint64 rawSize = row[5].toULongLong(nullptr, 16);
                if (!valid || !rawSize)
                {
                    pages_["Sections"]->details->appendPlainText("No file-backed bytes.");
                    return;
                }
                QFile file(executable_);
                if (!file.open(QIODevice::ReadOnly) || !file.seek(offset))
                {
                    pages_["Sections"]->details->appendPlainText(file.errorString());
                    return;
                }
                const QByteArray bytes = file.read(qMin<quint64>(64, rawSize));
                pages_["Sections"]->details->appendPlainText(
                    "File bytes: " + QString::fromLatin1(bytes.toHex(' ').toUpper()));
            });
    connect(navigation_, &QListWidget::currentRowChanged, stack_, &QStackedWidget::setCurrentIndex);
    connect(navigation_, &QListWidget::currentRowChanged, this,
            [this](int)
            {
                const QString name = currentPage();
                if (name == "Modules" || name == "Memory" || name == "Windows" || name == "Agent" ||
                    name == "Artifacts" || name == "Analysis")
                {
                    refreshPage(name);
                }
            });
    split->addWidget(navigation_);
    split->addWidget(stack_);
    split->setCollapsible(0, false);
    split->setStretchFactor(1, 1);
    split->setSizes({220, 1220});

    output_ = new QPlainTextEdit;
    output_->setReadOnly(true);
    output_->setFont(QFont("Consolas", 10));
    output_->setMaximumBlockCount(10000);
    output_->setPlaceholderText("Backend command output appears here.");
    auto* vertical = new DesktopSplitter(Qt::Vertical);
    vertical->setObjectName("OutputSplitter");
    vertical->addWidget(split);
    auto* outputPanel = new QWidget;
    outputPanel->setObjectName("OutputPanel");
    auto* outputLayout = new QVBoxLayout(outputPanel);
    outputLayout->setContentsMargins(8, 4, 8, 4);
    auto* outputHeader = new QHBoxLayout;
    outputHeader->addWidget(new QLabel("Output"));
    outputHeader->addStretch();
    auto* exportButton = new QPushButton(UiIcons::named("file-output"), "Export");
    outputHeader->addWidget(exportButton);
    connect(exportButton, &QPushButton::clicked, this, &MainWindow::exportLog);
    outputLayout->addLayout(outputHeader);
    outputLayout->addWidget(output_);
    vertical->addWidget(outputPanel);
    vertical->setSizes({680, 130});
    outputPanel->hide();
    connect(output_, &QPlainTextEdit::textChanged, outputPanel,
            [outputPanel, output = output_]
            { outputPanel->setVisible(!output->document()->isEmpty()); });
    layout->addWidget(vertical, 1);
    setCentralWidget(central);
    statusBar()->setSizeGripEnabled(false);
    statusBar()->hide();
    connect(statusBar(), &QStatusBar::messageChanged, target,
            [target](const QString& text) { target->setToolTip(text); });
    navigation_->setCurrentRow(0);
}
