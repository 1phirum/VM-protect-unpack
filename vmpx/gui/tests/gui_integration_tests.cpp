#include "main_window.h"
#include "operation_dialog.h"
#include <QAction>
#include <QApplication>
#include <QCoreApplication>
#include <QDialogButtonBox>
#include <QElapsedTimer>
#include <QFile>
#include <QLineEdit>
#include <QPushButton>
#include <QTemporaryDir>
#include <QThread>
#include <functional>

static bool waitUntil(const std::function<bool()>& predicate)
{
    QElapsedTimer timer;
    timer.start();
    while (!predicate() && timer.elapsed() < 15000)
    {
        QCoreApplication::processEvents();
        QThread::msleep(10);
    }
    return predicate();
}

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QCoreApplication::setOrganizationName("VMProtectUnpackTests");
    QCoreApplication::setApplicationName("GUI integration");
    Q_INIT_RESOURCE(icons);

    MainWindow window;
    if (window.recordCount("Sections") != 0)
    {
        return 1;
    }
    QAction* dump = window.findChild<QAction*>("action-dump");
    if (!dump || dump->isEnabled())
    {
        return 2;
    }
    bool loaded = false;
    QObject::connect(&window, &MainWindow::inspectionFinished, &app,
                     [&](bool success) { loaded = success; });
    window.openFile(QCoreApplication::applicationFilePath());
    if (!waitUntil([&] { return loaded; }) || window.recordCount("Sections") == 0 ||
        window.recordCount("Imports") == 0)
    {
        return 3;
    }

    CommandRunner runner;
    bool completed = false;
    int exitCode = -1;
    QString output;
    QObject::connect(&runner, &CommandRunner::output, &app,
                     [&](const QString& line) { output += line; });
    QObject::connect(&runner, &CommandRunner::completed, &app,
                     [&](const QString&, int code, bool)
                     {
                         completed = true;
                         exitCode = code;
                     });
    runner.start("info", {QCoreApplication::applicationFilePath()});
    if (!waitUntil([&] { return completed; }) || exitCode != 0 || !output.contains("sections"))
    {
        return 4;
    }

    QTemporaryDir directory;
    OperationContext context;
    context.pid = 1234;
    context.artifactDirectory = directory.path();
    context.address = "0x00400000";
    OperationDialog write("poke", context);
    QLineEdit* bytes = nullptr;
    for (QLineEdit* edit : write.findChildren<QLineEdit*>())
    {
        if (edit->text().isEmpty())
        {
            bytes = edit;
        }
    }
    if (!bytes)
    {
        return 5;
    }
    auto* buttons = write.findChild<QDialogButtonBox*>();
    bytes->setText("invalid");
    buttons->button(QDialogButtonBox::Ok)->click();
    if (write.result() == QDialog::Accepted)
    {
        return 6;
    }
    bytes->setText("90 90");
    buttons->button(QDialogButtonBox::Ok)->click();
    if (write.result() != QDialog::Accepted || !write.arguments().contains("90 90"))
    {
        return 7;
    }
    return 0;
}
