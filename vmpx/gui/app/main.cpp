#include "main_window.h"
#include "operation_dialog.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QFile>
#include <QFileInfo>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTimer>

int main(int argc, char** argv)
{
    QApplication app(argc, argv);
    QCoreApplication::setApplicationName("VM protect unpack");
    QCoreApplication::setOrganizationName("VMProtectUnpack");
    QApplication::setStyle("Fusion");
    QApplication::setFont(QFont("Segoe UI", 10));
    Q_INIT_RESOURCE(icons);
    QFile style(":/theme/desktop.qss");
    if (style.open(QIODevice::ReadOnly))
    {
        app.setStyleSheet(QString::fromUtf8(style.readAll()));
    }

    QCommandLineParser parser;
    parser.addHelpOption();
    parser.addOption({"open", "Inspect an executable.", "path"});
    parser.addOption({"screenshot", "Save an actual application screenshot.", "path"});
    parser.addOption({"page", "Select an inspection page.", "name"});
    parser.addOption({"pid", "Inspect an accessible x86 process.", "pid"});
    parser.addOption(
        {"dialog-preview", "Render an operation dialog without executing it.", "command"});
    parser.addOption({"smoke-report", "Save inspection results and exit.", "path"});
    parser.process(app);
    MainWindow window;
    window.show();
    if (parser.isSet("dialog-preview"))
    {
        OperationContext context;
        context.executable = parser.value("open");
        context.artifactDirectory = QCoreApplication::applicationDirPath() + "/artifacts";
        context.agentPath = QCoreApplication::applicationDirPath() + "/vmpxagent.dll";
        auto* dialog = new OperationDialog(parser.value("dialog-preview"), context, &window);
        dialog->show();
        QTimer::singleShot(250, &app,
                           [&, dialog]
                           {
                               bool saved = dialog->grab().save(parser.value("screenshot"));
                               app.exit(saved ? 0 : 1);
                           });
        return app.exec();
    }
    if (parser.isSet("smoke-report"))
    {
        QObject::connect(&window, &MainWindow::inspectionFinished, &app,
                         [&](bool success)
                         {
                             QTimer::singleShot(
                                 150, &app,
                                 [&, success]
                                 {
                                     QJsonObject report{
                                         {"success", success},
                                         {"overviewRows", window.recordCount("Overview")},
                                         {"sections", window.recordCount("Sections")},
                                         {"imports", window.recordCount("Imports")}};
                                     QFile output(parser.value("smoke-report"));
                                     bool saved = output.open(QIODevice::WriteOnly);
                                     if (saved)
                                     {
                                         output.write(QJsonDocument(report).toJson());
                                     }
                                     if (parser.isSet("screenshot"))
                                     {
                                         if (parser.isSet("page"))
                                         {
                                             window.showPage(parser.value("page"));
                                         }
                                         window.saveScreenshot(parser.value("screenshot"));
                                     }
                                     app.exit(success && saved ? 0 : 1);
                                 });
                         });
        QTimer::singleShot(30000, &app, [&] { app.exit(2); });
    }
    if (parser.isSet("open") && !parser.isSet("pid"))
    {
        QTimer::singleShot(0, &window, [&] { window.openFile(parser.value("open")); });
    }
    if (parser.isSet("pid"))
    {
        QTimer::singleShot(
            0, &window,
            [&] { window.attachProcess(parser.value("pid").toUInt(), parser.value("open")); });
    }
    if (parser.isSet("page") && !parser.isSet("smoke-report"))
    {
        window.showPage(parser.value("page"));
    }
    if (parser.isSet("screenshot") && !parser.isSet("smoke-report"))
    {
        auto* captureTimer = new QTimer(&app);
        QObject::connect(captureTimer, &QTimer::timeout, &app,
                         [&]
                         {
                             if (window.inspectionBusy())
                             {
                                 return;
                             }
                             window.saveScreenshot(parser.value("screenshot"));
                             app.exit(QFileInfo::exists(parser.value("screenshot")) ? 0 : 1);
                         });
        captureTimer->start(300);
        QTimer::singleShot(30000, &app, [&] { app.exit(2); });
    }
    return app.exec();
}
