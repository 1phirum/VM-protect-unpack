#include "ui_icons.h"
#include <QMap>

namespace UiIcons
{
QIcon named(const QString& name)
{
    const QString resource = ":/icons/" + name + ".svg";
    QIcon icon(resource);
    // Keep SVG strokes legible; disabled text and controls still show availability.
    icon.addFile(resource, QSize(), QIcon::Disabled);
    icon.addFile(resource, QSize(), QIcon::Selected);
    return icon;
}

QString pageName(const QString& page)
{
    static const QMap<QString, QString> names = {
        {"Overview", "file"},           {"Sections", "layers"},     {"Imports", "list-tree"},
        {"Modules", "package"},         {"Memory", "memory-stick"}, {"Hex editor", "binary"},
        {"Windows", "panels-top-left"}, {"Agent", "shield"},        {"Watch", "activity"},
        {"Analysis", "scan-line"},      {"Artifacts", "files"},     {"Session log", "terminal"}};
    return names.value(page, "file");
}

QString operationName(const QString& command)
{
    static const QMap<QString, QString> names = {
        {"launch", "play"},      {"inject", "plug"},           {"dump", "download"},
        {"snap", "save"},        {"oep", "scan-line"},         {"rebuild", "recycle"},
        {"run", "play"},         {"deobf", "scan-line"},       {"watch", "activity"},
        {"poke", "pencil"},      {"liveimports", "list-tree"}, {"imports", "list-tree"},
        {"memmap", "settings-2"}};
    return names.value(command, "play");
}

QString operationTitle(const QString& command)
{
    static const QMap<QString, QString> titles = {{"launch", "Launch target"},
                                                  {"inject", "Load agent DLL"},
                                                  {"dump", "Dump image"},
                                                  {"snap", "Save snapshot"},
                                                  {"oep", "Capture entry image"},
                                                  {"rebuild", "Rebuild PE image"},
                                                  {"run", "Validate image"},
                                                  {"deobf", "Analyze capture"},
                                                  {"watch", "Watch memory"},
                                                  {"poke", "Apply memory write"},
                                                  {"liveimports", "Inspect live imports"},
                                                  {"imports", "Inspect imports"},
                                                  {"memmap", "Inspect memory map"}};
    return titles.value(command, command);
}
} // namespace UiIcons
