#include "inspection.h"
#include <QCoreApplication>
#include <QFile>
#include <QTemporaryDir>
#include <windows.h>
#include <cstring>

static void countRows(void* context, const wchar_t* const*, size_t)
{
    ++*static_cast<int*>(context);
}

int main(int argc, char** argv)
{
    QCoreApplication app(argc, argv);
    vp_file_info info{};
    vp_error error{};
    int rows = 0;
    const std::wstring executable = QCoreApplication::applicationFilePath().toStdWString();
    if (vp_inspect_file(executable.c_str(), &info, countRows, nullptr, &rows, &error) != 0 ||
        !info.sections || rows != info.sections)
    {
        return 1;
    }
    QTemporaryDir directory;
    QFile invalid(directory.filePath("invalid.exe"));
    if (!invalid.open(QIODevice::WriteOnly) || invalid.write(QByteArray(128, 'X')) != 128)
    {
        return 2;
    }
    invalid.close();
    const std::wstring badPath = invalid.fileName().toStdWString();
    if (vp_inspect_file(badPath.c_str(), &info, nullptr, nullptr, nullptr, &error) == 0)
    {
        return 3;
    }
    rows = 0;
    if (vp_processes(countRows, &rows, &error) != 0 || rows == 0)
    {
        return 4;
    }
    const unsigned char source[] = {0x10, 0x20, 0x30, 0x40};
    unsigned char destination[sizeof(source)]{};
    size_t got = 0;
    if (vp_read(GetCurrentProcessId(), reinterpret_cast<uintptr_t>(source), destination,
                sizeof(destination), &got, &error) != 0 ||
        got != sizeof(source) || std::memcmp(source, destination, sizeof(source)) != 0)
    {
        return 5;
    }
    if (vp_read(GetCurrentProcessId(), 1, destination, sizeof(destination), &got, &error) == 0 ||
        got != 0)
    {
        return 6;
    }
    rows = 0;
    if (vp_process_inspect(GetCurrentProcessId(), 1, countRows, &rows, &error) != 0 || rows == 0)
    {
        return 7;
    }
    if (vp_read(GetCurrentProcessId(), 1, destination, sizeof(destination), nullptr, &error) == 0)
    {
        return 8;
    }
    return 0;
}
