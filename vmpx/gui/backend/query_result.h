#pragma once

#include "inspection.h"
#include <QStringList>

struct QueryResult
{
    QList<QStringList> sections;
    QList<QStringList> imports;
    vp_file_info fileInfo{};
    QString error;
};

inline void collectRows(void* context, const wchar_t* const* cells, size_t count)
{
    auto* rows = static_cast<QList<QStringList>*>(context);
    QStringList row;
    for (size_t index = 0; index < count; ++index)
    {
        row.append(QString::fromWCharArray(cells[index]));
    }
    rows->append(row);
}
