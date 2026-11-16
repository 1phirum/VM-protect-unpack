#include "record_model.h"
#include <QFont>
QVariant RecordModel::data(const QModelIndex& i, int role) const
{
    if (!i.isValid() || i.row() >= rows_.size())
    {
        return {};
    }
    const auto& row = rows_[i.row()];
    if (role == Qt::UserRole && i.column() < row.size())
    {
        const QString value = row[i.column()];
        bool numeric = false;
        const qulonglong number =
            value.toULongLong(&numeric, value.startsWith("0x", Qt::CaseInsensitive) ? 16 : 10);
        if (numeric)
        {
            return QVariant::fromValue(number);
        }
        return value;
    }
    if (role == Qt::DisplayRole || role == Qt::ToolTipRole)
    {
        return i.column() < row.size() ? row[i.column()] : QString{};
    }
    if (role == Qt::FontRole && i.column() < row.size() && row[i.column()].startsWith("0x"))
    {
        return QFont("Consolas", 10);
    }
    return {};
}
QVariant RecordModel::headerData(int n, Qt::Orientation o, int role) const
{
    if (role != Qt::DisplayRole)
    {
        return {};
    }
    return o == Qt::Horizontal && n < headers_.size() ? headers_[n] : QString::number(n + 1);
}
void RecordModel::setRecords(const QStringList& h, const QList<QStringList>& r)
{
    beginResetModel();
    headers_ = h;
    rows_ = r;
    endResetModel();
}
void RecordModel::append(const QStringList& r)
{
    if (rows_.size() >= 10000)
    {
        beginRemoveRows({}, 0, 0);
        rows_.removeFirst();
        endRemoveRows();
    }
    int n = rows_.size();
    beginInsertRows({}, n, n);
    rows_.append(r);
    endInsertRows();
}
QStringList RecordModel::row(int n) const
{
    return n >= 0 && n < rows_.size() ? rows_[n] : QStringList{};
}
