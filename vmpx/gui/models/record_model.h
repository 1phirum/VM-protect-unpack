#pragma once
#include <QAbstractTableModel>
#include <QStringList>
class RecordModel final : public QAbstractTableModel
{
    Q_OBJECT
public:
    explicit RecordModel(QObject* p = nullptr) : QAbstractTableModel(p)
    {
    }
    int rowCount(const QModelIndex& p = {}) const override
    {
        return p.isValid() ? 0 : rows_.size();
    }
    int columnCount(const QModelIndex& p = {}) const override
    {
        return p.isValid() ? 0 : headers_.size();
    }
    QVariant data(const QModelIndex&, int role = Qt::DisplayRole) const override;
    QVariant headerData(int, Qt::Orientation, int) const override;
    void setRecords(const QStringList& headers, const QList<QStringList>& rows);
    void append(const QStringList& row);
    QStringList row(int index) const;

private:
    QStringList headers_;
    QList<QStringList> rows_;
};
