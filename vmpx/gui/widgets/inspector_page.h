#pragma once
#include <QWidget>
#include <QTableView>
#include <QLineEdit>
#include <QLabel>
#include <QPlainTextEdit>
#include <QSortFilterProxyModel>
#include "record_model.h"
class InspectorPage final : public QWidget
{
    Q_OBJECT
public:
    explicit InspectorPage(const QString& title, QWidget* parent = nullptr);
    void setRecords(const QStringList&, const QList<QStringList>&);
    void setMessage(const QString&);
    void focusFilter();
    class QAction* addAction(const QString& label, const QString& icon);
    void addControls(QWidget* controls);
    RecordModel* model;
    QSortFilterProxyModel* proxy;
    QTableView* table;
    QPlainTextEdit* details;
    QLineEdit* filter;
    QLabel* message;
signals:
    void refreshRequested();
    void selectionChanged(const QStringList& row);

private:
    QLabel* count_;
    class QToolBar* toolbar_;
    class QAction* filterAction_;
    class QAction* refreshAction_;
};
