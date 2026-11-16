#pragma once

#include <QDialog>
#include "inspector_page.h"

class ProcessDialog final : public QDialog
{
    Q_OBJECT

public:
    explicit ProcessDialog(QWidget* parent = nullptr);
    quint32 selectedPid() const;
    QString selectedPath() const;

private:
    InspectorPage* page_;
    class QPushButton* attach_;
    QStringList selected_;
    void refresh();
};
