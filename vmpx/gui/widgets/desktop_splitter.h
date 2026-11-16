#pragma once

#include <QSplitter>

class DesktopSplitter final : public QSplitter
{
public:
    explicit DesktopSplitter(Qt::Orientation orientation = Qt::Horizontal,
                             QWidget* parent = nullptr);

protected:
    QSplitterHandle* createHandle() override;
};
