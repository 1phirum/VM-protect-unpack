#include "desktop_splitter.h"
#include <QEnterEvent>
#include <QMouseEvent>
#include <QPainter>

namespace
{
class DesktopSplitterHandle final : public QSplitterHandle
{
public:
    DesktopSplitterHandle(Qt::Orientation orientation, QSplitter* parent)
        : QSplitterHandle(orientation, parent)
    {
        setCursor(orientation == Qt::Horizontal ? Qt::SplitHCursor : Qt::SplitVCursor);
        setToolTip("Drag to resize panels");
        setAccessibleName("Resize panels");
    }

protected:
    void paintEvent(QPaintEvent*) override
    {
        const QColor background = dragging_  ? QColor("#e9edf1")
                                  : hovered_ ? QColor("#f3f5f7")
                                             : QColor("#ffffff");
        const QColor divider = dragging_ ? QColor("#7b8793") : QColor("#d5dbe1");
        const QColor grip = hovered_ || dragging_ ? QColor("#303840") : QColor("#7b8793");
        QPainter painter(this);
        painter.fillRect(rect(), background);
        painter.setPen(QPen(divider, 1));

        const bool verticalDivider = orientation() == Qt::Horizontal;
        const qreal centerX = width() / 2;
        const qreal centerY = height() / 2;
        if (verticalDivider)
        {
            painter.drawLine(QPointF(centerX + 0.5, 0), QPointF(centerX + 0.5, height()));
            painter.fillRect(QRectF(0, centerY - 12, width(), 24), background);
        }
        else
        {
            painter.drawLine(QPointF(0, centerY + 0.5), QPointF(width(), centerY + 0.5));
            painter.fillRect(QRectF(centerX - 12, 0, 24, height()), background);
        }

        painter.setRenderHint(QPainter::Antialiasing);
        painter.setPen(Qt::NoPen);
        painter.setBrush(grip);
        for (int offset = -5; offset <= 5; offset += 5)
        {
            const QPointF center = verticalDivider ? QPointF(centerX + 0.5, centerY + offset)
                                                   : QPointF(centerX + offset, centerY + 0.5);
            painter.drawEllipse(center, 1.25, 1.25);
        }
    }

    void enterEvent(QEnterEvent* event) override
    {
        hovered_ = true;
        update();
        QSplitterHandle::enterEvent(event);
    }

    void leaveEvent(QEvent* event) override
    {
        hovered_ = false;
        update();
        QSplitterHandle::leaveEvent(event);
    }

    void mousePressEvent(QMouseEvent* event) override
    {
        if (event->button() == Qt::LeftButton)
        {
            dragging_ = true;
            update();
        }
        QSplitterHandle::mousePressEvent(event);
    }

    void mouseReleaseEvent(QMouseEvent* event) override
    {
        if (event->button() == Qt::LeftButton)
        {
            dragging_ = false;
            hovered_ = rect().contains(event->position().toPoint());
            update();
        }
        QSplitterHandle::mouseReleaseEvent(event);
    }

private:
    bool hovered_ = false;
    bool dragging_ = false;
};
} // namespace

DesktopSplitter::DesktopSplitter(Qt::Orientation orientation, QWidget* parent)
    : QSplitter(orientation, parent)
{
    // Keep the drag target wider than the single-pixel divider.
    setHandleWidth(8);
    setOpaqueResize(true);
}

QSplitterHandle* DesktopSplitter::createHandle()
{
    return new DesktopSplitterHandle(orientation(), this);
}
