#include "navigation_delegate.h"

void NavigationDelegate::paint(QPainter* painter, const QStyleOptionViewItem& option,
                               const QModelIndex& index) const
{
    QStyleOptionViewItem rowOption(option);
    // The full-row selection already identifies the keyboard's current destination.
    rowOption.state &= ~QStyle::State_HasFocus;
    QStyledItemDelegate::paint(painter, rowOption, index);
}
