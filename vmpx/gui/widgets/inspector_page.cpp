#include "inspector_page.h"
#include "desktop_splitter.h"
#include "ui_icons.h"
#include <QAction>
#include <QVBoxLayout>
#include <QHeaderView>
#include <QToolBar>
InspectorPage::InspectorPage(const QString& title, QWidget* p) : QWidget(p)
{
    auto* layout = new QVBoxLayout(this);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(8);
    toolbar_ = new QToolBar(this);
    toolbar_->setObjectName("PageToolbar");
    toolbar_->setMovable(false);
    toolbar_->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);
    toolbar_->setIconSize(QSize(18, 18));
    filter = new QLineEdit;
    filter->setPlaceholderText("Filter " + title.toLower() + "…");
    filter->setAccessibleName("Filter " + title.toLower());
    filter->setMinimumWidth(140);
    filter->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Fixed);
    filter->setClearButtonEnabled(true);
    count_ = new QLabel("0 rows");
    filterAction_ = toolbar_->addWidget(filter);
    toolbar_->addWidget(count_);
    refreshAction_ = toolbar_->addAction(UiIcons::named("refresh-cw"), "Refresh");
    layout->addWidget(toolbar_);
    filter->addAction(UiIcons::named("search"), QLineEdit::LeadingPosition);
    message = new QLabel;
    message->setWordWrap(true);
    message->setObjectName("PageMessage");
    message->hide();
    layout->addWidget(message);
    model = new RecordModel(this);
    proxy = new QSortFilterProxyModel(this);
    proxy->setSourceModel(model);
    proxy->setFilterKeyColumn(-1);
    proxy->setFilterCaseSensitivity(Qt::CaseInsensitive);
    proxy->setSortCaseSensitivity(Qt::CaseInsensitive);
    proxy->setSortRole(Qt::UserRole);
    table = new QTableView;
    table->setModel(proxy);
    table->setSortingEnabled(true);
    table->sortByColumn(-1, Qt::AscendingOrder);
    table->setAlternatingRowColors(false);
    table->setSelectionBehavior(QAbstractItemView::SelectRows);
    table->setSelectionMode(QAbstractItemView::SingleSelection);
    table->setEditTriggers(QAbstractItemView::NoEditTriggers);
    table->setShowGrid(false);
    table->verticalHeader()->hide();
    table->verticalHeader()->setDefaultSectionSize(26);
    table->horizontalHeader()->setStretchLastSection(true);
    table->horizontalHeader()->setDefaultAlignment(Qt::AlignLeft | Qt::AlignVCenter);
    table->horizontalHeader()->setMinimumSectionSize(80);
    details = new QPlainTextEdit;
    details->setReadOnly(true);
    details->setFont(QFont("Consolas", 10));
    details->setPlaceholderText("Select a row to inspect its details.");
    auto* split = new DesktopSplitter(Qt::Vertical);
    split->setObjectName("InspectorSplitter");
    split->addWidget(table);
    split->addWidget(details);
    split->setSizes({540, 150});
    layout->addWidget(split, 1);
    connect(filter, &QLineEdit::textChanged, proxy, &QSortFilterProxyModel::setFilterFixedString);
    connect(refreshAction_, &QAction::triggered, this, &InspectorPage::refreshRequested);
    connect(table->selectionModel(), &QItemSelectionModel::currentRowChanged, this,
            [this](const QModelIndex& i)
            {
                auto row = model->row(proxy->mapToSource(i).row());
                QStringList lines;
                for (int column = 0; column < row.size(); ++column)
                {
                    const QString heading =
                        model->headerData(column, Qt::Horizontal, Qt::DisplayRole).toString();
                    lines.append(heading + ": " + row[column]);
                }
                details->setPlainText(lines.join("\n"));
                emit selectionChanged(row);
            });
    connect(proxy, &QAbstractItemModel::rowsInserted, this,
            [this] { count_->setText(QString::number(proxy->rowCount()) + " rows"); });
    connect(proxy, &QAbstractItemModel::modelReset, this,
            [this] { count_->setText(QString::number(proxy->rowCount()) + " rows"); });
    connect(filter, &QLineEdit::textChanged, this,
            [this]
            {
                count_->setText(proxy->rowCount() == 0 && model->rowCount() > 0
                                    ? "No matching rows"
                                    : QString::number(proxy->rowCount()) + " rows");
            });
}
void InspectorPage::setRecords(const QStringList& h, const QList<QStringList>& r)
{
    model->setRecords(h, r);
    table->resizeColumnsToContents();
    if (!h.isEmpty())
    {
        table->horizontalHeader()->setSectionResizeMode(
            h.size() - 1, h.size() >= 6 ? QHeaderView::Interactive : QHeaderView::Stretch);
        if (h.size() >= 6)
        {
            table->horizontalHeader()->setStretchLastSection(false);
            for (int column = 0; column < h.size(); ++column)
            {
                table->setColumnWidth(column,
                                      qMax(table->columnWidth(column), column == 0 ? 80 : 140));
            }
        }
        else
        {
            table->horizontalHeader()->setStretchLastSection(true);
        }
    }
    count_->setText(QString::number(proxy->rowCount()) + " rows");
}
void InspectorPage::setMessage(const QString& s)
{
    message->setText(s);
    message->setVisible(!s.isEmpty());
}
void InspectorPage::focusFilter()
{
    filter->setFocus();
    filter->selectAll();
}

QAction* InspectorPage::addAction(const QString& label, const QString& icon)
{
    auto* action = new QAction(UiIcons::named(icon), label, this);
    toolbar_->insertAction(refreshAction_, action);
    return action;
}

void InspectorPage::addControls(QWidget* controls)
{
    toolbar_->insertWidget(filterAction_, controls);
}
