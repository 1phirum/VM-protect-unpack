#include "process_dialog.h"
#include "query_result.h"
#include "ui_icons.h"
#include <QDialogButtonBox>
#include <QFutureWatcher>
#include <QPushButton>
#include <QVBoxLayout>
#include <QtConcurrent>

ProcessDialog::ProcessDialog(QWidget* parent) : QDialog(parent)
{
    setWindowTitle("Attach to process");
    setWindowIcon(UiIcons::named("monitor"));
    resize(850, 510);

    auto* layout = new QVBoxLayout(this);
    page_ = new InspectorPage("Processes", this);
    page_->details->hide();
    layout->addWidget(page_);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel, this);
    attach_ = buttons->addButton("Attach", QDialogButtonBox::AcceptRole);
    attach_->setIcon(UiIcons::named("monitor"));
    buttons->button(QDialogButtonBox::Cancel)->setIcon(UiIcons::named("x"));
    attach_->setEnabled(false);
    layout->addWidget(buttons);

    connect(buttons, &QDialogButtonBox::accepted, this, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(page_, &InspectorPage::refreshRequested, this, &ProcessDialog::refresh);
    connect(page_, &InspectorPage::selectionChanged, this,
            [this](const QStringList& row)
            {
                selected_ = row;
                bool compatible = row.size() == 4 && row[2] == "x86";
                attach_->setEnabled(compatible);
                page_->setMessage(compatible
                                      ? "Read-only inspection until an operation is selected."
                                      : "Choose an accessible x86 target for the x86 worker.");
            });
    refresh();
}

quint32 ProcessDialog::selectedPid() const
{
    return selected_.value(1).toUInt();
}

QString ProcessDialog::selectedPath() const
{
    return selected_.value(3);
}

void ProcessDialog::refresh()
{
    page_->setMessage("Reading running processes…");
    auto* watcher = new QFutureWatcher<QueryResult>(this);
    connect(watcher, &QFutureWatcher<QueryResult>::finished, this,
            [this, watcher]
            {
                QueryResult result = watcher->result();
                watcher->deleteLater();
                page_->setRecords({"Process", "PID", "Architecture", "Executable path"},
                                  result.sections);
                page_->setMessage(result.error);
            });
    watcher->setFuture(QtConcurrent::run(
        []
        {
            QueryResult result;
            vp_error error{};
            if (vp_processes(collectRows, &result.sections, &error) != 0)
            {
                result.error = QString::fromWCharArray(error.message);
            }
            return result;
        }));
}
