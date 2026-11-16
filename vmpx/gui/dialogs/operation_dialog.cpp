#include "operation_dialog.h"
#include "ui_icons.h"
#include <QCheckBox>
#include <QDialogButtonBox>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMap>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

OperationDialog::OperationDialog(const QString& command, const OperationContext& context,
                                 QWidget* parent)
    : QDialog(parent), command_(command), pid_(context.pid)
{
    setWindowTitle("VM protect unpack — " + UiIcons::operationTitle(command));
    setWindowIcon(UiIcons::named(UiIcons::operationName(command)));
    setMinimumWidth(660);
    auto* layout = new QVBoxLayout(this);
    auto* description = new QLabel("Configure the operation for the selected target.");
    description->setWordWrap(true);
    layout->addWidget(description);
    form_ = new QFormLayout;
    form_->setSpacing(12);
    layout->addLayout(form_);
    const QDir output(context.artifactDirectory);

    if (command == "launch")
    {
        addField("Executable", "--exe", context.executable, true, false, 1);
        addField("Wait timeout (ms)", "--wait-ms", "180000", true, true);
        addCheck("Disable armor", "--no-armor");
    }
    else if (command == "inject")
    {
        addField("Agent DLL", "--dll", context.agentPath, true, false, 1);
    }
    else if (command == "dump")
    {
        addField("Output capture", "--out", output.filePath("live.bin"), true, false, 2);
        addField("Maximum size (MiB)", "--max-mb", "600", true, true);
        addCheck("Allow partial capture", "--force");
    }
    else if (command == "snap")
    {
        addField("Output snapshot", "--out", output.filePath("snap.bin"), true, false, 2);
        addField("Lower address", "--lo", "", false, true);
        addCheck("All private regions", "--all-private");
    }
    else if (command == "oep")
    {
        addField("Output capture", "--out", output.filePath("oep.bin"), true, false, 2);
        addField("Wait before capture (ms)", "--wait-ms", "0", true, true);
    }
    else if (command == "rebuild")
    {
        addField("Original executable", "--file", context.executable, true, false, 1);
        addField("Image capture", "--live", output.filePath("live.bin"), true, false, 1);
        addField("Output executable", "--out", output.filePath("rebuilt.exe"), true, false, 2);
        addField("Image base override", "--base", "", false, true);
        addField("Entry RVA override", "--entry", "", false, true);
        addCheck("Reverse-resolve import slots", "--cast");
        addCheck("Restore writable data from original", "--clean-data");
    }
    else if (command == "run")
    {
        addField("Reconstructed executable", "--exe", output.filePath("rebuilt.exe"), true, false,
                 1);
        addField("Private snapshot", "--snap", output.filePath("snap.bin"), true, false, 1);
    }
    else if (command == "deobf")
    {
        addField("Image capture", "--live", output.filePath("live.bin"), true, false, 1);
        addField("Original executable", "--file", context.executable, false, false, 1);
        addField("Report directory", "--out", output.filePath("analysis"), true, false, 3);
        addCheck("Skip string analysis", "--no-strings");
    }
    else if (command == "watch")
    {
        addField("Address (optional)", "--addr", context.address, false, true);
        addField("Size (bytes)", "--size", "4096", true, true);
        addField("Access modes (r/w/x)", "--mode", "wx", true);
        addField("Duration (seconds)", "--seconds", "10", true, true);
        addField("Event output", "--out", output.filePath("watch.txt"), true, false, 2);
        addField("Capture directory", "--capture", "", false, false, 3);
    }
    else if (command == "poke")
    {
        addField("Address", "--addr", context.address, true, true);
        addField("Replacement bytes (hex)", "--bytes", "", true);
        description->setText("Write memory in PID " + QString::number(pid_) +
                             ". Review the address and bytes before applying.");
    }
    else if (command == "liveimports" || command == "imports")
    {
        addField("Function limit", "--limit", "300", true, true);
    }

    if (command == "memmap")
    {
        addField("Near address", "--near", context.address, false, true);
        addField("Radius (bytes)", "--radius", "33554432", true, true);
        addField("Minimum region size (KiB)", "--min-kb", "64", true, true);
        addCheck("Private regions only", "--private", true);
        addCheck("Include reserved regions", "--all");
    }
    error_ = new QLabel;
    error_->setWordWrap(true);
    layout->addWidget(error_);
    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Cancel | QDialogButtonBox::Ok);
    auto* confirm = buttons->button(QDialogButtonBox::Ok);
    confirm->setText(UiIcons::operationTitle(command));
    confirm->setIcon(UiIcons::named(UiIcons::operationName(command)));
    buttons->button(QDialogButtonBox::Cancel)->setIcon(UiIcons::named("x"));
    layout->addWidget(buttons);
    connect(buttons, &QDialogButtonBox::rejected, this, &QDialog::reject);
    connect(buttons, &QDialogButtonBox::accepted, this, &OperationDialog::validateAndAccept);
}

void OperationDialog::addField(const QString& label, const QString& flag, const QString& value,
                               bool required, bool numeric, int browse)
{
    auto* edit = new QLineEdit(value);
    edit->setObjectName(flag);
    edit->setClearButtonEnabled(true);
    edit->setCursorPosition(0);
    if (browse)
    {
        edit->setToolTip(QDir::toNativeSeparators(value));
        connect(edit, &QLineEdit::textChanged, edit,
                [edit](const QString& text) { edit->setToolTip(QDir::toNativeSeparators(text)); });
    }
    fields_.append({flag, edit, required, numeric});
    auto* container = new QWidget;
    auto* layout = new QHBoxLayout(container);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->addWidget(edit);
    if (browse)
    {
        auto* button = new QPushButton(UiIcons::named(browse == 2 ? "save" : "folder-open"), "");
        const QString action = browse == 1   ? "Select input file"
                               : browse == 2 ? "Select output file"
                                             : "Select directory";
        button->setObjectName("BrowseButton");
        button->setToolTip(action);
        button->setAccessibleName(action + " — " + label);
        button->setFixedSize(34, 34);
        button->setIconSize(QSize(18, 18));
        layout->addWidget(button);
        connect(button, &QPushButton::clicked, this,
                [this, edit, browse]
                {
                    QString path;
                    if (browse == 1)
                    {
                        path = QFileDialog::getOpenFileName(this, "Select input", edit->text());
                    }
                    else if (browse == 2)
                    {
                        path = QFileDialog::getSaveFileName(this, "Select output", edit->text());
                    }
                    else
                    {
                        path = QFileDialog::getExistingDirectory(this, "Select directory",
                                                                 edit->text());
                    }
                    if (!path.isEmpty())
                    {
                        edit->setText(QDir::toNativeSeparators(path));
                        edit->setCursorPosition(0);
                    }
                });
    }
    form_->addRow(label, container);
}

void OperationDialog::addCheck(const QString& label, const QString& flag, bool checked)
{
    auto* check = new QCheckBox(label);
    check->setObjectName(flag);
    check->setChecked(checked);
    checks_.append({flag, check});
    form_->addRow(check);
}

QStringList OperationDialog::arguments() const
{
    QStringList arguments;
    if (pid_ && command_ != "launch" && command_ != "run" && command_ != "deobf")
    {
        arguments << "--pid" << QString::number(pid_);
    }
    for (const Field& field : fields_)
    {
        if (!field.edit->text().trimmed().isEmpty())
        {
            arguments << field.flag << field.edit->text().trimmed();
        }
    }
    for (const Check& check : checks_)
    {
        if (check.widget->isChecked())
        {
            arguments << check.flag;
        }
    }
    return arguments;
}

QString OperationDialog::outputPath() const
{
    for (const Field& field : fields_)
    {
        if (field.flag == "--out")
        {
            return field.edit->text().trimmed();
        }
    }
    return {};
}

void OperationDialog::validateAndAccept()
{
    for (const Field& field : fields_)
    {
        QString value = field.edit->text().trimmed();
        if (field.required && value.isEmpty())
        {
            error_->setText("Required value missing: " + field.flag);
            field.edit->setFocus();
            return;
        }
        bool valid = true;
        quint64 number = 0;
        if (field.numeric && !value.isEmpty())
        {
            number =
                value.toULongLong(&valid, value.startsWith("0x", Qt::CaseInsensitive) ? 16 : 10);
        }
        if (!valid)
        {
            error_->setText("Invalid number: " + field.flag);
            return;
        }
        const QMap<QString, quint64> limits = {
            {"--seconds", 86400},   {"--wait-ms", 3600000},  {"--max-mb", 4096},
            {"--size", 1048576},    {"--limit", 65536},      {"--addr", 0xffffffff},
            {"--base", 0xffffffff}, {"--entry", 0xffffffff}, {"--lo", 0xffffffff}};
        if (field.numeric && !value.isEmpty() && limits.contains(field.flag) &&
            (number > limits[field.flag] ||
             (number == 0 &&
              (field.flag == "--seconds" || field.flag == "--size" || field.flag == "--max-mb"))))
        {
            error_->setText("Value outside the supported range: " + field.flag);
            return;
        }
        if ((field.flag == "--live" || field.flag == "--file" || field.flag == "--dll" ||
             field.flag == "--exe" || field.flag == "--snap") &&
            !value.isEmpty() && !QFileInfo::exists(value))
        {
            error_->setText("Input file does not exist: " + value);
            return;
        }
    }
    if (command_ == "poke")
    {
        QStringList args = arguments();
        QString bytes = args.value(args.indexOf("--bytes") + 1);
        static const QRegularExpression validBytes("^[0-9A-Fa-f]{2}(\\s+[0-9A-Fa-f]{2})*$");
        if (!validBytes.match(bytes).hasMatch() || bytes.size() > 12288)
        {
            error_->setText(
                "Enter hexadecimal byte pairs separated by spaces (maximum 4096 bytes).");
            return;
        }
    }
    if (command_ == "watch")
    {
        const QStringList values = arguments();
        const QString mode = values.value(values.indexOf("--mode") + 1);
        static const QRegularExpression validMode("^[rwxRWX]{1,3}$");
        if (!validMode.match(mode).hasMatch())
        {
            error_->setText("Watch mode must contain r, w, or x.");
            return;
        }
    }
    const QString output = outputPath();
    if (!output.isEmpty())
    {
        for (const Field& field : fields_)
        {
            if (field.flag == "--out" || field.edit->text().trimmed().isEmpty())
            {
                continue;
            }
            if (field.flag == "--file" || field.flag == "--live" || field.flag == "--exe" ||
                field.flag == "--snap")
            {
                if (QFileInfo(field.edit->text())
                        .absoluteFilePath()
                        .compare(QFileInfo(output).absoluteFilePath(), Qt::CaseInsensitive) == 0)
                {
                    error_->setText("Output must use a different path from the input file.");
                    return;
                }
            }
        }
        QString directory = command_ == "deobf" ? output : QFileInfo(output).absolutePath();
        if (!QDir().mkpath(directory))
        {
            error_->setText("Cannot create output directory: " + directory);
            return;
        }
    }
    accept();
}
