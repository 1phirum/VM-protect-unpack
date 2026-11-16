#pragma once

#include <QDialog>
#include <QStringList>

struct OperationContext
{
    quint32 pid = 0;
    QString executable;
    QString artifactDirectory;
    QString agentPath;
    QString address;
};

class OperationDialog final : public QDialog
{
public:
    OperationDialog(const QString& command, const OperationContext& context,
                    QWidget* parent = nullptr);
    QStringList arguments() const;
    QString outputPath() const;

private:
    struct Field
    {
        QString flag;
        class QLineEdit* edit;
        bool required;
        bool numeric;
    };
    struct Check
    {
        QString flag;
        class QCheckBox* widget;
    };
    QList<Field> fields_;
    QList<Check> checks_;
    class QFormLayout* form_;
    class QLabel* error_;
    QString command_;
    quint32 pid_;

    void addField(const QString& label, const QString& flag, const QString& value,
                  bool required = false, bool numeric = false, int browse = 0);
    void addCheck(const QString& label, const QString& flag, bool checked = false);
    void validateAndAccept();
};
