#pragma once
#include <QProcess>
#include <QTimer>
class CommandRunner final : public QObject
{
    Q_OBJECT
public:
    explicit CommandRunner(QObject* parent = nullptr);
    ~CommandRunner() override;
    bool busy() const;
    QString workerPath() const;
    void setWorkerPath(const QString& path);
    void start(const QString& command, const QStringList& arguments);
    void cancel();
signals:
    void output(const QString& line);
    void started(const QString& command);
    void completed(const QString& command, int exitCode, bool cancelled);

private:
    QProcess process_;
    QString worker_, command_;
    QByteArray pending_;
    bool cancelled_ = false, reported_ = false;
    quint64 generation_ = 0;
    void drain(bool final = false);
};
